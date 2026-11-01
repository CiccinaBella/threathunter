import unittest

from threathunter.ingest import normalize
from threathunter.rules import RuleError, parse_rule
from threathunter.engine import hunt


def rule(detection, **kw):
    return parse_rule({"title": "t", "id": kw.get("id", "R1"), "level": "medium", "detection": detection})


class RuleEngineTest(unittest.TestCase):
    def setUp(self):
        self.ev = normalize({"Computer": "PC1", "Image": r"C:\Tools\app.exe",
                             "CommandLine": "app.exe --mode alpha", "EventID": "1"})

    def test_aliases(self):
        self.assertEqual(self.ev["host"], "PC1")
        self.assertEqual(self.ev["event_id"], 1)

    def test_modifiers(self):
        self.assertTrue(rule({"s": {"process|endswith": r"\app.exe"}, "condition": "s"}).matches(self.ev))
        self.assertTrue(rule({"s": {"command_line|contains|all": ["mode", "alpha"]}, "condition": "s"}).matches(self.ev))
        self.assertFalse(rule({"s": {"command_line|contains|all": ["mode", "beta"]}, "condition": "s"}).matches(self.ev))
        self.assertTrue(rule({"s": {"event_id|gte": 1}, "condition": "s"}).matches(self.ev))

    def test_conditions(self):
        det = {"a": {"host": "PC1"}, "b": {"host": "PC2"}, "condition": "a and not b"}
        self.assertTrue(rule(det).matches(self.ev))
        det = {"sel_a": {"host": "PC9"}, "sel_b": {"host": "PC1"}, "condition": "1 of sel_*"}
        self.assertTrue(rule(det).matches(self.ev))
        det["condition"] = "all of sel_*"
        self.assertFalse(rule(det).matches(self.ev))

    def test_bad_condition(self):
        with self.assertRaises(RuleError):
            rule({"a": {"host": "x"}, "condition": "a and missing"})

    def test_hunt_groups_by_host(self):
        r = rule({"s": {"process|endswith": "app.exe"}, "condition": "s"})
        res = hunt([self.ev, self.ev], [r], analytics=[])
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].count, 2)


if __name__ == "__main__":
    unittest.main()
