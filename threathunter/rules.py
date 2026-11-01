"""Moteur de règles compatible avec un sous-ensemble de Sigma.

Format d'une règle (YAML) :

    title: PowerShell encodé
    id: TH-0001
    level: high                    # informational|low|medium|high|critical
    tags: [attack.execution, attack.t1059.001]
    detection:
      selection:
        process|endswith: '\\powershell.exe'
        command_line|contains: [' -enc', ' -encodedcommand']
      filter:
        user: 'SYSTEM'
      condition: selection and not filter

Modificateurs : contains, startswith, endswith, re, all, gt, gte, lt, lte, cidr.
Conditions : and, or, not, parenthèses, "1 of selection*", "all of selection*",
"1 of them", "all of them".
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from dataclasses import dataclass, field

import yaml

LEVEL_SCORE = {"informational": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


class RuleError(ValueError):
    pass


# --- Évaluation des valeurs -------------------------------------------------
def _match_value(actual, expected, modifiers: list[str]) -> bool:
    if actual is None:
        return expected is None
    if expected is None:
        return False
    mods = [m for m in modifiers if m != "all"]
    op = mods[0] if mods else "eq"

    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    if op == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if op == "re":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None

    a, e = str(actual).lower(), str(expected).lower()
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    # égalité, avec support des jokers Sigma (* et ?)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    if isinstance(actual, (int, float)) and not isinstance(actual, bool):
        try:
            return float(actual) == float(expected)
        except ValueError:
            return False
    return a == e


def _match_field(event: dict, key: str, expected) -> bool:
    name, *modifiers = key.split("|")
    actual = event.get(name.lower())
    values = expected if isinstance(expected, list) else [expected]
    if "all" in modifiers:
        return all(_match_value(actual, v, modifiers) for v in values)
    return any(_match_value(actual, v, modifiers) for v in values)


def _match_selection(event: dict, selection) -> bool:
    if isinstance(selection, list):  # liste de maps = OU
        return any(_match_selection(event, s) for s in selection)
    if isinstance(selection, dict):  # map = ET
        return all(_match_field(event, k, v) for k, v in selection.items())
    raise RuleError(f"Sélection invalide : {selection!r}")


# --- Parseur de condition ------------------------------------------------------
_TOKEN_RE = re.compile(r"\(|\)|[\w\*\-\.]+")


class _Condition:
    def __init__(self, text: str, names: list[str]):
        self.tokens = _TOKEN_RE.findall(text)
        self.names = names
        self.pos = 0
        self.tree = self._parse_or()
        if self.pos != len(self.tokens):
            raise RuleError(f"Condition invalide près de '{self.tokens[self.pos]}' : {text}")

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == "or":
            self._next()
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek() == "and":
            self._next()
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._parse_not())
        return self._parse_atom()

    def _parse_atom(self):
        tok = self._peek()
        if tok is None:
            raise RuleError("Condition incomplète")
        if tok == "(":
            self._next()
            node = self._parse_or()
            if self._peek() != ")":
                raise RuleError("Parenthèse fermante manquante")
            self._next()
            return node
        if tok in ("1", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._next().lower()
            self._next()
            pattern = self._next()
            targets = self.names if pattern == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            if not targets:
                raise RuleError(f"Aucune sélection ne correspond à '{pattern}'")
            return ("any" if quant == "1" else "all", targets)
        name = self._next()
        if name not in self.names:
            raise RuleError(f"Sélection inconnue '{name}'")
        return ("sel", name)

    def evaluate(self, results: dict[str, bool]) -> bool:
        def ev(node):
            kind = node[0]
            if kind == "sel":
                return results[node[1]]
            if kind == "not":
                return not ev(node[1])
            if kind == "and":
                return ev(node[1]) and ev(node[2])
            if kind == "or":
                return ev(node[1]) or ev(node[2])
            if kind == "any":
                return any(results[n] for n in node[1])
            if kind == "all":
                return all(results[n] for n in node[1])
            raise RuleError(kind)
        return ev(self.tree)


# --- Règle -------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    selections: dict
    condition: _Condition
    falsepositives: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def score(self) -> int:
        return LEVEL_SCORE.get(self.level, 5)

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags
                if t.lower().startswith("attack.t")]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags
                if t.lower().startswith("attack.") and not t.lower().startswith("attack.t")]

    def matches(self, event: dict) -> bool:
        results = {name: _match_selection(event, sel) for name, sel in self.selections.items()}
        return self.condition.evaluate(results)


def parse_rule(doc: dict, path: str = "") -> Rule:
    if not isinstance(doc, dict) or "detection" not in doc:
        raise RuleError(f"{path}: champ 'detection' manquant")
    detection = dict(doc["detection"])
    cond_text = detection.pop("condition", None)
    if not cond_text:
        raise RuleError(f"{path}: 'condition' manquante")
    if isinstance(cond_text, list):
        cond_text = " or ".join(f"({c})" for c in cond_text)
    selections = detection
    rule_id = str(doc.get("id") or os.path.splitext(os.path.basename(path))[0])
    return Rule(
        id=rule_id,
        title=doc.get("title", rule_id),
        level=str(doc.get("level", "medium")).lower(),
        description=doc.get("description", ""),
        tags=[str(t) for t in doc.get("tags", [])],
        selections=selections,
        condition=_Condition(str(cond_text), list(selections)),
        falsepositives=doc.get("falsepositives", []) or [],
        path=path,
    )


def load_rules(directory: str) -> list[Rule]:
    rules = []
    for root, _, names in os.walk(directory):
        for n in sorted(names):
            if n.endswith((".yml", ".yaml")):
                p = os.path.join(root, n)
                with open(p, encoding="utf-8") as fh:
                    for doc in yaml.safe_load_all(fh):
                        if doc:
                            rules.append(parse_rule(doc, p))
    return rules
