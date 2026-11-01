"""Orchestration : règles + IOC + analytiques + corrélation par hôte."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .analytics import ANALYTICS
from .findings import Finding, SEVERITY_ORDER, evidence_view
from .iocs import IOCMatcher
from .rules import Rule

# Ordre simplifié de la kill chain ATT&CK pour la corrélation
TACTIC_ORDER = ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation",
                "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection",
                "command_and_control", "exfiltration", "impact"]


@dataclass
class HuntResult:
    events_analyzed: int
    rules_loaded: int
    findings: list[Finding]
    hosts: list[dict]
    incidents: list[dict]
    started: datetime
    finished: datetime
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "events_analyzed": self.events_analyzed,
                "rules_loaded": self.rules_loaded,
                "findings": len(self.findings),
                "incidents": len(self.incidents),
                "by_severity": {s: sum(f.severity == s for f in self.findings) for s in SEVERITY_ORDER},
                "started": self.started.isoformat(),
                "finished": self.finished.isoformat(),
            },
            "incidents": self.incidents,
            "hosts": self.hosts,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


def run_rules(events: list[dict], rules: list[Rule], max_evidence=5) -> list[Finding]:
    grouped: dict[tuple[str, str], Finding] = {}
    for e in events:
        for r in rules:
            try:
                if not r.matches(e):
                    continue
            except Exception:  # une règle défectueuse ne doit pas interrompre la chasse
                continue
            host = str(e.get("host") or "?")
            key = (r.id, host)
            f = grouped.get(key)
            if f is None:
                f = grouped[key] = Finding(
                    hunt="rule", title=r.title, severity=r.level, host=host, description=r.description,
                    techniques=r.techniques, tactics=r.tactics, rule_id=r.id,
                    first_seen=e.get("_ts"), last_seen=e.get("_ts"), count=0,
                )
            f.count += 1
            f.last_seen = e.get("_ts") or f.last_seen
            if len(f.evidence) < max_evidence:
                f.evidence.append(evidence_view(e))
    return list(grouped.values())


def run_iocs(events: list[dict], matcher: IOCMatcher, max_evidence=5) -> list[Finding]:
    grouped: dict[tuple[str, str], Finding] = {}
    for e in events:
        for fld, ioc in matcher.match(e):
            host = str(e.get("host") or "?")
            key = (ioc.value, host)
            f = grouped.get(key)
            if f is None:
                f = grouped[key] = Finding(
                    hunt="ioc", title=f"Correspondance IOC ({ioc.type}) : {ioc.value}", severity="high",
                    host=host, description=ioc.description or f"Indicateur connu observé dans le champ {fld}.",
                    tactics=["command_and_control"] if ioc.type in ("ip", "domain") else ["execution"],
                    rule_id=f"IOC-{ioc.type.upper()}", first_seen=e.get("_ts"), last_seen=e.get("_ts"),
                    count=0, entities={"ioc": ioc.value, "field": fld},
                )
            f.count += 1
            f.last_seen = e.get("_ts") or f.last_seen
            if len(f.evidence) < max_evidence:
                f.evidence.append(evidence_view(e))
    return list(grouped.values())


def correlate(findings: list[Finding]) -> tuple[list[dict], list[dict]]:
    """Score de risque par hôte et détection d'incidents multi-tactiques."""
    by_host = defaultdict(list)
    for f in findings:
        by_host[f.host].append(f)
    hosts, incidents = [], []
    for host, fs in by_host.items():
        tactics = sorted({t for f in fs for t in f.tactics},
                         key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        techniques = sorted({t for f in fs for t in f.techniques})
        # score : somme des sévérités + bonus de diversité tactique
        score = sum(f.score for f in fs) + 5 * max(len(tactics) - 1, 0)
        hosts.append({"host": host, "risk_score": score, "findings": len(fs),
                      "tactics": tactics, "techniques": techniques})
        high = [f for f in fs if f.severity in ("high", "critical")]
        if len(tactics) >= 3 and high:
            times = [t for f in fs for t in (f.first_seen, f.last_seen) if t]
            incidents.append({
                "host": host,
                "title": f"Activité d'intrusion probable sur {host}",
                "severity": "critical" if len(tactics) >= 4 else "high",
                "tactics": tactics, "techniques": techniques,
                "first_seen": min(times).isoformat() if times else None,
                "last_seen": max(times).isoformat() if times else None,
                "timeline": [
                    {"time": f.first_seen.isoformat() if f.first_seen else None,
                     "title": f.title, "severity": f.severity}
                    for f in sorted(fs, key=lambda x: x.first_seen or datetime.min.replace(tzinfo=timezone.utc))
                ],
            })
    hosts.sort(key=lambda h: -h["risk_score"])
    incidents.sort(key=lambda i: (i["severity"] != "critical", i["host"]))
    return hosts, incidents


def hunt(events: list[dict], rules: list[Rule], matcher: IOCMatcher | None = None,
         analytics: list[str] | None = None, min_severity: str = "informational") -> HuntResult:
    started = datetime.now(timezone.utc)
    errors: list[str] = []
    findings = run_rules(events, rules)
    if matcher:
        findings += run_iocs(events, matcher)
    for name in (analytics if analytics is not None else list(ANALYTICS)):
        fn = ANALYTICS.get(name)
        if not fn:
            errors.append(f"Analytique inconnue : {name}")
            continue
        try:
            findings += fn(events)
        except Exception as exc:  # pragma: no cover - robustesse
            errors.append(f"{name}: {exc}")
    threshold = SEVERITY_ORDER.index(min_severity)
    findings = [f for f in findings if SEVERITY_ORDER.index(f.severity if f.severity in SEVERITY_ORDER else "medium") >= threshold]
    findings.sort(key=lambda f: (-f.score, f.host, f.title))
    hosts, incidents = correlate(findings)
    return HuntResult(len(events), len(rules), findings, hosts, incidents, started,
                      datetime.now(timezone.utc), errors)
