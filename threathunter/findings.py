"""Structure commune des résultats de chasse."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
SEVERITY_SCORE = {"informational": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


@dataclass
class Finding:
    hunt: str                 # "rule", "ioc" ou "analytic"
    title: str
    severity: str
    host: str
    description: str
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    rule_id: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 1
    evidence: list[dict] = field(default_factory=list)
    entities: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 5)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        for k in ("first_seen", "last_seen"):
            d[k] = d[k].isoformat() if d[k] else None
        return d


def evidence_view(event: dict, max_len: int = 400) -> dict:
    """Version compacte et sérialisable d'un événement, pour le rapport."""
    keys = ("timestamp", "host", "user", "event_id", "event_type", "process", "parent_process",
            "command_line", "src_ip", "dst_ip", "dst_port", "dns_query", "file_path",
            "registry_key", "hashes", "message", "_source")
    out = {}
    for k in keys:
        v = event.get(k)
        if v not in (None, ""):
            s = str(v)
            out[k] = s if len(s) <= max_len else s[:max_len] + "…"
    return out
