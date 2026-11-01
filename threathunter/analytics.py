"""Chasses comportementales (hypothèses statistiques, sans signature).

Chaque analytique prend la liste d'événements normalisés et renvoie des Findings.
"""
from __future__ import annotations

import base64
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from .findings import Finding, evidence_view


def _basename(path) -> str:
    return re.split(r"[\\/]", str(path or ""))[-1].lower()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --- 1. Beaconing C2 -----------------------------------------------------------
def hunt_beaconing(events, min_connections=8, max_cv=0.15, min_interval=5.0):
    """Connexions sortantes à intervalle régulier (faible coefficient de variation)."""
    flows = defaultdict(list)
    for e in events:
        if e.get("dst_ip") and e.get("_ts") and not _is_private(e["dst_ip"]):
            flows[(e.get("host", "?"), e["dst_ip"], e.get("dst_port"))].append(e)
    findings = []
    for (host, dst, port), evs in flows.items():
        if len(evs) < min_connections:
            continue
        times = sorted(x["_ts"] for x in evs)
        deltas = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        deltas = [d for d in deltas if d > 0]
        if len(deltas) < min_connections - 1:
            continue
        mean = statistics.mean(deltas)
        if mean < min_interval:
            continue
        cv = statistics.pstdev(deltas) / mean
        if cv <= max_cv:
            procs = Counter(_basename(x.get("process")) for x in evs if x.get("process"))
            findings.append(Finding(
                hunt="analytic", title="Beaconing réseau suspect (C2)",
                severity="high" if cv < 0.05 else "medium", host=host,
                description=(f"{len(evs)} connexions vers {dst}:{port} toutes les ~{mean:.0f}s "
                             f"(coefficient de variation {cv:.3f}). Processus : "
                             f"{', '.join(p for p, _ in procs.most_common(3)) or 'inconnu'}."),
                techniques=["T1071", "T1573"], tactics=["command_and_control"],
                rule_id="TH-A-BEACON", first_seen=times[0], last_seen=times[-1], count=len(evs),
                evidence=[evidence_view(x) for x in evs[:5]],
                entities={"dst_ip": dst, "dst_port": port, "interval_s": round(mean, 1), "cv": round(cv, 4)},
            ))
    return findings


def _is_private(ip) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip))
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


# --- 2. Brute force / password spraying -----------------------------------------
def _is_failure(e) -> bool:
    return e.get("event_type") == "auth_failure" or e.get("event_id") == 4625


def _is_success(e) -> bool:
    return e.get("event_type") == "auth_success" or e.get("event_id") == 4624


def hunt_bruteforce(events, threshold=10, window=timedelta(minutes=10), spray_users=5):
    findings = []
    by_src = defaultdict(list)
    for e in events:
        if (_is_failure(e) or _is_success(e)) and e.get("src_ip") and e.get("_ts"):
            by_src[e["src_ip"]].append(e)
    for src, evs in by_src.items():
        fails = [e for e in evs if _is_failure(e)]
        if len(fails) < threshold:
            continue
        # fenêtre glissante
        start, best = 0, (0, 0, 0)
        for end in range(len(fails)):
            while fails[end]["_ts"] - fails[start]["_ts"] > window:
                start += 1
            if end - start + 1 > best[0]:
                best = (end - start + 1, start, end)
        n, s, en = best
        if n < threshold:
            continue
        burst = fails[s:en + 1]
        users = {e.get("user") for e in burst if e.get("user")}
        last_fail = burst[-1]["_ts"]
        successes = [e for e in evs if _is_success(e) and timedelta(0) <= e["_ts"] - last_fail <= window]
        spraying = len(users) >= spray_users
        compromised = bool(successes)
        title = "Password spraying" if spraying else "Brute force d'authentification"
        if compromised:
            title += " suivi d'une connexion réussie"
        host = burst[-1].get("host", "?")
        findings.append(Finding(
            hunt="analytic", title=title,
            severity="critical" if compromised else ("high" if spraying else "medium"),
            host=host,
            description=(f"{n} échecs d'authentification depuis {src} en moins de "
                         f"{int(window.total_seconds() // 60)} min sur {len(users)} compte(s)"
                         + (f" ; connexion réussie ensuite pour : "
                            f"{', '.join(sorted({e.get('user', '?') for e in successes}))}." if compromised else ".")),
            techniques=["T1110.003" if spraying else "T1110.001"] + (["T1078"] if compromised else []),
            tactics=["credential_access"] + (["initial_access"] if compromised else []),
            rule_id="TH-A-BRUTE", first_seen=burst[0]["_ts"],
            last_seen=(successes[-1]["_ts"] if successes else last_fail), count=n,
            evidence=[evidence_view(e) for e in (burst[:3] + successes[:2])],
            entities={"src_ip": src, "users": sorted(users)[:20]},
        ))
    return findings


# --- 3. Relations parent/enfant rares (stacking) ---------------------------------
def hunt_rare_parent_child(events, max_count=1, min_population=50):
    pairs = Counter()
    examples = {}
    for e in events:
        if e.get("process") and e.get("parent_process"):
            key = (_basename(e["parent_process"]), _basename(e["process"]))
            pairs[key] += 1
            examples.setdefault(key, e)
    total = sum(pairs.values())
    if total < min_population:
        return []
    suspicious_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "w3wp.exe",
                          "sqlservr.exe", "httpd", "nginx", "java.exe", "acrord32.exe", "mshta.exe"}
    findings = []
    for (parent, child), c in pairs.items():
        if c > max_count:
            continue
        e = examples[(parent, child)]
        sev = "medium" if parent in suspicious_parents else "low"
        findings.append(Finding(
            hunt="analytic", title=f"Relation parent/enfant rare : {parent} → {child}",
            severity=sev, host=e.get("host", "?"),
            description=(f"Couple observé {c} fois sur {total} créations de processus "
                         "(analyse de fréquence / stacking)."),
            techniques=["T1059"], tactics=["execution"], rule_id="TH-A-RAREPC",
            first_seen=e.get("_ts"), last_seen=e.get("_ts"), count=c,
            evidence=[evidence_view(e)], entities={"parent": parent, "child": child},
        ))
    return findings


# --- 4. Lignes de commande obfusquées -------------------------------------------
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def hunt_obfuscated_commands(events, min_entropy=5.0, min_len=200):
    findings = []
    for e in events:
        cmd = str(e.get("command_line") or "")
        if len(cmd) < 40:
            continue
        reasons, decoded = [], None
        m = _B64_RE.search(cmd)
        if m:
            try:
                raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4))
                text = raw.decode("utf-16-le") if b"\x00" in raw[:20] else raw.decode("utf-8")
                if sum(ch.isprintable() for ch in text) / max(len(text), 1) > 0.9:
                    decoded = text
                    reasons.append("charge base64 décodable")
            except Exception:
                pass
        ent = shannon_entropy(cmd)
        if len(cmd) >= min_len and ent >= min_entropy:
            reasons.append(f"entropie élevée ({ent:.2f})")
        if cmd.count("^") >= 5 or cmd.count("`") >= 5 or re.search(r"(\+\s*['\"]\w{1,3}['\"]\s*){4,}", cmd):
            reasons.append("caractères d'échappement / concaténation")
        if not reasons:
            continue
        sev = "high" if decoded and re.search(r"(?i)downloadstring|iex|invoke-|net\.webclient|http", decoded) else "medium"
        findings.append(Finding(
            hunt="analytic", title="Ligne de commande obfusquée",
            severity=sev, host=e.get("host", "?"),
            description=f"Indicateurs : {', '.join(reasons)}."
                        + (f" Contenu décodé : {decoded[:300]}" if decoded else ""),
            techniques=["T1027", "T1059"], tactics=["defense_evasion", "execution"],
            rule_id="TH-A-OBFUSC", first_seen=e.get("_ts"), last_seen=e.get("_ts"),
            evidence=[evidence_view(e)], entities={"process": _basename(e.get("process"))},
        ))
    return findings


# --- 5. Domaines DGA / tunneling DNS -------------------------------------------
def hunt_dns_anomalies(events, label_entropy=3.8, min_label_len=12, tunnel_len=50):
    findings = []
    per_host = defaultdict(list)
    for e in events:
        q = e.get("dns_query")
        if not q:
            continue
        labels = str(q).lower().rstrip(".").split(".")
        if len(labels) < 2:
            continue
        sub = labels[0] if len(labels) == 2 else max(labels[:-2], key=len)
        longest = max(labels[:-1], key=len)
        if len(".".join(labels[:-2])) >= tunnel_len:
            per_host[(e.get("host", "?"), "tunnel", ".".join(labels[-2:]))].append(e)
        elif len(longest) >= min_label_len and shannon_entropy(longest) >= label_entropy and sub:
            per_host[(e.get("host", "?"), "dga", "")].append(e)
    for (host, kind, domain), evs in per_host.items():
        if kind == "tunnel" and len(evs) >= 5:
            findings.append(Finding(
                hunt="analytic", title=f"Tunneling DNS probable vers {domain}", severity="high", host=host,
                description=f"{len(evs)} requêtes avec sous-domaines très longs vers {domain}.",
                techniques=["T1071.004", "T1048"], tactics=["command_and_control", "exfiltration"],
                rule_id="TH-A-DNSTUN", first_seen=evs[0]["_ts"], last_seen=evs[-1]["_ts"], count=len(evs),
                evidence=[evidence_view(x) for x in evs[:5]], entities={"domain": domain},
            ))
        elif kind == "dga" and len(evs) >= 3:
            doms = sorted({x["dns_query"] for x in evs})
            findings.append(Finding(
                hunt="analytic", title="Domaines générés algorithmiquement (DGA)", severity="medium", host=host,
                description=f"{len(doms)} domaine(s) à forte entropie résolus : {', '.join(doms[:5])}…",
                techniques=["T1568.002"], tactics=["command_and_control"], rule_id="TH-A-DGA",
                first_seen=evs[0]["_ts"], last_seen=evs[-1]["_ts"], count=len(evs),
                evidence=[evidence_view(x) for x in evs[:5]], entities={"domains": doms[:20]},
            ))
    return findings


ANALYTICS = {
    "beaconing": hunt_beaconing,
    "bruteforce": hunt_bruteforce,
    "rare_parent_child": hunt_rare_parent_child,
    "obfuscation": hunt_obfuscated_commands,
    "dns": hunt_dns_anomalies,
}
