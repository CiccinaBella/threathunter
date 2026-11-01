"""Ingestion et normalisation des journaux.

Formats supportés :
  * JSON Lines (.jsonl / .ndjson) – un événement par ligne (Sysmon exporté, EDR, Zeek JSON...)
  * JSON (.json) – tableau d'événements ou objet {"events": [...]}
  * CSV (.csv) – en-tête obligatoire
  * auth.log / secure (syslog Linux, sshd / sudo)

Chaque événement est normalisé vers un schéma commun (champs en minuscules) tout
en conservant les champs d'origine, afin que les règles puissent utiliser l'un
ou l'autre.
"""
from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

# Champs d'origine (Sysmon, Windows, Zeek, ECS...) -> champ normalisé
FIELD_ALIASES = {
    "utctime": "timestamp", "@timestamp": "timestamp", "ts": "timestamp",
    "timecreated": "timestamp", "time": "timestamp", "date": "timestamp",
    "computer": "host", "hostname": "host", "computername": "host", "host.name": "host",
    "user": "user", "username": "user", "targetusername": "user", "user.name": "user",
    "subjectusername": "user",
    "image": "process", "process.executable": "process", "newprocessname": "process",
    "parentimage": "parent_process", "process.parent.executable": "parent_process",
    "parentprocessname": "parent_process",
    "commandline": "command_line", "process.command_line": "command_line",
    "eventid": "event_id", "event.code": "event_id",
    "sourceip": "src_ip", "id.orig_h": "src_ip", "source.ip": "src_ip",
    "ipaddress": "src_ip", "src": "src_ip",
    "destinationip": "dst_ip", "id.resp_h": "dst_ip", "destination.ip": "dst_ip",
    "dst": "dst_ip",
    "destinationport": "dst_port", "id.resp_p": "dst_port", "destination.port": "dst_port",
    "queryname": "dns_query", "query": "dns_query", "dns.question.name": "dns_query",
    "hashes": "hashes", "hash": "hashes", "sha256": "hashes", "md5": "hashes",
    "targetfilename": "file_path", "file.path": "file_path",
    "targetobject": "registry_key", "registry.path": "registry_key",
    "logontype": "logon_type",
}

TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
)


def parse_timestamp(value) -> datetime | None:
    """Convertit une valeur de temps hétérogène en datetime UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value)):
        num = float(value)
        if num > 1e12:  # millisecondes
            num /= 1000.0
        return datetime.fromtimestamp(num, tz=timezone.utc)
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _flatten(obj: dict, prefix: str = "") -> dict:
    out = {}
    for key, val in obj.items():
        full = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(val, dict):
            out.update(_flatten(val, full))
        else:
            out[full] = val
    return out


def normalize(raw: dict, source: str = "") -> dict:
    """Retourne un événement normalisé (clés en minuscules + alias communs)."""
    flat = _flatten(raw)
    event: dict = {}
    for key, val in flat.items():
        lk = key.lower()
        event[lk] = val
        alias = FIELD_ALIASES.get(lk)
        if alias and alias not in event:
            event[alias] = val
    for key in ("event_id", "dst_port", "logon_type"):
        if key in event and isinstance(event[key], str) and event[key].isdigit():
            event[key] = int(event[key])
    event["_ts"] = parse_timestamp(event.get("timestamp"))
    event["_source"] = source
    return event


# --- Parseur auth.log -------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)")
_SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")


def parse_auth_line(line: str, year: int | None = None) -> dict | None:
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        return None
    year = year or datetime.now(timezone.utc).year
    ts = datetime.strptime(f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    raw = {"timestamp": ts.isoformat(), "host": m["host"], "program": m["prog"], "message": m["msg"]}
    msg = m["msg"]
    if (f := _SSH_FAIL.search(msg)):
        raw.update(event_type="auth_failure", user=f["user"], src_ip=f["ip"])
    elif (s := _SSH_OK.search(msg)):
        raw.update(event_type="auth_success", user=s["user"], src_ip=s["ip"])
    elif m["prog"] == "sudo" and (su := _SUDO.match(msg)):
        raw.update(event_type="sudo", user=su["user"], command_line=su["cmd"].strip())
    else:
        raw["event_type"] = "syslog"
    return raw


# --- Chargement ---------------------------------------------------------------
def _iter_file(path: str) -> Iterator[dict]:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if ext in (".jsonl", ".ndjson"):
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        elif ext == ".json":
            data = json.load(fh)
            if isinstance(data, dict):
                data = data.get("events") or data.get("records") or [data]
            yield from (d for d in data if isinstance(d, dict))
        elif ext == ".csv":
            yield from csv.DictReader(fh)
        elif "auth" in name or "secure" in name or ext in (".log", ".syslog"):
            for line in fh:
                parsed = parse_auth_line(line)
                if parsed:
                    yield parsed


def load_events(paths: Iterable[str]) -> list[dict]:
    """Charge et normalise tous les événements des fichiers / dossiers donnés."""
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files.extend(os.path.join(root, n) for n in sorted(names))
        else:
            files.append(p)
    events = []
    for f in files:
        for raw in _iter_file(f):
            events.append(normalize(raw, source=os.path.basename(f)))
    events.sort(key=lambda e: e["_ts"] or datetime.min.replace(tzinfo=timezone.utc))
    return events
