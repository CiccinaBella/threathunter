"""Correspondance d'indicateurs de compromission (IOC).

Fichier IOC : une valeur par ligne (type détecté automatiquement), ou CSV
`type,value,description`. Les lignes commençant par # sont ignorées.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)

IP_FIELDS = ("src_ip", "dst_ip")
DOMAIN_FIELDS = ("dns_query", "url", "command_line")
HASH_FIELDS = ("hashes",)


@dataclass
class IOC:
    type: str
    value: str
    description: str = ""


def classify(value: str) -> str | None:
    v = value.strip().lower()
    try:
        ipaddress.ip_network(v, strict=False)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.fullmatch(v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def load_iocs(path: str) -> list[IOC]:
    iocs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0].lower() in ("ip", "domain", "hash"):
                iocs.append(IOC(parts[0].lower(), parts[1].lower(), ",".join(parts[2:])))
            else:
                kind = classify(parts[0])
                if kind:
                    iocs.append(IOC(kind, parts[0].lower(), ",".join(parts[1:])))
    return iocs


class IOCMatcher:
    def __init__(self, iocs: list[IOC]):
        self.networks = []
        self.ips: dict[str, IOC] = {}
        self.domains: dict[str, IOC] = {}
        self.hashes: dict[str, IOC] = {}
        for ioc in iocs:
            if ioc.type == "ip":
                if "/" in ioc.value:
                    self.networks.append((ipaddress.ip_network(ioc.value, strict=False), ioc))
                else:
                    self.ips[ioc.value] = ioc
            elif ioc.type == "domain":
                self.domains[ioc.value] = ioc
            elif ioc.type == "hash":
                self.hashes[ioc.value] = ioc

    def _domain_hit(self, text: str) -> IOC | None:
        text = text.lower()
        for dom, ioc in self.domains.items():
            # correspondance exacte ou sous-domaine, ou présence dans une URL / ligne de commande
            if text == dom or text.endswith("." + dom) or re.search(rf"(^|[^\w\-]){re.escape(dom)}($|[^\w\-])", text):
                return ioc
        return None

    def match(self, event: dict) -> list[tuple[str, IOC]]:
        hits = []
        for f in IP_FIELDS:
            v = event.get(f)
            if not v:
                continue
            v = str(v).lower()
            if v in self.ips:
                hits.append((f, self.ips[v]))
                continue
            try:
                addr = ipaddress.ip_address(v)
            except ValueError:
                continue
            for net, ioc in self.networks:
                if addr in net:
                    hits.append((f, ioc))
                    break
        if self.domains:
            for f in DOMAIN_FIELDS:
                v = event.get(f)
                if v and (ioc := self._domain_hit(str(v))):
                    hits.append((f, ioc))
        if self.hashes:
            for f in HASH_FIELDS:
                v = event.get(f)
                if v:
                    for h in _HASH_RE.findall(str(v)):
                        if h.lower() in self.hashes:
                            hits.append((f, self.hashes[h.lower()]))
        return hits
