"""Interface en ligne de commande.

    python -m threathunter hunt samples/ --rules rules/ --iocs samples/iocs.txt -o rapport.html
    python -m threathunter watch /var/log/hunt/ --interval 300 -o rapport.html
    python -m threathunter validate rules/
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .analytics import ANALYTICS
from .engine import hunt
from .findings import SEVERITY_ORDER
from .ingest import load_events
from .iocs import IOCMatcher, load_iocs
from .report import to_console, to_html, to_json
from .rules import RuleError, load_rules

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def _run_once(args) -> int:
    rules = load_rules(args.rules)
    matcher = IOCMatcher(load_iocs(args.iocs)) if args.iocs else None
    events = load_events(args.logs)
    analytics = None if args.analytics == "all" else [a for a in args.analytics.split(",") if a]
    result = hunt(events, rules, matcher, analytics=analytics, min_severity=args.min_severity)
    if not args.quiet:
        print(to_console(result))
    for out in args.output or []:
        (to_json if out.lower().endswith(".json") else to_html)(result, out)
        print(f"\nRapport écrit : {out}", file=sys.stderr)
    # code retour exploitable en CI / SOAR : 2 si incident ou résultat critique
    if result.incidents or any(f.severity == "critical" for f in result.findings):
        return 2
    return 1 if result.findings else 0


def cmd_hunt(args) -> int:
    return _run_once(args)


def cmd_watch(args) -> int:
    print(f"Chasse planifiée toutes les {args.interval}s (Ctrl+C pour arrêter)", file=sys.stderr)
    try:
        while True:
            code = _run_once(args)
            print(f"--- cycle terminé (code {code}) ---", file=sys.stderr)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def cmd_validate(args) -> int:
    try:
        rules = load_rules(args.rules)
    except (RuleError, Exception) as exc:
        print(f"ERREUR : {exc}")
        return 1
    ids = [r.id for r in rules]
    dups = {i for i in ids if ids.count(i) > 1}
    for r in rules:
        print(f"OK  {r.id:<10} [{r.level:<8}] {r.title}  {','.join(r.techniques)}")
    if dups:
        print(f"ERREUR : identifiants dupliqués {sorted(dups)}")
        return 1
    print(f"\n{len(rules)} règle(s) valide(s).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threathunter", description="Threat hunting automatisé")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("logs", nargs="+", help="Fichiers ou dossiers de journaux")
        sp.add_argument("--rules", default=DEFAULT_RULES, help="Dossier de règles YAML")
        sp.add_argument("--iocs", help="Fichier d'IOC (une valeur par ligne ou CSV type,valeur,desc)")
        sp.add_argument("-o", "--output", action="append", help="Rapport .html ou .json (répétable)")
        sp.add_argument("--analytics", default="all",
                        help=f"Liste séparée par des virgules parmi : {','.join(ANALYTICS)} (ou 'all', ou '')")
        sp.add_argument("--min-severity", default="low", choices=SEVERITY_ORDER)
        sp.add_argument("-q", "--quiet", action="store_true")

    h = sub.add_parser("hunt", help="Lancer une chasse")
    common(h)
    h.set_defaults(func=cmd_hunt)

    w = sub.add_parser("watch", help="Relancer la chasse périodiquement")
    common(w)
    w.add_argument("--interval", type=int, default=300)
    w.set_defaults(func=cmd_watch)

    v = sub.add_parser("validate", help="Valider les règles")
    v.add_argument("rules", nargs="?", default=DEFAULT_RULES)
    v.set_defaults(func=cmd_validate)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
