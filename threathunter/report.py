"""Génération des rapports (JSON, HTML autonome, console)."""
from __future__ import annotations

import html
import json

from .engine import HuntResult

SEV_COLORS = {"critical": "#b3261e", "high": "#d9480f", "medium": "#c28a00", "low": "#2f6fb0",
              "informational": "#6b7280"}


def to_json(result: HuntResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False, default=str)


def to_console(result: HuntResult) -> str:
    d = result.to_dict()["summary"]
    lines = [
        f"Événements analysés : {d['events_analyzed']}   Règles : {d['rules_loaded']}   "
        f"Résultats : {d['findings']}   Incidents : {d['incidents']}",
        "Sévérités : " + ", ".join(f"{k}={v}" for k, v in d["by_severity"].items() if v),
        "",
    ]
    if result.incidents:
        lines.append("=== INCIDENTS CORRÉLÉS ===")
        for i in result.incidents:
            lines.append(f"[{i['severity'].upper()}] {i['title']}  ({' → '.join(i['tactics'])})")
        lines.append("")
    lines.append("=== HÔTES LES PLUS À RISQUE ===")
    for h in result.hosts[:10]:
        lines.append(f"{h['risk_score']:>5}  {h['host']:<25} {h['findings']} résultat(s)")
    lines.append("")
    lines.append("=== RÉSULTATS ===")
    for f in result.findings:
        tech = ",".join(f.techniques)
        lines.append(f"[{f.severity.upper():<8}] {f.host:<20} {f.title} (x{f.count}) {tech}")
    if result.errors:
        lines += ["", "Erreurs : " + "; ".join(result.errors)]
    return "\n".join(lines)


def _e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def to_html(result: HuntResult, path: str) -> None:
    data = result.to_dict()
    s = data["summary"]
    sev_cards = "".join(
        f'<div class="card"><div class="n" style="color:{SEV_COLORS[k]}">{v}</div><div>{k}</div></div>'
        for k, v in reversed(list(s["by_severity"].items())))

    incidents = ""
    for i in data["incidents"]:
        tl = "".join(f'<li><code>{_e(t["time"])}</code> <span class="sev {t["severity"]}">{t["severity"]}</span> '
                     f'{_e(t["title"])}</li>' for t in i["timeline"])
        incidents += (f'<div class="incident"><h3><span class="sev {i["severity"]}">{i["severity"]}</span> '
                      f'{_e(i["title"])}</h3><p>Chaîne tactique : <b>{_e(" → ".join(i["tactics"]))}</b><br>'
                      f'Techniques : {_e(", ".join(i["techniques"]))}</p><ol>{tl}</ol></div>')
    incidents = incidents or "<p>Aucun incident multi-tactique corrélé.</p>"

    hosts = "".join(f'<tr><td>{_e(h["host"])}</td><td><b>{h["risk_score"]}</b></td><td>{h["findings"]}</td>'
                    f'<td>{_e(", ".join(h["tactics"]))}</td><td>{_e(", ".join(h["techniques"]))}</td></tr>'
                    for h in data["hosts"])

    rows = ""
    for idx, f in enumerate(data["findings"]):
        ev = "".join("<pre>" + _e(json.dumps(x, ensure_ascii=False, indent=1)) + "</pre>" for x in f["evidence"])
        links = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/" target="_blank">{_e(t)}</a>'
            for t in f["techniques"])
        rows += (f'<tr class="f" data-sev="{f["severity"]}" data-text="{_e((f["title"] + f["host"]).lower())}">'
                 f'<td><span class="sev {f["severity"]}">{f["severity"]}</span></td><td>{_e(f["host"])}</td>'
                 f'<td>{_e(f["title"])}<div class="muted">{_e(f["rule_id"])} · {_e(f["hunt"])}</div></td>'
                 f'<td>{f["count"]}</td><td>{links}</td><td>{_e(f["first_seen"])}</td>'
                 f'<td><details><summary>Détails</summary><p>{_e(f["description"])}</p>{ev}</details></td></tr>')

    page = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Rapport Threat Hunting</title>
<style>
:root{{--bg:#f7f7f8;--fg:#1c1c1e;--card:#fff;--muted:#6b7280;--line:#e5e7eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151517;--fg:#ececec;--card:#1f1f23;--muted:#9ca3af;--line:#33343a}}}}
body{{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:1200px;margin:auto;padding:24px 16px}}
h1{{margin:0 0 4px}} .muted{{color:var(--muted);font-size:12px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:110px}}
.card .n{{font-size:26px;font-weight:700}}
section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0;overflow-x:auto}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
.sev{{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;text-transform:uppercase}}
.critical{{background:#b3261e}}.high{{background:#d9480f}}.medium{{background:#c28a00}}.low{{background:#2f6fb0}}.informational{{background:#6b7280}}
.incident{{border-left:4px solid #b3261e;padding:4px 12px;margin:10px 0}}
pre{{white-space:pre-wrap;word-break:break-all;font-size:12px;background:var(--bg);padding:8px;border-radius:6px}}
input,select{{padding:6px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}}
a{{color:#2f6fb0}}
</style></head><body><main>
<h1>Rapport de Threat Hunting</h1>
<div class="muted">Généré le {_e(s["finished"])} · {s["events_analyzed"]} événements · {s["rules_loaded"]} règles</div>
<div class="cards"><div class="card"><div class="n">{s["incidents"]}</div><div>incidents</div></div>
<div class="card"><div class="n">{s["findings"]}</div><div>résultats</div></div>{sev_cards}</div>
<section><h2>Incidents corrélés</h2>{incidents}</section>
<section><h2>Hôtes par score de risque</h2><table><tr><th>Hôte</th><th>Score</th><th>Résultats</th><th>Tactiques</th><th>Techniques</th></tr>{hosts}</table></section>
<section><h2>Résultats</h2>
<p><input id="q" placeholder="Filtrer (hôte, titre)…"> <select id="s"><option value="">Toutes sévérités</option>
<option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option></select></p>
<table><tr><th>Sévérité</th><th>Hôte</th><th>Titre</th><th>Nb</th><th>ATT&amp;CK</th><th>Première vue</th><th></th></tr>{rows}</table></section>
</main><script>
const q=document.getElementById('q'),s=document.getElementById('s');
function f(){{document.querySelectorAll('tr.f').forEach(r=>{{r.style.display=(!s.value||r.dataset.sev===s.value)&&r.dataset.text.includes(q.value.toLowerCase())?'':'none'}})}}
q.oninput=f;s.onchange=f;
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
