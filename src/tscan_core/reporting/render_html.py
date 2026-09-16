"""Export HTML du rapport de sécurité au format ZAP (parité OWASP ZAP).

Reproduit la structure du rapport HTML « ZAP by Checkmarx Scanning Report »
afin que les deux documents se lisent de la même façon :

* en-tête avec le titre et la date de génération ;
* « Summary of Alerts » : compteurs par niveau de risque (Haut / Moyen /
  Faible / Pour information) ;
* tableau « Alertes » : liste des types d'alertes avec leur niveau de risque
  et le nombre d'instances ;
* « Alert Detail » : un tableau par type d'alerte, regroupant les instances
  (URL, paramètre, preuve, description, solution, références/CWE).

Document HTML autonome (CSS inline), échappant systématiquement tous les
contenus issus de la base ou des règles (XSS sûr).
"""

from __future__ import annotations

from collections import Counter
from html import escape

from tscan_core.reporting import (
    CWE_LINK_TEMPLATE,
    STATUS_LABEL,
    Report,
    ReportFinding,
    ReportTarget,
)

# Cartographie gravité Tscan -> niveau de risque ZAP.
RISK_ORDER = ["high", "medium", "low", "info"]
RISK_LEVEL = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}
RISK_LABEL = {
    3: "Haut",
    2: "Moyen",
    1: "Faible",
    0: "Pour information",
}
_RISK_ROW_ORDER = [3, 2, 1, 0]

# Couleurs de fond pour les pastilles de statut dans le tableau des alertes.
_STATUS_BG = {
    "confirmed": "#1a7f37",
    "probable": "#0969da",
    "potential_false_positive": "#bf8700",
    "false_positive": "#cf222e",
    "unvalidated": "#6e7781",
}


def _risk(finding: ReportFinding) -> int:
    """Niveau de risque ZAP (3..0) d'un résultat."""
    return RISK_LEVEL.get(finding.severity, 0)


def _risk_label(level: int) -> str:
    return RISK_LABEL[level]


_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<META http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Tscan - Rapport de sécurité (format ZAP)</title>
<style type="text/css">
body {{ font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; color: #000; font-size: 13px; }}
h1 {{ text-align: center; font-weight: bold; font-size: 28px; }}
h3 {{ font-size: 16px; }}
table {{ border: none; font-size: 13px; }}
td, th {{ padding: 3px 4px; word-break: break-word; }}
th {{ font-weight: bold; background-color: #666666; }}
td {{ background-color: #e8e8e8; }}
.spacer {{ margin: 10px; }}
.spacer-lg {{ margin: 40px; }}
.indent1 {{ padding: 4px 20px; }}
.indent2 {{ padding: 4px 40px; }}
.risk-3 {{ background-color: red; color: #FFF; }}
.risk-2 {{ background-color: orange; color: #FFF; }}
.risk-1 {{ background-color: yellow; color: #000; }}
.risk-0 {{ background-color: blue; color: #FFF; }}
.summary {{ width: 45%; }}
.summary th {{ color: #FFF; }}
.alerts {{ width: 75%; }}
.alerts th {{ color: #FFF; }}
.results {{ width: 100%; }}
.results th {{ text-align: left; }}
.left-header {{ display: inline-block; }}
</style>
</head>
<body>
<h1>Tscan - Rapport de sécurité</h1>
<p />
{site_blocks}
</body>
</html>
"""


def render_html(report: Report) -> str:
    """Rend un rapport au format HTML de style ZAP (RF-29, parité ZAP)."""
    site_blocks = "\n".join(_render_site(rt, report) for rt in report.targets)
    return _TEMPLATE.format(site_blocks=site_blocks)


def _render_site(target: ReportTarget, report: Report) -> str:
    findings = sorted(target.findings, key=lambda f: _risk(f), reverse=True)

    # Regroupe les résultats par titre : un type d'alerte, N instances.
    by_title: list[tuple[str, list[ReportFinding]]] = []
    seen: dict[str, int] = {}
    for f in findings:
        key = f.title
        if key in seen:
            by_title[seen[key]][1].append(f)
        else:
            seen[key] = len(by_title)
            by_title.append((key, [f]))

    # Summary of Alerts : nombre de TYPES d'alertes distincts par niveau de
    # risque (parité avec le rapport ZAP), et non le nombre d'instances.
    counts = Counter(_risk(group[0]) for _title, group in by_title)
    summary_rows = "\n".join(
        f"""<tr>
\t\t\t\t<td class="risk-{level}"><div>{_risk_label(level)}</div></td>
\t\t\t\t<td align="center"><div>{counts.get(level, 0)}</div></td>
\t\t\t</tr>"""
        for level in _RISK_ROW_ORDER
    )

    alert_rows = "\n".join(
        _render_alert_row(title, group) for title, group in by_title
    )

    details = "\n\t\t<div class=\"spacer\"></div>\n\t\t".join(
        _render_alert_detail(title, group) for title, group in by_title
    )

    return f"""
<h2>
\t\t
\t\tSite: {escape(target.target)}
\t\t
\t</h2>
\t<h3>Généré le {escape(report.generated_at)}</h3>
\t<h4>Tscan - moteur de scan de sécurité</h4>

\t<h3 class="left-header">Summary of Alerts</h3>
\t<table class="summary">
\t\t<tr>
\t\t\t<th width="45%" height="24">Niveau de risque</th>
\t\t\t<th width="55%" align="center">Number of Alerts</th>
\t\t</tr>
{summary_rows}
\t</table>
\t<div class="spacer-lg"></div>

\t<h3>Alertes</h3>
\t<table class="alerts">
\t\t<tr>
\t\t\t<th width="40%" height="24">Nom</th>
\t\t\t<th width="18%" align="center">Niveau de risque</th>
\t\t\t<th width="12%" align="center">Instances</th>
\t\t\t<th width="30%" align="center">Statut</th>
\t\t</tr>
{alert_rows}
\t</table>
\t<div class="spacer-lg"></div>

\t<h3>Alert Detail</h3>
\t\t{details}
"""


def _render_alert_row(title: str, group: list[ReportFinding]) -> str:
    risk = _risk(group[0])
    anchor = _anchor(group[0])
    instances = "Systemic" if len(group) >= 5 else str(len(group))
    status_badges = _status_badges(group)
    return (
        f"\t\t\t<tr>\n"
        f"\t\t\t\t<td><a href=\"#{anchor}\">{escape(title)}</a></td>\n"
        f"\t\t\t\t<td align=\"center\" class=\"risk-{risk}\">{_risk_label(risk)}</td>\n"
        f"\t\t\t\t<td align=\"center\">{instances}</td>\n"
        f"\t\t\t\t<td align=\"center\">{status_badges}</td>\n"
        f"\t\t\t</tr>"
    )


def _status_badges(group: list[ReportFinding]) -> str:
    """Rend une série de pastilles colorées pour les statuts présents dans le groupe."""
    from collections import Counter

    badge_style = (
        "display:inline-block; padding:1px 6px; margin:1px; border-radius:3px; "
        "font-size:11px; color:#fff; white-space:nowrap;"
    )
    counts = Counter(f.status.value for f in group)
    ordered = [s for s in ("confirmed", "probable", "potential_false_positive",
                           "false_positive", "unvalidated") if s in counts]
    parts: list[str] = []
    for status_key in ordered:
        label = STATUS_LABEL.get(status_key, status_key)
        color = _STATUS_BG.get(status_key, "#6e7781")
        count = counts[status_key]
        text = f"{label} ({count})" if count > 1 else label
        parts.append(
            f"<span style=\"{badge_style}background-color:{color}\">"
            f"{escape(text)}</span>"
        )
    return " ".join(parts)


def _render_alert_detail(title: str, group: list[ReportFinding]) -> str:
    risk = _risk(group[0])
    anchor = _anchor(group[0])
    first = group[0]
    description = first.description or ""
    recommendation = first.recommendation
    references = first.references or list(first.cwe_links)

    # WASC / identifiant : on réutilise l'external_id ou la catégorie.
    plugin_id = first.external_id or first.category

    instance_rows = "\n".join(_render_instance(f) for f in group)

    return f"""<table class="results">
\t\t\t\t<tr height="24">
\t\t\t\t\t<th width="20%" class="risk-{risk}"><a id="{anchor}"></a>
\t\t\t\t\t\t<div>{_risk_label(risk)}</div></th>
\t\t\t\t\t<th class="risk-{risk}">{escape(title)}</th>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">Description</td>
\t\t\t\t\t<td width="80%"><div>{_nl_to_br(escape(description))}</div></td>
\t\t\t\t</tr>
\t\t\t\t<TR vAlign="top"><TD colspan="2"></TD></TR>
{instance_rows}
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">Instances</td>
\t\t\t\t\t<td width="80%">{len(group)}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">Solution</td>
\t\t\t\t\t<td width="80%"><div>{_nl_to_br(escape(recommendation)) if recommendation else ''}</div></td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">Reference</td>
\t\t\t\t\t<td width="80%">{_render_references(references)}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">CWE Id</td>
\t\t\t\t\t<td width="80%">{_render_cwes(first.cwe_ids)}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%">Plugin Id</td>
\t\t\t\t\t<td width="80%">{escape(plugin_id)}</td>
\t\t\t\t</tr>
\t\t\t</table>
"""


def _render_instance(f: ReportFinding) -> str:
    param = ""
    evidence = " ; ".join(f.evidences) if f.evidences else ""
    status_label = STATUS_LABEL.get(f.status.value, f.status.value)
    return (
        f"""\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent1">URL</td>
\t\t\t\t\t<td width="80%"><a href="{escape(f.matched_at or '')}">{escape(f.matched_at or '')}</a></td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent2">Node Name</td>
\t\t\t\t\t<td width="80%">{escape(f.matched_at or '')}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent2">Statut (verdict)</td>
\t\t\t\t\t<td width="80%">{escape(status_label)}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent2">Méthode</td>
\t\t\t\t\t<td width="80%">GET</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent2">Parameter</td>
\t\t\t\t\t<td width="80%">{escape(param)}</td>
\t\t\t\t</tr>
\t\t\t\t<tr>
\t\t\t\t\t<td width="20%" class="indent2">Evidence</td>
\t\t\t\t\t<td width="80%">{_nl_to_br(escape(evidence))}</td>
\t\t\t\t</tr>
"""
    )


def _render_references(references: list[str]) -> str:
    if not references:
        return ""
    out = []
    for url in references:
        out.append(f'\t\t\t\t\t<a href="{escape(url)}">{escape(url)}</a>')
    return "\n\t\t\t\t\t\t<br />\n".join(out)


def _render_cwes(cwe_ids: list[str]) -> str:
    links = []
    for cwe_id in dict.fromkeys(cwe_ids):
        url = CWE_LINK_TEMPLATE.format(cwe_id=cwe_id)
        links.append(f'\t\t\t\t\t<a href="{escape(url)}">{escape(cwe_id)}</a>')
    return "\n".join(links) if links else escape("None")


def _nl_to_br(text: str) -> str:
    return text.replace("\n", "<br />")


def _anchor(f: ReportFinding) -> str:
    """Ancre stable : basée sur l'identifiant du résultat (numéro)."""
    return f"tscan-{f.id}"
