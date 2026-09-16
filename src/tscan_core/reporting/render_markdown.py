"""Export Markdown du rapport de sécurité.

Format texte simple, lisible tel quel dans un terminal ou une issue :
alternative à l'export HTML (RF-29). Le contenu n'est pas échappé (le
Markdown est un format texte), mais les caractères de contrôle sont
neutralisés pour éviter les fuites de formatage.
"""

from __future__ import annotations

from tscan_core.reporting import SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, Report

_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def render_markdown(report: Report) -> str:
    """Rend un rapport au format Markdown."""
    lines = [
        "# Rapport de sécurité Tscan",
        "",
        f"- Généré le : {report.generated_at}",
        f"- Résultats : {report.total_findings} sur {len(report.targets)} cible(s)",
        "",
        "## Résumé",
        "",
        "### Gravité",
        "",
        "| Gravité | Nombre |",
        "| --- | ---: |",
    ]

    severities = sorted(
        report.overall_severity_counts.items(), key=lambda kv: _SEVERITY_RANK.get(kv[0], 99)
    )
    for sev_key, sev_count in severities:
        sev_label = SEVERITY_LABEL.get(sev_key, sev_key)
        lines.append(f"| {sev_label} | {sev_count} |")

    lines += ["", "### Statut", "", "| Statut | Nombre |", "| --- | ---: |"]

    statuses = sorted(
        report.overall_status_counts.items(),
        key=lambda kv: (kv[0] == "confirmed", kv[0]),
    )
    for sta_key, sta_count in statuses:
        sta_label = STATUS_LABEL.get(sta_key, sta_key)
        lines.append(f"| {sta_label} | {sta_count} |")

    for target in report.targets:
        lines += [
            "",
            f"## Cible : {target.target}",
            "",
            f"{len(target.findings)} résultat(s) :",
        ]
        for f in sorted(target.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 99)):
            score = f"{f.confidence_score:.2f}" if f.confidence_score is not None else "—"
            lines += [
                "",
                f"### #{f.id} — {f.title}",
                "",
                (
                f"- Gravité : **{SEVERITY_LABEL.get(f.severity, f.severity).upper()}** "
                f"— Statut : {STATUS_LABEL.get(f.status.value, f.status.value)} — Score : {score}"
            ),
                f"- Catégorie : {f.category}",
            ]
            if f.matched_at:
                lines.append(f"- Emplacement : `{f.matched_at}`")
            if f.external_id:
                lines.append(f"- Identifiant externe : `{f.external_id}`")
            if f.description:
                lines += ["", f.description]
            if f.score_explanation:
                lines += ["", "*Explication du score :*"]
                lines += [f"  - {line}" for line in f.score_explanation]
            if f.evidences:
                lines += ["", "*Preuves :*"]
                lines += [f"  - `{e}`" for e in f.evidences]
            if f.recommendation:
                lines += ["", "*Recommandation :*", "", f.recommendation]
            if f.references or f.cwe_links:
                lines += ["", "*Sources vérifiables :*"]
                lines += [f"  - {url}" for url in f.references + f.cwe_links]
            if f.status_history:
                lines += ["", "*Historique du statut :*"]
                lines += [f"  - {h}" for h in f.status_history]

    return "\n".join(lines) + "\n"