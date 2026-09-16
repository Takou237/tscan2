"""Générateur de rapport de sécurité (RF-27, RF-28, RF-29).

Assemble un rapport structuré à partir des résultats en base : un résumé
exécutif (compteurs par gravité et par statut, par cible) et des détails
techniques (par résultat : titre, gravité, statut, score, emplacement,
description, explication du score, preuves, historique de statut).

Les recommandations (RF-28) sont issues de la règle YAML liée à chaque
résultat (`recommendation` et `references` du fichier de règle), complétées
par les références CWE de la table `knowledge/cwe_reference.yaml`, avec le
lien MITRE associé : chaque recommandation renvoie ainsi vers une source
vérifiable en ligne.

L'export proprement dit (HTML, Markdown) vit dans `render_html.py` et
`render_markdown.py` : le générateur produit un objet `Report` neutre,
indépendant du format de sortie (RF-29).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from tscan_core.knowledge_base import load_cwe_reference
from tscan_core.models import Finding, FindingStatus
from tscan_core.models import Scan as _Scan
from tscan_core.rule_engine import load_rules
from tscan_core.rule_engine.schema import RuleDefinition

# Ordre d'affichage des gravités dans le rapport, de la plus critique à la
# plus informative.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Ordre d'affichage des statuts dans le résumé exécutif.
STATUS_ORDER = [
    FindingStatus.CONFIRMED,
    FindingStatus.PROBABLE,
    FindingStatus.POTENTIAL_FALSE_POSITIVE,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.UNVALIDATED,
]

SEVERITY_LABEL = {
    "critical": "Critique",
    "high": "Élevée",
    "medium": "Moyenne",
    "low": "Faible",
    "info": "Information",
    "other": "Autre",
}

STATUS_LABEL = {
    FindingStatus.CONFIRMED.value: "Confirmé",
    FindingStatus.PROBABLE.value: "Probable",
    FindingStatus.POTENTIAL_FALSE_POSITIVE.value: "Potentiel faux positif",
    FindingStatus.FALSE_POSITIVE.value: "Faux positif",
    FindingStatus.UNVALIDATED.value: "Non validé",
}

CWE_LINK_TEMPLATE = "https://cwe.mitre.org/data/definitions/{cwe_id}.html"


@dataclass
class ReportFinding:
    """Détail technique d'un résultat, prêt à être affiché dans un rapport."""

    id: int
    title: str
    description: str | None
    severity: str
    status: FindingStatus
    confidence_score: float | None
    category: str
    matched_at: str | None
    external_id: str | None
    scan_source: str
    scan_started_at: str
    score_explanation: list[str]
    evidences: list[str]
    status_history: list[str]
    recommendation: str
    references: list[str]
    cwe_ids: list[str]
    cwe_links: list[str]


@dataclass
class ReportCveContext:
    """Contexte CVE d'un résultat de composant vulnérable, le cas échéant."""

    cve_id: str
    description: str | None
    cvss_severity: str | None


@dataclass
class ReportTarget:
    """Section d'un rapport : tout ce qui concerne une cible donnée."""

    target: str
    findings: list[ReportFinding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class Report:
    """Rapport complet : en-tête, résumé exécutif global et sections par cible."""

    generated_at: str
    targets: list[ReportTarget]
    total_findings: int
    overall_severity_counts: dict[str, int] = field(default_factory=dict)
    overall_status_counts: dict[str, int] = field(default_factory=dict)


def _severity_bucket(severity: str) -> str:
    return severity if severity in SEVERITY_ORDER else "other"


def _status_bucket(status: FindingStatus) -> str:
    return status.value


def _counters(findings: list[ReportFinding]) -> tuple[dict[str, int], dict[str, int]]:
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    severity_counts["other"] = 0
    status_counts: dict[str, int] = {s.value: 0 for s in STATUS_ORDER}
    for finding in findings:
        severity_counts[_severity_bucket(finding.severity)] += 1
        status_counts[_status_bucket(finding.status)] += 1
    return severity_counts, status_counts


def _rule_map() -> dict[str, RuleDefinition]:
    """Indexe les règles chargées par identifiant.

    Un échec de chargement des règles n'empêche pas la génération du rapport :
    les résultats restent présentés, simplement sans recommandation associée.
    """
    try:
        return {rule.id: rule for rule in load_rules()}
    except Exception:  # noqa: BLE001 - tout échec de chargement doit rester silencieux ici
        return {}


def generate_report(
    session: Session,
    target: str | None = None,
    statuses: set[FindingStatus] | None = None,
) -> Report:
    """Construit un `Report` à partir des résultats en base.

    `target` limite le rapport à une cible ; `statuses` (si fourni) restreint
    aux statuts demandés. Les résultats sont triés par gravité (critique en
    premier) puis par emplacement.
    """
    query = session.query(Finding).order_by(Finding.id)
    if target is not None:
        query = query.join(Finding.scan).filter(_Scan.target == target)
    findings = query.all()
    if statuses is not None:
        findings = [f for f in findings if f.status in statuses]

    rules = _rule_map()
    cwe_by_category = _cwe_index()

    findings_by_target: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_target.setdefault(finding.scan.target, []).append(finding)

    report_targets: list[ReportTarget] = []
    for target_name in sorted(findings_by_target):
        raw = findings_by_target[target_name]
        raw.sort(key=lambda f: SEVERITY_ORDER.index(_severity_bucket(f.severity)))
        report_findings = [_to_report_finding(f, rules, cwe_by_category) for f in raw]
        severity_counts, status_counts = _counters(report_findings)
        report_targets.append(
            ReportTarget(
                target=target_name,
                findings=report_findings,
                severity_counts=severity_counts,
                status_counts=status_counts,
            )
        )

    all_findings = [rf for rt in report_targets for rf in rt.findings]
    overall_severity, overall_status = _counters(all_findings)

    return Report(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        targets=report_targets,
        total_findings=len(all_findings),
        overall_severity_counts=overall_severity,
        overall_status_counts=overall_status,
    )


def _cwe_index() -> dict[str, list[tuple[str, str]]]:
    """Index CWE par catégorie Tscan : `{catégorie: [(CWE-xx, lien MITRE)]}`."""
    cwes = load_cwe_reference()
    index: dict[str, list[tuple[str, str]]] = {}
    for entry in cwes.values():
        link = CWE_LINK_TEMPLATE.format(cwe_id=entry.id)
        index.setdefault(entry.category, []).append((entry.id, link))
    return index


def _to_report_finding(
    finding: Finding,
    rules: dict[str, RuleDefinition],
    cwe_by_category: dict[str, list[tuple[str, str]]],
) -> ReportFinding:
    rule = rules.get(finding.rule_id) if finding.rule_id else None
    if rule is None and finding.category:
        for candidate in rules.values():
            if candidate.category == finding.category:
                rule = candidate
                break

    recommendation = (rule.recommendation if rule else "").strip()
    references = list(rule.references) if rule else []
    cwe_ids = [cwe_id for cwe_id, _link in cwe_by_category.get(finding.category, [])]
    cwe_links = [link for _cwe_id, link in cwe_by_category.get(finding.category, [])]

    score_explanation: list[str] = []
    if finding.score_explanation:
        import json

        try:
            score_explanation = json.loads(finding.score_explanation)
        except json.JSONDecodeError:
            score_explanation = [finding.score_explanation]

    evidences = [e.content_text for e in finding.evidences if e.content_text] or [
        e.content_path for e in finding.evidences if e.content_path
    ]

    history = [
        f"{entry.old_status.value if entry.old_status else '(aucun)'} -> "
        f"{entry.new_status.value} ({entry.changed_by})"
        for entry in finding.status_history
    ]

    return ReportFinding(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        confidence_score=finding.confidence_score,
        category=finding.category,
        matched_at=finding.matched_at,
        external_id=finding.external_id,
        scan_source=finding.scan.source,
        scan_started_at=(finding.scan.started_at.isoformat() if finding.scan.started_at else ""),
        score_explanation=score_explanation,
        evidences=evidences,
        status_history=history,
        recommendation=recommendation,
        references=references,
        cwe_ids=cwe_ids,
        cwe_links=cwe_links,
    )