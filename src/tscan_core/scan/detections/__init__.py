"""Détections de la semaine 8 (RF-19 XSS, RF-21 CSRF, RF-22 SQLi et familles
complémentaires : fichiers sensibles, listing de répertoire, CORS, TLS).

Contrairement aux checks déclaratifs de la 7b, ces familles sont évaluées en
code : leur logique de sonde (charges de test bénignes, signatures de
contenu, lecture d'un certificat) est trop spécifique pour être exprimée en
YAML. Chaque module sous-jacent expose `run(...)` et renvoie des
`DetectionResult` ; ce module les persiste en `Finding` liés au scan, au
statut `Probable` (la confirmation humaine finale reste RF-12).

Toutes les sondes sont non destructives (ES-03) : GET uniquement, charges
inoffensives ou signatures, aucune action d'écriture sur la cible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from tscan_core.models import Evidence, EvidenceType, Finding, FindingStatus, Scan
from tscan_core.scan.config import ScanConfig, ScanConfigError
from tscan_core.scan.progress import notify

__all__ = [
    "DetectionResult",
    "FindingInfo",
    "check_deadline",
    "persist_result",
    "run_active_detections",
]


@dataclass(frozen=True)
class FindingInfo:
    """Vue allégée d'un résultat produit par le scan, pour les interfaces."""

    title: str
    severity: str
    category: str
    matched_at: str


@dataclass(frozen=True)
class DetectionResult:
    """Un constat d'une détection de la semaine 8, avant persistance."""

    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    matched_at: str
    evidence_text: str
    probe_info: dict | None = None


# Cache paresseux des métadonnées de règles (chargées une seule fois) pour
# affecter à chaque constat son score de confiance de base.
_RULES_BY_ID: dict | None = None


def _base_score_for(rule_id: str) -> float:
    """Score de confiance de base de la règle d'un constat (repli 0,50)."""
    global _RULES_BY_ID
    if _RULES_BY_ID is None:
        from tscan_core.rule_engine.loader import load_rules

        _RULES_BY_ID = {r.id: r for r in load_rules()}
    rule = _RULES_BY_ID.get(rule_id)
    return rule.confidence_base if rule is not None else 0.5


def check_deadline(config: ScanConfig, started_at: datetime) -> None:
    """Stoppe le scan si la durée maximale est atteinte ou si l'utilisateur a
    demandé son interruption (parité OWASP ZAP).

    Vérifié entre les grandes étapes (chaque requête est bornée par son
    propre timeout) : la durée d'un scan reste prévisible sans mener une
    chronométrie en interruption permanente. Si `config.max_duration_seconds`
    vaut `None`, aucune borne de durée ne s'applique (le scan s'arrête quand
    le crawl a épuisé les pages ou quand l'utilisateur l'interrompt).
    Partagé avec l'orchestrateur.
    """
    from tscan_core.scan.interrupt import ScanCancelledError

    interrupt = getattr(config, "_interrupt", None)
    if interrupt is not None and interrupt.is_set():
        raise ScanCancelledError("Scan interrompu par l'utilisateur.")

    if config.max_duration_seconds is not None:
        elapsed = (datetime.now(UTC) - started_at).total_seconds()
        if elapsed > config.max_duration_seconds:
            raise ScanConfigError(
                f"Scan stoppé : durée maximale de {config.max_duration_seconds}s dépassée "
                f"({elapsed:.1f}s écoulées)."
            )


def persist_result(
    session: Session,
    scan: Scan,
    result: DetectionResult,
) -> FindingInfo:
    """Crée le `Finding` et sa preuve pour un constat de détection.

    Le constat reçoit immédiatement le score de confiance de base de sa règle
    (statut ``Probable``) ; la re-vérification (RF-23) l'ajustera ensuite sans
    jamais confirmer — « Confirmée » est une décision d'analyste (RF-12).
    """
    base_score = _base_score_for(result.rule_id)
    finding = Finding(
        scan_id=scan.id,
        rule_id=result.rule_id,
        title=result.title[:255],
        description=result.description,
        category=result.category,
        severity=result.severity,
        matched_at=result.matched_at,
        status=FindingStatus.PROBABLE,
        confidence_score=base_score,
    )
    finding.score_explanation = json.dumps(
        [
            "Constat produit par le moteur de scan actif de Tscan.",
            f"Score de base de la règle {result.rule_id} : {base_score:.2f}.",
            (
                "Statut Probable : la confirmation finale relève de la revue de "
                "l'analyste (RF-12)."
            ),
        ],
        ensure_ascii=False,
    )
    session.add(finding)
    session.flush()  # identifiant requis par la preuve
    if result.probe_info:
        finding.probe_json = json.dumps(result.probe_info, ensure_ascii=False)
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=result.evidence_text,
        )
    )
    return FindingInfo(
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        matched_at=finding.matched_at,
    )


def run_active_detections(
    session: Session,
    scan: Scan,
    config: ScanConfig,
    root,
    client,
    observations: dict,
    started_at: datetime,
    pages: dict,
    on_event=None,
) -> list[FindingInfo]:
    """Exécute les détections actives permises par le périmètre et persiste
    les constats. Une sonde en échec réseau est tracée dans `observations`
    (ES-05) sans interrompre le scan ; la durée maximale, elle, interrompt.

    `on_event` reçoit le début de chaque famille et chaque sonde GET émise
    par les modules de détection (`ScanProgressEvent`), pour afficher le
    déroulement en temps réel.
    """
    allowed = config.allowed_tests
    findings: list[FindingInfo] = []

    # Chaque famille est persistée et commitée immédiatement après son
    # exécution (au fil de l'eau) : si `check_deadline` interrompt le scan
    # (durée maximale) ou si un arrêt manuel survient ensuite, les constats
    # des familles déjà terminées sont conservés en base (ES-05), comme
    # l'arrêt propre de OWASP ZAP. Le commit rend aussi les constats visibles
    # dès leur détection depuis les autres connexions (l'interface, qui lit la
    # base dans un autre fil pendant le scan — S11).
    def _commit(batch: list[DetectionResult]) -> None:
        for result in batch:
            findings.append(persist_result(session, scan, result))
        session.commit()

    if "xss" in allowed:
        notify(on_event, "detect", "Détection XSS réfléchi…", 50)
        _commit(xss.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "csrf" in allowed:
        notify(on_event, "detect", "Détection CSRF (formulaires POST sans jeton)…", 55)
        _commit(csrf.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "sqli" in allowed:
        notify(on_event, "detect", "Détection injection SQL error-based…", 60)
        _commit(sqli.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "sensitive-files" in allowed:
        notify(on_event, "detect", "Détection fichiers sensibles…", 65)
        _commit(sensitive_files.run(config, client, root, observations, started_at, on_event))
        check_deadline(config, started_at)
    if "directory-listing" in allowed:
        notify(on_event, "detect", "Détection listing de répertoire…", 70)
        _commit(directory_listing.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "cors" in allowed:
        notify(on_event, "detect", "Détection CORS permissif…", 75)
        _commit(cors.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "tls" in allowed:
        notify(on_event, "detect", "Détection TLS faible…", 80)
        _commit(tls_weak.run(config, observations))
    if "cookies" in allowed:
        notify(on_event, "detect", "Analyse des cookies de session…", 81)
        _commit(cookies.run(config, client, root, observations, started_at, pages, on_event))
    if "waf" in allowed:
        notify(on_event, "detect", "Détection WAF…", 82)
        _commit(waf.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "path-traversal" in allowed:
        notify(on_event, "detect", "Détection traversée de répertoire…", 63)
        _commit(path_traversal.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "open-redirect" in allowed:
        notify(on_event, "detect", "Détection redirection ouverte…", 64)
        _commit(open_redirect.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "cmd-injection" in allowed:
        notify(on_event, "detect", "Détection injection de commande OS…", 66)
        _commit(cmd_injection.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "ssti" in allowed:
        notify(on_event, "detect", "Détection injection de template (SSTI)…", 67)
        _commit(ssti.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "ssrf" in allowed:
        notify(on_event, "detect", "Détection SSRF…", 68)
        _commit(ssrf.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "header-injection" in allowed:
        notify(on_event, "detect", "Détection injection de headers (CRLF)…", 69)
        _commit(header_injection.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "weak-hash" in allowed:
        notify(on_event, "detect", "Détection de hachages faibles…", 84)
        _commit(weak_hash.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "csp" in allowed or "sri" in allowed or "xdomain-js" in allowed or "timestamp" in allowed:
        # Familles passives (parité ZAP) : analyse des en-têtes et du HTML déjà
        # crawlées. Sans requête supplémentaire, le délai ne change pas.
        if "csp" in allowed:
            notify(on_event, "detect", "Analyse Content-Security-Policy…", 83)
            _commit(csp.run(config, client, root, observations, started_at, pages, on_event))
        if "sri" in allowed:
            notify(on_event, "detect", "Analyse de l'intégrité des ressources (SRI)…", 83)
            _commit(sri.run(config, client, root, observations, started_at, pages, on_event))
        if "xdomain-js" in allowed:
            notify(on_event, "detect", "Inclusion de scripts JavaScript tiers…", 83)
            _commit(xdomain_js.run(config, client, root, observations, started_at, pages, on_event))
        if "timestamp" in allowed:
            notify(on_event, "detect", "Divulgation d'horodatages…", 83)
            _commit(timestamp.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "security-headers" in allowed:
        notify(on_event, "detect", "Analyse des en-têtes de sécurité (HSTS, X-Content-Type-Options, X-Powered-By)…", 84)
        _commit(security_headers.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "big-redirect" in allowed:
        notify(on_event, "detect", "Détection de redirections géantes (fuite d'URL sensibles)…", 85)
        _commit(big_redirect.run(config, client, root, observations, started_at, pages, on_event))
        check_deadline(config, started_at)
    if "zap-passives" in allowed:
        notify(on_event, "detect", "Parité ZAP : alertes passives (cache, en-têtes, HTML, authentification)…", 86)
        _commit(zap_passive.run(config, client, root, observations, started_at, pages, on_event))

    return findings


# Imports placés en fin de fichier : les modules du package utilisent
# `DetectionResult` et `FindingInfo` (définis ci-dessus) dans leurs signatures,
# un import en tête créerait une référence circulaire pendant l'initialisation.
from . import (
    big_redirect,
    cmd_injection,
    cookies,
    cors,
    csp,
    csrf,
    directory_listing,
    header_injection,
    open_redirect,
    path_traversal,
    security_headers,
    sensitive_files,
    sqli,
    sri,
    ssrf,
    ssti,
    timestamp,
    tls_weak,
    waf,
    weak_hash,
    xdomain_js,
    xss,
    zap_passive,
)