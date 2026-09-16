"""Orchestrateur du scan actif de Tscan (chapitre 10, RF-15 à RF-20).

Ordonne les étapes d'un scan actif et garantit le respect du cadre de
sécurité défini par `ScanConfig` :

1. vérification de l'autorisation explicite (ES-01) -- aucun scan actif ne
   peut être enregistré sans elle ;
2. validation des règles déclaratives avant tout enregistrement (un check
   mal formé refuse le scan avec une erreur explicite, il ne peut pas
   échouer en silence) ;
3. journalisation du scan en base dès le départ (cible, horodatages,
   périmètre appliqué, mode sécurisé) -- ES-05 : chaque scan actif est
   tracé, y compris en cas d'échec réseau ;
4. reconnaissance : requête racine, puis sonde TLS pour une cible https ;
5. fingerprinting passif des technologies (RF-16) ;
6. détections de la semaine 7b : en-têtes de sécurité manquants (RF-17),
   clickjacking (RF-17), accès non autorisé basique par sondes GET bénignes
   (RF-20), composants vulnérables connus via le cache CVE local (RF-18) ;
7. clôture du scan (horodatage de fin, durée).

Les détections produisent des `Finding` liés au scan, au statut `Probable`
(constat passif, non confirmé activement : la confirmation active est le
bloc de la semaine 8).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from tscan_core.knowledge_base.update_manager import lookup_component
from tscan_core.models import (
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Scan,
    ScanType,
    TechnologyDetection,
)
from tscan_core.recon import fingerprint
from tscan_core.recon.client import (
    ReconError,
    RootResponse,
    create_http_client,
    fetch_root,
    fetch_url,
)
from tscan_core.recon.crawler import crawl
from tscan_core.recon.fingerprint import TechnologyMatch
from tscan_core.recon.tls import TlsInfo, TlsProbeError, probe_tls
from tscan_core.rule_engine.loader import load_rules
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.scan.checks import CheckResult, evaluate_rule_checks, validate_rule_checks
from tscan_core.scan.config import ScanConfig, ScanConfigError
from tscan_core.scan.confirmation import reverify_active_findings
from tscan_core.scan.detections import FindingInfo, check_deadline, run_active_detections
from tscan_core.scan.interrupt import ScanCancelledError, ScanInterrupt
from tscan_core.scan.progress import notify
from tscan_core.scan.request_log import RequestHistory

ENGINE_SOURCE = "tscan_engine"

# Chaque détection 7b est liée à la règle de sa famille (celle-ci doit exister
# dans rules/ : son identifiant est chargé dynamiquement, cette constante ne
# sert que de filet de sécurité si le fichier venait à disparaître).
FALLBACK_COMPONENT_RULE_ID = "RULE-VULNCOMP-001"

_CHECK_FAMILIES = {"headers", "clickjacking", "bac"}

# Familles de détection actives de la semaine 8 : implémentées en code dans
# `tscan_core.scan.detections`, exécutées quand leur nom figure dans le
# périmètre autorisé par l'utilisateur (ES-02).
_ACTIVE_DETECTION_TESTS = {
    "xss",
    "csrf",
    "sqli",
    "sensitive-files",
    "directory-listing",
    "cors",
    "tls",
    "path-traversal",
    "open-redirect",
    "cmd-injection",
    "ssti",
    "ssrf",
    "header-injection",
    "weak-hash",
    "security-headers",
    "big-redirect",
    "zap-passives",
}


@dataclass(frozen=True)
class ScanOutcome:
    """Résultat d'un scan actif retourné aux interfaces (CLI, GUI)."""

    scan_id: int
    target: str
    duration_seconds: float
    technologies: list[TechnologyMatch]
    recon_observations: dict
    findings: list[FindingInfo] = field(default_factory=list)
    # Re-vérification RF-23 : nombre de constats reproductibles et nombre de
    # constats placés en potentiel faux positif (aucune confirmation : elle
    # relève de l'analyste, RF-12).
    reproduced: int = 0
    potential_false_positives: int = 0
    interrupted: bool = False
    # Journal structuré des requêtes HTTP du scan (format « History » ZAP),
    # à destination des interfaces : ID, horodatages WAT, méthode, URL, code,
    # raison. Vide si aucun écouteur de requête n'a été fourni.
    request_log: RequestHistory = field(default_factory=RequestHistory)


def run_recon_scan(
    session: Session,
    config: ScanConfig,
    http_client: httpx.Client | None = None,
    on_event=None,
    on_request=None,
    request_delay: float | None = None,
    interrupt: ScanInterrupt | None = None,
) -> ScanOutcome:
    """Exécute le scan actif autorisé (reconnaissance + détections passives).

    Le scan est journalisé en base avant toute sonde (ES-05) : même un scan
    dont la cible ne répond pas laisse une trace exploitable. Les erreurs
    réseau sont enregistrées dans `recon_json` puis remontées à l'appelant
    (`ReconError`) pour affichage.

    `http_client` permet d'injecter un client simulé dans les tests ; le
    client réel est créé ici sinon (le seul autre composant à créer un client
    réseau pour une cible, avec `probe_tls`).

    `on_event` est un écouteur optionnel appelé à chaque étape observable du
    scan (`ScanProgressEvent` de `tscan_core.scan.progress`, semaine 11) :
    sondes GET, TLS, crawl, détections et re-vérifications, pour afficher la
    progression en temps réel depuis les interfaces.

    `interrupt` (parité OWASP ZAP) : un `ScanInterrupt` par lequel l'interface
    peut demander l'arrêt du scan à tout moment. S'il n'est pas fourni, un
    drapeau interne est créé ; il est attaché à la configuration et le scan
    se clôture proprement (constats déjà enregistrés conservés) quand il est
    levé.
    """
    if not config.authorized:  # ES-01
        raise ScanConfigError(
            "Scan refusé : aucune autorisation explicite pour la cible "
            f"{config.target!r} (ES-01). Relancez avec --authorized après confirmation."
        )

    if interrupt is None:
        interrupt = ScanInterrupt()
    # Le drapeau est attaché à la config (frozen) pour que `check_deadline`,
    # appelée partout, le lise sans changer sa signature.
    object.__setattr__(config, "_interrupt", interrupt)

    rules = _load_rules_for(config)

    started_at = datetime.now(UTC)
    notify(on_event, "start", f"Scan actif démarré sur {config.target}", 0)
    scan = Scan(
        scan_type=ScanType.ACTIVE_SCAN,
        source=ENGINE_SOURCE,
        target=config.target,
        authorized=True,
        safe_mode=config.safe_mode,
        config_json=config.to_json(),
    )
    session.add(scan)
    session.commit()  # le scan est tracé dès le départ, même si le réseau échoue

    observations: dict = {}
    technologies: list[TechnologyMatch] = []
    findings: list[FindingInfo] = []
    if http_client is None:
        if request_delay is None:
            # Valeur par défaut depuis le rayon : rythme prudent entre requêtes.
            from tscan_core.recon.client import DEFAULT_REQUEST_DELAY

            request_delay = DEFAULT_REQUEST_DELAY
        http_client = create_http_client(
            verify_tls=config.verify_tls, request_delay=request_delay
        )
    client = http_client

    # Journal structuré des requêtes (format « History » ZAP) : quand un
    # écouteur `on_request` est fourni (interface graphique), on branche un
    # `RequestHistory` sur le client pour que chaque requête GET soit
    # remontée en temps réel (ID, horodatages WAT, méthode, URL, code, raison).
    request_log: RequestHistory = RequestHistory(on_record=on_request)
    if on_request is not None:
        client._tscan_request_log = request_log  # type: ignore[attr-defined]

    try:
        notify(on_event, "recon", f"GET {config.target} (racine)…", 5)
        root = fetch_root(client, config.target)
        observations = {
            "status_code": root.status_code,
            "final_url": root.final_url,
            "body_truncated": root.body_truncated,
            "server_header": root.headers.get("server"),
        }
        notify(on_event, "recon", f"GET {root.final_url} -> {root.status_code}", 10)
        check_deadline(config, started_at)

        if config.scheme == "https":
            notify(on_event, "tls", f"Sonde TLS {config.hostname}:{config.port}…", 15)
            observations["tls"] = _probe_tls_observation(config)
            notify(on_event, "tls", "Sonde TLS terminée", 15)

        check_deadline(config, started_at)

        if "fingerprint" in config.allowed_tests:
            technologies = fingerprint.fingerprint_response(
                root.headers, root.body, fingerprint.load_technologies()
            )
            for match in technologies:
                session.add(
                    TechnologyDetection(
                        scan_id=scan.id,
                        technology_name=match.name,
                        label=match.label,
                        version=match.version,
                        cpe_alias=match.cpe_alias,
                        source=match.source,
                    )
                )
            if technologies:
                labels = ", ".join(
                    f"{m.label} {m.version or ''}".strip() for m in technologies[:6]
                )
                notify(
                    on_event,
                    "fingerprint",
                    f"Fingerprint : {len(technologies)} technologie(s) ({labels})",
                    20,
                )
            else:
                notify(on_event, "fingerprint", "Aucune technologie reconnue", 20)

        if "components" in config.allowed_tests:
            findings += _detect_vulnerable_components(session, scan, technologies, rules)
            # Constats de composants visibles en direct depuis les autres
            # connexions (interface), comme le reste du scan au fil de l'eau.
            session.commit()
    except (ReconError, ScanConfigError) as exc:
        # ES-05 : un scan interrompu (réseau injoignable, durée maximale
# atteinte) reste tracé, clôturé et daté, avant remontée de l'erreur.
        observations["error"] = str(exc)
        scan.recon_json = json.dumps(observations, ensure_ascii=False)
        scan.finished_at = datetime.now(UTC)
        session.commit()
        notify(on_event, "error", f"Scan interrompu : {exc}", None)
        raise
    except ScanCancelledError:
        # Arrêt manuel (bouton « Arrêter » / Ctrl+C) pendant reconnaissance :
        # le scan est clôturé proprement et retourne `interrupted=True`, sans
        # propager l'exception (parité OWASP ZAP : arrêt propre, constats
        # déjà trouvés conservés).
        observations["error"] = "Scan interrompu par l'utilisateur."
        observations["crawl_stats"] = observations.get("crawl_stats", {})
        observations["crawl_stats"]["stopped_by_interrupt"] = True
        scan.recon_json = json.dumps(observations, ensure_ascii=False)
        scan.finished_at = datetime.now(UTC)
        session.commit()
        notify(on_event, "error", "Scan interrompu par l'utilisateur.", None)
        duration = (datetime.now(UTC) - started_at).total_seconds()
        return ScanOutcome(
            scan_id=scan.id,
            target=config.target,
            duration_seconds=duration,
            technologies=technologies,
            recon_observations=observations,
            findings=findings,
            reproduced=0,
            potential_false_positives=0,
            interrupted=True,
            request_log=request_log,
        )

    # ── Crawl des pages du site (RF-24) ───────────────────────────────
    # Le crawlur découvre toutes les pages accessibles en suivant les liens
    # internes, ce qui permet aux modules de détection de tester un périmètre
    # beaucoup plus large que les seuls chemins prédéfinis.
    pages: dict[str, RootResponse] = {}
    if ("headers" in config.allowed_tests or "clickjacking" in config.allowed_tests
            or "bac" in config.allowed_tests or _ACTIVE_DETECTION_TESTS & config.allowed_tests):
        try:
            notify(
                on_event,
                "crawl",
                f"Crawl de {config.target} (profondeur {config.crawl_max_depth})…",
                20,
            )
            pages = crawl(
                client,
                config.target,
                max_depth=config.crawl_max_depth,
                max_pages=config.crawl_max_pages,
                max_duration_seconds=config.crawl_max_duration,
                started_at=started_at,
                observations=observations,
                on_event=on_event,
                concurrency=6,
                interrupt=interrupt,
            )
            observations["crawl_stats"] = observations.get("crawl_stats", {})
            observations["crawl_stats"]["pages_found"] = len(pages)
            notify(on_event, "crawl", f"Crawl terminé : {len(pages)} page(s)", 35)
        except ReconError as exc:
            observations["crawl_error"] = str(exc)
            notify(on_event, "crawl", f"Crawl interrompu : {exc}", None)

    # Un crawl stoppé manuellement (ScanInterrupt) arrête proprement le scan
    # avant les détections : les pages déjà crawleurs restent analysées.
    interrupted = interrupt.is_set()
    if interrupted:
        observations["crawl_stats"]["stopped_by_interrupt"] = True

    if _CHECK_FAMILIES & config.allowed_tests and not interrupted:
        try:
            check_findings, pages = _run_declarative_checks(
                session,
                scan,
                config,
                root,
                rules,
                client,
                observations,
                started_at,
                pages,
                on_event,
            )
            findings += check_findings
# Détections déclaratives (en-têtes, clickjacking, BAC) : commit
            # immédiat pour que l'interface les voie dès ce bloc terminé.
            session.commit()
            notify(
                on_event,
                "checks",
                f"{len(check_findings)} constat(s) déclaratif(s) (en-têtes, clickjacking, BAC)",
                45,
            )
        except ReconError as exc:
            # Une sonde de détection qui échoue sur le réseau ne doit pas
            # faire échouer tout le scan : le constat est tracé, le reste des
            # observations reste valide. (La durée maximale, elle, interrompt.)
            observations["detections_error"] = str(exc)
        except ScanCancelledError:
            interrupted = True
            observations["detections_error"] = "Scan interrompu par l'utilisateur."
        except ScanConfigError as exc:
            # ES-05 : la durée maximale (check_deadline) est une interruption
            # à part entière pendant les détections : le scan se clôture
            # proprement et conserve les constats déjà accumulés, au lieu de
            # propager l'exception et de les perdre (parité OWASP ZAP).
            interrupted = True
            observations["detections_error"] = f"Scan interrompu : durée maximale atteinte ({exc})."

    if _ACTIVE_DETECTION_TESTS & config.allowed_tests and not interrupted:
        try:
            findings += run_active_detections(
                session, scan, config, root, client, observations, started_at, pages, on_event
            )
        except ReconError as exc:
            observations["detections_error"] = str(exc)
        except ScanCancelledError:
            interrupted = True
            observations["detections_error"] = "Scan interrompu par l'utilisateur."
        except ScanConfigError as exc:
            # ES-05 : même traitement que l'interruption manuelle — la durée
            # maximale atteinte pendant les détections actives conserve les
            # constats déjà enregistrés et clôture le scan proprement.
            interrupted = True
            observations["detections_error"] = f"Scan interrompu : durée maximale atteinte ({exc})."

    reverify_stats = {"reproduced": 0, "potential_false_positives": 0, "probe_errors": 0}
    if findings and not interrupted:
        try:
            notify(
                on_event,
                "confirm",
                "Re-vérification active des constats (RF-23)…",
                85,
            )
            reverify_stats = reverify_active_findings(
                session, scan, config, client, observations, started_at, on_event
            )
        except ReconError as exc:
            # Sondes de re-vérification indisponibles (réseau) : les constats
            # concernés restent Probable ; le scan continue (ES-05).
            observations["confirmations_error"] = str(exc)
            notify(on_event, "confirm", f"Re-vérifications indisponibles : {exc}", None)
        except ScanCancelledError:
            interrupted = True
            observations["confirmations_error"] = "Scan interrompu par l'utilisateur."
        except ScanConfigError as exc:
            # ES-05 : durée maximale atteinte pendant la re-vérification : les
            # constats déjà trouvés sont conservés, le scan se clôture.
            interrupted = True
            observations["confirmations_error"] = f"Scan interrompu : durée maximale atteinte ({exc})."

    scan.recon_json = json.dumps(observations, ensure_ascii=False)
    scan.finished_at = datetime.now(UTC)
    session.commit()

    # La durée est calculée avec des horodatages Python purs : relire
    # `scan.finished_at` depuis SQLite renverrait un datetime sans fuseau
    # (SQLite ne stocke pas le fuseau), non soustraisible au départ UTC.
    duration = (datetime.now(UTC) - started_at).total_seconds()
    reproduced = reverify_stats["reproduced"]
    pfps = reverify_stats["potential_false_positives"]
    if interrupted:
        notify(
            on_event,
            "done",
            f"Scan interrompu par l'utilisateur après {duration:.1f}s — "
            f"{len(findings)} constat(s) enregistré(s) (statut Probable).",
            100,
        )
        return ScanOutcome(
            scan_id=scan.id,
            target=config.target,
            duration_seconds=duration,
            technologies=technologies,
            recon_observations=observations,
            findings=findings,
            reproduced=reproduced,
            potential_false_positives=pfps,
            interrupted=True,
            request_log=request_log,
        )
    notify(
        on_event,
        "done",
        f"Scan terminé en {duration:.1f}s — {len(findings)} constat(s) au statut "
        f"Probable, {reproduced} re-vérifié(s) reproductible(s), {pfps} potentiel(s) "
        "faux positif(s) — la confirmation finale relève de l'analyste.",
        100,
    )
    return ScanOutcome(
        scan_id=scan.id,
        target=config.target,
        duration_seconds=duration,
        technologies=technologies,
        recon_observations=observations,
        findings=findings,
        reproduced=reproduced,
        potential_false_positives=pfps,
        request_log=request_log,
    )


def _load_rules_for(config: ScanConfig) -> list[RuleDefinition]:
    """Charge les règles des familles concernées par le scan et les valide.

    Appelé avant l'enregistrement du scan : une règle mal formée refuse le
    scan avec une erreur explicite (même principe que `validate_target`).
    """
    active = {"headers", "clickjacking", "bac", "components"} & config.allowed_tests
    if not active:
        return []

    rules = load_rules()
    for rule in rules:
        if rule.checks:
            try:
                validate_rule_checks(rule)
            except Exception as exc:
                raise ScanConfigError(str(exc)) from exc
    return rules


def _run_declarative_checks(
    session: Session,
    scan: Scan,
    config: ScanConfig,
    root: RootResponse,
    rules: list[RuleDefinition],
    client: httpx.Client,
    observations: dict,
    started_at: datetime,
    crawled_pages: dict[str, RootResponse] | None = None,
    on_event=None,
) -> tuple[list[FindingInfo], dict[str, RootResponse]]:
    """Évalue les checks déclaratifs (headers, clickjacking, BAC).

    Les checks `path_status` exigent des sondes GET bénignes
    supplémentaires : elles sont préparées ici (une par chemin, toutes
    bornées par la durée maximale du scan), puis les règles sont évaluées
    sur la racine et sur ces sondes. Aucune sonde destructrice (ES-03) et
    aucun crawling (ES-02 : on ne sort pas de la cible ni de la liste
    fermée des chemins de la règle). Retourne les constats et la table des
    pages sondées (réutilisée par les détections actives de la semaine 8,
    pour ne pas re-sonder un chemin déjà connu).

    `crawled_pages` contient les pages découvertes par le crawlur, réutilisées
    pour ne pas refaire de requêtes redondantes.
    """
    pages: dict[str, RootResponse] = dict(crawled_pages) if crawled_pages else {}
    if "bac" in config.allowed_tests:
        base = config.target.rstrip("/")
        for rule in rules:
            for raw in rule.checks:
                if raw.get("type") != "path_status":
                    continue
                check_deadline(config, started_at)
                path = raw["path"]
                abs_url = f"{base}{path}"
                try:
                    pages[abs_url] = fetch_url(client, abs_url)
                    notify(
                        on_event,
                        "checks",
                        f"GET {abs_url} -> {pages[abs_url].status_code}",
                        None,
                    )
                except ReconError as exc:
                    observations.setdefault("sondes", {})[path] = str(exc)
                    notify(on_event, "checks", f"GET {abs_url} -> échec ({exc})", None)

    findings: list[FindingInfo] = []
    allowed = config.allowed_tests
    for rule in rules:
        if not rule.checks:
            continue
        eligible = any(
            (raw.get("type") == "path_status" and "bac" in allowed)
            or (raw.get("type") == "header_absent" and "headers" in allowed)
            or (raw.get("type") == "clickjacking" and "clickjacking" in allowed)
            for raw in rule.checks
        )
        if not eligible:
            continue

        results = evaluate_rule_checks(rule, root, pages)
        for result in results:
            findings.append(
                _persist_finding(
                    session, scan, result, base_score=rule.confidence_base
                )
            )

    return findings, pages


def _persist_finding(
    session: Session, scan: Scan, result: CheckResult, base_score: float | None = None
) -> FindingInfo:
    """Crée le `Finding` et sa preuve pour un constat de check déclaratif.

    `base_score` : score de confiance de la règle YAML. Le constat démarre à
    cette valeur ; la re-vérification (RF-23) l'ajustera ensuite sans jamais
    confirmer — « Confirmée » est une décision d'analyste (RF-12).
    """
    finding = Finding(
        scan_id=scan.id,
        rule_id=result.rule_id,
        check_id=result.check_id,
        title=result.description[:255],
        description=result.description,
        category=result.category,
        severity=result.severity,
        matched_at=result.matched_url,
        status=FindingStatus.PROBABLE,
    )
    if base_score is not None:
        finding.confidence_score = base_score
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


def _detect_vulnerable_components(
    session: Session,
    scan: Scan,
    technologies: list[TechnologyMatch],
    rules: list[RuleDefinition],
) -> list[FindingInfo]:
    """RF-18 : correspondance version détectée -> CVE du cache local.

    Aucun appel réseau : `lookup_component(allow_network=False)` ne lit que
    le cache CVE local, préalablement rempli par la commande explicite
    `tscan lookup-cve` (ES-09). Un composant jamais interrogé ne produit
    aucun résultat -- l'absence de connaissance n'est pas une preuve.
    """
    vuln_rule = next((r for r in rules if r.category == "vulnerable_component"), None)
    findings: list[FindingInfo] = []

    for match in technologies:
        if match.version is None or match.cpe_alias is None:
            continue  # sans version, aucune correspondance CVE fiable (choix 7a)

        entries = lookup_component(
            session, f"{match.cpe_alias} {match.version}", allow_network=False
        )
        for entry in entries:
            if not entry.cve_id:
                continue  # entrée sentinelle : interrogé, aucune CVE connue

            severity = (entry.cvss_severity or "medium").lower()
            title = f"{match.label} {match.version} : {entry.cve_id}"
            description = entry.description or (
                f"Le composant {match.label} {match.version}, détecté sur la cible, "
                f"correspond à la vulnérabilité connue {entry.cve_id}."
            )
            evidence_text = (
                f"{match.label} {match.version} (preuve : {match.source}) -> {entry.cve_id}"
            )

            base_score = vuln_rule.confidence_base if vuln_rule else 0.5
            finding = Finding(
                scan_id=scan.id,
                rule_id=vuln_rule.id if vuln_rule else FALLBACK_COMPONENT_RULE_ID,
                title=title[:255],
                description=description,
                category="vulnerable_component",
                severity=severity,
                matched_at=scan.target,
                status=FindingStatus.PROBABLE,
                confidence_score=base_score,
            )
            finding.score_explanation = json.dumps(
                [
                    "Constat produit par le moteur de scan actif de Tscan.",
                    "Correspondance composant détecté -> CVE connue (cache local).",
                    f"Score de base de la règle : {base_score:.2f}.",
                    (
                        "Statut Probable : la confirmation finale relève de la revue de "
                        "l'analyste (RF-12)."
                    ),
                ],
                ensure_ascii=False,
            )
            session.add(finding)
            session.flush()
            session.add(
                Evidence(
                    finding_id=finding.id,
                    evidence_type=EvidenceType.NOTE,
                    content_text=evidence_text,
                )
            )
            findings.append(
                FindingInfo(
                    title=finding.title,
                    severity=finding.severity,
                    category=finding.category,
                    matched_at=finding.matched_at,
                )
            )

    return findings


def _probe_tls_observation(config: ScanConfig) -> dict:
    """Sonde TLS de la cible ; une défaillance n'interrompt pas le scan."""
    try:
        tls_info: TlsInfo = probe_tls(config.hostname, config.port)
    except TlsProbeError as exc:
        return {"error": str(exc)}
    return tls_info.to_dict()

