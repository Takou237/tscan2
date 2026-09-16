"""Re-vérification active non destructive des constats de scan (RF-23).

Phase de seconde observation du scan actif : une fois les détections
persistées (statut ``Probable``), ce module re-évalue chaque constat pour
ajuster SA CONFIANCE, sans jamais se substituer à la décision de l'analyste
(RF-12) :

- fait décisif **reproduit** par une nouvelle requête -> score renforcé
  (plafonné à 0,85) mais statut inchangé (``Probable``) : le moteur ne
  confirme jamais, « Confirmée » est un verdict humain ;
- fait décisif **contredit** par une nouvelle observation (familles à
  re-vérification précise) -> statut ``potentiel_faux_positif`` et score
  réduit, pour revue analytique prioritaire (comme la confiance « Low » de
  ZAP) ;
- sonde de re-vérification **en échec réseau** -> constat laissé tel quel,
  échec tracé (ES-05).

La re-vérification réutilise les familles de détection déjà implémentées
(``tscan_core.scan.detections`` et ``tscan_core.scan.checks``) : aucune
logique de test n'est dupliquée ici.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from tscan_core.knowledge_base.update_manager import lookup_component
from tscan_core.models import Evidence, EvidenceType, Finding, FindingStatus, Scan
from tscan_core.recon import fingerprint
from tscan_core.recon.client import ReconError, RootResponse, fetch_url

# Cadence de re-vérification : une sonde qui échoue n'a pas besoin de la
# politique robuste de reconnaissance (3 tentatives, backoff exponentiel,
# timeout 10 s ≈ 35 s par échec). Cible bloquante en fin de scan = des dizaines
# de re-vérifications : on réduit à 1 tentative / timeout 5 s (ES-02).
_REVERIFY_KWARGS = {"max_retries": 1, "backoff": 0.2, "timeout": 5.0}
from tscan_core.recon.fingerprint import load_technologies
from tscan_core.recon.tls import TlsProbeError, probe_tls
from tscan_core.rule_engine.loader import load_rules
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.scan.checks import EXPOSED_STATUSES, evaluate_rule_checks
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import (
    check_deadline,
    cmd_injection,
    cors,
    csrf,
    directory_listing,
    header_injection,
    open_redirect,
    path_traversal,
    sensitive_files,
    sqli,
    ssrf,
    ssti,
    tls_weak,
    weak_hash,
    xss,
)
from tscan_core.scan.progress import notify
from tscan_core.status import AUTOMATIC_ACTOR, change_status

# La re-vérification (RF-23) ajuste la confiance sans jamais CONFIRMER : le
# moteur plafonne volontairement son score (0,85) sous le seuil de la décision
# humaine (0,95) pour que le statut « Confirmée » reste la signature de
# l'analyste (RF-12).
REVERIFY_BOOST = 0.10
REVERIFY_CAP = 0.85
REVERIFY_PENALTY = 0.15
PFP_FLOOR = 0.30

NOT_REPRODUCED_REASON = (
    "Fait décisif non reproduit lors de la re-vérification active non destructive "
    "(RF-23) : constat placé en potentiel faux positif pour revue analytique."
)

# Familles dont la re-vérification est une ré-observation PRÉCISE du même
# fait (même en-tête, même check, même route, même CVE rattachable, ou même
# charge de sonde rejouée via `probe_info`) : une non-reproduction y est une
# vraie contradiction, donc un signal de faux positif. Les familles en code
# SANS charge rejouable (passives : CSRF, cookies, CSP, SRI, timestamp, ...)
# rejouent leur famille entière sur un périmètre plus restreint : une
# non-reproduction n'y est pas une preuve de faux positif.
_PRECISE_RECHECK_RULE_IDS = frozenset(
    {
        # Déclaratives : ré-observation précise d'un en-tête / check / route / CVE.
        "RULE-MISCONFIG-001",
        "RULE-CLICKJACKING-001",
        "RULE-BAC-001",
        "RULE-VULNCOMP-001",
        # Actives avec charge rejouable (`probe_info`) : sqli, xss, ssti,
        # commande, ssrf, path traversal, fichiers sensibles, listing, CORS,
        # redirection ouverte, injection de header.
        "RULE-SQLI-001",
        "RULE-XSS-001",
        "RULE-SSTI-001",
        "RULE-CMD-INJECTION-001",
        "RULE-SSRF-001",
        "RULE-PATH-TRAVERSAL-001",
        "RULE-SENSITIVE-FILES-001",
        "RULE-LISTING-001",
        "RULE-CORS-001",
        "RULE-OPEN-REDIRECT-001",
        "RULE-HDR-INJECTION-001",
    }
)


def reverify_active_findings(
    session: Session,
    scan: Scan,
    config: ScanConfig,
    client,
    observations: dict,
    started_at: datetime,
    on_event=None,
) -> dict:
    """Re-vérifie la confiance des constats du scan (RF-23), sans confirmer.

    Retourne ``{"reproduced": n, "potential_false_positives": m, "probe_errors": k}``.

    Ajustement de confiance (ZAP-like) :
    - fait reproduit -> score renforcé (plafonné à 0,85), statut inchangé
      (``Probable`` : seule l'analyste confirme, RF-12) ;
    - fait contredit (familles à re-vérification précise) -> statut
      ``potentiel_faux_positif``, score réduit, historique tracé ;
    - sonde en échec réseau -> constat laissé tel quel (ES-05).

    Ne lève jamais ``ReconError``.
    """
    candidates = (
        session.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.status == FindingStatus.PROBABLE)
        .all()
    )
    if not candidates:
        return {"reproduced": 0, "potential_false_positives": 0, "probe_errors": 0}

    rules = {rule.id: rule for rule in load_rules()}
    cache: dict = {}
    reproduced = 0
    potential_false_positives = 0
    probe_errors = 0

    for finding in candidates:
        check_deadline(config, started_at)
        if finding.confidence_score is None:
            # Filet de sécurité : tout constat doit avoir un score de base.
            rule = rules.get(finding.rule_id)
            base = rule.confidence_base if rule else 0.5
            finding.confidence_score = base
            if rule is not None:
                finding.score_explanation = _base_score_explanation(rule)

        notify(on_event, "confirm", f"Re-vérification de « {finding.title} »…", None)
        try:
            ok = _one(session, finding, config, client, observations, rules, cache, on_event)
        except ReconError as exc:
            observations.setdefault("confirmations", {})[finding.id] = str(exc)
            probe_errors += 1
            notify(on_event, "confirm", f"Sonde échouée pour « {finding.title} »", None)
            continue

        if ok:
            _reward(session, finding)
            reproduced += 1
            notify(
                on_event,
                "confirm",
                f"« {finding.title} » — fait reproduit, score renforcé",
                None,
            )
        elif finding.rule_id in _PRECISE_RECHECK_RULE_IDS:
            _flag_potential_false_positive(session, finding)
            potential_false_positives += 1
            notify(
                on_event,
                "confirm",
                f"« {finding.title} » — fait contredit, potentiel faux positif",
                None,
            )
        else:
            _note_not_reproduced(session, finding)

    if reproduced:
        observations["reproduced"] = reproduced
    if potential_false_positives:
        observations["potential_false_positives"] = potential_false_positives
    if probe_errors:
        observations["probe_errors"] = probe_errors

    return {
        "reproduced": reproduced,
        "potential_false_positives": potential_false_positives,
        "probe_errors": probe_errors,
    }


def _one(
    session: Session,
    finding: Finding,
    config: ScanConfig,
    client,
    observations: dict,
    rules: dict[str, RuleDefinition],
    cache: dict,
    on_event=None,
) -> bool:
    """Re-observation du constat : True si le fait décisif est toujours observé.

    Aucun effet de bord sur le score ni le statut : la décision de renforcer
    (``_reward``), de signaler un potentiel faux positif (``_flag_...``) ou de
    laisser le constat tel quel (`_note_not_reproduced`) revient à l'appelant.

    Deux stratégies :
    - **Ré-observation précise** (familles à charge rejouable, RF-23) : quand
      le constat porte un `probe_info` (URL de re-sonde + signal décisif), on
      rejoue EXACTEMENT la charge qui avait produit le constat et on vérifie
      que le signal caractéristique se reproduit. Une non-reproduction y est
      une vraie contradiction, donc un signal de faux positif.
    - **Ré-observation de famille** (repli historique) : sinon, on ré-exécute
      la famille entière sur un périmètre restreint ; une non-reproduction n'y
      est pas une preuve de faux positif (simple note).
    """
    probe_info = _probe_info_of(finding)
    if probe_info is not None:
        return _precise_reobserve(
            session, finding, config, client, probe_info, cache, on_event, rules
        )

    runner = _CODE_RUNNERS.get(finding.rule_id)
    if runner is not None:
        fresh_keys = runner(config, client, observations, cache, on_event)
        return _match_key(finding.matched_at) in fresh_keys

    rule = rules.get(finding.rule_id)
    if rule is None:
        return False  # règle disparue entre-temps : aucune re-observation possible

    if finding.rule_id == "RULE-MISCONFIG-001":
        check = _check_by_id(rule, finding.check_id)
        header = (check.get("header") or "").strip().lower()
        root = _fresh_root(config, client, cache, on_event)
        return header not in root.headers

    if finding.rule_id == "RULE-CLICKJACKING-001":
        root = _fresh_root(config, client, cache, on_event)
        return bool(evaluate_rule_checks(rule, root))

    if finding.rule_id == "RULE-BAC-001":
        check = _check_by_id(rule, finding.check_id)
        path = check.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return False
        page = _page_path(config, client, cache, path, on_event)
        return page.status_code in EXPOSED_STATUSES

    if finding.rule_id == "RULE-VULNCOMP-001":
        return _component_reproduced(session, finding, config, client, cache)

    return False  # famille inconnue


def _probe_info_of(finding: Finding) -> dict | None:
    """Décode le `probe_info` d'un constat (sérialisé en `probe_json`)."""
    if not finding.probe_json:
        return None
    try:
        value = json.loads(finding.probe_json)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def _precise_reobserve(
    session: Session,
    finding: Finding,
    config: ScanConfig,
    client,
    probe_info: dict,
    cache: dict,
    on_event,
    rules: dict[str, RuleDefinition],
) -> bool:
    """Rejoue la charge exacte du constat et vérifie que le signal se reproduit.

    `session`/`rules` sont passés pour les variantes qui relèvent d'une
    ré-observation indirecte (composants) ; la plupart des familles n'en ont
    pas besoin.
    """
    del session, rules
    request_url = probe_info.get("request_url")
    if not isinstance(request_url, str) or not request_url:
        return False

    headers = probe_info.get("headers")
    if isinstance(headers, dict):
        headers = {str(k): str(v) for k, v in headers.items()}
    else:
        headers = None

    page = fetch_url(client, request_url, headers=headers, **_REVERIFY_KWARGS)
    notify(on_event, "confirm", f"GET {request_url} -> {page.status_code}", None)

    signals = probe_info.get("signals")
    if isinstance(signals, list) and signals:
        return all(_recheck_signal(sig, page) for sig in signals)

    signal_type = probe_info.get("signal_type")
    if signal_type is None:
        return False
    return _recheck_special(signal_type, probe_info, page)


def _recheck_signal(signal: dict, page) -> bool:
    """Vérifie un signal élémentaire contre la réponse rejouée."""
    stype = signal.get("type")
    value = signal.get("value")
    if stype == "status":
        return page.status_code == value
    if stype == "status_in":
        return page.status_code in value
    if stype == "body_marker":
        return str(value).lower() in page.body.lower()
    if stype == "body_contains":
        return str(value) in page.body
    if stype == "body_regex":
        try:
            return bool(re.search(str(value), page.body))
        except re.error:
            return False
    return True  # type inconnu : ne pas conclure à un faux positif


def _recheck_special(signal_type: str, probe_info: dict, page) -> bool:
    """Ré-observation des signaux de famille spécifiques (non génériques)."""
    if signal_type == "cors_permissive":
        # CORS : re-sonde avec l'en-tête Origin de test et vérifie la violation.
        from tscan_core.scan.detections.cors import _is_permissive

        return page.headers.get("access-control-allow-origin") is not None and _is_permissive(page)

    if signal_type == "open_redirect":
        # Redirection ouverte : la réponse doit encore rediriger vers un hôte externe.
        from tscan_core.scan.detections.open_redirect import (
            _redirects_outside,
            urlparse,
        )

        target_host = urlparse(probe_info.get("request_url", "")).netloc
        status = page.status_code
        if status not in (300, 301, 302, 303, 307, 308):
            return False
        location = page.headers.get("location", "")
        return _redirects_outside(location, target_host)

    if signal_type == "header_injection_marker":
        # Injection de header : le marqueur doit être reflété dans un en-tête.
        from tscan_core.scan.detections.header_injection import (
            _marker_in_non_standard_header,
        )

        return _marker_in_non_standard_header(page)

    marker = probe_info.get("signal_value")
    if signal_type == "body_marker":
        return page.body and str(marker).lower() in page.body.lower()
    if signal_type == "body_contains":
        return page.body and str(marker) in page.body
    if signal_type == "body_regex":
        try:
            return page.body and bool(re.search(str(marker), page.body))
        except re.error:
            return False
    return True  # type inconnu : ne pas conclure à un faux positif


def _base_score_explanation(rule: RuleDefinition) -> str:
    """Explication de score d'un constat encore non re-vérifié."""
    return json.dumps(
        [
            "Constat produit par le moteur de scan actif de Tscan.",
            (
                f"Score de base de la règle {rule.id} ({rule.name}) : "
                f"{rule.confidence_base:.2f}."
            ),
            "Statut Probable : seule une revue de l'analyste peut confirmer (RF-12).",
        ],
        ensure_ascii=False,
    )


def _load_explanation(finding: Finding) -> list[str]:
    """Reconstruit la liste d'explications de score d'un constat."""
    if not finding.score_explanation:
        return []
    try:
        value = json.loads(finding.score_explanation)
        return value if isinstance(value, list) else [str(value)]
    except json.JSONDecodeError:
        return [finding.score_explanation]


def _reward(session: Session, finding: Finding) -> None:
    """Renforce la confiance d'un constat reproduit, sans changer le statut."""
    old = finding.confidence_score or 0.5
    new = min(REVERIFY_CAP, old + REVERIFY_BOOST)
    finding.confidence_score = round(new, 2)

    explanation = _load_explanation(finding)
    explanation.append(
        "Re-vérification active non destructive positive (RF-23) : le fait décisif "
        f"a été reproduit sur {finding.matched_at or finding.scan.target}. Score "
        f"porté de {old:.2f} à {finding.confidence_score:.2f} (plafonné à "
        f"{REVERIFY_CAP:.2f} — le statut « Confirmée » reste une décision "
        "d'analyste, RF-12)."
    )
    finding.score_explanation = json.dumps(explanation, ensure_ascii=False)
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=(
                "Re-vérification active non destructive : le fait décisif a été "
                "reproduit par une nouvelle requête (RF-23). Statut laissé "
                "Probable — la confirmation finale relève de l'analyste (RF-12)."
            ),
        )
    )


def _flag_potential_false_positive(session: Session, finding: Finding) -> None:
    """Fait contredit par la nouvelle observation : constat en potentiel faux
    positif (à revoir par l'analyste), score réduit, historique tracé."""
    old = finding.confidence_score or 0.5
    new = max(PFP_FLOOR, old - REVERIFY_PENALTY)
    finding.confidence_score = round(new, 2)

    explanation = _load_explanation(finding)
    explanation.append(
        "Re-vérification active contradictoire (RF-23) : le fait décisif n'est "
        f"plus reproduit sur {finding.matched_at or finding.scan.target}. Score "
        f"réduit de {old:.2f} à {finding.confidence_score:.2f} — constat placé "
        "en potentiel faux positif pour revue analytique."
    )
    finding.score_explanation = json.dumps(explanation, ensure_ascii=False)
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=(
                "Re-vérification active non destructive contradictoire : le fait "
                "décisif n'a pas été reproduit (ou a disparu) sur une nouvelle "
                "requête. Constat placé en potentiel faux positif pour revue analytique."
            ),
        )
    )
    change_status(
        session,
        finding,
        FindingStatus.POTENTIAL_FALSE_POSITIVE,
        changed_by=AUTOMATIC_ACTOR,
        reason=NOT_REPRODUCED_REASON,
    )


def _note_not_reproduced(session: Session, finding: Finding) -> None:
    """Famille en code : non-reproduction sur le périmètre restreint de la
    confirmation. Le constat reste Probable, sans changer de score, mais une
    trace est laissée pour l'analyste."""
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=(
                "Re-vérification active : le fait n'a pas été re-produit par la "
                "sonde de confirmation (périmètre restreint de la famille). "
                "Constat laissé Probable pour revue analytique."
            ),
        )
    )


# --- Familles en code : re-vérification par ré-observation directe ---


def _run_xss(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in xss.run(config, client, root, observations, on_event=on_event)
    }


def _run_csrf(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in csrf.run(config, client, root, observations, on_event=on_event)
    }


def _run_sqli(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in sqli.run(config, client, root, observations, on_event=on_event)
    }


def _run_sensitive(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in sensitive_files.run(config, client, root, observations, on_event=on_event)
    }


def _run_listing(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in directory_listing.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_cors(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in cors.run(config, client, root, observations, on_event=on_event)
    }


def _run_path_traversal(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in path_traversal.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_open_redirect(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in open_redirect.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_cmd_injection(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in cmd_injection.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_ssti(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in ssti.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_ssrf(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in ssrf.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_header_injection(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in header_injection.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_weak_hash(
    config: ScanConfig, client, observations: dict, cache: dict, on_event=None
) -> set[str]:
    root = _fresh_root(config, client, cache, on_event)
    return {
        _match_key(r.matched_at)
        for r in weak_hash.run(
            config, client, root, observations, pages={}, on_event=on_event
        )
    }


def _run_tls(config: ScanConfig, client, observations: dict, cache: dict) -> set[str]:
    del client, observations, cache
    try:
        info = probe_tls(config.hostname, config.port)
    except TlsProbeError:
        return set()
    return {_match_key(r.matched_at) for r in tls_weak.run(config, {"tls": info.to_dict()})}


_CODE_RUNNERS = {
    "RULE-XSS-001": _run_xss,
    "RULE-CSRF-001": _run_csrf,
    "RULE-SQLI-001": _run_sqli,
    "RULE-SENSITIVE-FILES-001": _run_sensitive,
    "RULE-LISTING-001": _run_listing,
    "RULE-CORS-001": _run_cors,
    "RULE-TLS-WEAK-001": _run_tls,
    "RULE-PATH-TRAVERSAL-001": _run_path_traversal,
    "RULE-OPEN-REDIRECT-001": _run_open_redirect,
    "RULE-CMD-INJECTION-001": _run_cmd_injection,
    "RULE-SSTI-001": _run_ssti,
    "RULE-SSRF-001": _run_ssrf,
    "RULE-HDR-INJECTION-001": _run_header_injection,
    "RULE-WEAK-HASH-001": _run_weak_hash,
}


# --- Composants vulnérables : ré-expression + correspondance CVE locale ---


def _component_reproduced(
    session: Session,
    finding: Finding,
    config: ScanConfig,
    client,
    cache: dict,
) -> bool:
    """Vrai si la même CVE du titre est toujours rattachable à la même version
    détectée sur une nouvelle réponse de la cible (cache CVE local uniquement,
    aucun appel réseau hors cible, ES-09)."""
    match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", finding.title or "")
    if match is None:
        return False

    root = _fresh_root(config, client, cache)
    matches = fingerprint.fingerprint_response(
        root.headers, root.body, load_technologies()
    )
    for technology in matches:
        if technology.version is None or technology.cpe_alias is None:
            continue
        for entry in lookup_component(
            session,
            f"{technology.cpe_alias} {technology.version}",
            allow_network=False,
        ):
            if entry.cve_id == match.group(0):
                return True
    return False


# --- Utilitaires ---


def _fresh_root(config: ScanConfig, client, cache: dict, on_event=None) -> RootResponse:
    """Requête fraîche vers la racine de la cible (même sonde qu'à la
    reconnaissance), partagée entre familles pendant la re-vérification."""
    if "root" not in cache:
        cache["root"] = fetch_url(client, config.target, **_REVERIFY_KWARGS)
        notify(
            on_event, "confirm", f"GET {config.target} -> {cache['root'].status_code}", None
        )
    return cache["root"]


def _page_path(config: ScanConfig, client, cache: dict, path: str, on_event=None) -> RootResponse:
    """Re-sonde la même route fermée qu'à la détection ; le résultat est mis
    en cache pour les éventuels autres constats du même chemin."""
    key = f"page:{path}"
    if key not in cache:
        url = f"{config.target.rstrip('/')}{path}"
        cache[key] = fetch_url(client, url, **_REVERIFY_KWARGS)
        notify(on_event, "confirm", f"GET {url} -> {cache[key].status_code}", None)
    return cache[key]


def _match_key(url: str | None) -> str:
    """Clé d'identité d'un constat : schéma + hôte + chemin normalisés.

    La querystring est volontairement écartée ; une sonde de re-vérification
    génère une nouvelle valeur aléatoire (nonce XSS, variation de charge SQLi).
    """
    if not url:
        return ""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def _check_by_id(rule: RuleDefinition, check_id: str | None) -> dict:
    """Cherche le check d'une règle par son identifiant ; sinon premier check."""
    if check_id is not None:
        for raw in rule.checks:
            if raw.get("id") == check_id:
                return raw
    return rule.checks[0] if rule.checks else {}