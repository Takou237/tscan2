"""Détection de redirections « géantes » (feuille de route : parité OWASP ZAP,
alerte 10043 « Big Redirect Detected (Potential Sensitive Information Leak) »).

Une redirection (3xx) dont l'en-tête `Location` est très long (>100
caractères) et porte une chaîne de requête peut transférer des jetons de
session, des clés ou d'autres données sensibles via l'URL : c'est une fuite
d'information. La sonde est non destructive (ES-03) : GET sur quelques
chemins banals sans suivre la redirection (`follow_redirects=False`), on lit
simplement l'en-tête `Location` (ES-09 : aucune ressource externe contactée).
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.progress import notify
from tscan_core.scan.request_log import RequestRecord, format_wat

# Parité ZAP : 100 (longueur minimale de l'URI de redirection) + requête.
MIN_LOCATION_LENGTH = 100

RULE_ID = "RULE-BIG-REDIRECT-001"
CATEGORY = "information_disclosure"
SEVERITY = "low"

# Chemins plausibles de redirection applicative (canonisation, paramètres de
# campagne...) — aucun paramètre n'est fourni : on mesure la redirection réelle.
_PROBE_PATHS = ("/", "/inscription", "/connexion", "/panier", "/a-propos")


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at=None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    del root

    base = config.target.rstrip("/")
    request_log = getattr(client, "_tscan_request_log", None)
    results: list[DetectionResult] = []
    seen_locations: set[str] = set()

    # Périmètre des sondes : les chemins globaux (parité ZAP : redirections
    # applicatives) + les URLs réellement découvertes par le crawl — c'est sur
    # ces pages que le spider ZAP observe les redirections « géantes »
    # (ex. /editeur-cv chez le client réel).
    probe_urls: list[str] = [f"{base}{path}" for path in _PROBE_PATHS]
    if pages:
        for url in pages:
            if url not in probe_urls:
                probe_urls.append(url)

    seen_paths: set[str] = set()

    # Arrêt anticipé (ES-02) : sur une cible bloquante, chaque sonde coûte le
    # timeout complet ; après 3 échecs consécutifs, la suite du périmètre
    # subira le même sort — inutile d'enchaîner des minutes d'échecs.
    consecutive_errors = 0
    _MAX_CONSECUTIVE_ERRORS = 3

    with httpx.Client(follow_redirects=False, timeout=5.0) as redirect_client:
        for url in probe_urls:
            if url.rstrip("/") in seen_paths:
                continue
            seen_paths.add(url.rstrip("/"))
            sent_at = datetime.now(UTC)
            try:
                resp = redirect_client.get(url)
                consecutive_errors = 0
                received_at = datetime.now(UTC)
                if request_log is not None:
                    try:
                        reason = resp.reason_phrase or ""
                    except AttributeError:  # pragma: no cover
                        reason = ""
                    request_log.add(
                        RequestRecord(
                            id=request_log.next_id(),
                            sent_at=format_wat(sent_at),
                            received_at=format_wat(received_at),
                            method="GET",
                            url=url,
                            status_code=resp.status_code,
                            reason=reason,
                        )
                    )
            except httpx.HTTPError as exc:
                if request_log is not None:
                    request_log.add(
                        RequestRecord(
                            id=request_log.next_id(),
                            sent_at=format_wat(sent_at),
                            received_at=format_wat(datetime.now(UTC)),
                            method="GET",
                            url=url,
                            status_code=None,
                            reason="",
                        )
                    )
                observations.setdefault("sondes", {})[url] = str(exc)
                notify(on_event, "detect", f"GET {url} -> échec ({exc})", None)
                consecutive_errors += 1
                if consecutive_errors >= _MAX_CONSECUTIVE_ERRORS:
                    notify(
                        on_event,
                        "detect",
                        "Sondes big-redirect interrompues : cible injoignable "
                        f"({consecutive_errors} échecs consécutifs)",
                        None,
                    )
                    break
                continue

            status = resp.status_code
            notify(on_event, "detect", f"GET {url} -> {status}", None)
            if status not in (301, 302, 303, 307, 308):
                continue

            location = resp.headers.get("location", "").strip()
            if not _is_big_redirect(location):
                continue
            if location in seen_locations:
                continue
            seen_locations.add(location)

            results.append(
                DetectionResult(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    severity=SEVERITY,
                    title="Big Redirect Detected (Potential Sensitive Information Leak)",
                    description=(
                        "La cible répond par une redirection dont l'URI `Location` est "
                        "très longue et porte une chaîne de requête. Une telle URL peut "
                        "transférer des jetons de session, des clés ou d'autres données "
                        "sensibles — en clair dans le `Referer` et les journaux."
                    ),
                    matched_at=url,
                    evidence_text=(
                        f"GET {url} -> {status} : Location {len(location)} caractères "
                        f"avec chaîne de requête ({location[:120]}...)"
                    ),
                    probe_info={
                        "request_url": url,
                        "method": "GET",
                        "signal_type": "big_redirect",
                        "signal_value": location,
                    },
                )
            )
        # Fin de boucle : on ne multiplie pas les preuves pour des redirections
        # identiques sur plusieurs chemins.

    return results


def _is_big_redirect(location: str) -> bool:
    """Vrai si l'URI de redirection est « géante » : longue et avec requête."""
    if len(location) < MIN_LOCATION_LENGTH:
        return False
    parts = urlsplit(location)
    return bool(parts.query)