"""Détection de redirection ouverte (open redirect) par sonde bénigne.

Sonde GET non destructive (ES-03) : la charge est une URL vers un domaine
externe fictif (``//peer.example.invalid``). Si la cible répond par une
redirection 3xx dont le ``Location`` pointe vers un hôte *différent* de la
cible, le constat est émis. Aucune ressource externe n'est contactée (ES-09) :
on n'effectue pas le suivi de la redirection, on se contente de lire l'en-tête.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.progress import notify
from tscan_core.scan.request_log import RequestRecord, format_wat

# Domaine externe fictif : .invalid n'est jamais résolu.
EXTERNAL_ORIGIN = "peer.example.invalid"
REDIRECT_PARAMS = ("redirect", "next", "url", "return", "goto")

RULE_ID = "RULE-OPEN-REDIRECT-001"
SEVERITY = "medium"
CATEGORY = "open-redirect"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at=None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    del root, started_at, pages

    base = config.target.rstrip("/")
    target_host = urlparse(config.target).netloc
    results: list[DetectionResult] = []

    # La sonde ne doit PAS suivre la redirection (sinon httpx tenterait de
    # joindre le domaine externe fictif .invalid). On utilise un client dédié
    # `follow_redirects=False`, qui ne quitte jamais la cible (ES-09) : on lit
    # l'en-tête `Location` d'une éventuelle réponse 3xx.
    request_log = getattr(client, "_tscan_request_log", None)
    with httpx.Client(follow_redirects=False, timeout=10.0) as redirect_client:
        for param in REDIRECT_PARAMS:
            for path in ("/", "/login", "/redirect", "/go"):
                value = f"//{EXTERNAL_ORIGIN}/"
                url = f"{base}{path}?{param}={value}"
                sent_at = datetime.now(UTC)
                try:
                    resp = redirect_client.get(url)
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
                    continue

                status = resp.status_code
                notify(on_event, "detect", f"GET {url} -> {status}", None)
                if status not in (300, 301, 302, 303, 307, 308):
                    continue

                location = resp.headers.get("location", "")
                if not _redirects_outside(location, target_host):
                    continue

                results.append(
                    DetectionResult(
                        rule_id=RULE_ID,
                        category=CATEGORY,
                        severity=SEVERITY,
                        title="Redirection ouverte probable",
                        description=(
                            "La cible redirige vers un hôte externe en suivant une valeur "
                            "contrôlée dans une paramètre d'URL (`Location` reflété). Une "
                            "redirection ouverte peut être détournée pour du phishing ou "
                            "contourner des validations d'origine."
                        ),
                        matched_at=url,
                        evidence_text=(
                            f"GET {url} -> {status} : Location={location!r}"
                        ),
                        probe_info={
                            "request_url": url,
                            "method": "GET",
                            "signal_type": "open_redirect",
                            "signal_value": location,
                        },
                    )
                )
                # Un constat suffit par paramètre : inutile de multiplier les
                # preuves sur les chemins restants.
                break

    return results


def _redirects_outside(location: str, target_host: str) -> bool:
    """Vrai si l'emplacement de redirection pointe hors de la cible."""
    loc = location.strip()
    if not loc:
        return False
    target_base = target_host.split(":")[0]
    # Redirection vers un hôte complet (`scheme://hote/...`).
    if "://" in loc:
        host = urlparse(loc).netloc.split(":")[0]
        return host != target_base
    # Redirection schéma-relative (`//hote/...`).
    if loc.startswith("//"):
        host = loc.split("/")[2].split(":")[0]
        return host != target_base
    return False