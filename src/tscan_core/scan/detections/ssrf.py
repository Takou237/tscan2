"""Détection de SSRF (Server-Side Request Forgery) par sonde bénigne à marqueur.

Sonde GET non destructive (ES-03) : la charge est une URL locale
(``http://127.0.0.1:PORT``) ou un hôte résolu vers ``localhost``. Si la réponse
contient un marqueur réfléchi indiquant que le serveur a effectivement réalisé
la requête (corps d'erreur ou page chargée), le constat est émis. Aucun réseau
sortant n'est généré : l'URL pointe vers la propre boucle locale de la cible
(ES-09 : aucune ressource externe contactée).
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Paramètres d'URL classiquement vulnérables au SSRF.
SSRF_PARAMS = ("url", "fetch", "load", "uri", "src", "path", "dest")

# Signatures d'une réponse indiquant que le serveur a chargé la ressource
# (corps de réponse typique d'une page de démonstration SSRF).
SSRF_SIGNATURES = (
    "internal ip",
    "127.0.0.1",
    "localhost",
    "internal server",
    "loopback",
    "ssrf",
    "could not resolve",
)

# Chemins à sonder.
PROBE_PATHS = ("/", "/api", "/load", "/fetch", "/proxy")


RULE_ID = "RULE-SSRF-001"
SEVERITY = "high"
CATEGORY = "ssrf"


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
    results: list[DetectionResult] = []

    for path in PROBE_PATHS:
        for param in SSRF_PARAMS:
            # L'URL testée pointe vers la boucle locale de la cible.
            probe_url = f"{base}{path}?{param}=http://127.0.0.1/"
            page = probe_fetch(client, probe_url, observations, on_event)
            if page is None:
                continue

            if page.status_code not in (200, 204, 500, 502, 503):
                continue

            marker = _matching_signature(page.body)
            if marker is None:
                continue

            results.append(
                DetectionResult(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    severity=SEVERITY,
                    title="SSRF (Server-Side Request Forgery) probable",
                    description=(
                        "Un paramètre accepte une URL pointant vers la boucle locale "
                        "(127.0.0.1) et le serveur la traite : le corps de la réponse "
                        "contient des marqueurs internes. Un attaquant pourrait interroger "
                        "des services internes, lire des secrets (IAM, metadata) ou "
                        "atterrir sur des interfaces d'administration non exposées."
                    ),
                    matched_at=page.final_url,
                    evidence_text=(
                        f"GET {page.final_url} -> {page.status_code} : "
                        f"signature SSRF ({marker!r}) détectée pour le paramètre {param!r}"
                    ),
                    probe_info={
                        "request_url": probe_url,
                        "method": "GET",
                        "signals": [
                            {"type": "status_in", "value": [200, 204, 500, 502, 503]},
                            {"type": "body_marker", "value": marker},
                        ],
                    },
                )
            )
            break
        if results:
            break

    return results


def _matching_signature(body: str) -> str | None:
    """Retourne la première signature SSRF présente dans le corps, sinon None."""
    lowered = body.lower()
    for signature in SSRF_SIGNATURES:
        if signature in lowered:
            return signature
    return None