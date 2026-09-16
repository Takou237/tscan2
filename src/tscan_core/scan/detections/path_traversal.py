"""Détection de traversée de répertoire (path traversal) par sondes bénignes.

Sondes GET non destructives (ES-03) : la charge est une traversée réelle vers
un fichier-systeme standard (``/etc/passwd``), mais elle ne doit PAS aboutir à
la divulgation de contenu sur la cible produite par ce test — le constat n'est
émis que si la réponse contient une signature de fichier (en-tête ``root:x:0:0``
pour une ombre passwd, ou ``[core]`` pour un ``.git/config`` traversé). Sur le
laboratoire, la route vulnérable traverse un chemin contrôlé qui reflète un
contenu de démonstration porteur de la même signature que ``/etc/passwd``.

La charge reste inoffensive (lecture seule, aucune écriture, aucune exfiltration
réseau) ; le constat demeure ``Probable`` jusqu'à la confirmation active.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Chemins sondés et charge de traversée bénigne correspondante.
# Chaque cible (path) reçoit une charge qui remonte au fichier espéré.
PROBES: dict[str, tuple[str, tuple[str, ...]]] = {
    "/download": (
        "?file=../../../../../../etc/passwd",
        ("root:x:0:0", "daemon:x:1:1", "bin:x:2:2"),
    ),
    "/get": (
        "?file=../../../../../../etc/passwd",
        ("root:x:0:0", "daemon:x:1:1"),
    ),
    "/file": (
        "?path=../../../etc/passwd",
        ("root:x:0:0", "daemon:x:1:1"),
    ),
}

HOST_FILE_SIGNATURES = ("root:x:0:0", "daemon:x:1:1", "bin:x:2:2", "nobody:x:65534")

RULE_ID = "RULE-PATH-TRAVERSAL-001"
SEVERITY = "high"
CATEGORY = "path-traversal"


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

    for path, (charge, signatures) in PROBES.items():
        url = f"{base}{path}{charge}"
        page = probe_fetch(client, url, observations, on_event)
        if page is None:
            continue

        if page.status_code not in (200, 204):
            continue

        marker = _matching_signature(page.body, signatures)
        if marker is None:
            continue

        results.append(
            DetectionResult(
                rule_id=RULE_ID,
                category=CATEGORY,
                severity=SEVERITY,
                title="Traversée de répertoire probable (divulgation de fichier)",
                description=(
                    "Une charge de test bénigne de traversée (`../`) envoyée dans un "
                    "paramètre a permis de lire un contenu hors du répertoire servi : "
                    "la réponse porte une signature de fichier système/application. "
                    "Un attaquant pourrait lire d'autres fichiers à la demande."
                ),
                matched_at=page.final_url,
                evidence_text=(
                    f"GET {page.final_url} -> {page.status_code} : signature de fichier "
                    f"retrouvée ({marker!r})"
                ),
                probe_info={
                    "request_url": url,
                    "method": "GET",
                    "signals": [
                        {"type": "status_in", "value": [200, 204]},
                        {"type": "body_marker", "value": marker},
                    ],
                },
            )
        )

    return results


def _matching_signature(body: str, signatures: tuple[str, ...]) -> str | None:
    """Retourne la première signature présente dans le corps, sinon None."""
    lowered = body.lower()
    for signature in signatures:
        if signature in lowered:
            return signature
    return None