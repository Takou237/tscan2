"""Détection de configuration CORS permissive (family Security Misconfiguration).

Sonde une requête GET avec un en-tête `Origin` d'un site tiers de test
(`https://attacker.example.invalid`, domaine réservé qui ne peut pas exister)
et lit les en-têtes de réponse. Deux configurations menacent le même modèle de
menace : `Access-Control-Allow-Origin: *` (toute origine peut lire la réponse)
et le reflet sans restriction de l'origine envoyée (`credentials` ou non), qui
permet à un site tiers de lire des données réservées à un utilisateur
authentifié sur la cible. Le constat est `Probable` : l'exploitation dépend du
contenu exact des réponses et de leur usage de cookies.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch, select_probe_urls

# Domaine réservé (RFC 6761) : ne peut être résolu, n'est donc jamais une
# vraie origine -- la sonde reste bénigne et sans effet hors périmètre (ES-02).
TEST_ORIGIN = "https://attacker.example.invalid"

# Périmètre fermé : la racine et les endpoints d'API les plus porteurs de
# données personnelles ou de fonctionnalités utilisateur.
PROBE_PATHS = ("/", "/api/", "/api/v1/", "/graphql", "/cors-open", "/cors-echo", "/contact")

RULE_ID = "RULE-CORS-001"
SEVERITY = "medium"
CATEGORY = "security_misconfiguration"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde les pages découvertes avec un en-tête Origin de test et constate les
    configurations permissives.

    Utilise les pages crawlées lorsqu'elles sont disponibles, sinon les
    chemins prédéfinis.
    """
    del root, started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Échantillon BORNÉ de pages (ES-02) : CORS sonde chaque page avec un
    # en-tête Origin, ce qui génère une requête par page. Borrner à 12 pages
    # maximales garde un volume prévisible (≈12 requêtes au lieu de 60+).
    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    for url in probe_urls:
        page = probe_fetch(
            client, url, observations, on_event,
            label="detect", timeout=5.0,
            headers={"Origin": TEST_ORIGIN},
        )
        if page is None:
            continue

        if _is_permissive(page):
            results.append(
                DetectionResult(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    severity=SEVERITY,
                    title="Configuration CORS permissive",
                    description=(
                        "La réponse à la requête portant un Origin de site tiers accorde "
                        "un accès de lecture excessif (origine sauvage ou reflet du "
                        "n'importe quelle origine). Un site tiers pourrait lire les "
                        "réponses réservées aux visiteurs légitimes."
                    ),
                    matched_at=page.final_url,
                    evidence_text=f"GET {page.final_url} -> {page.status_code} : {_cors_violation(page)}",
                    probe_info={
                        "request_url": url,
                        "method": "GET",
                        "headers": {"Origin": TEST_ORIGIN},
                        "signal_type": "cors_permissive",
                    },
                )
            )

    return results


def _is_permissive(page: RootResponse) -> bool:
    """Vérifie une configuration CORS permissive."""
    allow_origin = page.headers.get("access-control-allow-origin")
    allow_credentials = page.headers.get("access-control-allow-credentials", "").lower()
    reflected = allow_origin == TEST_ORIGIN
    return allow_origin == "*" or (reflected and allow_credentials == "true")


def _cors_violation(page: RootResponse) -> str:
    """Description lisible de la violation CORS observée sur une réponse."""
    allow_origin = page.headers.get("access-control-allow-origin")
    if allow_origin == "*":
        return "Access-Control-Allow-Origin: * (origine sauvage)"
    allow_credentials = page.headers.get("access-control-allow-credentials", "").lower()
    return (
        f"reflet de l'origine de test avec Access-Control-Allow-Credentials: "
        f"{allow_credentials} (lecture de données avec identifiants)"
    )