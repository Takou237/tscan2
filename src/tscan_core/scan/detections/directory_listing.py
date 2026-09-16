"""Détection de listing de répertoire exposé (family Security Misconfiguration).

Sondes GET bénignes sur des chemins fermés de répertoires courants (ES-02) ;
un constat est émis quand la réponse affiche le contenu d'un répertoire, ce
que les serveurs web bien configurés refusent d'indexer (souvent 403). La
signature « Index of / » est la plus répandue chez les serveurs de fichiers
bénins comme malveillants : sa présence sur la cible indique une exposition
de la liste des fichiers du dossier.
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch, select_probe_urls

# Périmètre fermé des répertoires sondés (ES-02) : noms les plus courants de
# dossiers que les applications exposent par erreur.
PROBE_PATHS = ("/", "/files/", "/uploads/", "/backup/", "/data/", "/images/", "/assets/")

INDEX_RE = re.compile(r"Index\s+of\s+", re.IGNORECASE)

RULE_ID = "RULE-LISTING-001"
SEVERITY = "medium"
CATEGORY = "information_disclosure"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde les pages découvertes et constate les listings exposés.

    Utilise les pages crawlées lorsqu'elles sont disponibles, sinon les
    chemins prédéfinis. La racine est réutilisée depuis la reconnaissance
    lorsqu'elle figure déjà dans `pages` (aucune requête redondante).
    """
    del started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Échantillon BORNÉ de pages (ES-02) : le listing de répertoire est un
    # test par page, borné à 12 pages pour garder un volume prévisible.
    probe_urls = select_probe_urls(base, pages or {}, PROBE_PATHS, prioritize_query=False)

    for url in probe_urls:
        # Réutiliser la page crawlée si disponible (aucune requête réseau).
        page = None
        if pages:
            for crawled_url, crawled_page in pages.items():
                if crawled_url.rstrip("/") == url.rstrip("/"):
                    page = crawled_page
                    break
        if page is None:
            page = probe_fetch(client, url, observations, on_event)
            if page is None:
                continue

        if page.status_code != 200:
            continue
        if not INDEX_RE.search(page.body):
            continue

        results.append(
            DetectionResult(
                rule_id=RULE_ID,
                category=CATEGORY,
                severity=SEVERITY,
                title=f"Listing de répertoire exposé : {url}",
                description=(
                    f"Le répertoire {url} affiche la liste de son contenu (Index of). "
                    "Un attaquant peut découvrir les fichiers qui y sont stockés, ce qui "
                    "facilite la recherche de fichiers sensibles ou d'une faille d'accès."
                ),
                matched_at=page.final_url,
                evidence_text=(
                    f"GET {page.final_url} -> {page.status_code} : page de listing "
                    f"('Index of {url}') affichée au lieu d'une interdiction d'indexation"
                ),
                probe_info={
                    "request_url": url,
                    "method": "GET",
                    "signals": [
                        {"type": "status", "value": 200},
                        {"type": "body_regex", "value": r"Index\s+of\s+"},
                    ],
                },
            )
        )

    return results