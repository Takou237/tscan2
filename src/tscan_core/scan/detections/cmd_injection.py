"""Détection d'injection de commande OS par sonde bénigne à marqueur.

Sonde GET non destructive (ES-03) : la charge est ``; echo TSCAN-OK`` ou
``| echo TSCAN-OK``. Si la réponse contient le marqueur ``TSCAN-OK``, le
paramètre transite par un shell sans préparation ; c'est une injection de
commande OS probable. La charge reste inoffensive : elle ne fait qu'afficher
un marqueur, sans modification de fichier, sans exfiltration, sans rapport
réseau sortant (ES-09).
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import (
    is_blocked,
    probe_fetch,
    select_probe_urls,
    skip_blocked_url,
)
from tscan_core.scan.detections.xss import _with_query

CHARGES = ("; echo TSCAN-OK", "| echo TSCAN-OK", "|| echo TSCAN-OK")
MARKER = "TSCAN-OK"
PROBE_PATHS = ("/", "/cmd", "/exec", "/run", "/api", "/index.php")

RULE_ID = "RULE-CMD-INJECTION-001"
SEVERITY = "critical"
CATEGORY = "cmd-injection"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at=None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    del root, started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Échantillon BORNÉ de pages (ES-02) : pas la totalité des pages crawlées.
    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    blocked_urls: set[str] = set()
    for url in probe_urls:
        if skip_blocked_url(url, blocked_urls):
            continue
        for charge in CHARGES:
            probe_url = _with_query(url, {"cmd": charge})
            page = probe_fetch(client, probe_url, observations, on_event)
            if page is None:
                continue
            if is_blocked(page.status_code):
                # La page entière est filtrée : on la laisse de côté pour la
                # famille (un WAF ne devient pas vulnérable avec une autre charge).
                blocked_urls.add(url.rstrip("/"))
                break

            if MARKER in page.body:
                results.append(
                    DetectionResult(
                        rule_id=RULE_ID,
                        category=CATEGORY,
                        severity=SEVERITY,
                        title="Injection de commande OS probable",
                        description=(
                            "Une charge de test bénigne (`; echo TSCAN-OK`) envoyée dans "
                            "un paramètre provoque l'exécution d'un sous-shell côté serveur "
                            "et le marqueur est reflété dans la réponse. Un attaquant pourrait "
                            "exécuter n'importe quelle commande du système."
                        ),
                        matched_at=page.final_url,
                        evidence_text=(
                            f"GET {page.final_url} -> {page.status_code} : "
                            f"marqueur {MARKER!r} retrouvé pour la charge {charge!r}"
                        ),
                        probe_info={
                            "request_url": probe_url,
                            "method": "GET",
                            "signal_type": "body_contains",
                            "signal_value": MARKER,
                            "charge": charge,
                        },
                    )
                )
                return results

    return results