"""Détection d'injection de template (SSTI) par sonde bénigne à marqueur.

Sonde GET non destructive (ES-03) : la charge est ``{{7*7}}`` et la réponse est
analysée pour la présence du résultat arithmétique ``49``. Si le résultat est
retranscrit, le moteur de template évalue l'expression côté serveur, c'est une
injection SSTI probable. La charge est strictement inoffensive (ES-03) : aucune
action sur le système, aucune donnée sollicitée.
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

# Charges de test et leurs résultats attendus.
# Ne teste pas de chaîne concaténée (\"\".join) — on veut un calcul arithmétique
# simple dont le résultat est un nombre entier facilement identifiable.
PAYLOADS: list[tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]
PARAMS = ("name", "input", "template", "page", "q")

RULE_ID = "RULE-SSTI-001"
SEVERITY = "high"
CATEGORY = "ssti"

# Chemins à tester si pas de pages crawlées.
PROBE_PATHS = ("/", "/page", "/render", "/template", "/view")


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

    # Échantillon BORNÉ de pages à sonder (ES-02) : pas la totalité du crawl.
    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    blocked_urls: set[str] = set()
    for url in probe_urls:
        if skip_blocked_url(url, blocked_urls):
            continue
        for payload, expected in PAYLOADS:
            for param in PARAMS:
                probe_url = _with_query(url, {param: payload})
                page = probe_fetch(client, probe_url, observations, on_event)
                if page is None:
                    continue
                if is_blocked(page.status_code):
                    # Page entière filtrée (WAF) : inutile de sonder les autres
                    # paramètres ni les charges suivantes, ils subiraient le
                    # même sort. On passe à la page suivante.
                    blocked_urls.add(url.rstrip("/"))
                    break
                if url.rstrip("/") in blocked_urls:
                    break

                if _body_contains_marker(page.body, expected):
                    results.append(
                        DetectionResult(
                            rule_id=RULE_ID,
                            category=CATEGORY,
                            severity=SEVERITY,
                            title="Injection de template serveur (SSTI) probable",
                            description=(
                                "Une charge de test bénigne (`{7*7}`) envoyée dans un "
                                "paramètre est évaluée côté serveur et le résultat (49) "
                                "est retranscrit dans la réponse : le moteur de template "
                                "traite le paramètre comme du code, permettant l'exécution "
                                "de code arbitraire."
                            ),
                            matched_at=page.final_url,
                            evidence_text=(
                                f"GET {page.final_url} -> {page.status_code} : "
                                f"résultat {expected!r} détecté pour la charge {payload!r}"
                            ),
                            probe_info={
                                "request_url": probe_url,
                                "method": "GET",
                                "signal_type": "body_regex",
                                "signal_value": rf"(?<![0-9]){expected}(?![0-9])",
                                "charge": payload,
                            },
                        )
                    )
                    return results

    return results


def _body_contains_marker(body: str, expected: str) -> bool:
    """Vrai si la chaîne attendue est un nombre isolé dans le corps (pas dans du texte)."""
    import re

    # Cherche le nombre attendu isolé dans un contexte HTML/texte.
    return bool(re.search(rf"(?<![0-9]){re.escape(expected)}(?![0-9])", body))