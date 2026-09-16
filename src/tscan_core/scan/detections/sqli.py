"""Détection d'injection SQL error-based par sondes bénignes (RF-22).

Deux charges inoffensives (ES-03, RF-24) sont envoyées dans le paramètre de
recherche : un guillemet simple suivi d'un commentaire de fin de ligne. Aucune
charge ne peut modifier ni exfiltrer de données (pas d'union, pas de serveur
de sortie, pas de clause continue) : si la requête interne est construite par
concaténation, le serveur répond par une erreur SQL explicite, dont les
marqueurs sont recherchés dans la réponse. C'est le plus conservateur des
indicateurs d'injection (visible, sans effet de bord) : le constat reste
`Probable` jusqu'à la confirmation active.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.fuzzing import MAX_PARAMS_PER_SCAN
from tscan_core.scan.detections.probe import (
    is_blocked,
    probe_fetch,
    select_probe_urls,
    skip_blocked_url,
)
from tscan_core.scan.detections.xss import _with_query

# Charges bénignes : une apostrophe casse la syntaxe éventuelle, le commentaire
# isole l'excédent de requête. Rien de plus : aucune donnée sollicitée.
CHARGES = ("' --", "' #")

# Marqueurs explicites d'une erreur de moteur de base de données dans la réponse.
SQL_ERROR_MARKERS = (
    "sql syntax",
    "syntax error",
    "unclosed quotation",
    "unterminated string literal",
    "you have an error in your sql",
    "warning: mysql",
    "ora-",
    "psycopg2",
    "sqlite3.operationalerror",
    "mysql_fetch",
    "pdoexception",
    "invalid query",
)

# Périmètre fermé des sondes (ES-02) : racine et chemins de recherche courants.
PROBE_PATHS = ("/", "/search", "/search.php", "/index.php", "/products")

RULE_ID = "RULE-SQLI-001"
SEVERITY = "high"
CATEGORY = "sqli"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde la cible avec des charges d'erreur bénignes et constate toute
    erreur SQL remontée dans la réponse.

    Utilise les pages crawlées lorsqu'elles sont disponibles, sinon les
    chemins prédéfinis.
    """
    del root, started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Paramètres découverts par le crawl (fuzzing ciblé) : on sonde aussi les
    # champs de formulaires réellement présents, pas seulement le `q` classique.
    context_params = list(observations.get("params_found", []))
    # Plafonnement (ES-02) : même logique que la famille XSS — borné à
    # MAX_PARAMS_PER_SCAN, `q` toujours couvert (2 charges × 10 params ×
    # 12 pages ≈ 240 requêtes au lieu de plusieurs milliers).
    if "q" in context_params:
        context_params.remove("q")
    context_params.insert(0, "q")
    context_params = context_params[:MAX_PARAMS_PER_SCAN]

    # Échantillon BORNÉ de pages à sonder : plutôt que la totalité des pages
    # crawlées (des centaines sur un gros site), on sonde un sous-ensemble
    # représentatif priorisant les chemins de recherche/requête (ES-02).
    # Avec un WAF, une seule 412 sur un paramètre suffit à prouver le filtrage
    # : on cesse alors de sonder les autres paramètres de la page.
    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    blocked_urls: set[str] = set()
    for url in probe_urls:
        if skip_blocked_url(url, blocked_urls):
            continue
        found = False
        for charge in CHARGES:
            for param in context_params:
                probe_url = _with_query(url, {param: charge})
                page = probe_fetch(client, probe_url, observations, on_event)
                if page is None:
                    continue
                if is_blocked(page.status_code):
                    # La page entière est filtrée : une charge suivante sur un
                    # autre paramètre subirait le même sort. On marque le chemin
                    # pour ne plus le sonder.
                    blocked_urls.add(url.rstrip("/"))
                    break

                marker = _find_sql_error_marker(page.body)
                if marker is not None:
                    results.append(
                        DetectionResult(
                            rule_id=RULE_ID,
                            category=CATEGORY,
                            severity=SEVERITY,
                            title="Erreur SQL exposée : injection SQL error-based probable",
                            description=(
                                "Une charge de test bénigne (apostrophe + commentaire) "
                                "provoque une erreur de syntaxe SQL remontée dans la réponse : "
                                "le paramètre est inséré dans la requête sans préparation. Une "
                                "exploitation réelle pourrait lire ou altérer des données."
                            ),
                            matched_at=page.final_url,
                            evidence_text=(
                                f"GET {page.final_url} -> {page.status_code} : marqueur "
                                f"d'erreur SQL détecté ({marker!r}) pour la charge {charge!r}"
                            ),
                            probe_info={
                                "request_url": probe_url,
                                "method": "GET",
                                "signal_type": "body_marker",
                                "signal_value": marker,
                                "charge": charge,
                            },
                        )
                    )
                    found = True
                    break  # une charge suffit par paramètre : inutile d'enchaîner
            if found:
                break
            if url.rstrip("/") in blocked_urls:
                break
        if found:
            break  # constat trouvé : pas de sondes redondantes sur les paths restants

    return results


def _find_sql_error_marker(body: str) -> str | None:
    """Retourne le premier marqueur d'erreur SQL présent dans le corps, sinon None."""
    lowered = body.lower()
    for marker in SQL_ERROR_MARKERS:
        if marker in lowered:
            return marker
    return None
