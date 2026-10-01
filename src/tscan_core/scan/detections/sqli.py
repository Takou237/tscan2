"""Détection d'injection SQL error-based par analyse différentielle (RF-22, P1/P2).

Analyse différentielle (P1) : plutôt que de signaler tout marqueur d'erreur
SQL présent dans une réponse, chaque couple (page, paramètre) est évalué sur
TROIS requêtes GET bénignes (ES-03) :

1. **requête normale** (baseline) : le paramètre porte une valeur bénigne ;
2. **requête modifiée** : le paramètre porte une charge qui casse la syntaxe
   (`' --`, `' #`) — aucune donnée lue ni modifiée, aucun UNION, pas de
   serveur de sortie ;
3. **requête corrigée** : le paramètre porte la charge corrigée (`''`),
   qui restaure la syntaxe si le paramètre est réellement injecté dans une
   requête SQL construite par concaténation.

Verdict différentiel : le marqueur d'erreur SQL n'est concluant que s'il
n'apparaît QUE dans la réponse modifiée. S'il est également présent dans la
baseline (page statique qui parle de SQL, documentation, erreur affichée en
permanence) ou dans la réponse corrigée (serveur qui renvoie la même erreur
quelle que soit l'entrée), le signal est du bruit : le moteur S'ABSTIENT
(RF-12) et compte l'abstention dans `observations["anti_fp"]`.

Sentinelle anti soft-404 (P2) : la réponse modifiée est en outre comparée au
contrôle négatif du serveur (chemin inexistant aléatoire, module
`sentinel.py`) ; une réponse indiscernable du bruit de fond ne produit pas de
constat, quel que soit son contenu.

Le constat, lorsqu'il est posé, porte la trace complète des trois réponses
(`probe_info["differential"]`) : la re-vérification (RF-23) rejoue la charge
de rupture et l'analyste dispose de la preuve différentielle (ES-08).
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
from tscan_core.scan.detections.sentinel import (
    count_abstained,
    get_calibration,
    is_noise,
)
from tscan_core.scan.detections.xss import _with_query

# Charges bénignes de rupture de syntaxe : une apostrophe casse la syntaxe
# éventuelle, le commentaire isole l'excédent de requête. Rien de plus.
CHARGES = ("' --", "' #")

# Charge corrigée (P1) : deux apostrophes = littéral chaîne vide correctement
# échappé en SQL. Sur un paramètre réellement injectable, la requête interne
# redevient syntaxiquement valide : pas d'erreur. Sur un serveur bruyant,
# l'erreur réapparaît — c'est précisément ce que le verdict différentiel
# utilise pour distinguer la faille du bruit.
CORRECTED_CHARGE = "''"

# Valeur bénigne de la requête normale (baseline, P1).
BASELINE_VALUE = "tscan-baseline"

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

# Périmètre fermé des sondes (ES-02) : racine, chemins de recherche courants
# et une page statique de bruit (le laboratoire y expose un article qui
# « parle » de SQL : le verdict différentiel doit s'abstenir dessus).
PROBE_PATHS = ("/", "/search", "/static-error", "/search.php", "/index.php", "/products")

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
    """Sonde la cible par analyse différentielle et constate les erreurs SQL
    présentes UNIQUEMENT sous charge de rupture.

    Utilise les pages crawlées lorsqu'elles sont disponibles, sinon les
    chemins prédéfinis. Les compteurs d'abstention sont tenus dans
    `observations["anti_fp"]` (bilan anti-faux positifs du rapport, P5).
    """
    del root, started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Sentinelle anti soft-404 (P2) : une seule requête de calibration par
    # scan (mise en cache dans `observations["sentinelle"]`), partagée avec
    # les autres familles qui utilisent le module `sentinel.py`.
    calibration, calibration_token = get_calibration(config, client, observations, on_event)

    # Paramètres découverts par le crawl (fuzzing ciblé) : on sonde aussi les
    # champs de formulaires réellement présents, pas seulement le `q` classique.
    # Plafonnement (ES-02) : borné à MAX_PARAMS_PER_SCAN, `q` toujours couvert.
    context_params = list(observations.get("params_found", []))
    if "q" in context_params:
        context_params.remove("q")
    context_params.insert(0, "q")
    context_params = context_params[:MAX_PARAMS_PER_SCAN]

    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    blocked_urls: set[str] = set()
    noisy_urls: set[str] = set()  # pages dont la réponse porte du bruit statique
    for url in probe_urls:
        if skip_blocked_url(url, blocked_urls) or skip_blocked_url(url, noisy_urls):
            continue

        # Requête normale (baseline, P1) : même page, valeur bénigne du
        # paramètre. Une baseline en échec réseau ou bloquée par un WAF
        # empêche toute conclusion différentielle : page laissée de côté.
        baseline = None
        for param in context_params:
            baseline_url = _with_query(url, {param: BASELINE_VALUE})
            baseline = probe_fetch(client, baseline_url, observations, on_event)
            if baseline is not None and not is_blocked(baseline.status_code):
                break
            if baseline is not None and is_blocked(baseline.status_code):
                blocked_urls.add(url.rstrip("/"))
                baseline = None
                break
        if baseline is None:
            continue
        baseline_markers = _marker_set(baseline.body)

        found = False
        for param in context_params:
            for charge in CHARGES:
                probe_url = _with_query(url, {param: charge})
                page = probe_fetch(client, probe_url, observations, on_event)
                if page is None:
                    continue
                if is_blocked(page.status_code):
                    # La page entière est filtrée : une charge suivante sur un
                    # autre paramètre subirait le même sort. On marque le chemin.
                    blocked_urls.add(url.rstrip("/"))
                    break

                markers = _marker_set(page.body)
                if not markers:
                    continue

                # ── Verdict différentiel (P1) ────────────────────────────
                # Le marqueur doit être ABSENT de la baseline (page normale).
                # S'il y figure, la page produit ce marqueur sans injection :
                # bruit statique, aucune sonde de cette page n'est concluante.
                if markers & baseline_markers:
                    noisy_urls.add(url.rstrip("/"))
                    count_abstained(
                        observations,
                        "sqli",
                        probe_url,
                        (
                            "marqueur d'erreur SQL déjà présent sur la requête "
                            "normale (baseline) : bruit statique, non conclusif (P1)"
                        ),
                    )
                    break

                # Requête corrigée (P1) : la charge `''` restaure la syntaxe.
                corrected_url = _with_query(url, {param: CORRECTED_CHARGE})
                corrected = probe_fetch(client, corrected_url, observations, on_event)
                if corrected is not None and _marker_set(corrected.body) & markers:
                    count_abstained(
                        observations,
                        "sqli",
                        probe_url,
                        (
                            "marqueur d'erreur SQL également présent avec la charge "
                            "corrigée ('') : le serveur renvoie la même erreur "
                            "quelle que soit l'entrée (P1)"
                        ),
                    )
                    continue

                # ── Sentinelle anti soft-404 (P2) ────────────────────────
                if is_noise(page, calibration, calibration_token):
                    count_abstained(
                        observations,
                        "sqli",
                        probe_url,
                        (
                            "réponse indiscernable de la sentinelle anti soft-404 "
                            "(page générique du serveur) (P2)"
                        ),
                    )
                    break

                marker = min(markers)
                results.append(
                    DetectionResult(
                        rule_id=RULE_ID,
                        category=CATEGORY,
                        severity=SEVERITY,
                        title="Erreur SQL différentielle : injection SQL error-based probable",
                        description=(
                            "Une charge bénigne de rupture de syntaxe (apostrophe + "
                            "commentaire) provoque une erreur SQL ABSENTE de la requête "
                            "normale et DISPARAISSANT avec la charge corrigée : le "
                            "paramètre est inséré dans une requête SQL construite par "
                            "concaténation. Une exploitation réelle pourrait lire ou "
                            "altérer des données."
                        ),
                        matched_at=page.final_url,
                        evidence_text=(
                            f"GET {page.final_url} -> {page.status_code} : marqueur "
                            f"d'erreur SQL détecté ({marker!r}) pour la charge {charge!r}. "
                            f"Analyse différentielle (P1) : marqueur absent de la requête "
                            f"normale et de la requête corrigée ({corrected_url}). "
                            "Sentinelle anti soft-404 (P2) : réponse distincte du "
                            "contrôle négatif."
                        ),
                        probe_info={
                            "request_url": probe_url,
                            "method": "GET",
                            "signal_type": "body_marker",
                            "signal_value": marker,
                            "charge": charge,
                            "differential": {
                                "baseline_value": BASELINE_VALUE,
                                "corrected_charge": CORRECTED_CHARGE,
                                "corrected_url": corrected_url,
                                "baseline_markers": sorted(baseline_markers),
                                "corrected_markers": [],
                                "sentinelle": "distincte",
                            },
                        },
                    )
                )
                found = True
                break  # une charge suffit par paramètre : inutile d'enchaîner
            if found:
                break
            if url.rstrip("/") in blocked_urls or url.rstrip("/") in noisy_urls:
                break
        if found:
            # Un constat différentiel validé est compté (bilan P5 du rapport).
            stats = observations.setdefault("anti_fp", {})
            differentials = stats.setdefault("differentielles_validees", {})
            differentials["sqli"] = differentials.get("sqli", 0) + 1
            break  # constat trouvé : pas de sondes redondantes sur les paths restants

    return results


def _marker_set(body: str) -> set[str]:
    """Ensemble des marqueurs d'erreur SQL présents dans un corps de réponse."""
    lowered = (body or "").lower()
    return {marker for marker in SQL_ERROR_MARKERS if marker in lowered}
