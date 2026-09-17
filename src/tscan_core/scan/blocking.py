"""Détection d'une cible qui bloque le scanner (anti-bot/WAF).

Une cible peut refuser le scan actif de Tscan : filtrage anti-bot, WAF ou
rate limiting déclenché par le volume de requêtes (observé sur le terrain :
racine en 200 au premier scan, puis 403 avec un crawl quasi vide au scan
suivant). Le bilan d'un scan ainsi bloqué est **incomplet** — peu de constats
sont produits pour comparer — et il ne doit pas être présenté comme un site
sain. Ce module fournit l'heuristique partagée par le service de ré-observation
et les interfaces (CLI, GUI) pour la détecter et l'annoncer explicitement.

Deux indices, observables dans `recon_json` :
- la racine répond 401/403/429 (refus explicite du serveur) — ou la sonde
  racine échoue en réseau (`error` sans statut) ;
- le crawl borné ne trouve (presque) rien alors que la limite autorisait
  bien plus (le crawler n'a pu extraire aucun lien depuis la racine).

Le refus (ou l'échec) de la sonde racine suffit à déclarer la cible
bloquée. Le crawl vide, lui, ne déclenche l'avertissement qu'**accompagné**
d'un refus ou d'une erreur : seul, sur une racine 200, il reste ambigu —
un vrai petit site sans liens extractibles produit le même profil.
"""

from __future__ import annotations

# Un crawl borné qui trouve moins de pages que ce seuil alors que la limite
# était plus haute signale un crawler bloqué (racine sans lien extractible ou
# refusée). Vrai sur le terrain : otakutique.com, 40 pages crawlées au 1er
# scan, 1 page (la racine refusée) au suivant. Indice **cumulable** : seul, un
# crawl vide sur une racine 200 reste ambigu (petit site réel sans liens), il
# ne déclenche l'avertissement qu'accompagné d'un refus ou d'une erreur recon.
BLOCKED_CRAWL_PAGE_THRESHOLD = 1

# Statuts de refus explicite du serveur sur la racine.
BLOCKED_ROOT_STATUSES = (401, 403, 429)

_BLOCKING_LABELS = {
    "root_refused": "racine refusée (HTTP {status})",
    "crawl_empty": "crawl quasi vide ({pages} page(s) crawlée(s))",
    "recon_error": "sonde racine en échec ({error})",
}


def detect_target_blocking(recon_observations: dict | None) -> tuple[bool, list[str]]:
    """Détecte qu'une cible a refusé le scan, d'après ses observations recon.

    `recon_observations` est le dictionnaire stocké dans `recon_json`
    (clés utilisées : `status_code`, `crawl_stats.pages_found`, `error`).

    Règles (dans l'ordre) :
    1. racine en 401/403/429 → bloquée (refus explicite) ;
    2. sonde racine en échec réseau (`error` présent sans statut) → bloquée ;
    3. crawl quasi vide **accompagné** d'un refus ou d'une erreur → bloquée
       (renforce la raison) ; seul, sur une racine 200, il reste ambigu
       (petit site réel sans liens extractibles) et ne déclenche rien.

    Retourne `(bloqué, raisons)` : les raisons sont des libellés lisibles,
    destinés aux messages d'avertissement des interfaces ; liste vide si le
    scan s'est déroulé normalement.
    """
    recon = recon_observations or {}
    reasons: list[str] = []

    root_status = recon.get("status_code")
    root_refused = isinstance(root_status, int) and root_status in BLOCKED_ROOT_STATUSES
    if root_refused:
        reasons.append(_BLOCKING_LABELS["root_refused"].format(status=root_status))

    recon_failed = "error" in recon and not isinstance(root_status, int)
    if recon_failed:
        reasons.append(_BLOCKING_LABELS["recon_error"].format(error=recon["error"]))

    pages = (recon.get("crawl_stats") or {}).get("pages_found")
    crawl_empty = isinstance(pages, int) and pages <= BLOCKED_CRAWL_PAGE_THRESHOLD
    if crawl_empty and (root_refused or recon_failed):
        reasons.append(_BLOCKING_LABELS["crawl_empty"].format(pages=pages))

    return bool(reasons), reasons
