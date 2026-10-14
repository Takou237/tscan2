"""Périmètre des réponses analysées passivement.

Les modules passifs d'en-têtes itèrent la racine + les pages récoltées. Or la
table `pages` transmise par l'orchestrateur mélange deux origines :

* les pages réellement servies, découvertes par le crawl (`recon.crawler`) ;
* les sondes de chemins émises pour les checks BAC (`path_status`) — ces
  réponses peuvent être des 404/403 (chemin absent ou protégé) : ce ne sont
  pas des pages de l'application, mais des artefacts internes du scanner.

Rapporter un en-tête de sécurité « absent » sur une page d'erreur issue d'une
sonde interne est du bruit (faux positif) : une cible saine se voit attribuer
des dizaines de constats d'en-têtes sur `/admin/`, `/config/`, `/wp-admin/`...
qui répondent 404. Ce module centralise le filtre : seules les réponses
réellement servies (statut HTTP 2xx) sont analysées ; la racine est toujours
incluse (c'est la réponse validée de la cible), et les doublons sont écartés.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse

# Statuts considérés comme une page réellement servie par l'application.
_SERVED_MIN = 200
_SERVED_MAX = 299


def is_served(page: RootResponse) -> bool:
    """Vrai si la réponse a été réellement servie (statut HTTP 2xx)."""
    status = page.status_code
    return status is not None and _SERVED_MIN <= status <= _SERVED_MAX


def served_pages(root: RootResponse, pages: dict | None) -> list[RootResponse]:
    """Racine + pages récoltées réellement servies (statut 2xx), sans doublon.

    Les sondes de chemins (BAC) qui répondent 404/403 sont écartées : ce ne
    sont pas des pages de l'application, les analyser produit des faux
    positifs d'en-têtes manquants.
    """
    checked: list[RootResponse] = [root]
    seen: set[str] = {root.final_url or root.request_url}
    for page in (pages or {}).values():
        key = page.final_url or page.request_url
        if key in seen:
            continue
        if not is_served(page):
            continue
        seen.add(key)
        checked.append(page)
    return checked
