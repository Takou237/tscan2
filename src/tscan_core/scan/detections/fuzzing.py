"""Extraction des points d'entrée réels de la cible pour le fuzzing ciblé.

La feuille de route (« attaques ciblées par contexte ») recommande d'injecter
les charges uniquement dans les paramètres effectivement présents dans les
pages crawlées — champs de formulaires et paramètres de requête — plutôt que
dans un seul paramètre deviné en dur (`q`).

Ce module fournit deux utilitaires purs, sans réseau :

* `extract_query_params` : les noms de paramètres apparaissant dans les URLs
  crawlées (les requêtes de la cible sont conservées par le crawlur, ES-03).
* `extract_form_fields`  : les champs des formulaires HTML des pages crawlées
  (action GET/POST et noms d'inputs), pour les détections GET bénignes.

Les détections XSS/SQLi consomment ces paramètres pour élargir leur périmètre
de sonde de façon *contextuelle*, tout en restant non destructives (ES-03).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from tscan_core.recon.client import RootResponse

# Nom maximal de paramètres distincts sondés par famille, pour borner le nombre
# de requêtes d'un scan (ES-02, durée prévisible).
MAX_PARAMS_PER_SCAN = 10

_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_FORM_ACTION_RE = re.compile(
    r'<form\b[^>]*\baction\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)


def extract_query_params(pages: dict[str, RootResponse]) -> list[str]:
    """Retourne les noms de paramètres uniques présents dans les URLs crawlées.

    `pages` associe l'URL (conservée avec sa query) à sa réponse. Les
    paramètres sont triés par fréquence d'apparition (les plus courants
    d'abord) ; la liste est bornée à `MAX_PARAMS_PER_SCAN`.
    """
    counts: dict[str, int] = {}
    for url in pages:
        if not url.startswith("http"):
            continue
        parsed = urlparse(url)
        if not parsed.query:
            continue
        for name in parse_qs(parsed.query):
            counts[name] = counts.get(name, 0) + 1
    ordered = sorted(counts, key=lambda n: (-counts[n], n))
    return ordered[:MAX_PARAMS_PER_SCAN]


def extract_form_fields(page: RootResponse) -> list[str]:
    """Retourne les noms des champs de formulaires d'une page (inputs nommés).

    Les champs des formulaires en **GET** sont des candidats naturels au
    fuzzing de requête (la valeur remplace celle du champ). Les formulaires
    POST restent hors périmètre : Tscan est en mode sécurisé GET-only (ES-03).
    """
    fields: list[str] = []
    for match in _INPUT_RE.finditer(page.body):
        name = match.group(1).strip()
        if name and name not in fields:
            fields.append(name)
    return fields[:MAX_PARAMS_PER_SCAN]


def _form_actions(page: RootResponse) -> list[str]:
    """Actions des formulaires d'une page (usage interne)."""
    return [m.group(1).strip() for m in _FORM_ACTION_RE.finditer(page.body)]