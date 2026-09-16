"""Rotation des charges de test (encodage / détournement), en écho au Fuzzer
d'OWASP ZAP.

Un WAF se mesure aussi à l'aune des variantes d'encodage de la charge : une
charge bloquée en forme « brute » doit l'être aussi une fois encodée. La
rotation produit quelques variantes bénignes (ES-03) — encodage URL simple,
double, casse mixte des mots-clés, commentaires MySQL — et le module WAF
compare leur sort : si seule la forme brute est rejetée, des formes
équivalentes atteignent l'application (filtre contournable).
"""

from __future__ import annotations

from urllib.parse import quote

# Variantes que seule une *re-lecture* (double décodage) ou une normalisation
# fine attraperait. Leur passage signale un filtre contournable par encodage.
ENCODED_ONLY_LABELS = frozenset({"url-encode double", "comment mysql"})


def payload_variants(charge: str) -> tuple[dict[str, str], ...]:
    """Variantes de codage d'une charge de test bénigne.

    Toutes sont inoffensives (balise sans exécution, amorce SQL tronquée) :
    seule leur forme d'encodage diffère. La première est la forme « brute »
    classique (encodage URL appliqué par le client) ; les suivantes testent
    si le filtre laisse passer des formes équivalentes côté applicatif.
    """
    variants = (
        {"label": "brute", "value": quote(charge, safe="")},
        {"label": "url-encode double", "value": quote(quote(charge, safe=""), safe="")},
        {"label": "casse mixte", "value": quote(_toggle_case(charge), safe="")},
    )
    if " OR " in charge.upper():
        # Commentaire-blanc MySQL : l'opérateur n'apparaît plus comme « or 1=1 ».
        variants += ({"label": "comment mysql", "value": quote("'/**/OR/**/1=1/**/--", safe="")},)
    return variants


def _toggle_case(text: str) -> str:
    """Alterne la casse des lettres (ex. `<script>` -> `<ScRiPt>`)."""
    out: list[str] = []
    upper = False
    for ch in text:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)