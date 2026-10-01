"""Sentinelle anti soft-404 partagée entre les familles de détection (P2).

Le contrôle négatif historique (semaine 12, check ``path_status`` du BAC)
reposait sur la calibration de ``checks.py`` : une requête GET vers un chemin
inexistant aléatoire établit le « bruit de fond » du serveur, et une réponse
de sonde indiscernable du contrôle ne produit pas de constat. Ce contrôle
n'était cependant exécuté que pour la famille BAC : les sondes des familles
actives (SQLi, XSS, SSTI, fichiers sensibles, listing, ...) restaient
exposées au piège des serveurs qui répondent 200 avec une page générique
(accueil habillé, recherche, erreur personnalisée) pour N'IMPORTE quel
chemin ou N'IMPORTE quel paramètre — un marqueur présent dans cette page
générique (« Index of », signature de fichier, texte d'erreur) aurait
produit un faux positif.

Ce module généralise le contrôle négatif à toutes les familles actives :
une seule requête de calibration par scan (cache mémoire module,
réinitialisé par l'orchestrateur au début de chaque scan), puis chaque
sonde concernée est comparée au contrôle avec la même logique que
``checks.py`` (_is_generic_response), réutilisée telle quelle pour ne pas
dupliquer la sémantique (RF-12 : en cas de doute, le moteur s'abstient et
documente).

Une sonde écartée par la sentinelle n'est PAS un faux négatif assumé en
silence : elle est comptée dans ``observations["anti_fp"]`` (compteurs
d'abstention) et tracée pour la revue analytique — le bilan du scan
affiche que le contrôle négatif a bien fonctionné (ES-05).
"""

from __future__ import annotations

from tscan_core.recon.client import ReconError, RootResponse, fetch_url
from tscan_core.scan.checks import _is_generic_response, new_calibration_token
from tscan_core.scan.progress import notify

# Clé d'observation : le dictionnaire de calibration est mis en cache dans
# `observations["sentinelle"]` pour ne jamais dépasser une requête par scan.
# L'objet `RootResponse` n'étant pas sérialisable, il vit dans un cache mémoire
# module (un scan = un processus) ; l'observation persistée (`recon_json`)
# ne contient que `sentinelle_meta` (URL, statut, jeton).
_OBS_KEY = "sentinelle"
# Cache mémoire module (un scan = un processus) ; réinitialisé par scan via
# `reset_calibration()` — sans cela, la calibration d'un scan précédent
# (autre cible, autre serveur) fuiterait dans le scan courant.
_MEMORY_CACHE: dict | None = None


def reset_calibration() -> None:
    """Réinitialise le cache mémoire de la sentinelle (appelé au début de
    chaque scan par l'orchestrateur : une calibration par scan, jamais
    partagée entre deux scans)."""
    global _MEMORY_CACHE
    _MEMORY_CACHE = None


def get_calibration(
    config,
    client,
    observations: dict,
    on_event=None,
) -> tuple[RootResponse | None, str | None]:
    """Retourne la réponse du chemin-sentinelle et son jeton (une par scan).

    Premier appel : GET vers ``/tscan-calib-<jeton>`` (jeton aléatoire) ;
    appels suivants : lecture du cache mémoire, aucune requête
    supplémentaire. Un échec réseau n'est pas fatal : la calibration vaut
    ``(None, None)`` pour tout le reste du scan et les sondes restent
    évaluées par leurs propres critères (même sémantique que l'orchestrateur
    pour le BAC).

    L'objet ``RootResponse`` n'est PAS sérialisable : il vit exclusivement
    dans le cache mémoire module. Les observations persistées
    (``recon_json``, ES-05) ne reçoivent que ``sentinelle_meta`` (URL,
    statut, jeton) — du JSON pur, sans collision avec la clé ``sentinelle``
    utilisée par la calibration BAC de l'orchestrateur.
    """
    global _MEMORY_CACHE
    if _MEMORY_CACHE is not None:
        return _MEMORY_CACHE.get("response"), _MEMORY_CACHE.get("token")

    base = config.target.rstrip("/")
    token = new_calibration_token()
    url = f"{base}/tscan-calib-{token}"
    try:
        page = fetch_url(client, url)
        notify(on_event, "detect", f"GET {url} -> {page.status_code} (sentinelle)", None)
    except ReconError as exc:
        # Sentinelle indisponible : les sondes restent évaluées normalement,
        # l'échec est tracé (ES-05) exactement comme pour le BAC. La
        # calibration est considérée faite pour ce scan (une seule tentative).
        observations.setdefault("sondes", {})["sentinelle"] = str(exc)
        observations["sentinelle_meta"] = {"url": url, "status_code": None, "token": token}
        _MEMORY_CACHE = {"response": None, "token": token, "url": url}
        notify(on_event, "detect", f"GET {url} -> échec ({exc})", None)
        return None, token

    observations["sentinelle_meta"] = {
        "url": url,
        "status_code": page.status_code,
        "token": token,
    }
    _MEMORY_CACHE = {"response": page, "token": token, "url": url}
    return page, token


def is_noise(probe: RootResponse, calibration: RootResponse | None, token: str | None) -> bool:
    """Vrai si la réponse de la sonde est indiscernable du bruit de fond.

    Délègue à ``checks.py::_is_generic_response`` (même sémantique que le
    check `path_status` : réflexion du jeton, corps quasi identiques, mêmes
    mots principaux). Sans calibration disponible, aucune sonde n'est
    écartée par ce contrôle (on ne conclut pas dans l'autre sens non plus).
    """
    if calibration is None:
        return False
    return _is_generic_response(probe, calibration, token)


def count_abstained(observations: dict, family: str, url: str, reason: str) -> None:
    """Trace une sonde écartée par la sentinelle (compteur d'abstention P5).

    Les compteurs alimentent le bilan « méthodologie anti-faux positifs »
    du rapport : ils prouvent que le contrôle négatif a été exécuté et qu'il
    a écarté des réponses non concluantes au lieu de produire des constats.
    """
    stats = observations.setdefault("anti_fp", {})
    probes = stats.setdefault("sondes_ecartees", [])
    probes.append({"famille": family, "url": url, "raison": reason})
    stats["total_ecartees"] = len(probes)
    families = stats.setdefault("par_famille", {})
    families[family] = families.get(family, 0) + 1
