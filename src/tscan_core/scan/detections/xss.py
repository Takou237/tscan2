"""Détection de réflexion de paramètre non échappée (RF-19, XSS réfléchi).

Le constat repose sur une charge bénigne non destructrice (ES-03) : le
paramètre envoyé contient une balise vide portant un « nonce » aléatoire ;
si la réponse la reflète telle quelle (sans échappement HTML), le même
mécanisme permettrait d'injecter un script réel. Le paramètre `q` est un
choix volontaire : c'est le paramètre de recherche le plus commun, il est
couvert par le laboratoire de test et le périmètre fermé des sondes (ES-02).

Une réflexion constatée est forte, mais la preuve d'exécution relève de la
confirmation active (RF-23, semaine 8) : le constat reste `Probable`.
"""

from __future__ import annotations

import re
import uuid

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

# Périmètre fermé des sondes XSS (ES-02) : racine + chemins de recherche courants.
PROBE_PATHS = ("/", "/search", "/search.php", "/index.php", "/echo", "/contact")

RULE_ID = "RULE-XSS-001"
SEVERITY = "high"
CATEGORY = "xss"

# Parité ZAP 10031 « User Controllable HTML Element Attribute (Potential XSS) » :
# un paramètre de requête est reflété dans un attribut HTML de la réponse.
# Détection passive (aucune charge envoyée), sévérité info (fait potentiel).
RULE_XSS_ATTR = "RULE-XSS-ATTR-001"
ATTR_SEVERITY = "info"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde la cible avec une charge bénigne et constate toute réflexion brute.

    Utilise les pages crawlées lorsqu'elles sont disponibles, sinon les
    chemins prédéfinis. Les pages crawlées sont prioritaires car elles
    représentent le vrai contenu du site. Complète l'analyse active par une
    passe passive de réflexion dans les attributs HTML (parité ZAP 10031).
    """
    del started_at  # non utilisé : la sonde cible des chemins découverts

    nonce = uuid.uuid4().hex[:10]
    payload = f'"><i data-tscan-xss="{nonce}">'
    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Paramètres découverts par le crawl (feuille de route « fuzzing ciblé ») :
    # en plus du `q` classique, on sonde les champs de formulaires et les noms
    # de paramètres de requête réellement présents dans les pages crawlées.
    context_params = list(observations.get("params_found", []))
    # Plafonnement (ES-02, durée prévisible) : le crawl d'un gros CMS découvre
    # des dizaines de paramètres (ex. product_cat_N de WooCommerce) ; pages ×
    # paramètres × charge représente alors des milliers de requêtes. On borne
    # à MAX_PARAMS_PER_SCAN, avec le paramètre de recherche `q` toujours couvert.
    if "q" in context_params:
        context_params.remove("q")
    context_params.insert(0, "q")
    context_params = context_params[:MAX_PARAMS_PER_SCAN]

    # Échantillon BORNÉ de pages à sonder (ES-02) : priorité aux chemins de
    # recherche/requête, plafonné ; une page filtrée par un WAF (412/403)
    # sur un paramètre sera laissée de côté pour les suivants.
    probe_urls = select_probe_urls(base, pages, PROBE_PATHS)

    blocked_urls: set[str] = set()
    for url in probe_urls:
        if skip_blocked_url(url, blocked_urls):
            continue
        for param in context_params:
            probe_url = _with_query(url, {param: payload})
            page = probe_fetch(client, probe_url, observations, on_event)
            if page is None:
                continue
            if is_blocked(page.status_code):
                blocked_urls.add(url.rstrip("/"))
                break
            if f'data-tscan-xss="{nonce}"' in page.body:
                results.append(
                    DetectionResult(
                        rule_id=RULE_ID,
                        category=CATEGORY,
                        severity=SEVERITY,
                        title="Réflexion de paramètre sans échappement (XSS réfléchi potentiel)",
                        description=(
                            "La charge de test reflétée telle quelle dans la réponse emploie "
                            "la syntaxe exacte d'une balise HTML : un paramètre malveillant "
                            "pourrait être exécuté dans le navigateur d'un visiteur."
                        ),
                        matched_at=page.final_url,
                        evidence_text=(
                            f"Payload {payload!r} reflété sans échappement dans la réponse de "
                            f"{page.final_url} (statut {page.status_code})"
                        ),
                        probe_info={
                            "request_url": probe_url,
                            "method": "GET",
                            "signal_type": "body_contains",
                            "signal_value": f'data-tscan-xss="{nonce}"',
                            "charge": payload,
                        },
                    )
                )
                break  # une réflexion suffit à lever le doute ; pas de sondes redondantes
        if results:
            break

    # Passe passive (parité ZAP 10031) : un paramètre de requête réellement
    # présent dans les pages crawlées est reflété dans un attribut HTML
    # (ex. ?lang=fr -> <html lang="fr">). Aucune charge envoyée.
    if pages and not any(r.rule_id == RULE_XSS_ATTR for r in results):
        attr = _first_attribute_reflection(pages)
        if attr is not None:
            url, param, value = attr
            results.append(
                DetectionResult(
                    rule_id=RULE_XSS_ATTR,
                    category=CATEGORY,
                    severity=ATTR_SEVERITY,
                    title="User Controllable HTML Element Attribute (Potential XSS)",
                    description=(
                        "Un paramètre de requête contrôlable par l'utilisateur est "
                        "reflété dans un attribut HTML de la réponse sans "
                        "échappement spécifique : une valeur malveillante pourrait "
                        "échapper l'attribut et injecter un balisage."
                    ),
                    matched_at=url,
                    evidence_text=(
                        f"Le paramètre « {param} » vaut {value!r} et est reflété dans "
                        f"un attribut HTML de {url}"
                    ),
                    probe_info={
                        "request_url": url,
                        "method": "GET",
                        "signal_type": "attribute_reflection",
                        "signal_value": value,
                        "param": param,
                    },
                )
            )

    return results


def _first_attribute_reflection(pages: dict) -> tuple[str, str, str] | None:
    """Retourne (url, param, valeur) du premier paramètre de requête reflété
    dans un attribut HTML d'une page crawlée (None si aucun)."""
    from html import escape as html_escape
    from urllib.parse import parse_qsl, urlsplit

    for page in pages.values():
        query = urlsplit(page.request_url).query
        if not query:
            continue
        for param, raw_values in _group_params(parse_qsl(query)):
            value = raw_values[0]
            if not value or len(value) > 64:
                continue
            attribute_value = html_escape(value, quote=True)
            for rendered in {value, attribute_value}:
                if not rendered:
                    continue
                if re.search(r'[\w:-]+\s*=\s*["\']' + re.escape(rendered) + r'["\']', page.body):
                    return page.final_url, param, value
    return None


def _group_params(pairs):
    """Regroupe les valeurs par clé (première valeur non vide conservée)."""
    groups: dict[str, list[str]] = {}
    for key, value in pairs:
        groups.setdefault(key, []).append(value)
    return groups.items()


def _with_query(url: str, params: dict[str, str]) -> str:
    """Ajoute des paramètres de requête à une URL en préservant la structure."""
    from urllib.parse import urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    query = parsed.query
    separator = "&" if query else ""
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query + separator + urlencode(params),
            parsed.fragment,
        )
    )
