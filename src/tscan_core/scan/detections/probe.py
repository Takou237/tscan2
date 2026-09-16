"""Sondes partagées des détections actives (bornes de volume, parité ZAP).

Les familles paramétriques (SQLi, XSS, SSTI, cmd-injection) sondaient
historiquement **toutes** les pages découvertes par le crawl × tous les
paramètres × chaque charge : sur un grand site (WordPress ~60+ pages), cela
représente des dizaines de milliers de requêtes et rendait le scan interminable.

Ce module centralise les bornes qui rendent ces sondes **prévisibles et
rapides** sans sacrifier la détection (parité OWASP ZAP, qui borne lui aussi
son Fuzzer) :

* `select_probe_urls` -- échantillon **borné** de pages à sonder par famille
  (priorité aux chemins de recherche/requête, HTML uniquement), dédupliqué ;
* `skip_blocked_url` / `is_blocked` -- arrêt par famille dès qu'un WAF bloque
  (412/403/429) une page : un filtre ne devient pas vulnérable, inutile de
  re-sonder les autres paramètres de la même page ;
* `probe_fetch` -- GET de sonde avec **peu de tentatives et un backoff court**
  (le crawl et la racine gardent la politique robuste du client).
"""

from __future__ import annotations

from urllib.parse import urlparse

from tscan_core.recon.client import ReconError, RootResponse, fetch_url
from tscan_core.scan.progress import notify

# Nombre maximal de pages *distinctes* sondées par une famille paramétrique.
# Plutôt que les centaines de pages d'un grand crawl, on sonder un échantillon
# représentatif : la détection d'une injection ne dépend pas du volume de
# pages, mais de la présence d'un paramètre vulnérable — un échantillon borné
# la trouve aussi bien, en un nombre de requêtes prévisible (ES-02).
MAX_PROBE_PAGES = 12

# Statuts d'une réponse qui signalent un filtrage au niveau de la page entière
# (WAF / anti-bot) : une page qui bloque un paramètre bloquera les suivants.
_BLOCKED_STATUSES = frozenset({403, 412, 429, 503})

# Extensions de ressources non HTML, jamais sondées (aucune réflexion possible).
_STATIC_EXTS = frozenset(
    {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".tar", ".gz", ".rar",
        ".mp3", ".mp4", ".avi", ".mov", ".webm",
    }
)


def is_html_url(url: str) -> bool:
    """Vrai si l'URL pointe probablement vers une page HTML (pas une ressource statique)."""
    path = urlparse(url).path.lower()
    for ext in _STATIC_EXTS:
        if path.endswith(ext):
            return False
    return True


def is_blocked(status_code: int) -> bool:
    """Vrai si un statut de réponse signale un blocage de la page entière."""
    return status_code in _BLOCKED_STATUSES


def skip_blocked_url(url: str, blocked_urls: set[str]) -> bool:
    """Vrai si l'URL (ou sa racine de chemin) a déjà été bloquée : dans ce cas
    on cesse de sonder les autres paramètres de la même page."""
    return url.rstrip("/") in blocked_urls


def select_probe_urls(
    base: str,
    pages: dict | None,
    probe_paths: tuple[str, ...] | list[str],
    max_pages: int = MAX_PROBE_PAGES,
    prioritize_query: bool = True,
) -> list[str]:
    """Retourne une liste **bornée** d'URLs à sonder pour une famille.

    Les pages crawlées sont prioritaires (elles portent le vrai contenu) mais
    l'échantillon est plafonné à `max_pages` pour garder un volume prévisible.
    Les chemins fermés de la famille (`probe_paths`) complètent l'échantillon
    s'ils n'y figurent pas déjà. Les ressources non HTML sont écartées (ES-02).

    `prioritize_query` : quand le nombre de pages crawlées dépasse le plafond,
    les chemins qui ressemblent à des points d'entrée (recherche/requête) sont
    sondés d'abord — ce sont les plus susceptibles de réfléchir un paramètre.
    """
    base = base.rstrip("/")
    seen: set[str] = set()
    ordered: list[str] = []

    def _add(url: str) -> None:
        key = url.rstrip("/")
        if key in seen:
            return
        if not is_html_url(url):
            return
        seen.add(key)
        ordered.append(url)

    crawled: list[str] = []
    if pages:
        for key in pages:
            if key.startswith("http"):
                crawled.append(key)
            elif key.startswith("/"):
                crawled.append(f"{base}{key}")

    if prioritize_query:
        # Chemins de recherche/requête et points d'entrée d'abord.
        _QUERY_HINTS = ("search", "query", "echo", "reflect", "find", "lookup",
                        "result", "contact", "api", "?")
        crawled.sort(
            key=lambda u: (
                not any(h in u.lower() for h in _QUERY_HINTS),
                u,
            )
        )

    for url in crawled[:max_pages]:
        _add(url)

    # Compléter avec les chemins fermés si l'échantillon est sous le plafond,
    # ou toujours s'assurer que la racine est couverte.
    for path in probe_paths:
        _add(f"{base}{path}")

    return ordered


def probe_fetch(
    client,
    url: str,
    observations: dict,
    on_event=None,
    label: str = "detect",
    max_retries: int = 1,
    backoff: float = 0.2,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
) -> RootResponse | None:
    """GET de sonde de détection avec un nombre réduit de tentatives, un
    backoff court et un **timeout réduit** (5s par défaut au lieu de 10s).

    Sur un site avec WAF lent, chaque sonde bloquée peut prendre le timeout
    complet avant de renvoyer 412 : avec 60+ pages × 15 paramètres, un
    timeout de 10s rendrait le scan interminable. Un timeout de 5s pour les
    sondes de détection est un bon compromis entre fiabilité et vitesse.

    L'échec réseau est tracé dans `observations["sondes"]` (ES-05) et notifié ;
    renvoie `None` (au lieu de lever) pour que les familles enchaînent sans
    interrompre le scan. `headers` permet d'ajouter des en-têtes spécifiques
    (ex : `Origin` pour le contrôle CORS).
    """
    try:
        page = fetch_url(
            client, url,
            max_retries=max_retries,
            backoff=backoff,
            timeout=timeout,
            headers=headers,
        )
        notify(on_event, label, f"GET {url} -> {page.status_code}", None)
        return page
    except ReconError as exc:
        observations.setdefault("sondes", {})[url] = str(exc)
        notify(on_event, label, f"GET {url} -> échec ({exc})", None)
        return None
