"""Crawlur de pages web pour le scan actif (RF-15, RF-24).

Découvre automatiquement les pages accessibles d'un site web en suivant les
liens internes trouvés dans le HTML, pour que les modules de détection
testent un périmètre plus large que les seuls chemins prédéfinis.

Respecte le cadre de sécurité : reste dans le domaine de la cible, borné par
une profondeur (RF-24) et une durée (ES-02) maximales, uniquement des GET
non destructifs (ES-03), User-Agent identifiable (ES-05). Les pages
découvertes sont mises en cache et réutilisées par les détections (évite les
requêtes redondantes).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlunparse

from tscan_core.recon.client import ReconError, RootResponse, fetch_url
from tscan_core.scan.progress import notify

# Nombre maximal de pages à crawler pendant un scan (périmètre limitable RF-24).
MAX_PAGES = 30

# Ressources statiques/binaires sans HTML à suivre.
_SKIP_EXTENSIONS = frozenset(
    {
        ".3gp", ".avi", ".csv", ".css", ".eot", ".gif", ".gz", ".ico",
        ".jpeg", ".jpg", ".js", ".json", ".mov", ".mp3", ".mp4", ".otf",
        ".pdf", ".png", ".rar", ".svg", ".tar", ".ttf", ".txt", ".webm",
        ".woff", ".woff2", ".xml", ".zip",
    }
)

# Liens internes sans intérêt (ancre, mailto, javascript:, data:, blob:).
_IGNORE_URL_PATTERNS = re.compile(r"^(#|javascript:|mailto:|tel:|data:|blob:)", re.IGNORECASE)

# URLs de pagination / paramètres de recherche ou tri : pages quasi identiques.
_PAGINATION_PATTERNS = re.compile(
    r"[?&](page|p|offset|start|from|limit|per_page|pagina|seite|szukaj|q|sort|order|filter|search|query)=",
    re.IGNORECASE,
)

# Profondeur de crawl maximale par défaut (0 = racine seule).
DEFAULT_MAX_DEPTH = 2

# Expression régulière d'extraction des liens <a href="..."> (insensible à la
# casse). Le groupe 1 capture la valeur de l'attribut href.
_HREF_RE = re.compile(
    r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)

# URLs candidates supplémentaires : actions de formulaires, iframes, et liens
# <link href> (flux, pages alternées). Les formulaires mènent à des actions qui
# méritent d'être dans le périmètre (fuzzing ciblé) ; <link/iframe> découvrent
# des pages autrement invisibles.
_FORM_ACTION_RE = re.compile(
    r'<form\b[^>]*\baction\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_IFRAME_RE = re.compile(
    r'<iframe\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)
_LINK_RE = re.compile(
    r'<link\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)


def crawl(
    client,
    target: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = MAX_PAGES,
    max_duration_seconds: float = 60.0,
    started_at=None,
    observations: dict | None = None,
    on_event=None,
    concurrency: int = 6,
    interrupt=None,
) -> dict[str, RootResponse]:
    """Crawl le site cible et retourne {url: RootResponse} des pages découvertes.

    Les pages hors domaine, statiques et les URLs non HTTP sont ignorées.
    `client` est le client HTTP de la reconnaissance ; `started_at` borne la
    durée totale du scan parent ; `observations` est enrichi (stats et erreurs).
    `on_event` reçoit chaque page récupérée (`ScanProgressEvent`) pour afficher
    le déroulement du crawl en temps réel. Les requêtes sont émises en parallèle
    (`concurrency` = nombre de travailleurs) comme le fait OWASP ZAP, ce qui
    accélère fortement le crawl d'un grand site.

    `max_pages`, `max_depth` et `max_duration_seconds` acceptent `None` pour ne
    poser aucune borne (crawl exhaustif, parité OWASP ZAP). `interrupt` est un
    `ScanInterrupt` optionnel : dès qu'il est levé, le crawl s'arrête proprement.
    """
    if observations is None:
        observations = {}

    base_parsed = urlparse(target)
    base_netloc = base_parsed.netloc.lower()
    base_scheme = base_parsed.scheme.lower()

    observations["crawl_stats"] = {"pages_found": 0, "max_depth_reached": 0}

    # File de travail (BFS). Les pages sont traitées niveau par niveau (BFS
    # strict) mais les requêtes d'un même niveau sont émises en parallèle :
    # on conserve l'ordre de découverte tout en accélérant fortement le crawl
    # (parité de comportement avec le spider intégré d'OWASP ZAP).
    visited: set[str] = set()
    current_level: list[tuple[str, int]] = [(target, 0)]

    # Découverte d'assets via robots.txt et sitemap.xml. Les URLs découvertes
    # sont ajoutées comme racines (profondeur 0) ; la déduplication est faite
    # par l'ensemble `visited`.
    robots_urls = _parse_robots_txt(client, target, base_netloc, base_scheme)
    for url in robots_urls:
        if _normalize_url(url) not in visited:
            current_level.append((url, 0))

    # Si des sitemaps sont trouvés dans robots.txt, les parser
    sitemap_urls = [url for url in robots_urls if "sitemap" in url.lower()]
    for sitemap_url in sitemap_urls:
        sitemap_pages = _parse_sitemap_xml(client, sitemap_url, base_netloc, base_scheme)
        for url in sitemap_pages:
            if _normalize_url(url) not in visited:
                current_level.append((url, 0))

    pages: dict[str, RootResponse] = {}
    seen_in_level: set[str] = set()
    for url, _depth in current_level:
        norm = _normalize_url(url)
        if norm in visited or norm in seen_in_level:
            continue
        seen_in_level.add(norm)
    current_level = [(url, depth) for url, depth in current_level
                     if _normalize_url(url) in seen_in_level]

    # Marque la racine et les seeds comme visitées avant de commencer.
    for url, _depth in current_level:
        visited.add(_normalize_url(url))

    def _pages_cap_reached() -> bool:
        return max_pages is not None and len(pages) >= max_pages

    def _can_extract(depth: int) -> bool:
        # On ne découvre des liens que si l'on peut encore descendre d'un
        # niveau (enfants de profondeur depth+1) : `depth < max_depth`,
        # sauf quand aucune profondeur maximale n'est posée (None).
        return max_depth is None or depth < max_depth

    while current_level and not _pages_cap_reached():
        if interrupt is not None and interrupt.is_set():
            observations["crawl_stats"]["stopped_by_interrupt"] = True
            break
        # Limite le nombre de pages du niveau courant à ce qu'il reste de place.
        remaining = None if max_pages is None else max_pages - len(pages)
        if remaining is None:
            level = current_level
            current_level = []
        else:
            level = current_level[:remaining]
            current_level = current_level[remaining:] if len(current_level) > remaining else []

        # Récupération parallèle des pages du niveau.
        results: list[tuple[str, int, RootResponse | Exception | None]] = []
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            future_map = {
                pool.submit(
                    _fetch_crawl_page, client, url, depth, started_at,
                    max_duration_seconds, observations, interrupt
                ): (url, depth)
                for url, depth in level
            }
            for fut in as_completed(future_map):
                url, depth = future_map[fut]
                try:
                    results.append((url, depth, fut.result()))
                except ReconError as exc:
                    results.append((url, depth, exc))

        if observations["crawl_stats"].get("stopped_by_duration") or (
            interrupt is not None and interrupt.is_set()
        ):
            if interrupt is not None and interrupt.is_set():
                observations["crawl_stats"]["stopped_by_interrupt"] = True
            return pages

        next_level: list[tuple[str, int]] = []
        for url, depth, outcome in results:
            normalized = _normalize_url(url)
            if isinstance(outcome, Exception):
                observations.setdefault("crawl_errors", {})[url] = str(outcome)
                notify(on_event, "crawl", f"GET {url} -> échec ({outcome})", None)
                continue
            if outcome is None:
                continue
            pages[normalized] = outcome
            notify(
                on_event,
                "crawl",
                f"GET {url} -> {outcome.status_code}",
                20 + int(15 * min(len(pages) / max(1, max_pages or 1), 1.0)),
            )
            observations["crawl_stats"]["pages_found"] = len(pages)
            observations["crawl_stats"]["max_depth_reached"] = max(
                observations["crawl_stats"]["max_depth_reached"], depth
            )
            # Découverte contextuelle des paramètres (pour le fuzzing ciblé).
            page_params = _collect_params(outcome.body, url, base_netloc)
            for name in page_params:
                discovered = observations.setdefault("params_found", [])
                if name not in discovered:
                    discovered.append(name)
            if _can_extract(depth):
                for link in _extract_links(outcome.body, url, base_netloc, base_scheme):
                    link_norm = _normalize_url(link)
                    if link_norm in visited or link_norm in seen_in_level:
                        continue
                    seen_in_level.add(link_norm)
                    next_level.append((link, depth + 1))

        # Le reste du niveau courant (déjà réservé) précède les nouvelles
        # découvertes : on préserve l'ordre BFS.
        for url, depth in current_level:
            norm = _normalize_url(url)
            if norm not in seen_in_level:
                seen_in_level.add(norm)
        current_level = current_level + next_level

    if observations["crawl_stats"].get("stopped_by_interrupt"):
        observations["crawl_stats"]["stopped_by_interrupt"] = True
    return pages


def _fetch_crawl_page(client, url, depth, started_at, max_duration_seconds,
                      observations, interrupt=None):
    """Récupère une page du crawl ; renvoie None si la limite de durée est
    atteinte ou si l'utilisateur a interrompu (signal d'arrêt), ou lève
    ReconError en échec réseau."""
    if interrupt is not None and interrupt.is_set():
        observations.setdefault("crawl_stats", {})["stopped_by_interrupt"] = True
        return None
    if started_at is not None and max_duration_seconds is not None:
        from datetime import UTC, datetime
        elapsed = (datetime.now(UTC) - started_at).total_seconds()
        if elapsed > max_duration_seconds:
            observations.setdefault("crawl_stats", {})["stopped_by_duration"] = True
            return None
    return fetch_url(client, url)




def _extract_links(
    html: str, base_url: str, base_netloc: str, base_scheme: str
) -> list[str]:
    """Extrait les URLs absolues du HTML dans le même domaine : liens `href`,
    actions de formulaires, iframes et liens `<link>`. Filtre ressources
    statiques, pagination et paramètres de recherche/tri."""
    links: list[str] = []
    # Petit espace de nommage local pour ne pas polluer l'import de module.
    candidates = []
    for regex in (_HREF_RE, _FORM_ACTION_RE, _IFRAME_RE, _LINK_RE):
        for match in regex.finditer(html):
            candidates.append(match.group(1))
    for href in candidates:
        if not href or _IGNORE_URL_PATTERNS.match(href):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.netloc.lower() != base_netloc:
            continue
        if parsed.scheme.lower() not in ("http", "https"):
            continue
        ext = _get_extension(parsed.path)
        if ext in _SKIP_EXTENSIONS:
            continue
        if _PAGINATION_PATTERNS.search(absolute):
            continue
        clean = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                parsed.params,
                "",
                "",
            )
        )
        if clean not in links:
            links.append(clean)
    return links


def _normalize_url(url: str) -> str:
    """Normalise une URL : minuscules, sans query, sans fragment, sans '/' final."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", "", ""))


def _get_extension(path: str) -> str:
    """Retourne l'extension d'un chemin d'URL (en minuscules)."""
    dot = path.rfind(".")
    if dot == -1:
        return ""
    return path[dot:].lower().split("?")[0]


def _parse_robots_txt(
    client, base_url: str, base_netloc: str, base_scheme: str
) -> list[str]:
    """Récupère et parse /robots.txt pour extraire les URLs Sitemap et les chemins Allow."""
    robots_url = f"{base_scheme}://{base_netloc}/robots.txt"
    try:
        response = fetch_url(client, robots_url)
        if response.status_code != 200:
            return []
    except ReconError:
        return []

    urls: list[str] = []
    lines = response.body.splitlines()
    for line in lines:
        line = line.strip()
        if line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            if sitemap_url:
                absolute = urljoin(base_url, sitemap_url)
                parsed = urlparse(absolute)
                if parsed.netloc.lower() == base_netloc:
                    urls.append(absolute)
        elif line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                absolute = urljoin(base_url, path)
                parsed = urlparse(absolute)
                if parsed.netloc.lower() == base_netloc:
                    urls.append(absolute)
    return urls


def _parse_sitemap_xml(
    client, sitemap_url: str, base_netloc: str, base_scheme: str
) -> list[str]:
    """Parse un fichier sitemap.xml pour extraire les URLs de pages."""
    try:
        response = fetch_url(client, sitemap_url)
        if response.status_code != 200:
            return []
    except ReconError:
        return []

    urls: list[str] = []
    loc_pattern = re.compile(r"<loc>(.*?)</loc>", re.IGNORECASE)
    for match in loc_pattern.finditer(response.body):
        url = match.group(1).strip()
        if url:
            parsed = urlparse(url)
            if parsed.netloc.lower() == base_netloc and parsed.scheme.lower() in ("http", "https"):
                urls.append(url)
    return urls


# Champs de formulaire et paramètres de requête extraits du HTML pour le
# fuzzing contextuel (feuille de route « attaques ciblées par contexte »).
_FORM_INPUT_RE = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)


def _collect_params(html: str, base_url: str, base_netloc: str) -> list[str]:
    """Retourne les noms de paramètres uniques présents dans une page : noms
    d'inputs de formulaires et noms de paramètres des liens internes."""
    params: list[str] = []

    # Champs de formulaires (les noms seront des candidats au fuzzing GET).
    for match in _FORM_INPUT_RE.finditer(html):
        name = match.group(1).strip()
        if name and name not in params:
            params.append(name)

    # Paramètres de requête des liens internes (pagination, recherche, tri).
    for match in _HREF_RE.finditer(html):
        href = match.group(1)
        if not href or _IGNORE_URL_PATTERNS.match(href):
            continue
        absolute = urljoin(base_url, href)
        if urlparse(absolute).netloc.lower() != base_netloc:
            continue
        from urllib.parse import parse_qsl

        for query_name in dict(parse_qsl(urlparse(absolute).query, keep_blank_values=True)):
            if query_name not in params:
                params.append(query_name)

    return params
