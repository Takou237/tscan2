"""Parité passive OWASP ZAP : lot d'alertes passives fréquentes des scans ZAP.

But (demande utilisateur 27/09/2026) : corroborer une plus grande fraction des
alertes ZAP importées en produisant des constats portant **exactement** les
mêmes titres d'alerte que le parseur ZAP — la passe « titre normalisé + hôte »
de la ré-observation s'en sert pour corroborer.

Chaque alerte est mappée à sa règle ZAP d'origine et émise au plus une fois
par scan (agrégée sur la racine + les pages crawlées, comme le style du module
CSP). L'analyse est 100 % passive : aucune requête supplémentaire.
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

CATEGORY_MISCONFIG = "security_misconfiguration"
CATEGORY_INFO = "information_disclosure"

_SKIP_CONTENT_TYPES = ("text/css", "application/javascript", "text/javascript")

_SUSPICIOUS_COMMENT = re.compile(r"\b(?:TODO|FIXME|HACK|BUG|XXX)\b", re.IGNORECASE)

_MODERN_JS = re.compile(
    r"async\s+function\b|=>\s*[{(\s]|"
    r"\bfetch\s*\(|\bWebSocket\s*\(|document\.querySelector\s*\(|"
    r"\.map\s*\(|localStorage|sessionStorage|navigator\.serviceWorker\s*"
)

_CACHE_COMPLIANT = re.compile(r"\b(?:no-store|no-cache)\b")
_CACHE_PUBLIC = re.compile(r"\bpublic\b|\bmax-age\b")

_BASE64_RUN = re.compile(
    r"(?<![\w=/+-])([A-Za-z0-9+/]{40,}={0,2})(?![\w=+/])"
)
_MD5_HASH = re.compile(r"(?<![a-f0-9])\b[a-f0-9]{32}\b(?![\w-])")
_SOURCE_CODE = re.compile(
    r"<\?php|<%|System\.out\.println|Traceback \(most recent call last\)|def \w+\(self"
)
_ANCHOR = re.compile(r"<a\b[^>]*>", re.IGNORECASE)


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive des réponses déjà récoltées (racine + pages)."""
    del config, client, observations, started_at, on_event

    checked = [root]
    if pages:
        checked.extend(pages.values())

    results: list[DetectionResult] = []
    root_url = root.final_url

    # 1. En-tête Content-Type absent (parité ZAP 10096 « Content-Type Header
    #    Missing »).
    missing_ct = [p.final_url for p in checked if "content-type" not in p.headers]
    if missing_ct:
        results.append(_result(
            "RULE-CT-MISSING-001", CATEGORY_MISCONFIG, "info",
            "Content-Type Header Missing",
            "La réponse ne déclare aucun en-tête Content-Type : le navigateur doit "
            "deviner le type MIME du contenu (MIME sniffing), ce qui peut aboutir à "
            "une exécution de contenu inattendu.",
            root_url, missing_ct,
        ))

    # 2. Commentaires suspicieux dans le HTML (parité ZAP 10027).
    suspicious = []
    for p in checked:
        if not _is_html(p.headers) or not p.body:
            continue
        if _SUSPICIOUS_COMMENT.search(p.body):
            suspicious.append(p.final_url)
    if suspicious:
        results.append(_result(
            "RULE-SUSPICOMM-001", CATEGORY_INFO, "info",
            "Information Disclosure - Suspicious Comments",
            "Le code HTML contient des commentaires suspicieux (TODO, FIXME, HACK, "
            "BUG, XXX) qui peuvent révéler des fonctionnalités inachevées ou des "
            "points d'entrée non documentés.",
            root_url, suspicious,
        ))

    # 3. Application web moderne (parité ZAP 10101/10102 « Modern Web
    #    Application ») : marqueurs ES6+/API navigateur dans les scripts.
    modern = []
    for p in checked:
        if not _is_html(p.headers) or not p.body:
            continue
        if _MODERN_JS.search(p.body):
            modern.append(p.final_url)
    if modern:
        results.append(_result(
            "RULE-MODERN-APP-001", CATEGORY_INFO, "info",
            "Modern Web Application",
            "La page utilise des API JavaScript modernes (ES6, fetch, Web Workers, "
            "localStorage...) : la surface d'attaque côté client diffère d'un site "
            "classique et mérite une analyse ciblée.",
            root_url, modern,
        ))

    # 4. Directives Cache-Control faibles ou absentes (parité ZAP 10049
    #    « Re-examine Cache-control Directives »).
    weak_cache = []
    for p in checked:
        if not _is_html(p.headers):
            continue
        cc = p.headers.get("cache-control", "")
        if not cc or not _CACHE_COMPLIANT.search(cc):
            weak_cache.append(p.final_url)
    if weak_cache:
        results.append(_result(
            "RULE-CACHE-CONTROL-001", CATEGORY_MISCONFIG, "info",
            "Re-examine Cache-control Directives",
            "La réponse ne déclare pas (ou déclare de façon incomplète) les "
            "directives Cache-Control : le contenu peut être mis en cache par le "
            "navigateur ou un proxy et relu ultérieurement. Revoir les directives "
            "de cache des pages sensibles.",
            root_url, weak_cache,
        ))

    # 5. Contenu servi depuis un cache CDN (parité ZAP « Retrieved from
    #    Cache ») : en-têtes Age / CF-Cache-Status / X-Cache...
    cached = []
    for p in checked:
        h = p.headers
        age = h.get("age", "").strip()
        via = h.get("via", "").lower()
        if (
            age
            or h.get("cf-cache-status", "").lower().startswith("hit")
            or "hit" in h.get("x-cache", "").lower()
            or "cache" in via
        ):
            cached.append(p.final_url)
    if cached:
        results.append(_result(
            "RULE-RETRIEVED-CACHE-001", CATEGORY_MISCONFIG, "info",
            "Retrieved from Cache",
            "La réponse porte la marque d'une mise en cache (Age, CF-Cache-Status, "
            "X-Cache, Via) : un contenu sensible pourrait avoir transité par un "
            "cache intermédiaire.",
            root_url, cached,
        ))

    # 6. Permissions-Policy absent (parité ZAP 10063).
    no_permissions = [p.final_url for p in checked if "permissions-policy" not in p.headers]
    if no_permissions:
        results.append(_result(
            "RULE-PERMISSIONS-NOTSET-001", CATEGORY_MISCONFIG, "info",
            "Permissions Policy Header Not Set",
            "L'en-tête Permissions-Policy n'est pas défini : les fonctionnalités "
            "navigateur (microphone, caméra, géolocalisation...) ne sont pas "
            "restreintes par défaut pour les cadres de tiers.",
            root_url, no_permissions,
        ))

    # 7. X-Frame-Options absent (parité ZAP 10020, anti-clickjacking).
    no_xfo = [p.final_url for p in checked if "x-frame-options" not in p.headers]
    if no_xfo:
        results.append(_result(
            "RULE-XFO-NOTSET-001", CATEGORY_MISCONFIG, "low",
            "X-Frame-Options Header Not Set",
            "L'en-tête X-Frame-Options n'est pas défini : la page peut être "
            "embarquée dans une frame d'un site tiers (clickjacking).",
            root_url, no_xfo,
        ))

    # 8. En-têtes serveur révélateurs (parité ZAP 10026/10036/10061/10052/10056).
    server_headers = [f"{p.final_url} : {p.headers['server']}" for p in checked if "server" in p.headers]
    if server_headers:
        results.append(_result(
            "RULE-SERVER-HEADER-001", CATEGORY_INFO, "info",
            "Server Header Information Leak",
            "L'en-tête HTTP Server révèle le nom et souvent la version du serveur "
            "web : une information qui aide l'attaquant à choisir son exploitation.",
            root_url, server_headers,
        ))
    for header, rule_id, title in (
        ("x-aspnet-version", "RULE-XASPNET-001", "X-AspNet-Version Response Header"),
        ("x-chromelogger-data", "RULE-XCHROME-001", "X-ChromeLogger-Data Header Information Leak"),
        ("x-debug-token", "RULE-XDEBUG-001", "X-Debug-Token Information Leak"),
    ):
        leaks = [f"{p.final_url} : {p.headers[header]}" for p in checked if header in p.headers]
        if leaks:
            results.append(_result(
                rule_id, CATEGORY_INFO, "low", title,
                f"L'en-tête {header} expose des informations internes de la "
                "plaque (version, identifiant de débogage).",
                root_url, leaks,
            ))

    # 9. Reverse tabnabbing (parité ZAP 10070) : lien target=_blank sans
    #    rel=noopener.
    tabnabbing = []
    for p in checked:
        if not _is_html(p.headers) or not p.body:
            continue
        if any(
            'target="_blank"' in anchor.lower() or "target='_blank'" in anchor.lower()
            for anchor in _ANCHOR.findall(p.body)
        ) and not re.search(
            r"rel\s*=\s*[\"'][^\"']*(?:noopener|noreferrer)", p.body, re.IGNORECASE
        ):
            tabnabbing.append(p.final_url)
    if tabnabbing:
        results.append(_result(
            "RULE-TABNABBING-001", CATEGORY_INFO, "low",
            "Reverse Tabnabbing",
            "Un lien ouvre une nouvelle page (target=\"_blank\") sans rel=\"noopener "
            "noreferrer\" : la page de destination peut réécrire la fenêtre "
            "d'origine (phishing).",
            root_url, tabnabbing,
        ))

    # 10. Authentification faible (parité ZAP 10045 « Weak Authentication
    #     Method ») : schéma Basic.
    weak_auth = [p.final_url for p in checked if "basic" in p.headers.get("www-authenticate", "").lower()]
    if weak_auth:
        results.append(_result(
            "RULE-WEAK-AUTH-001", CATEGORY_MISCONFIG, "low",
            "Weak Authentication Method",
            "La ressource utilise le schéma d'authentification HTTP Basic : les "
            "identifiants transitent en clair (base64).",
            root_url, weak_auth,
        ))

    # 11. Hachages (MD5...) et blobs base64 dans le HTML (parité ZAP 10097,
    #     10094) et code source exposé (10099).
    hash_urls, base64_urls, source_urls = [], [], []
    for p in checked:
        if not _is_html(p.headers) or not p.body:
            continue
        body = p.body
        md5_matches = _MD5_HASH.findall(body)
        if len(md5_matches) >= 1:
            hash_urls.append(f"{p.final_url} : {md5_matches[0]}")
        long_base64 = [m for m in _BASE64_RUN.findall(body) if not _is_data_uri_context(body, m)]
        if long_base64:
            base64_urls.append(f"{p.final_url} : {long_base64[0][:40]}...")
        if _SOURCE_CODE.search(body):
            source_urls.append(p.final_url)
    if hash_urls:
        results.append(_result(
            "RULE-HASH-001", CATEGORY_INFO, "info",
            "Hash Disclosure",
            "La réponse contient des chaînes au format de hachages MD5 (32 "
            "caractères hexadécimaux) : un mot de passe ou un jeton haché pourrait "
            "être exposé.",
            root_url, hash_urls,
        ))
    if base64_urls:
        results.append(_result(
            "RULE-BASE64-001", CATEGORY_INFO, "info",
            "Base64 Disclosure",
            "La réponse contient un long bloc au format base64 : des données "
            "encodées (jetons, mots de passe, contenu) pourraient être extraites "
            "simplement.",
            root_url, base64_urls,
        ))
    if source_urls:
        results.append(_result(
            "RULE-SOURCE-001", CATEGORY_INFO, "low",
            "Source Code Disclosure",
            "La réponse expose des fragments de code source (PHP, Java, Python, "
            "SGBD) : le code applicatif ne devrait jamais être renvoyé au client.",
            root_url, source_urls,
        ))

    # 12. Requête d'authentification identifiée (parité ZAP 10111) : page ou
    #     URL d'authentification (login/inscription) vue par le crawl.
    auth_req = [p.final_url for p in checked if _is_auth_request(p)]
    if auth_req:
        results.append(_result(
            "RULE-AUTH-REQ-001", CATEGORY_MISCONFIG, "info",
            "Authentication Request Identified",
            "Une requête d'authentification (formulaire de connexion, inscription) "
            "a été identifiée : la cible porte la gestion des identifiants qui "
            "mérite une revue d'authentification.",
            root_url, auth_req,
        ))

    # 13. Réponse de gestion de session identifiée (parité ZAP 10112) : la
    #     réponse pose un jeton de session (Set-Cookie avec identifiant de
    #     session).
    session_mgmt = [p.final_url for p in checked if _is_session_response(p)]
    if session_mgmt:
        results.append(_result(
            "RULE-SESSION-MGMT-001", CATEGORY_MISCONFIG, "info",
            "Session Management Response Identified",
            "La réponse identifie un jeton de gestion de session (cookie de "
            "session, identifiant JSESSIONID/PHPSESSID...) : la protection de "
            "session doit être revue (HttpOnly, Secure, SameSite).",
            root_url, session_mgmt,
        ))

    # 14. Informations sensibles dans l'URL (parité ZAP 10024) : paramètres
    #     nommés de façon révélatrice (email, token, password...) observés dans
    #     les URLs crawlées.
    sensitive_urls = _sensitive_in_url(checked)
    if sensitive_urls:
        results.append(_result(
            "RULE-SENSITIVE-URL-001", CATEGORY_INFO, "info",
            "Information Disclosure - Sensitive Information in URL",
            "Des paramètres d'URL portant des informations sensibles (email, "
            "jeton, mot de passe...) ont été observés : ces valeurs peuvent "
            "transiter en clair dans les journaux et le Referer.",
            root_url, sensitive_urls,
        ))

    # 15. Configuration inter-domaines (parité ZAP 10098) : en-têtes CORS
    #     permissifs ou absents sur les réponses crawlées.
    cors_misconfig = [p.final_url for p in checked if _is_cors_misconfig(p)]
    if cors_misconfig:
        results.append(_result(
            "RULE-CROSS-DOMAIN-001", CATEGORY_MISCONFIG, "low",
            "Cross-Domain Misconfiguration",
            "La réponse expose une configuration CORS permissive (origine sauvage "
            "ou reflétée) : un domaine tiers pourrait lire le contenu de la "
            "réponse.",
            root_url, cors_misconfig,
        ))

    # 16. Incompatibilité de charset (parité ZAP 90011) : le jeu de caractères
    #     déclaré par l'en-tête Content-Type diffère de celui du contenu
    #     (balise meta charset).
    charset_mismatch = [p.final_url for p in checked if _charset_mismatch(p)]
    if charset_mismatch:
        results.append(_result(
            "RULE-CHARSET-001", CATEGORY_MISCONFIG, "info",
            "Charset Mismatch",
            "Le jeu de caractères déclaré par l'en-tête Content-Type diffère de "
            "celui annoncé dans le HTML : un contenu mal interprété peut "
            "entraîner un affichage altéré voire une injection.",
            root_url, charset_mismatch,
        ))

    return results


def _result(rule_id: str, category: str, severity: str, title: str, description: str,
            root_url: str, offending: list[str]) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        matched_at=root_url,
        evidence_text=" ; ".join(dict.fromkeys(offending)),
    )


def _is_html(headers: dict[str, str]) -> bool:
    ctype = headers.get("content-type", "").lower()
    return "html" in ctype or not ctype


def _is_data_uri_context(body: str, match: str) -> bool:
    """Ignore les blobs base64 précédés de `data:` (URI de données légitime)."""
    index = body.find(match)
    start = max(0, index - len("data:image/png;base64,"))
    return "data:" in body[start:index]


# --- Requête d'authentification (10111) ---
_AUTH_ACTIONS = r"\b(?:login|connexion|signin|sign-up|signup|inscription|" \
    r"authenticate|registration|register)\b"
_AUTH_URL_RE = re.compile(_AUTH_ACTIONS, re.IGNORECASE)
_AUTH_INPUT = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"'](?:password)[\"']", re.IGNORECASE)


def _is_auth_request(page) -> bool:
    """Vrai si la page est une requête d'authentification (URL ou action
    d'authentification, ou formulaire avec champ mot de passe)."""
    url = (page.final_url or "").lower()
    request_url = (getattr(page, "request_url", "") or "").lower()
    if _AUTH_URL_RE.search(url) or _AUTH_URL_RE.search(request_url):
        return True
    return bool(_AUTH_INPUT.search(page.body or ""))


# --- Gestion de session (10112) ---
_SESSION_COOKIE_RE = re.compile(
    r"(?:jsessionid|phpsessid|asp\.net_sessionid|cfid|cf_token|session|sid|"
    r"wordpress_logged_in|auth_token|sessionid|esw_sessionid|"
    r"nopcommerce_customer)\s*=", re.IGNORECASE
)


def _is_session_response(page) -> bool:
    """Vrai si la réponse pose un jeton de session reconnaissable."""
    set_cookie = (page.headers.get("set-cookie") or "").lower()
    return bool(_SESSION_COOKIE_RE.search(set_cookie))


# --- Informations sensibles dans l'URL (10024) ---
_SENSITIVE_PARAMS = (
    "email", "mail", "token", "password", "pass", "pwd", "api_key", "apikey",
    "secret", "author", "comment", "ssn", "credit", "card", "sessionid",
)


def _sensitive_in_url(checked: list) -> list[str]:
    """URLs portant un paramètre nommé de façon sensible."""
    found: list[str] = []
    for page in checked:
        url = page.final_url or page.request_url or ""
        params = _split_query_params(url)
        matched = {k for k, v in params.items() if v and k.lower() in _SENSITIVE_PARAMS}
        if matched:
            names = ", ".join(sorted(matched))
            found.append(f"{url} (paramètres : {names})")
    return found


def _split_query_params(url: str) -> dict[str, str]:
    """Extrait les paramètres de requête d'une URL (sans import external)."""
    from urllib.parse import parse_qsl, urlsplit

    query = urlsplit(url).query
    return {k: v for k, v in parse_qsl(query)}


# --- Configuration inter-domaines CORS (10098) ---
_CORS_ALLOW_ORIGIN = re.compile(r"access-control-allow-origin\s*:", re.IGNORECASE)


def _is_cors_misconfig(page) -> bool:
    """Vrai si la réponse déclare un CORS permissif (* ou reflet d'une
    origine)."""
    allow_origin = page.headers.get("access-control-allow-origin", "")
    allow_credentials = page.headers.get("access-control-allow-credentials", "").lower()
    if not allow_origin:
        return False
    if allow_origin == "*" or allow_origin.strip() == "*":
        return True
# L'origine reflétée est évaluée sur l'en-tête réel : on signale aussi
    # l'absence de restriction quand des identifiants sont accordés sans
    # liste blanche explicite (ZAP : ACAO reflétée).
    return bool(
        allow_credentials == "true" and len(allow_origin.strip()) <= 128
    )


# --- Incompatibilité de charset (90011) ---
_CHARSET_HEADER_RE = re.compile(r"charset\s*=\s*[\"']?([\w\-\.]+)", re.IGNORECASE)
_META_CHARSET_RE = re.compile(
    r"<meta\b[^>]*\bcharset\s*=\s*[\"']([\w\-\.]+)[\"']", re.IGNORECASE
)


def _charset_mismatch(page) -> bool:
    """Vrai si le charset déclaré (en-tête) diffère de celui du HTML (meta)."""
    body = page.body or ""
    if not _is_html(page.headers) or not body:
        return False
    header_value = page.headers.get("content-type", "")
    header_match = _CHARSET_HEADER_RE.search(header_value)
    meta_match = _META_CHARSET_RE.search(body)
    if not header_match or not meta_match:
        return False
    return header_match.group(1).lower() != meta_match.group(1).lower()