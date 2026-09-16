"""Éléments communs à tous les parseurs d'import (RF-01, RF-02, RF-03).

Chaque parseur (`nuclei.py`, `zap.py`, ...) convertit le format propre à son
outil source vers `ParsedFinding`, une structure intermédiaire commune. Cette
étape en deux temps (format source -> `ParsedFinding` -> `Finding` SQLAlchemy)
est ce qui permet au reste du cœur de ne jamais connaître le format d'origine
(modèle pivot, chapitre 10) : un nouveau parseur n'a besoin de produire que des
`ParsedFinding`, sans toucher au code qui les enregistre en base.

La normalisation de catégorie ci-dessous est volontairement simple (des règles
par mots-clés) : elle vise seulement à rattacher un résultat importé à l'une
des cinq familles du MVP (chapitre 2) pour permettre un premier tri. Elle ne
remplace pas le moteur de règles du bloc corrélation/validation (semaines 5-6),
qui affinera statut et score à partir de ce premier rattachement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Catégories du MVP, telles que définies au chapitre 2 du cahier des charges.
CATEGORY_SECURITY_MISCONFIGURATION = "security_misconfiguration"
CATEGORY_VULNERABLE_COMPONENT = "vulnerable_component"
CATEGORY_XSS = "xss"
CATEGORY_BROKEN_ACCESS_CONTROL = "broken_access_control"
CATEGORY_CSRF = "csrf"
CATEGORY_SQLI = "sqli"  # bonus MVP (RF-22), hors des cinq familles garanties
CATEGORY_OTHER = "other"
CATEGORY_SSRF = "ssrf"
CATEGORY_SSTI = "ssti"
CATEGORY_CMD_INJECTION = "cmd-injection"
CATEGORY_OPEN_REDIRECT = "open-redirect"
CATEGORY_PATH_TRAVERSAL = "path-traversal"
CATEGORY_HEADER_INJECTION = "header-injection"
CATEGORY_INFORMATION_DISCLOSURE = "information_disclosure"

# Règles de rattachement par mots-clés, évaluées dans l'ordre : la première
# catégorie dont un mot-clé apparaît dans le texte d'indice est retenue.
# L'ordre est significatif : les catégories spécifiques (ssrf, ssti...)
# précèdent les catégories larges (security_misconfiguration, other).
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    # --- Familles spécifiques (ordre = priorité : les plus ciblées en premier) ---
    (CATEGORY_XSS, (
        "xss", "cross-site-scripting", "cross site scripting",
        "reflected-xss", "stored-xss", "dom-xss",
    )),
    (CATEGORY_CSRF, (
        "csrf", "cross-site request forgery", "cross-site-request-forgery",
        "anti-csrf", "missing-csrf",
    )),
    (CATEGORY_SQLI, (
        "sqli", "sql-injection", "sql injection",
        "blind-sqli", "sql-injection-blind",
    )),
    (CATEGORY_SSRF, (
        "ssrf", "server-side-request-forgery", "server side request forgery",
    )),
    (CATEGORY_SSTI, (
        "ssti", "server-side-template-injection",
        "template-injection", "template injection",
    )),
    (CATEGORY_CMD_INJECTION, (
        "xml-injection", "json-injection",
        "cmd-injection", "command-injection",
        "rce", "remote-code-execution", "remote code execution",
        "os-command",
    )),
    (CATEGORY_OPEN_REDIRECT, (
        "open-redirect", "url-redirect",
        "unvalidated-redirect", "unvalidated redirect",
    )),
    (CATEGORY_PATH_TRAVERSAL, (
        "path-traversal", "directory-traversal",
        "lfi", "local-file-inclusion", "file-inclusion",
    )),
    (CATEGORY_HEADER_INJECTION, (
        "header-injection", "crlf-injection", "crlf",
    )),
    # --- Auto-référence / gestion de session (parité ZAP : alertes de
    # constat sans menace propre — Authentication Request Identified 10111,
    # Session Management Response Identified 10112). Catégorie « other » :
    # aucune catégorie de menace du MVP ne correspond à un simple constat.
    (CATEGORY_OTHER, (
        "authentication request", "session management response",
        "authentication request identified", "session management response identified",
    )),
    # --- Composant vulnérable (avant information-disclosure) ---
    (
        CATEGORY_VULNERABLE_COMPONENT,
        (
            "outdated", "vulnerable-version", "known-vulnerability",
            "cve-", "deprecated-version", "end-of-life",
        ),
    ),
    # --- Contrôle d'accès interrompu ( AVANT information-disclosure ) ---
    # Les keywords hyphenés (admin-panel, directory-listing) matchent les
    # template-ids Nuclei comme "exposed-admin-panel", "directory-listing-test".
    (
        CATEGORY_BROKEN_ACCESS_CONTROL,
        (
            "access-control", "exposed-panel", "exposed-admin-panel",
            "admin-panel", "admin panel",
            "directory-listing", "directory listing",
            "idor", "insecure-direct-object",
            "auth-bypass", "authentication-bypass",
            "privilege-escalation",
        ),
    ),
    # --- Divulgation d'informations (fichiers sensibles, technologie) ---
    (CATEGORY_INFORMATION_DISCLOSURE, (
        "information-disclosure", "information-leak", "info-leak",
        "tech-detect", "technology-detection",
        "sensitive-file", "backup-file", "config-file",
        "exposed-file", "debug-enabled",
        ".env", ".git", ".svn", ".htaccess",
        "phpinfo", "server-status", "server-info",
        "default-installation", "default-page",
        "wp-content", "wp-admin", "wp-includes",
        "wordpress-detect", "apache-detect", "nginx-detect",
        "php-detect", "tomcat-detect", "jenkins-detect",
        "iis-detect", "lighttpd-detect",
        "openresty-detect",
        "weak-hash", "weak-cipher", "weak-ssl",
        "x-powered-by",
        "sensitive information",
        # Parité ZAP : alertes passives d'information divulguée.
        "timestamp disclosure", "timestamp",
        "suspicious comment", "modern web application",
        "server header", "server response header",
        "x-aspnet-version", "x-chromelogger", "x-debug-token",
        "base64 disclosure", "hash disclosure", "source code disclosure",
        "tabnabbing", "reverse tabnabbing",
        "sensitive information in url",
    )),
    # --- Configuration erronée (catch-all le plus large, en dernier) ---
    (
        CATEGORY_SECURITY_MISCONFIGURATION,
        (
            "misconfig", "misconfiguration",
            "clickjacking", "x-frame-options",
            "security-headers", "security headers",
            "ssl", "tls", "certificate",
            "csp", "content-security-policy",
            "cors", "cross-origin", "access-control-allow",
            "cookies", "cookie", "set-cookie",
            "cookiejar", "httponly", "secure-flag",
            "subresource-integrity", "sri",
            "sub resource integrity", "integrity attribute",
            "cross domain javascript", "cross-domain javascript",
            "cross domain misconfiguration", "cross-domain misconfiguration",
            "inter domaines", "inter-domaines",
            "waf", "firewall",
            "cache-control",
            "charset", "charset mismatch", "incompatibilit\u00e9 de charset",
            # NB : « exposed » (mot seul) n'est PAS un mot-clé de
            # security_misconfiguration : trop générique, il ferait absorber
            # des noms comme « Exposed Administration Panel » (BAC, tags
            # « exposed-panel ») par le nom seul alors que la priorité au nom
            # les réclame. Les formes spécifiques (exposure, exposed-file,
            # exposed-panel) restent classées dans leur catégorie respective.
            "exposure",
            "x-content-type-options", "x-xss-protection",
            "strict-transport-security", "referrer-policy",
            "permissions-policy", "feature-policy",
            "open-port", "unnecessary-service",
            "server-version", "banner-grab",
            # Parité ZAP : alertes passives de configuration.
            "content-type", "content type",
            "retrieved from cache", "cache hit",
            "weak authentication", "basic auth", "basic-authentication",
        ),
    ),
]


def normalize_category(*hints: str | None) -> str:
    """Rattache un résultat importé à l'une des catégories du MVP à partir
    d'indices textuels (nom, description, tags, identifiant de template...).

    Le **nom** (premier indice : titre d'alerte, template-id, pluginName)
    fait foi avant le texte libre (description) : un nom porte un signal de
    catégorie bien plus fiable qu'une description générique, qui peut
    mentionner d'autres attaques sans y correspondre. Exemple : les alertes
    ZAP « Content Security Policy » décrivent la menace *Cross Site Scripting
    (XSS)* dans leur texte — sans la priorité au nom, elles seraient
    rattachées à `xss` alors qu'elles relèvent de `security_misconfiguration`.
    Si le nom ne fournit aucune catégorie, l'ensemble des indices est exploré.

    Retourne `CATEGORY_OTHER` si aucun mot-clé connu n'est trouvé, plutôt que
    de deviner : un rattachement incertain doit rester visible comme tel
    plutôt que d'être forcé dans une catégorie du MVP par excès de confiance.
    """
    name = hints[0] if hints else None
    if name:
        category = _match_keywords(name.lower())
        if category is not None:
            return category

    haystack = " ".join(h for h in hints if h).lower()
    return _match_keywords(haystack) or CATEGORY_OTHER


def _match_keywords(haystack: str) -> str | None:
    """Retourne la première catégorie dont un mot-clé apparaît dans `haystack`
    (None si aucun mot-clé ne matche).

    Les sigles de 3 lettres (`rce`, `sri`, `tls`, `ssl`, `lfi`, `waf`,
    `xss`, `csp`...) sont comparés comme **mots entiers** : un sous-texte
    comme « rce » dans « resource » ne doit pas suffire. Les mots-clés de
    4 caractères ou plus (`cve-`, `.env`, `cors`, phrases...) restent en
    sous-chaîne (tolérance aux variantes).
    """
    tokens = set(re.findall(r"[a-z0-9]+", haystack))
    for category, keywords in _CATEGORY_KEYWORDS:
        for keyword in keywords:
            if keyword in tokens or (
                len(keyword) >= 4 and keyword in haystack
            ):
                return category
    return None


def normalize_severity(raw_severity: str | None) -> str:
    """Ramène une gravité exprimée par un outil source vers le vocabulaire
    interne de Tscan : info, low, medium, high, critical."""
    if not raw_severity:
        return "info"
    value = raw_severity.strip().lower()
    known = {"info", "informational", "low", "medium", "high", "critical"}
    if value in known:
        return "info" if value == "informational" else value
    return "info"


@dataclass
class ParsedFinding:
    """Représentation intermédiaire commune, produite par chaque parseur
    avant conversion en `Finding` SQLAlchemy (modèle pivot, chapitre 10)."""

    title: str
    category: str
    severity: str
    raw_result: str
    description: str | None = None
    external_id: str | None = None
    matched_at: str | None = None
    extra: dict = field(default_factory=dict)
