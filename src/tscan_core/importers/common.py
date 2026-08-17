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

from dataclasses import dataclass, field

# Catégories du MVP, telles que définies au chapitre 2 du cahier des charges.
CATEGORY_SECURITY_MISCONFIGURATION = "security_misconfiguration"
CATEGORY_VULNERABLE_COMPONENT = "vulnerable_component"
CATEGORY_XSS = "xss"
CATEGORY_BROKEN_ACCESS_CONTROL = "broken_access_control"
CATEGORY_CSRF = "csrf"
CATEGORY_SQLI = "sqli"  # bonus MVP (RF-22), hors des cinq familles garanties
CATEGORY_OTHER = "other"

# Règles de rattachement par mots-clés, évaluées dans l'ordre : la première
# catégorie dont un mot-clé apparaît dans le texte d'indice est retenue.
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (CATEGORY_XSS, ("xss", "cross-site-scripting", "cross site scripting")),
    (CATEGORY_CSRF, ("csrf", "cross-site request forgery", "cross-site-request-forgery")),
    (CATEGORY_SQLI, ("sqli", "sql-injection", "sql injection")),
    (
        CATEGORY_VULNERABLE_COMPONENT,
        ("outdated", "vulnerable-version", "known-vulnerability", "cve-"),
    ),
    (
        CATEGORY_BROKEN_ACCESS_CONTROL,
        ("access-control", "exposed-panel", "directory-listing", "admin panel", "exposure"),
    ),
    (
        CATEGORY_SECURITY_MISCONFIGURATION,
        (
            "misconfig",
            "clickjacking",
            "x-frame-options",
            "security-headers",
            "ssl",
            "tls",
            "csp",
            "content-security-policy",
        ),
    ),
]


def normalize_category(*hints: str | None) -> str:
    """Rattache un résultat importé à l'une des catégories du MVP à partir
    d'indices textuels (nom, description, tags, identifiant de template...).

    Retourne `CATEGORY_OTHER` si aucun mot-clé connu n'est trouvé, plutôt que
    de deviner : un rattachement incertain doit rester visible comme tel
    plutôt que d'être forcé dans une catégorie du MVP par excès de confiance.
    """
    haystack = " ".join(h for h in hints if h).lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return category
    return CATEGORY_OTHER


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
