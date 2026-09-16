"""Périmètre et limites d'un scan actif (RF-24, ES-01, ES-02, ES-03).

Ce module concentre toutes les contraintes de cadre d'un scan actif : la
cible autorisée, les types de tests admis, la profondeur, la durée maximale
et le mode sécurisé. L'orchestrateur (`tscan_core.scan.orchestrator`)
n'exécute rien sans un `ScanConfig` valide, et ne peut pas enregistrer un
scan actif dont `authorized` est faux (ES-01) : la confirmation explicite de
l'utilisateur est vérifiée ici, pas seulement demandée dans l'interface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Types de tests connus du moteur. Les blocs de détection des semaines 7-8
# (headers, clickjacking, bac, components, puis xss, csrf, sqli, fichiers
# sensibles, listing de répertoire, CORS et TLS faible) ajoutent ici leur nom
# avec leur implémentation ; la présence d'un nom dans cet ensemble ne
# garantit pas encore qu'une sonde existe pour lui.
TEST_TYPES: frozenset[str] = frozenset(
    {
        "recon",
        "fingerprint",
        "headers",
        "clickjacking",
        "bac",
        "components",
        "xss",
        "csrf",
        "sqli",
        "sensitive-files",
        "directory-listing",
        "cors",
        "tls",
        "cookies",
        "waf",
        "csp",
        "sri",
        "xdomain-js",
        "timestamp",
        "security-headers",
        "big-redirect",
        "zap-passives",
        "path-traversal",
        "open-redirect",
        "cmd-injection",
        "ssti",
        "ssrf",
        "header-injection",
        "weak-hash",
    }
)

# Jeu de tests exécuté par défaut lors d'un scan actif. Contrairement au
# comportement initial (reconnaissance + fingerprinting uniquement), un scan
# lance désormais TOUTES les familles de détection non destructives par défaut
# (headers, clickjacking, BAC, composants, XSS, CSRF, SQLi, fichiers sensibles,
# listing, CORS, TLS). Cette activité reste encadrée par le mode sécurisé
# GET-only (ES-03) et par les bornes de durée/profondeur (ES-02) ; l'option
# `--tests` (CLI) ou le champ « Types de test » (GUI) permet de restreindre le
# périmètre si nécessaire.
DEFAULT_ALLOWED_TESTS: frozenset[str] = frozenset(TEST_TYPES)

# Ports par défaut selon le schéma, utilisés notamment pour la sonde TLS.
DEFAULT_PORTS = {"http": 80, "https": 443}


class ScanConfigError(Exception):
    """Levée lorsqu'une configuration de scan est invalide ou que l'une des
    exigences de sécurité (ES-01 à ES-03) n'est pas satisfaite."""


def validate_target(target: str) -> str:
    """Valide et normalise l'URL cible d'un scan actif.

    Exige un schéma http/https explicite et un nom d'hôte non vide (une
    adresse IP, dont 127.0.0.1 pour le laboratoire de test, est acceptée).
    Retourne l'URL normalisée (hôte en minuscules, chemin conservé).
    """
    stripped = target.strip()
    if not stripped:
        raise ScanConfigError("Cible vide : précisez une URL http(s), ex : https://example.test")

    parsed = urlparse(stripped)
    if parsed.scheme not in ("http", "https"):
        raise ScanConfigError(
            f"Schéma '{parsed.scheme}' non supporté : seuls http:// et https:// sont acceptés."
        )
    if not parsed.hostname:
        raise ScanConfigError("Cible sans nom d'hôte valide.")

    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    return f"{parsed.scheme}://{host}{port}{path}"


@dataclass(frozen=True)
class ScanConfig:
    """Configuration immuable d'un scan actif, définie avant exécution."""

    target: str
    authorized: bool
    max_depth: int = 2
    # Aucune durée maximale par défaut (None) : comme OWASP ZAP, le scan
    # s'arrête quand le crawl a épuisé les pages découvertes ou quand
    # l'utilisateur l'interrompt. Une valeur entière borne le scan (tests).
    max_duration_seconds: int | None = None
    allowed_tests: frozenset[str] = field(default_factory=lambda: DEFAULT_ALLOWED_TESTS)
    safe_mode: bool = True
    verify_tls: bool = True

    # Bornes du crawl. `crawl_max_pages` a un défaut de 40 pages : un scan
    # explore un échantillon représentatif des pages du site au lieu de
    # crawler exhaustivement des centaines de pages (notamment sur de gros
    # CMS type WordPress), ce qui rend la durée du scan prévisible (ES-02).
    # Un crawl exhaustif reste possible en passant explicitement `None`
    # (parité OWASP ZAP — le scan s'arrête quand les pages sont épuisées ou
    # à l'interruption). `crawl_max_depth` et `crawl_max_duration` restent
    # `None` (aucune borne) par défaut.
    DEFAULT_CRAWL_MAX_PAGES = 40
    crawl_max_pages: int | None = DEFAULT_CRAWL_MAX_PAGES
    crawl_max_depth: int | None = None
    crawl_max_duration: int | None = None

    def __post_init__(self) -> None:
        normalized = validate_target(self.target)
        object.__setattr__(self, "target", normalized)

        if self.max_depth < 1:
            raise ScanConfigError("max_depth doit être au moins 1.")
        if self.max_duration_seconds is not None and self.max_duration_seconds < 1:
            raise ScanConfigError("max_duration_seconds doit être ≥ 1 (ou None pour aucun plafond).")
        if self.crawl_max_pages is not None and self.crawl_max_pages < 1:
            raise ScanConfigError("crawl_max_pages doit être ≥ 1 (ou None pour aucun plafond).")
        if self.crawl_max_depth is not None and self.crawl_max_depth < 0:
            raise ScanConfigError("crawl_max_depth doit être ≥ 0 (0 = racine seule) ou None.")
        if self.crawl_max_duration is not None and self.crawl_max_duration < 1:
            raise ScanConfigError("crawl_max_duration doit être ≥ 1 seconde (ou None).")
        unknown = self.allowed_tests - TEST_TYPES
        if unknown:
            raise ScanConfigError(
                f"Types de tests inconnus : {', '.join(sorted(unknown))}. "
                f"Types connus : {', '.join(sorted(TEST_TYPES))}."
            )

    @property
    def hostname(self) -> str:
        return urlparse(self.target).hostname

    @property
    def port(self) -> int:
        parsed = urlparse(self.target)
        return parsed.port or DEFAULT_PORTS[parsed.scheme]

    @property
    def scheme(self) -> str:
        return urlparse(self.target).scheme

    def to_json(self) -> str:
        """Périmètre sérialisé, pour la journalisation du scan (ES-05)."""
        return json.dumps(
            {
                "target": self.target,
                "authorized": self.authorized,
                "max_depth": self.max_depth,
                "max_duration_seconds": self.max_duration_seconds,
                "allowed_tests": sorted(self.allowed_tests),
                "safe_mode": self.safe_mode,
                "verify_tls": self.verify_tls,
                "crawl_max_pages": self.crawl_max_pages,
                "crawl_max_depth": self.crawl_max_depth,
                "crawl_max_duration": self.crawl_max_duration,
            },
            ensure_ascii=False,
        )
