"""Détection de hachages faibles / legacy dans les fichiers exposés.

Module passif (parité ZAP : scanning rules) : analyse le corps des pages
déjà crawlées (pas de requête supplémentaire) à la recherche de schémas de
hachage de mot de passe utilisant des algorithmes faibles (MD5, SHA1) ou
sans sel cryptographique. Le constat est émis si le corps contient un
hachage hexadécinal de 32 ou 40 caractères associé à un contexte de mot
de passe (``password``, ``passwd``, ``hash``, ``$1$``, ``$2a$``, ``{SHA}``).

Ce module n'exécute aucune vérification de dictionnaire : il signale
uniquement la présence d'un hachage faible dans un fichier exposé, pas
la cracked-ness. Le constat reste ``Probable`` jusqu'à la confirmation
humaine (RF-12).
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Schémas de hachages faibles détectés dans le corps d'une réponse.
# Chaque pattern expose un groupe nommé `hash` contenant le hachage brut.
HASH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("MD5-crypt", re.compile(r"\$1\$(?P<hash>[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{22,})")),
    ("APR1-MD5", re.compile(r"\$apr1\$(?P<hash>[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{22,})")),
    ("bcrypt", re.compile(r"\$2[aby]\$(?P<hash>\d{2}\$[A-Za-z0-9./]{53})")),
    ("SHA-crypt", re.compile(r"\{SHA\}(?P<hash>[A-Za-z0-9+/]+=*)")),
    ("MySQL-4.1+", re.compile(r"\*(?P<hash>[A-F0-9]{40})")),
    ("MD5", re.compile(r"(?<![0-9a-fA-F])(?P<hash>[0-9a-fA-F]{32})(?![0-9a-fA-F])")),
    ("SHA1", re.compile(r"(?<![0-9a-fA-F])(?P<hash>[0-9a-fA-F]{40})(?![0-9a-fA-F])")),
]

# Mots-clés contextuels indiquant qu'un hash trouvé est bien un hash de
# mot de passe (et non un hash de contenu, un UUID, etc.).
CONTEXT_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "hash",
    "secret",
    "token",
    "credential",
    "admin",
)

# Chemins de fichiers qui sont, par eux-mêmes, un fort signal de fichier de
# mots de passe : un hash qu'on y trouve est un hash de mot de passe.
_PASSWORD_FILE_MARKERS = (".htpasswd", ".htaccess", "/passwd", "users")

RULE_ID = "RULE-WEAK-HASH-001"
SEVERITY = "medium"
CATEGORY = "information_disclosure"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at=None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive des pages crawlées + sondes sur fichiers sensibles.

    Le module vérifie d'abord les pages déjà crawlées (sans requête
    supplémentaire) pour des schémas de hachage faible, puis sonde les
    chemins fermés classiques (``.htpasswd``, etc.) pour les mêmes motifs.
    """
    del started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []
    checked_urls: set[str] = set()

    # --- 1) Pages crawlées (passif : aucune requête supplémentaire) --------
    pages_to_check: list[RootResponse] = [root]
    if pages:
        pages_to_check.extend(pages.values())

    for page in pages_to_check:
        hash_info = _find_weak_hash(page, url=page.final_url)
        if hash_info is not None:
            results.append(_make_result(hash_info, page.final_url))
        checked_urls.add(page.final_url)

    # --- 2) Fichiers sensibles fermés (active : sonde GET bénigne) --------
    sensitive_paths = ("/.htpasswd", "/.htaccess", "/wp-config.php", "/config.php")
    for path in sensitive_paths:
        url = f"{base}{path}"
        if url in checked_urls:
            continue
        page = probe_fetch(client, url, observations)
        if page is None:
            continue

        if page.status_code not in (200, 204):
            continue

        hash_info = _find_weak_hash(page, url=url)
        if hash_info is not None:
            results.append(_make_result(hash_info, page.final_url))
            break

    return results


def _make_result(hash_info: dict, url: str) -> DetectionResult:
    return DetectionResult(
        rule_id=RULE_ID,
        category=CATEGORY,
        severity=SEVERITY,
        title=f"Hachage faible détecté : {hash_info['algo']}",
        description=(
            f"Un hachage de mot de passe utilisant l'algorithme {hash_info['algo']} "
            f"est présent dans une réponse publique. Un attaquant pourrait casser ce "
            f"hachage hors-ligne pour récupérer le mot de passe en clair."
        ),
        matched_at=url,
        evidence_text=(
            f"GET {url} : hachage {hash_info['algo']} "
            f"retrouvé ({hash_info['hash']!r}) dans un contexte de mot de passe"
        ),
    )


def _find_weak_hash(page: RootResponse, url: str = "") -> dict | None:
    """Analyse le corps de la réponse et retourne un weak hash trouvé ou None."""
    # Un fichier de mots de passe (ex. .htpasswd) est un signal contextuel
    # fort : tout hash legacy qu'on y trouve compte, même sans mot-clé proche.
    url_is_password_file = any(mark in url.lower() for mark in _PASSWORD_FILE_MARKERS)
    body_lower = page.body.lower()
    for algo, pattern in HASH_PATTERNS:
        for match in pattern.finditer(page.body):
            candidate = match.group("hash")
            if candidate is None:
                continue
            # Vérifie le contexte : le hash doit être proche d'un mot-clé de
            # mot de passe, OU le chemin de la réponse indique un fichier de
            # mots de passe.
            if url_is_password_file:
                return {"algo": algo, "hash": candidate}
            start = max(0, match.start() - 50)
            context = body_lower[start : match.start() + 50]
            if any(keyword in context for keyword in CONTEXT_KEYWORDS):
                return {"algo": algo, "hash": candidate}
    return None