"""Détection de fichiers sensibles exposés (famille Security Misconfiguration).

Sondes GET bénignes (ES-03) sur des chemins fermés (ES-02 : pas de crawling)
dont le nom est standard (fichiers de configuration, sauvegardes, exports
SQL) ; le constat n'est émis que si le statut est un succès ET qu'une
signature de contenu attendue pour ce chemin est retrouvée dans la réponse.
Exiger une signature réduit le risque de faux positif : une réponse 200 sur
un chemin connu mais « vide » (page générique d'un framework) n'est pas
suffisante pour conclure à une exposition.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Chemins fermés et signatures de contenu attendues : un constat n'est émis
# que si le corps de la réponse contient l'une des signatures du chemin.
SENSITIVE_PATHS: dict[str, tuple[str, ...]] = {
    "/.git/config": ("[core]", "repositoryformatversion", "url = "),
    "/.git/HEAD": ("ref:", "refs/"),  # exposé si le dépôt est entièrement servi
    "/.env": ("APP_KEY", "DB_PASSWORD", "SECRET_KEY", "DATABASE_URL", "AWS_SECRET"),
    "/.svn/entries": ("dir", "12", "svn"),  # métadonnées Subversion
    "/web.config.bak": ("<configuration", "connectionStrings"),
    "/config.php.bak": ("<?php", "mysql", "host"),
    "/backup.zip": ("PK",),  # en-tête de fichier ZIP
    "/dump.sql": ("CREATE TABLE", "INSERT INTO", "DROP TABLE"),
    "/db.sql": ("CREATE TABLE", "INSERT INTO", "DROP TABLE"),
    "/README.md": ("#!/usr",),  # placeholder : volontairement non matérialisé
}

# Exclusions de signatures trop génériques qui valideraient une page 404 custom.
_DISALLOWED_SIGNATURES = frozenset({"url = ", "ref:", "refs/", "host", "svn", "12", "dir"})

RULE_ID = "RULE-SENSITIVE-FILES-001"
SEVERITY = "high"
CATEGORY = "information_disclosure"


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde les chemins de fichiers sensibles fermés et constate les
    expositions confirmées par une signature de contenu."""
    del root, started_at

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    for path, signatures in SENSITIVE_PATHS.items():
        url = f"{base}{path}"
        page = probe_fetch(client, url, observations, on_event)
        if page is None:
            continue

        if page.status_code not in (200, 204):
            continue

        matching = _matching_signatures(page.body, signatures, path)
        if not matching:
            continue

        results.append(
            DetectionResult(
                rule_id=RULE_ID,
                category=CATEGORY,
                severity=SEVERITY,
                title=f"Fichier sensible exposé : {path}",
                description=(
                    f"Le fichier {path} est accessible publiquement (statut 200) et son "
                    "contenu correspond à un fichier sensible (configuration, archive, "
                    "export de base de données). Sa présence peut divulguer des secrets "
                    "ou du code source à un attaquant non authentifié."
                ),
                matched_at=page.final_url,
                evidence_text=(
                    f"GET {page.final_url} -> {page.status_code} : signatures de contenu "
                    f"retrouvées ({', '.join(matching[:3])})"
                ),
                probe_info={
                    "request_url": url,
                    "method": "GET",
                    "signals": [
                        {"type": "status", "value": page.status_code},
                        {"type": "body_marker", "value": matching[0]},
                    ],
                    "path": path,
                },
            )
        )

    return results


def _matching_signatures(body: str, signatures: tuple[str, ...], path: str) -> list[str]:
    """Signatures du chemin présentes dans le corps, hors exclusions.

    Les exclusions neutralisent des signatures trop larges sur des textes
    courts où elles ne seraient pas significatives (la signature « url = »
    seule ne prouve rien sans « [core] » ou une ligne de dépôt).
    """
    lowered = body.lower()
    matched: list[str] = []
    for signature in signatures:
        if signature.lower() not in lowered:
            continue
        if signature in _DISALLOWED_SIGNATURES and not _has_context_signature(body, path):
            continue
        matched.append(signature)
    return matched


def _has_context_signature(body: str, path: str) -> bool:
    """Vrai si la réponse porte une signature contextuelle forte du chemin."""
    lowered = body.lower()
    context = {
        "/.git/config": ("[core]", "repositoryformatversion"),
        "/.git/HEAD": ("refs/heads", "ref: refs"),
        "/.svn/entries": ("svn", "dir"),
        "/dump.sql": ("create table", "insert into"),
        "/db.sql": ("create table", "insert into"),
        "/backup.zip": ("pk\x03\x04",),
        "/.env": ("app_key", "db_password", "secret_key"),
    }
    return any(sig in lowered for sig in context.get(path, ()))