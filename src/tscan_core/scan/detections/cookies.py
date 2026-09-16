"""Analyse passive des cookies de session (feuille de route « Analyse passive »).

Vérifie sur la réponse racine (et les pages crawlées) que chaque cookie
`Set-Cookie` porte les drapeaux de sécurité recommandés : `HttpOnly` (invisible
au JavaScript, atténue le vol de session XSS), `Secure` (transmis seulement en
HTTPS) et `SameSite` (contraint l'envoi cross-site, atténue le CSRF).

Passif : aucune sonde supplémentaire ; les en-têtes de la réponse sont déjà
collectés lors de la reconnaissance/crawl. Un constat par cookie dépourvu de
drapeau, avec la valeur de l'attribut en preuve (jamais la valeur du cookie :
ne pas fuiter le secret de session dans les preuves, cohérent avec ES-08).
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

RULE_ID = "RULE-COOKIE-001"
CATEGORY = "security_misconfiguration"
SEVERITY = "medium"

# Un nouveau cookie commence par un nom suivi d'un '='. Les valeurs elles-mêmes
# contiennent rarement de virgule ; ce découpage sépare `Set-Cookie`s multiples
# regroupés par httpx dans une seule ligne.
_SET_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[^=;,\s]+=)")


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse les cookies de la racine et des pages crawlées.

    `client`, `started_at`, `on_event` sont ignorés : contrôle purement passif
    sur des réponses déjà récoltées (signature commune des détections).
    """
    del client, started_at, on_event
    results: list[DetectionResult] = []

    responses = [root]
    if pages:
        responses.extend(pages.values())

    for page in responses:
        for cookie, flags in _iter_cookies(page):
            missing: list[str] = []
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if "secure" not in flags:
                missing.append("Secure")
            if not any(flag.startswith("samesite") for flag in flags):
                missing.append("SameSite")
            if not missing:
                continue

            name, _value = cookie.split("=", 1) if "=" in cookie else (cookie, "")
            results.append(
                DetectionResult(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    severity=SEVERITY,
                    title="Cookie de session sans drapeaux de sécurité complets",
                    description=(
                        f"Le cookie {name!r} n'est pas protégé par "
                        f"{', '.join(missing)}. Un attaquant pourrait le lire via "
                        "XSS (absence d'HttpOnly), l'intercepter en clair (absence "
                        "de Secure) ou l'envoyer lors d'une requête cross-site "
                        "(absence de SameSite)."
                    ),
                    matched_at=page.final_url,
                    evidence_text=(
                        f"Set-Cookie {name}=*** (valeur masquée) sans "
                        f"{', '.join(missing)} sur {page.final_url}"
                    ),
                )
            )

    return results


def _iter_cookies(page: RootResponse) -> list[tuple[str, list[str]]]:
    """Décompose les en-têtes Set-Cookie d'une réponse en (cookie, drapeaux).

    Retourne une liste de couples (paire nom=valeur, liste d'attributs en
    minuscules) pour vérifier la présence des drapeaux de sécurité.
    """
    raw = page.headers.get("set-cookie")
    if not raw:
        return []

    # httpx regroupe plusieurs Set-Cookie avec ", " : on découpe sur les sauts
    # de cookie, puis chaque fragment est analysé en attributs.
    fragments = _SET_COOKIE_SPLIT_RE.split(raw)
    cookies: list[tuple[str, list[str]]] = []

    for fragment in fragments:
        parts = [p.strip() for p in fragment.split(";")]
        first = parts[0] if parts else ""
        if "=" not in first:
            continue
        cookies.append((first, _normalize_flags(parts[1:])))

    return cookies


def _normalize_flags(attrs: list[str]) -> list[str]:
    """Normalise chaque attribut de cookie en jeton minuscule (nom ou nom=valeur)."""
    flags: list[str] = []
    for attr in attrs:
        token = attr.strip().lower()
        if not token or token.startswith(","):
            continue
        flags.append(token)
    return flags