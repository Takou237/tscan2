"""Détection de formulaires POST sans jeton anti-CSRF (RF-21).

Le constat est passif : lecture seule des pages candidates (aucune écriture,
aucun POST, ES-03), puis analyse du HTML déjà récupéré pour y trouver des
formulaires soumis par POST sans champ de jeton reconnu. La liste des noms de
jetons est le dénominateur commun des frameworks courants (Django, Rails,
Laravel, ASP.NET...) ; un formulaire protégé par un autre mécanisme (double
soumission de cookie, SameSite strict) échapperait à ce contrôle, le constat
reste donc `Probable` et sera confirmé activement en RF-23.
"""

from __future__ import annotations

import re

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.probe import probe_fetch

# Noms de champs de jeton couramment générés par les frameworks web.
TOKEN_NAMES = frozenset(
    {
        "csrf",
        "_csrf",
        "csrf_token",
        "csrfmiddlewaretoken",
        "authenticity_token",
        "__requestverificationtoken",
        "xsrf",
        "_token",
        "token",
    }
)

# Périmètre fermé des pages candidates (ES-02) : la racine du site et les
# chemins d'application les plus porteurs de formulaires de saisie.
PROBE_PATHS = ("/", "/contact", "/login", "/register", "/signup", "/profile")

RULE_ID = "RULE-CSRF-001"
SEVERITY = "medium"
CATEGORY = "csrf"

_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_METHOD_RE = re.compile(r"method\s*=\s*[\"'](post)[\"']", re.IGNORECASE)
_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Recherche un formulaire POST sans jeton anti-CSRF sur les pages découvertes.

    Réutilise les pages déjà en mémoire (crawl ou reconnaissance) sans
    refaire de requête HTTP quand c'est possible.
    """
    del root, started_at  # non utilisé : les sondes sont bornées par leur propre timeout

    base = config.target.rstrip("/")
    results: list[DetectionResult] = []

    # Construire la liste des pages à analyser.
    probe_urls: list[str] = []
    if pages:
        for key in pages:
            if key.startswith("http"):
                probe_urls.append(key)
            elif key.startswith("/"):
                probe_urls.append(f"{base}{key}")
    for path in PROBE_PATHS:
        full = f"{base}{path}"
        if full not in [u.rstrip("/") for u in probe_urls]:
            probe_urls.append(full)

    for url in probe_urls:
        # Réutiliser la page crawlée si disponible (aucune requête réseau).
        page = None
        if pages:
            for crawled_url, crawled_page in pages.items():
                if crawled_url.rstrip("/") == url.rstrip("/"):
                    page = crawled_page
                    break
        if page is None:
            page = probe_fetch(client, url, observations, on_event)
            if page is None:
                continue

        if page.status_code != 200:
            continue

        for form in _extract_post_forms(page.body):
            if _block_has_token(form):
                continue
            results.append(
                DetectionResult(
                    rule_id=RULE_ID,
                    category=CATEGORY,
                    severity=SEVERITY,
                    title="Formulaire POST sans jeton anti-CSRF",
                    description=(
                        "Le formulaire soumet des données par POST sans champ de jeton "
                        "anti-CSRF reconnu (CSRF, _token, authenticity_token...). Une "
                        "requête forgée depuis un autre site pourrait le soumettre au nom "
                        "d'un utilisateur authentifié."
                    ),
                    matched_at=page.final_url,
                    evidence_text=(
                        f"Formulaire POST sans jeton anti-CSRF sur {page.final_url} "
                        f"(statut {page.status_code})"
                    ),
                )
            )
            break  # un formulaire vulnérable suffit : les suivants seraient redondants

    return results


def _extract_post_forms(body: str) -> list[str]:
    """Blocs `<form>...</form>` soumis par POST dans un texte HTML."""
    blocks: list[str] = []
    for match in _FORM_RE.finditer(body):
        end = body.lower().find("</form>", match.end())
        block = body[match.start() : end if end != -1 else len(body)]
        if _METHOD_RE.search(block):
            blocks.append(block)
    return blocks


def _block_has_token(block: str) -> bool:
    """Vrai si le bloc contient un input portant un nom de jeton reconnu."""
    for input_match in _INPUT_RE.finditer(block):
        input_tag = block[input_match.start() : input_match.end()]
        name_match = _NAME_RE.search(input_tag)
        if name_match and name_match.group(1).lower() in TOKEN_NAMES:
            return True
    return False