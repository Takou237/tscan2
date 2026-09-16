"""Analyse passive de la politique Content-Security-Policy (CSP) (feuille de
route : parité OWASP ZAP, alertes 10038 / 10055).

La CSP est la principale défense navigateur contre XSS et l'injection de
données. On l'analyse de façon 100 % passive, sur les réponses déjà
récoltées (racine + pages crawlées) : elle n'est jamais modifiée et aucune
requête supplémentaire n'est émise.

Constats émis, chacun avec sa propre règle (parité d'alertes ZAP) :

* CSP non définie           -> RULE-CSP-NOTSET-001   (moyenne)
* directing wildcard `*`    -> RULE-CSP-WILDCARD-001 (moyenne)
* `unsafe-inline` script    -> RULE-CSP-UNSAFE-INLINE-SCRIPT-001 (moyenne)
* `unsafe-inline` style     -> RULE-CSP-UNSAFE-INLINE-STYLE-001  (moyenne)
* directive sans fallback   -> RULE-CSP-NO-FALLBACK-001 (moyenne)
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

# Règles émises selon le constat.
RULE_NOTSET = "RULE-CSP-NOTSET-001"
RULE_WILDCARD = "RULE-CSP-WILDCARD-001"
RULE_UNSAFE_SCRIPT = "RULE-CSP-UNSAFE-INLINE-SCRIPT-001"
RULE_UNSAFE_STYLE = "RULE-CSP-UNSAFE-INLINE-STYLE-001"
RULE_NO_FALLBACK = "RULE-CSP-NO-FALLBACK-001"

CATEGORY = "security_misconfiguration"
SEVERITY = "medium"

# Directives qui ne reportent PAS sur default-src : si absentes, tout est
# permis pour leur catégorie (parité du plugin ZAP 10055).
_NO_FALLBACK_DIRECTIVES = (
    "base-uri",
    "form-action",
    "frame-ancestors",
    "plugin-types",
    "object-src",
)

# Directives dont la source est normalement le souci du modele de menace.
_SOURCE_DIRECTIVES = (
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "frame-src",
    "font-src",
    "media-src",
    "object-src",
    "manifest-src",
    "worker-src",
)

# Directives de source considérées « trop larges » si elles utilisent `*`.
_WILDCARD_DIRECTIVES = (
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "frame-src",
    "font-src",
    "media-src",
    "object-src",
    "manifest-src",
    "worker-src",
)


def _header_csps(headers: dict[str, str]) -> list[str]:
    """Retourne toutes les valeurs du (des) en-tête CSP (une seule clé,
    mais la valeur peut concaténer plusieurs politiques séparées par
    virgule ; on l'analyse globalement)."""
    return [v for k, v in headers.items() if k.lower() == "content-security-policy"]


def _parse_directives(policy: str) -> dict[str, str]:
    """Découpe une politique CSP en un dict {directive: valeur}."""
    result: dict[str, str] = {}
    for token in policy.split(";"):
        token = token.strip()
        if not token:
            continue
        parts = token.split(None, 1)
        directive = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        result[directive] = value
    return result


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Analyse passive de la CSP sur la racine et les pages crawlées."""
    del config, client, started_at, on_event
    checked = [root]
    if pages:
        checked.extend(pages.values())

    notset_found = False
    wildcards: list[str] = []
    unsafe_scripts: list[str] = []
    unsafe_styles: list[str] = []
    no_fallback: list[str] = []

    for page in checked:
        csps = _header_csps(page.headers)
        has_csp = bool(csps)

        if has_csp:
            for policy in csps:
                dirs = _parse_directives(policy)
                for directive in _WILDCARD_DIRECTIVES:
                    value = dirs.get(directive)
                    if value and "*" in value:
                        wildcards.append(f"{directive} sur {page.final_url}")
                script = dirs.get("script-src", "")
                if "unsafe-inline" in script:
                    unsafe_scripts.append(page.final_url)
                style = dirs.get("style-src", "")
                if "unsafe-inline" in style:
                    unsafe_styles.append(page.final_url)
                for directive in _NO_FALLBACK_DIRECTIVES:
                    if directive not in dirs:
                        no_fallback.append(f"{directive} sur {page.final_url}")
        else:
            notset_found = True

    results: list[DetectionResult] = []

    if notset_found:
        results.append(
            DetectionResult(
                rule_id=RULE_NOTSET,
                category=CATEGORY,
                severity=SEVERITY,
                title="Content Security Policy (CSP) Header Not Set",
                description=(
                    "La Content Security Policy (CSP) n'est pas définie : aucune "
                    "politique n'annonce aux navigateurs les sources autorisées de "
                    "contenu (script, style, image, cadre...). Sans elle, les attaques "
                    "de type XSS et injection de données sont moins bien atténuées."
                ),
                matched_at=root.final_url,
                evidence_text="En-tête Content-Security-Policy absent de la réponse",
            )
        )

    if wildcards:
        results.append(
            DetectionResult(
                rule_id=RULE_WILDCARD,
                category=CATEGORY,
                severity=SEVERITY,
                title="CSP: Wildcard Directive",
                description=(
                    "La politique CSP autorise des sources sauvages (wildcard '*') ou "
                    "ne définit pas certaines directives de source, ce qui équivaut à "
                    "tout autoriser pour leur catégorie."
                ),
                matched_at=root.final_url,
                evidence_text=" ; ".join(dict.fromkeys(wildcards)),
            )
        )

    if unsafe_scripts:
        results.append(
            DetectionResult(
                rule_id=RULE_UNSAFE_SCRIPT,
                category=CATEGORY,
                severity=SEVERITY,
                title="CSP: script-src unsafe-inline",
                description=(
                    "La directive script-src de la CSP inclut 'unsafe-inline' : les "
                    "scripts en ligne sont autorisés, ce qui affaiblit la protection "
                    "contre XSS."
                ),
                matched_at=unsafe_scripts[0],
                evidence_text="script-src inclut unsafe-inline",
            )
        )

    if unsafe_styles:
        results.append(
            DetectionResult(
                rule_id=RULE_UNSAFE_STYLE,
                category=CATEGORY,
                severity=SEVERITY,
                title="CSP: style-src unsafe-inline",
                description=(
                    "La directive style-src de la CSP inclut 'unsafe-inline' : les "
                    "styles en ligne sont autorisés, ce qui affaiblit la protection "
                    "contre le claquage de contenus."
                ),
                matched_at=unsafe_styles[0],
                evidence_text="style-src inclut unsafe-inline",
            )
        )

    if no_fallback:
        results.append(
            DetectionResult(
                rule_id=RULE_NO_FALLBACK,
                category=CATEGORY,
                severity=SEVERITY,
                title="CSP: Failure to Define Directive with No Fallback",
                description=(
                    "La politique CSP ne définit pas au moins une directive sans "
                    "fallback (form-action, base-uri, frame-ancestors...). Les "
                    "omettre revient à tout autoriser pour leur catégorie."
                ),
                matched_at=root.final_url,
                evidence_text=" ; ".join(dict.fromkeys(no_fallback))
                or "directive(s) sans fallback non définie(s)",
            )
        )

    return results
