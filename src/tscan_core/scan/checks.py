"""Évaluation des checks déclaratifs du moteur de scan (semaine 7b, RF-17, RF-20).

Les règles YAML du dossier `rules/` peuvent porter une section `checks:`
facultative : des conditions simples, évaluées par le moteur de scan sur les
réponses HTTP déjà récoltées ou sur des sondes GET bénignes supplémentaires.
C'est la matérialisation du choix d'architecture « checks déclaratifs
hybrides » : les conditions simples vivent dans les règles (modifiables sans
toucher au code), les familles qui exigent une logique de test plus complexe
(XSS, CSRF) restent en code à partir de la semaine 8.

Types de checks supportés :

* `header_absent` : l'en-tête HTTP nommé est absent de la réponse racine
  (Security Misconfiguration, RF-17). Aucune requête supplémentaire.
* `clickjacking`   : ni `X-Frame-Options` ni `Content-Security-Policy` avec
  `frame-ancestors` ne protègent la cible (RF-17). Aucune requête
  supplémentaire.
* `path_status`    : une sonde GET bénigne (non destructive, ES-03) sur un
  chemin donné retourne un statut indicatif d'exposition (par défaut
  200/204/301/302) au lieu d'une réponse protégée (401/403/404) -- Broken
  Access Control basique (RF-20).

Un check mal formé ou d'un type inconnu interrompt l'évaluation avec une
erreur explicite, au même principe que les autres chargeurs du cœur : un
check de sécurité qui échoue en silence est un risque, pas un détail.
"""

from __future__ import annotations

from dataclasses import dataclass

from tscan_core.recon.client import RootResponse
from tscan_core.rule_engine.schema import RuleDefinition

# Statuts indicatifs d'une exposition non autorisée pour un `path_status`
# (page livrée au lieu d'un refus) ; les statuts 401/403/404 sont considérés
# comme une protection correcte au niveau du MVP (RF-20).
EXPOSED_STATUSES = (200, 204, 301, 302)


class CheckError(Exception):
    """Levée lorsqu'une règle porte des checks mal formés ou inconnus."""


@dataclass(frozen=True)
class CheckResult:
    """Un check qui a échoué : c'est un résultat de sécurité (`Finding`).

    `matched_url` est la réponse HTTP exacte où le constat a été fait (ES-08 :
    chaque résultat pointe vers la preuve). `severity` vaut celle du check,
    sinon celle de la règle.
    """

    rule_id: str
    rule_name: str
    category: str
    check_id: str
    description: str
    severity: str
    matched_url: str
    evidence_text: str


def validate_rule_checks(rule: RuleDefinition) -> None:
    """Valide la structure des checks d'une règle (types connus, champs requis).

    Appelée par l'orchestrateur avant l'enregistrement d'un scan : une règle
    invalide doit refuser le scan (erreur explicite), pas être ignorée en
    silence au milieu d'un test.
    """
    for raw in rule.checks:
        check_type = raw.get("type")
        if check_type == "header_absent":
            header_name = raw.get("header")
            if not isinstance(header_name, str) or not header_name.strip():
                raise CheckError(
                    f"Check header_absent sans en-tête 'header' dans la règle {rule.id}."
                )
        elif check_type == "clickjacking":
            continue  # aucun paramètre : tout est défini par la règle
        elif check_type == "path_status":
            path = raw.get("path")
            if not isinstance(path, str) or not path.startswith("/"):
                raise CheckError(
                    f"Check path_status sans chemin '/...' dans la règle {rule.id}."
                )
        else:
            raise CheckError(
                f"Check inconnu dans la règle {rule.id} : {check_type!r} "
                f"(types supportés : header_absent, clickjacking, path_status)."
            )


def evaluate_rule_checks(
    rule: RuleDefinition,
    root: RootResponse,
    pages: dict[str, RootResponse] | None = None,
) -> list[CheckResult]:
    """Évalue les checks d'une règle et retourne les constats (un par check).

    `pages` associe un chemin de la cible à sa réponse HTTP (sondes GET
    bénignes déjà effectuées pour les checks `path_status`). Aucun appel
    réseau ici : les sondes sont préparées par l'orchestrateur.
    """
    validate_rule_checks(rule)
    results: list[CheckResult] = []
    pages = pages or {}

    for raw in rule.checks:
        check_type = raw.get("type")
        if check_type == "header_absent":
            result = _evaluate_header_absent(rule, raw, root)
        elif check_type == "clickjacking":
            result = _evaluate_clickjacking(rule, root)
        elif check_type == "path_status":
            result = _evaluate_path_status(rule, raw, pages)
        else:
            raise CheckError(
                f"Check inconnu dans la règle {rule.id} : {check_type!r} "
                f"(types supportés : header_absent, clickjacking, path_status)."
            )

        if result is not None:
            results.append(result)

    return results


def _evaluate_header_absent(rule: RuleDefinition, raw: dict, root: RootResponse) -> CheckResult | None:
    header_name = raw.get("header")
    if not isinstance(header_name, str) or not header_name.strip():
        raise CheckError(f"Check header_absent sans en-tête 'header' dans la règle {rule.id}.")

    if root.headers.get(header_name.strip().lower()) is not None:
        return None

    description = raw.get("description") or f"En-tête HTTP {header_name} absent de la réponse."
    return CheckResult(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        check_id=raw.get("id", f"header:{header_name}"),
        description=description,
        severity=raw.get("severity", rule.severity),
        matched_url=root.final_url,
        evidence_text=f"En-tête HTTP {header_name} absent de la réponse de {root.final_url}",
    )


def _evaluate_clickjacking(rule: RuleDefinition, root: RootResponse) -> CheckResult | None:
    xfo = root.headers.get("x-frame-options")
    csp = root.headers.get("content-security-policy")
    csp_blocks_frames = csp is not None and "frame-ancestors" in csp

    if xfo is not None or csp_blocks_frames:
        return None

    csp_note = "aucune politique Content-Security-Policy" if csp is None else "CSP sans frame-ancestors"
    description = (
        "La cible n'est pas protégée contre le clickjacking : aucun en-tête "
        "X-Frame-Options ni politique Content-Security-Policy avec frame-ancestors."
    )
    return CheckResult(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        check_id="clickjacking",
        description=description,
        severity=rule.severity,
        matched_url=root.final_url,
        evidence_text=(
            f"X-Frame-Options absent, {csp_note} sur {root.final_url}"
        ),
    )


def _evaluate_path_status(rule: RuleDefinition, raw: dict, pages: dict) -> CheckResult | None:
    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise CheckError(f"Check path_status sans chemin '/...' dans la règle {rule.id}.")

    # Les clés de `pages` peuvent être des chemins relatifs (/admin) ou des
    # URLs absolues (https://target.com/admin). On cherche les deux.
    page = pages.get(path)
    if page is None:
        for key, val in pages.items():
            if key.endswith(path) or key.rstrip("/").endswith(path.rstrip("/")):
                page = val
                break
    if page is None:
        return None

    if page.status_code not in EXPOSED_STATUSES:
        return None

    description = raw.get("description") or (
        f"Ressource {path} accessible sans authentification."
    )
    return CheckResult(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        check_id=raw.get("id", f"path:{path}"),
        description=description,
        severity=raw.get("severity", rule.severity),
        matched_url=page.final_url,
        evidence_text=(
            f"GET {page.final_url} -> {page.status_code} "
            "(réponse indicatrice d'exposition ; une protection renverrait 401/403/404)"
        ),
    )
