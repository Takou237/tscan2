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
  Access Control basique (RF-20). Une redirection vers une page
  d'authentification (ex : /wp-admin/ -> /wp-login.php) est une protection
  correcte, pas une exposition.

Un check mal formé ou d'un type inconnu interrompt l'évaluation avec une
erreur explicite, au même principe que les autres chargeurs du cœur : un
check de sécurité qui échoue en silence est un risque, pas un détail.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from tscan_core.knowledge_base.fp_signatures import get_category, load_fp_signatures
from tscan_core.recon.client import RootResponse
from tscan_core.rule_engine.schema import RuleDefinition

# Statuts indicatifs d'une exposition non autorisée pour un `path_status`
# (page livrée au lieu d'un refus) ; les statuts 401/403/404 sont considérés
# comme une protection correcte au niveau du MVP (RF-20). Pour 301/302, la
# destination compte : une redirection vers une page de login est une
# protection (voir `is_path_exposed`), pas une exposition.
EXPOSED_STATUSES = (200, 204, 301, 302)

# Signatures de pages d'authentification : une redirection vers l'une de
# ces pages est la signature d'une ressource PROTÉGÉE (ex : WordPress répond
# 302 /wp-admin/ -> /wp-login.php), pas d'un panneau exposé — classique
# source de faux positif si on se contente de compter le statut de
# redirection. La liste vit dans knowledge/fp_signatures.yaml (catégorie
# `auth_pages`) : elle s'étend sans toucher au code, au même principe que
# les règles du dossier rules/. En l'absence de la catégorie (fichier
# restreint ou ancien), le repli ci-dessous couvre les pages de connexion
# les plus répandues.
_AUTH_CATEGORY_ID = "auth_pages"
_AUTH_FALLBACK_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "log-in",
    "authent",
    "oauth",
    "session",
)
_auth_category = get_category(load_fp_signatures(), _AUTH_CATEGORY_ID)
AUTH_PAGE_MARKERS = _auth_category.path_markers if _auth_category else _AUTH_FALLBACK_MARKERS


def _is_auth_page(path: str) -> bool:
    """Détecte qu'un chemin mène vers une page d'authentification."""
    lowered = (path or "").lower()
    return any(marker in lowered for marker in AUTH_PAGE_MARKERS)


def is_path_exposed(
    page: RootResponse,
    calibration: RootResponse | None = None,
    calibration_token: str | None = None,
) -> bool:
    """Décide si la réponse d'une sonde `path_status` signale une exposition.

    Quatre cas :
    - statut hors 200/204/301/302 (401/403/404…) : protégé, pas d'exposition ;
    - redirection 301/302 vers une page d'authentification (en-tête
      `Location`) : protection correcte, pas d'exposition ;
    - 200/204 atteint après redirection suivie (le client HTTP suit les
      redirections, max 3) alors que la ressource finale est une page de
      login : la ressource initiale est protégée, pas d'exposition ;
    - 200/204 indiscernable de la réponse au chemin-sentinelle (contrôle
      négatif `calibration`, voir `_is_generic_response`) : la cible
      fabrique des soft-404, le statut ne prouve rien — pas de constat.

    Les autres cas (200 direct, redirection vers une ressource quelconque)
    restent indicatifs d'exposition : le constat part en revue analytique.
    """
    if page.status_code not in EXPOSED_STATUSES:
        return False

    if page.status_code in (301, 302):
        location = page.headers.get("location", "")
        redirect_to_auth = bool(location) and _is_auth_page(urlparse(location).path)
        return not redirect_to_auth

    # 200/204 : si la sonde a suivi une redirection et atterrit sur une page
    # d'authentification, la ressource initiale est protégée (le 200 est
    # celui de la page de login, pas celui du panneau).
    final_path = urlparse(page.final_url or "").path
    request_path = urlparse(page.request_url or "").path
    if final_path != request_path and _is_auth_page(final_path):
        return False

    # 200/204 : contrôle négatif. Si la réponse ressemble à celle obtenue
    # sur un chemin inexistant aléatoire (soft-404), l'exposition présumée
    # n'est pas démontrée — on ne conclut pas.
    calibrated = calibration is not None and _is_generic_response(
        page, calibration, calibration_token
    )
    return not calibrated


# --- Sentinelle anti soft-404 (contrôle négatif) -------------------------
# Certains serveurs répondent 200 avec une page générique (accueil,
# recherche, erreur habillée) pour N'IMPORTE quel chemin : un `path_status`
# naïf y verrait des ressources exposées partout. La parade est le contrôle
# négatif : on sonde d'abord un chemin inexistant aléatoire, et toute
# réponse de la cible qui ressemble à celle du contrôle est jugée
# indiscernable du bruit de fond — donc non concluante.

_CALIBRATION_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def new_calibration_token(length: int = 12) -> str:
    """Jeton aléatoire pour le chemin-sentinelle (ex : tscan-calib-k3v9x2m4qp1z).

    L'aléa empêche de tomber par hasard sur une ressource réelle et rend la
    comparaison de corps fiable : le marqueur ne peut pas figurer dans une
    page générée indépendamment du contrôle.
    """
    return "".join(random.choices(_CALIBRATION_ALPHABET, k=length))


def _token_similarity(body: str, token: str | None) -> float:
    """Partie du jeton-sentinelle présente dans un corps de page (0.0 à 1.0).

    Une page de soft-404 réfléchit souvent une partie de l'URL demandée
    (« La page tscan-calib-k3v9… n'existe pas ») : comparer la ressemblance
    au seul marqueur évite de compter cette réflexion comme du contenu
    propre au chemin sonde.
    """
    if not token:
        return 0.0
    if token in body:
        return 1.0
    fragment = max(4, len(token) // 2)
    hits = sum(1 for i in range(len(token) - fragment + 1) if token[i : i + fragment] in body)
    return hits / max(1, len(token) - fragment + 1)


def _tokenize(text: str) -> set[str]:
    """Jeu de mots significatifs d'une page (texte HTML réduit, mots ≥ 4)."""
    stripped = re.sub(r"<[^>]+>", " ", text or "")
    return set(re.findall(r"[a-z0-9]{4,}", stripped.lower()))


def _is_generic_response(
    probe: RootResponse, calibration: RootResponse, calibration_token: str | None
) -> bool:
    """Décide que la réponse de la sonde est « générique » (soft-404).

    Trois indices, dans l'ordre :
    1. le corps du contrôle réfléchit le jeton du chemin-sentinelle et
       celui de la sonde non (ou moins) : le serveur fabrique des pages
       « introuvable » à la demande, le 200 de la sonde est du même acabit ;
    2. les deux corps sont quasi identiques (≥ 0.90) après retrait du
       jeton : même page générée pour deux chemins différents ;
    3. mêmes mots principaux (≥ 0.90) entre les deux pages.
    Un seul indice suffit : en cas de doute, on ne conclut pas — c'est le
    compromis choisi pour limiter les faux positifs (RF-12).
    """
    reflection_gap = _token_similarity(calibration.body, calibration_token) - _token_similarity(
        probe.body, calibration_token
    )
    if reflection_gap > 0.3:
        return True

    strip_token = lambda body: body.replace(calibration_token or "", "").replace(
        (probe.request_url or "").rstrip("/"), ""
    )
    probe_body = strip_token(probe.body)
    calibration_body = strip_token(calibration.body)
    if probe_body and calibration_body:
        a, b = _tokenize(probe_body), _tokenize(calibration_body)
        words_ratio = len(a & b) / max(1, min(len(a), len(b)))
        length_ratio = min(len(probe_body), len(calibration_body)) / max(1, max(len(probe_body), len(calibration_body)))
        if words_ratio >= 0.9 and length_ratio >= 0.5:
            return True
    return False


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
    calibration: RootResponse | None = None,
    calibration_token: str | None = None,
) -> list[CheckResult]:
    """Évalue les checks d'une règle et retourne les constats (un par check).

    `pages` associe un chemin de la cible à sa réponse HTTP (sondes GET
    bénignes déjà effectuées pour les checks `path_status`). Aucun appel
    réseau ici : les sondes sont préparées par l'orchestrateur.

    `calibration` est la réponse du chemin-sentinelle (contrôle négatif anti
    soft-404, voir `is_path_exposed`) ; `None` si la sentinelle n'a pas pu
    être réalisée — les checks restent alors évalués sur leur statut seul.
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
            result = _evaluate_path_status(rule, raw, pages, calibration, calibration_token)
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


def _evaluate_path_status(
    rule: RuleDefinition,
    raw: dict,
    pages: dict,
    calibration: RootResponse | None = None,
    calibration_token: str | None = None,
) -> CheckResult | None:
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

    if not is_path_exposed(page, calibration, calibration_token):
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
