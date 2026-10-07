"""Whitelist non destructive des constats (filtrage avant listage et rapport).

Un scan produit mécaniquement du bruit : constats « info » de très faible
confiance, divulgations d'horodatages, fuites `X-Powered-By`... Ces constats
restent en base — le filtrage est **non destructif**, aucune suppression n'est
jamais écrite (RF-05 / ES-07) — mais ils sont écartés de l'affichage
(`tscan list`) et de la génération des rapports (`generate_report`), afin que
le lecteur voie d'abord ce qui mérite revue.

Les règles vivent dans le fichier versionné `knowledge/finding_whitelist.yaml`,
au même principe que les signatures de faux positifs (`fp_signatures.yaml`) et
la table CWE (`cwe_reference.yaml`) : elles s'étendent sans toucher au code
(BNF-10). Ce module ne fait aucun appel réseau.

Convention de correspondance d'une règle :
- les critères déclarés sont combinés par **ET** (gravité ET confiance AND titre) ;
- `title_contains` est une liste de fragments réunis par **OU** (insensible à la
  casse) ;
- un constat dont le score de confiance est absent n'est jamais écarté par un
  critère de confiance : **en cas de doute, le constat est conservé** (le
  filtrage ouvre, il ne ferme jamais).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from tscan_core.app_paths import data_root

if TYPE_CHECKING:
    from tscan_core.models import Finding

DEFAULT_WHITELIST_FILE = data_root() / "knowledge" / "finding_whitelist.yaml"

# Critères reconnus dans la section `match` d'une règle. Une clé inconnue est
# refusée au chargement : une faute de frappe (`confidence_lte`) ne doit pas
# désactiver silencieusement un filtre de sécurité.
MATCH_KEYS = frozenset({"severity", "confidence_lt", "title_contains"})


class WhitelistError(Exception):
    """Levée lorsque le fichier de whitelist est mal formé.

    Au même principe que les autres chargeurs du cœur : une table de
    connaissances invalide est signalée explicitement, pas ignorée en silence.
    Les points d'appel (`tscan list`, `generate_report`) rattrapent l'erreur et
    continuent **sans filtrage** : c'est le sens non destructif du mécanisme.
    """


@dataclass(frozen=True)
class WhitelistRule:
    """Une règle d'écartement : au moins un critère, combinés par ET.

    `severities`, `confidence_lt` et `title_contains` sont None/vides quand le
    critère n'est pas déclaré dans le YAML (il est alors neutralisé).
    """

    id: str
    name: str
    reason: str = ""
    enabled: bool = True
    severities: tuple[str, ...] = ()
    confidence_lt: float | None = None
    title_contains: tuple[str, ...] = ()

    def matches(self, finding: Finding) -> bool:
        """Vrai si le constat satisfait **tous** les critères déclarés."""
        if self.severities and (finding.severity or "").lower() not in self.severities:
            return False
        if self.confidence_lt is not None:
            score = finding.confidence_score
            # Score absent : critère non vérifiable -> on conserve le constat.
            if score is None or score >= self.confidence_lt:
                return False
        if self.title_contains:
            title = (finding.title or "").lower()
            if not any(fragment in title for fragment in self.title_contains):
                return False
        return True


@dataclass(frozen=True)
class Whitelist:
    """Contenu de `knowledge/finding_whitelist.yaml` après validation."""

    enabled: bool = True
    rules: tuple[WhitelistRule, ...] = ()


def _require_str_list(value: object, context: str, key: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise WhitelistError(f"{context} : '{key}' doit être une liste de texte non vide.")
    return [item.strip() for item in value]


def load_whitelist(path: Path | str = DEFAULT_WHITELIST_FILE) -> Whitelist:
    """Charge et valide la whitelist.

    Lève `WhitelistError` si le fichier est absent, illisible, ou mal formé :
    règle sans `id`, identifiant dupliqué, `match` vide ou sans critère,
    critère inconnu, type de valeur incorrect.
    """
    whitelist_path = Path(path)
    try:
        with whitelist_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise WhitelistError(f"{whitelist_path} : fichier illisible ({exc}).") from exc
    except yaml.YAMLError as exc:
        raise WhitelistError(f"{whitelist_path} : YAML invalide ({exc}).") from exc

    if not isinstance(raw, dict):
        raise WhitelistError(
            f"{whitelist_path} : un mapping ('enabled', 'rules') est attendu."
        )

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise WhitelistError(f"{whitelist_path} : 'enabled' doit être un booléen.")

    rules_raw = raw.get("rules", [])
    if not isinstance(rules_raw, list) or not all(
        isinstance(entry, dict) for entry in rules_raw
    ):
        raise WhitelistError(
            f"{whitelist_path} : une liste de règles (mappings) est attendue."
        )

    rules: list[WhitelistRule] = []
    seen_ids: set[str] = set()
    for entry in rules_raw:
        rule_id = entry.get("id")
        context = f"{whitelist_path} : règle sans id ({entry.get('name')!r})"
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise WhitelistError(context)
        context = f"{whitelist_path} : règle '{rule_id}'"
        if rule_id in seen_ids:
            raise WhitelistError(f"{whitelist_path} : identifiant de règle dupliqué '{rule_id}'.")
        seen_ids.add(rule_id)

        rule_enabled = entry.get("enabled", True)
        if not isinstance(rule_enabled, bool):
            raise WhitelistError(f"{context} : 'enabled' doit être un booléen.")

        match = entry.get("match")
        if not isinstance(match, dict) or not match:
            raise WhitelistError(f"{context} : 'match' doit être un mapping de critères non vide.")
        unknown = sorted(set(match) - MATCH_KEYS)
        if unknown:
            raise WhitelistError(
                f"{context} : critère(s) inconnu(s) {unknown} "
                f"(attendus : {sorted(MATCH_KEYS)})."
            )

        severities = (
            [item.lower() for item in _require_str_list(match["severity"], context, "severity")]
            if "severity" in match
            else []
        )
        title_contains = (
            [
                item.lower()
                for item in _require_str_list(
                    match["title_contains"], context, "title_contains"
                )
            ]
            if "title_contains" in match
            else []
        )
        confidence_lt = match.get("confidence_lt")
        if confidence_lt is not None and (
            isinstance(confidence_lt, bool)
            or not isinstance(confidence_lt, (int, float))
            or confidence_lt < 0
        ):
            raise WhitelistError(
                f"{context} : 'confidence_lt' doit être un nombre positif."
            )
        if not severities and confidence_lt is None and not title_contains:
            raise WhitelistError(
                f"{context} : 'match' sans critère exploitable "
                "(severity, confidence_lt, title_contains)."
            )

        rules.append(
            WhitelistRule(
                id=rule_id,
                name=str(entry.get("name") or rule_id),
                reason=str(entry.get("reason") or ""),
                enabled=rule_enabled,
                severities=tuple(severities),
                confidence_lt=float(confidence_lt) if confidence_lt is not None else None,
                title_contains=tuple(title_contains),
            )
        )
    return Whitelist(enabled=enabled, rules=tuple(rules))


def finding_matches_whitelist(
    finding: Finding, whitelist: Whitelist | None
) -> tuple[bool, str]:
    """Indique si un constat doit être écarté, et pourquoi.

    Retourne `(False, "")` quand rien ne correspond, quand la whitelist est
    globalement désactivée (`enabled: false`) ou absente (`None`).
    """
    if whitelist is None or not whitelist.enabled:
        return False, ""
    for rule in whitelist.rules:
        if rule.enabled and rule.matches(finding):
            return True, rule.reason or rule.name
    return False, ""


def apply_whitelist(
    findings: list[Finding], path: Path | str = DEFAULT_WHITELIST_FILE
) -> list[Finding]:
    """Filtre une liste de constats (non destructif) selon la whitelist.

    Un fichier absent ou mal formé **désactive le filtrage** (fail-open) : le
    résultat contient alors davantage de constats, jamais moins.
    """
    try:
        whitelist = load_whitelist(path)
    except WhitelistError:
        return list(findings)
    return [finding for finding in findings if not finding_matches_whitelist(finding, whitelist)[0]]
