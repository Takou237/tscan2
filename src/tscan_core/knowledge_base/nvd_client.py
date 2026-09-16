"""Client de l'API NVD (National Vulnerability Database), REST v2.0.

Interroge `services.nvd.nist.gov` à la demande (par mot-clé ou par
identifiant CPE), plutôt que de rapatrier l'intégralité de la base -- choix
de périmètre validé pour ce bloc (RF-33 : « sous-ensemble ciblé »). Aucune
clé d'API n'est requise pour un usage à faible volume, ce qui convient à un
scan ponctuel de quelques composants détectés sur une cible.

Ce module ne fait qu'interroger et parser : la mise en cache est de la
responsabilité de `tscan_core.knowledge_base.cache`, et seul
`tscan_core.knowledge_base.update_manager` est censé l'appeler directement
(chapitre 10 : le gestionnaire de mise à jour est le seul composant autorisé
à faire des appels réseau).

Conformément à l'exigence ES-11, la donnée récupérée est validée avant toute
intégration en cache : garde-fou sur la taille de la réponse et validation du
format de chaque identifiant CVE (au-delà du chiffrement de transport HTTPS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Garde-fou de taille (octets) au-delà duquel la réponse est rejetée : l'API
# NVD renvoie typiquement quelques dizaines de kilo-octets par page ; cette
# borne protège contre une réponse anormalement grande (DoS / contenu piégé).
MAX_NVD_BYTES = 5 * 1024 * 1024

# Format canonique d'un identifiant CVE. Une vulnérabilité dont l'identifiant
# ne respecte pas ce format est rejetée (ES-11) : elle ne peut pas être une
# CVE NVD valide.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class NvdClientError(Exception):
    """Levée en cas de réponse inattendue de l'API NVD (réseau, format)."""


@dataclass
class CveRecord:
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    published: str | None
    raw_json: str


def _query_cves(http_client: httpx.Client, params: dict[str, str]) -> list[CveRecord]:
    """GET /rest/json/cves/2.0 avec les paramètres donnés, puis parsing.

    ES-11 : la réponse est rejetée si elle dépasse `MAX_NVD_BYTES`, et chaque
    CVE retournée doit porter un identifiant au format valide. Toute anomalie
    lève `NvdClientError` ; aucune donnée n'est alors mise en cache.
    """
    try:
        response = http_client.get(
            NVD_API_URL,
            params=params,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise NvdClientError(f"Échec de la requête vers l'API NVD : {exc}") from exc

    if len(response.content) > MAX_NVD_BYTES:
        raise NvdClientError(
            f"Réponse NVD rejetée : taille {len(response.content)} octets > "
            f"limite d'intégrité {MAX_NVD_BYTES} (ES-11)."
        )

    try:
        data = response.json()
    except ValueError as exc:  # JSON invalide
        raise NvdClientError(f"Réponse NVD non exploitable (JSON invalide) : {exc}") from exc

    items = data.get("vulnerabilities", [])
    if not isinstance(items, list):
        raise NvdClientError("Structure de réponse NVD inattendue : 'vulnerabilities' n'est pas une liste.")

    try:
        records = [_parse_vulnerability(item) for item in items]
    except (KeyError, TypeError) as exc:
        raise NvdClientError(f"Structure de réponse NVD inattendue : {exc}") from exc

    for record in records:
        if not CVE_ID_RE.match(record.cve_id):
            raise NvdClientError(f"Identifiant CVE invalide dans la réponse NVD : {record.cve_id!r} (ES-11).")

    return records


def search_cve_by_keyword(
    http_client: httpx.Client, keyword: str, results_per_page: int = 5
) -> list[CveRecord]:
    """Interroge l'API NVD par mot-clé (ex : "jquery 1.11.0") et retourne les
    CVE correspondantes, les plus pertinentes en premier (ordre renvoyé par
    l'API elle-même).
    """
    return _query_cves(http_client, {"keywordSearch": keyword, "resultsPerPage": results_per_page})


def search_cve_by_cpe(
    http_client: httpx.Client, cpe_name: str, results_per_page: int = 5
) -> list[CveRecord]:
    """Recherche les CVE liées à un identifiant CPE (ex :
    cpe:2.3:a:jquery:jquery:1.11.0).

    C'est la méthode fiable de correspondance version -> CVE (RF-18) : NVD
    lie chaque CVE aux CPE concernés, alors que la recherche par mot-clé ne
    matche que la phrase exacte dans les descriptions -- lesquelles ne
    contiennent que rarement "produit version" mot pour mot.
    """
    return _query_cves(http_client, {"cpeName": cpe_name, "resultsPerPage": results_per_page})


def _parse_vulnerability(item: dict) -> CveRecord:
    import json

    cve = item["cve"]
    descriptions = cve.get("descriptions", [])
    description_en = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    metrics = cve.get("metrics", {})
    cvss_score, cvss_severity = _extract_best_cvss(metrics)

    return CveRecord(
        cve_id=cve["id"],
        description=description_en,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        published=cve.get("published"),
        raw_json=json.dumps(item, ensure_ascii=False),
    )


def _extract_best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Retient la métrique CVSS la plus récente disponible : v3.1, sinon
    v3.0, sinon v2 -- dans cet ordre de préférence, conformément à la
    pratique usuelle de lecture des réponses NVD (schéma confirmé section 4
    du cahier des charges)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0]["cvssData"]
            return cvss_data.get("baseScore"), cvss_data.get("baseSeverity")

    entries = metrics.get("cvssMetricV2")
    if entries:
        cvss_data = entries[0]["cvssData"]
        severity = entries[0].get("baseSeverity")
        return cvss_data.get("baseScore"), severity

    return None, None
