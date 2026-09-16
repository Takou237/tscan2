"""Client du catalogue CISA KEV (Known Exploited Vulnerabilities).

Contrairement à NVD, le flux KEV est petit (quelques milliers d'entrées) et
se prête à une synchronisation complète plutôt qu'à une interrogation à la
demande (RF-33, chapitre 4 : « CISA KEV comme couche de priorisation »).

Conformément à l'exigence ES-11, la donnée récupérée fait l'objet d'une
validation d'intégrité avant toute intégration en base : garde-fou sur la
taille du flux (éviter une réponse anormalement grande / une bombe de
décompression) et validation du format de chaque identifiant CVE. Ces contrôles
sont distincts du chiffrement de transport (HTTPS/TLS) et opèrent sur le contenu
lui-même, une fois désérialisé.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Garde-fou de taille (octets) au-delà duquel le flux est rejeté comme
# anormal : le catalogue KEV réel fait quelques méga-octets ; cette borne
# protège contre un serveur compromis ou un contenu piégé.
MAX_KEV_BYTES = 20 * 1024 * 1024

# Format canonique d'un identifiant CVE (ex. CVE-2021-44228). Une entrée dont
# l'identifiant ne respecte pas ce format est rejetée : elle ne peut pas être
# une vulnérabilité CISA valide.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class KevClientError(Exception):
    """Levée en cas de réponse inattendue du flux CISA KEV."""


@dataclass
class KevRecord:
    cve_id: str
    vulnerability_name: str
    vendor_project: str | None
    date_added: str | None
    known_ransomware_use: str | None


def fetch_kev_catalog(http_client: httpx.Client) -> list[KevRecord]:
    """Télécharge et parse l'intégralité du catalogue CISA KEV.

    ES-11 : le contenu est rejeté s'il dépasse `MAX_KEV_BYTES` ou si au moins
    une entrée porte un identifiant CVE invalide. En cas de rejet, aucune
    donnée n'est intégrée en base (l'appelant reçoit une erreur).
    """
    try:
        response = http_client.get(KEV_FEED_URL)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise KevClientError(f"Échec du téléchargement du catalogue CISA KEV : {exc}") from exc

    if len(response.content) > MAX_KEV_BYTES:
        raise KevClientError(
            f"Flux CISA KEV rejeté : taille {len(response.content)} octets > "
            f"limite d'intégrité {MAX_KEV_BYTES} (ES-11)."
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise KevClientError(f"Catalogue CISA KEV non exploitable (JSON invalide) : {exc}") from exc

    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise KevClientError("Le catalogue CISA KEV ne contient pas de clé 'vulnerabilities' exploitable.")

    try:
        return [_parse_entry(entry) for entry in vulnerabilities]
    except KevClientError:
        raise
    except (KeyError, TypeError) as exc:
        raise KevClientError(f"Entrée KEV mal formée : {exc}") from exc


def _parse_entry(entry: dict) -> KevRecord:
    cve_id = entry["cveID"]
    if not CVE_ID_RE.match(cve_id):
        raise KevClientError(f"Identifiant CVE invalide dans le flux KEV : {cve_id!r} (ES-11).")
    return KevRecord(
        cve_id=cve_id,
        vulnerability_name=entry.get("vulnerabilityName", ""),
        vendor_project=entry.get("vendorProject"),
        date_added=entry.get("dateAdded"),
        known_ransomware_use=entry.get("knownRansomwareCampaignUse"),
    )
