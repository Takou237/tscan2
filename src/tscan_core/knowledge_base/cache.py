"""Cache local de la base de connaissances (RF-33, RF-34).

Sépare la logique de persistance (cette table) de la logique d'interrogation
réseau (`nvd_client`, `kev_client`) : ces deux clients ne connaissent pas la
base de données, et ce module ne fait aucun appel réseau. C'est
`update_manager` qui les assemble.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from tscan_core.knowledge_base.kev_client import KevRecord
from tscan_core.knowledge_base.nvd_client import CveRecord
from tscan_core.models import CachedCve, KevEntry


def get_cached_cves(session: Session, query: str) -> list[CachedCve]:
    """Retourne les résultats déjà mis en cache pour cette requête, sans
    déclencher d'appel réseau. Liste vide si la requête n'a jamais été
    interrogée (à distinguer d'une requête interrogée mais sans résultat --
    ce cas est représenté par `store_cve_results` avec une liste vide, qui
    crée tout de même une marque de passage -- voir ce module plus bas)."""
    return session.query(CachedCve).filter_by(query=query).all()


def has_cached_query(session: Session, query: str) -> bool:
    """Indique si cette requête a déjà été interrogée, qu'elle ait ou non
    renvoyé des résultats -- distinction nécessaire pour éviter de
    réinterroger le réseau à chaque scan pour un composant sans CVE connue."""
    return session.query(CachedCve).filter_by(query=query).first() is not None


def store_cve_results(session: Session, query: str, records: list[CveRecord]) -> list[CachedCve]:
    """Persiste les résultats d'une interrogation NVD. Si `records` est vide
    (composant interrogé, aucune CVE trouvée), une entrée sentinelle est tout
    de même créée (cve_id vide) pour que `has_cached_query` retourne vrai et
    évite une réinterrogation inutile."""
    if not records:
        sentinel = CachedCve(query=query, cve_id="", description=None)
        session.add(sentinel)
        session.commit()
        return [sentinel]

    cached = [
        CachedCve(
            query=query,
            cve_id=record.cve_id,
            description=record.description,
            cvss_score=record.cvss_score,
            cvss_severity=record.cvss_severity,
            published=record.published,
            raw_json=record.raw_json,
        )
        for record in records
    ]
    session.add_all(cached)
    session.commit()
    return cached


def get_kev_entry(session: Session, cve_id: str) -> KevEntry | None:
    """Retourne l'entrée KEV pour cette CVE si elle est activement exploitée,
    None sinon. Ne déclenche aucun appel réseau : suppose que le catalogue a
    déjà été synchronisé via `sync_kev_catalog`."""
    return session.get(KevEntry, cve_id)


def sync_kev_catalog(session: Session, records: list[KevRecord]) -> int:
    """Remplace le contenu local du catalogue KEV par les entrées fournies.

    Le catalogue est rechargé intégralement plutôt que fusionné entrée par
    entrée : c'est plus simple et largement suffisant vu la taille modeste
    du flux (chapitre 4), et ça garantit qu'une entrée retirée du catalogue
    source (rare mais possible) disparaît aussi localement.
    """
    session.query(KevEntry).delete()
    entries = [
        KevEntry(
            cve_id=record.cve_id,
            vulnerability_name=record.vulnerability_name,
            vendor_project=record.vendor_project,
            date_added=record.date_added,
            known_ransomware_use=record.known_ransomware_use,
        )
        for record in records
    ]
    session.add_all(entries)
    session.commit()
    return len(entries)
