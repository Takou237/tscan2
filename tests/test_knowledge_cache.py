"""Tests du cache local de la base de connaissances (RF-33, RF-34)."""

from __future__ import annotations

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.knowledge_base.cache import (
    get_cached_cves,
    get_kev_entry,
    has_cached_query,
    store_cve_results,
    sync_kev_catalog,
)
from tscan_core.knowledge_base.kev_client import KevRecord
from tscan_core.knowledge_base.nvd_client import CveRecord


def test_store_and_retrieve_cve_results() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        assert not has_cached_query(session, "jquery 1.11.0")

        records = [
            CveRecord(
                cve_id="CVE-2020-11022", description="...", cvss_score=6.1,
                cvss_severity="MEDIUM", published="2020-04-29", raw_json="{}",
            )
        ]
        store_cve_results(session, "jquery 1.11.0", records)

        assert has_cached_query(session, "jquery 1.11.0")
        cached = get_cached_cves(session, "jquery 1.11.0")
        assert len(cached) == 1
        assert cached[0].cve_id == "CVE-2020-11022"


def test_store_empty_results_creates_sentinel_to_avoid_reasking() -> None:
    """Un composant interrogé sans résultat doit rester marqué comme
    interrogé, pour ne pas réinterroger le réseau à chaque scan."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        store_cve_results(session, "composant-sans-cve-connue", [])
        assert has_cached_query(session, "composant-sans-cve-connue")
        cached = get_cached_cves(session, "composant-sans-cve-connue")
        assert len(cached) == 1
        assert cached[0].cve_id == ""


def test_sync_kev_catalog_and_lookup() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        assert get_kev_entry(session, "CVE-2021-44228") is None

        records = [
            KevRecord(
                cve_id="CVE-2021-44228", vulnerability_name="Log4Shell",
                vendor_project="Apache", date_added="2021-12-10", known_ransomware_use="Known",
            )
        ]
        count = sync_kev_catalog(session, records)
        assert count == 1

        entry = get_kev_entry(session, "CVE-2021-44228")
        assert entry is not None
        assert entry.vulnerability_name == "Log4Shell"
        assert get_kev_entry(session, "CVE-inconnue") is None


def test_sync_kev_catalog_replaces_previous_content() -> None:
    """Une resynchronisation doit refléter le catalogue le plus récent, pas
    accumuler les anciennes entrées indéfiniment."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        sync_kev_catalog(
            session,
            [KevRecord("CVE-OLD-0001", "Ancienne entrée", None, None, None)],
        )
        sync_kev_catalog(
            session,
            [KevRecord("CVE-2021-44228", "Log4Shell", "Apache", "2021-12-10", "Known")],
        )

        assert get_kev_entry(session, "CVE-OLD-0001") is None
        assert get_kev_entry(session, "CVE-2021-44228") is not None
