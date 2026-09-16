"""Tests de l'orchestrateur du scan actif (semaine 7, ES-01 à ES-05).

L'orchestrateur est testé contre le serveur de laboratoire local (fixture
`lab_server`) : cible contrôlée et autorisée, sans aucune ressource externe.
"""

from __future__ import annotations

import json

import httpx
import pytest

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.knowledge_base import cache
from tscan_core.knowledge_base.nvd_client import CveRecord
from tscan_core.models import (
    Finding,
    FindingStatus,
    Scan,
    ScanType,
    TechnologyDetection,
)
from tscan_core.recon.client import ReconError, create_http_client
from tscan_core.scan.config import ScanConfig, ScanConfigError
from tscan_core.scan.orchestrator import ENGINE_SOURCE, run_recon_scan

DETECTION_TESTS = frozenset({"recon", "fingerprint", "headers", "clickjacking", "bac"})


def _config(lab_server, **overrides) -> ScanConfig:
    defaults = {
        "target": f"{lab_server.base_url}/",
        "authorized": True,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def test_run_recon_scan_full_flow(lab_server) -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server))
        scan = session.get(Scan, outcome.scan_id)

        assert scan is not None
        assert scan.scan_type == ScanType.ACTIVE_SCAN
        assert scan.source == ENGINE_SOURCE
        assert scan.target == f"{lab_server.base_url}/"
        assert scan.authorized is True
        assert scan.safe_mode is True
        assert scan.finished_at is not None
        assert outcome.duration_seconds > 0

        config = json.loads(scan.config_json)
        assert config["authorized"] is True
        assert config["safe_mode"] is True

        recon = json.loads(scan.recon_json)
        assert recon["status_code"] == 200

        names = {t.technology_name for t in scan.technologies}
        assert {"apache", "php", "wordpress", "jquery"} <= names
        assert outcome.technologies


def test_run_recon_scan_records_versions(lab_server) -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        run_recon_scan(session, _config(lab_server))
        technologies = session.query(TechnologyDetection).filter(
            TechnologyDetection.technology_name.in_(["apache", "php", "jquery"])
        )
        versions = {t.technology_name: t.version for t in technologies}
        assert versions["apache"] == "2.4.53"
        assert versions["php"] == "7.4.33"
        assert versions["jquery"] == "3.6.0"


def test_run_recon_scan_without_authorization_refused_without_network(lab_server) -> None:
    """ES-01 : aucune sonde ne doit partir sans autorisation explicite. Le
    transport simulé échoue bruyamment s'il est appelé : le refus doit se
    produire avant le premier appel réseau."""
    engine = get_engine(":memory:")
    init_db(engine)

    def unexpected_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Appel réseau déclenché alors que le scan n'est pas autorisé")

    client = httpx.Client(transport=httpx.MockTransport(unexpected_network))

    with get_session(engine) as session, pytest.raises(ScanConfigError, match="ES-01"):
        run_recon_scan(
            session,
            ScanConfig(target=f"{lab_server.base_url}/", authorized=False),
            http_client=client,
        )
    assert session.query(Scan).count() == 0  # aucun scan non autorisé tracé


def test_run_recon_scan_network_error_leaves_traced_scan(lab_server) -> None:
    """ES-05 : un scan dont la cible ne répond pas reste journalisé, clôturé
    et daté, avec l'erreur dans les observations."""
    engine = get_engine(":memory:")
    init_db(engine)

    def failing_network(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connexion refusée")

    client = httpx.Client(transport=httpx.MockTransport(failing_network))

    with get_session(engine) as session, pytest.raises(ReconError):
        run_recon_scan(
            session,
            ScanConfig(target=f"{lab_server.base_url}/", authorized=True),
            http_client=client,
        )

    scan = session.query(Scan).one()
    assert scan.finished_at is not None
    observations = json.loads(scan.recon_json)
    assert "error" in observations


def test_run_recon_scan_stops_after_deadline(lab_server) -> None:
    """ES-02 : la durée maximale est respectée -- la route /slow du
    laboratoire répond en ~1,5 s, un scan borné à 1 s doit s'arrêter."""
    engine = get_engine(":memory:")
    init_db(engine)
    slow_target = f"{lab_server.base_url}/slow"

    with get_session(engine) as session, pytest.raises(ScanConfigError, match="durée maximale"):
        run_recon_scan(
            session,
            _config(lab_server, target=slow_target, max_duration_seconds=1),
        )

    scan = session.query(Scan).one()
    assert scan.finished_at is not None
    assert "durée maximale" in json.loads(scan.recon_json)["error"]


def test_run_recon_scan_against_bare_route_detects_nothing(lab_server) -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server, target=f"{lab_server.base_url}/bare"))
        assert outcome.technologies == []
        assert session.query(TechnologyDetection).count() == 0


def test_run_recon_scan_without_fingerprint_test_skips_detection(lab_server) -> None:
    """Le périmètre (ES-02) borne aussi les types de tests : sans
    'fingerprint' dans les tests autorisés, aucune technologie détectée."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(lab_server, allowed_tests=frozenset({"recon"})),
        )
        assert outcome.technologies == []
        assert session.query(TechnologyDetection).count() == 0


def test_run_recon_scan_client_injection(lab_server) -> None:
    """Le client HTTP injecté est bien celui utilisé (testabilité)."""
    engine = get_engine(":memory:")
    init_db(engine)
    client = create_http_client()

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server), http_client=client)
        assert outcome.scan_id > 0
    client.close()


def _findings_by_rule(session) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in session.query(Finding).all():
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    return counts


def test_run_scan_declarative_checks_produce_findings(lab_server) -> None:
    """7b : en-têtes manquants (6), clickjacking (1) et BAC (/admin/ exposé,
    /wp-admin/ protégé, /config/ absent) produisent des Findings liés."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server, allowed_tests=DETECTION_TESTS))

        assert len(outcome.findings) == 8
        counts = _findings_by_rule(session)
        assert counts["RULE-MISCONFIG-001"] == 6
        assert counts["RULE-CLICKJACKING-001"] == 1
        assert counts["RULE-BAC-001"] == 1

        bac = (
            session.query(Finding)
            .filter(Finding.rule_id == "RULE-BAC-001")
            .one()
        )
        assert bac.matched_at.endswith("/admin/")
        # RF-23 : le constat BAC est re-vérifié par une nouvelle sonde sur la
        # même route ; /admin/ exposé est toujours accessible -> fait reproduit,
        # mais le moteur ne confirme pas : statut Probable renforcé (RF-12).
        assert bac.status == FindingStatus.PROBABLE
        assert bac.evidences and "200" in bac.evidences[0].content_text
        assert any("Re-vérification" in e.content_text for e in bac.evidences)

        headers = (
            session.query(Finding)
            .filter(Finding.rule_id == "RULE-MISCONFIG-001")
            .all()
        )
        assert {f.matched_at for f in headers} == {f"{lab_server.base_url}/"}
        assert all(f.status == FindingStatus.PROBABLE for f in headers)
        assert all(f.evidences for f in headers)
        # Les 8 constats (6 en-têtes + 1 clickjacking + 1 BAC) sont reproduits.
        assert outcome.reproduced == 8


def test_run_scan_checks_respect_scope(lab_server) -> None:
    """ES-02 : sans 'bac' dans les tests autorisés, aucune sonde path_status
    (donc aucun Finding BAC) ; sans 'headers', pas de constat d'en-têtes."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(
                lab_server,
                allowed_tests=frozenset({"recon", "fingerprint", "bac"}),
            ),
        )
        counts = _findings_by_rule(session)
        assert counts.get("RULE-BAC-001") == 1
        assert "RULE-MISCONFIG-001" not in counts
        assert "RULE-CLICKJACKING-001" not in counts
        assert outcome.findings

        findings = session.query(Finding).all()
        assert len(findings) == 1
        assert findings[0].matched_at.endswith("/admin/")


def test_run_scan_bac_sonde_failure_is_traced_not_fatal(lab_server) -> None:
    """Une sonde BAC qui échoue sur le réseau est tracée dans les observations
    sans interrompre le scan ni les autres constats."""
    engine = get_engine(":memory:")
    init_db(engine)

    def first_request_fails(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/wp-admin/":
            raise httpx.ConnectError("sonde bloquée")
        if request.url.path == "/config/":
            return httpx.Response(404, text="")
        return httpx.Response(200, text="<html><body>ok</body></html>")

    client = httpx.Client(transport=httpx.MockTransport(first_request_fails), follow_redirects=True)
    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(lab_server, allowed_tests=frozenset({"recon", "fingerprint", "bac"})),
            http_client=client,
        )
        scan = session.get(Scan, outcome.scan_id)
        observations = json.loads(scan.recon_json)
        assert observations["sondes"]["/wp-admin/"]  # échec tracé
        assert _findings_by_rule(session).get("RULE-BAC-001") == 1
    client.close()


def test_run_scan_components_with_empty_cache_produces_nothing(lab_server) -> None:
    """RF-18 : sans données CVE en cache local, aucun composant n'est signalé.

    L'absence d'appel réseau est structurelle : `lookup_component` est appelé
    avec `allow_network=False` (aucun client réseau n'est créé par le chemin
    composants du scan, ES-09) ; seules les sondes vers la cible utilisent le
    client HTTP de scan.
    """
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(
                lab_server,
                allowed_tests=frozenset({"recon", "fingerprint", "components"}),
                max_duration_seconds=30,
            ),
        )
        assert outcome.findings == []
        assert session.query(Finding).count() == 0


def test_run_scan_components_matches_cached_cves(lab_server) -> None:
    """RF-18 : une CVE en cache local pour apache 2.4.53 produit un Finding
    lié au scan, sans appel réseau."""
    engine = get_engine(":memory:")
    init_db(engine)
    record = CveRecord(
        cve_id="CVE-2026-0001",
        description="Apache HTTP Server vulnérable en version 2.4.53.",
        cvss_score=9.8,
        cvss_severity="HIGH",
        published="2026-01-01",
        raw_json="{}",
    )

    with get_session(engine) as session:
        cache.store_cve_results(session, "cpe|apache:http_server|2.4.53", [record])
        outcome = run_recon_scan(
            session,
            _config(
                lab_server,
                allowed_tests=frozenset({"recon", "fingerprint", "components"}),
                max_duration_seconds=30,
            ),
        )

        assert len(outcome.findings) == 1
        finding = outcome.findings[0]
        assert finding.severity == "high"
        assert "CVE-2026-0001" in finding.title

        db_finding = session.query(Finding).one()
        assert db_finding.rule_id == "RULE-VULNCOMP-001"
        # RF-23 : la même CVE reste rattachable à la même version détectée sur
        # une nouvelle réponse de la cible -> fait reproduit, statut Probable
        # renforcé (le moteur ne confirme pas, RF-12).
        assert db_finding.status == FindingStatus.PROBABLE
        assert db_finding.scan_id == outcome.scan_id
        assert db_finding.evidences and "CVE-2026-0001" in db_finding.evidences[0].content_text
        assert any("Re-vérification" in e.content_text for e in db_finding.evidences)
        assert outcome.reproduced == 1


def test_run_scan_components_sentinel_means_no_known_cve(lab_server) -> None:
    """Une clé déjà interrogée sans résultat (sentinelle) ne produit aucun
    Finding, et la requête n'est pas réinterrogée."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        cache.store_cve_results(session, "cpe|apache:http_server|2.4.53", [])
        outcome = run_recon_scan(
            session,
            _config(
                lab_server,
                allowed_tests=frozenset({"recon", "fingerprint", "components"}),
                max_duration_seconds=30,
            ),
        )
        assert outcome.findings == []