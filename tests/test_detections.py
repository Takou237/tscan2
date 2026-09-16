"""Tests des détections actives de la semaine 8 (RF-19 XSS, RF-21 CSRF, RF-22
SQLi et familles complémentaires : fichiers sensibles, listing de répertoire,
CORS, TLS faible).

Les modules sont testés de deux façons complémentaires : unitairement (chaque
module `run(...)` contre le laboratoire local, qui fournit des routes
vulnérables et leurs contre-exemples) et en intégration (via
`run_recon_scan`, qui persiste les Findings liés au scan). Aucune ressource
externe n'est contactée (ES-09).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus, Scan, ScanType
from tscan_core.recon.client import RootResponse, create_http_client, fetch_root
from tscan_core.scan.config import ScanConfig, ScanConfigError
from tscan_core.scan.detections import (
    cors,
    csrf,
    directory_listing,
    run_active_detections,
    sensitive_files,
    sqli,
    xss,
)
from tscan_core.scan.detections.tls_weak import run as run_tls
from tscan_core.scan.orchestrator import run_recon_scan

ALL_S8_TESTS = frozenset(
    {"recon", "xss", "csrf", "sqli", "sensitive-files", "directory-listing", "cors"}
)


def _config(lab_server, **overrides) -> ScanConfig:
    defaults = {
        "target": f"{lab_server.base_url}/",
        "authorized": True,
        "max_duration_seconds": 60,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _run_module(module, config, client, root, observations=None):
    """Appelle `module.run` avec la signature commune des détections."""
    return module.run(config, client, root, observations or {}, None)


# --- XSS (RF-19) ---------------------------------------------------------


def test_xss_detects_unescaped_reflection(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(xss, config, client, root)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-XSS-001"
        assert results[0].severity == "high"
        assert "/echo" in results[0].matched_at
        assert "data-tscan-xss" in results[0].evidence_text
    finally:
        client.close()


def test_xss_escaped_route_is_not_detected(lab_server) -> None:
    """Le contre-exemple /escape échappe le paramètre : aucun constat, même si
    le contenu reflété est présent."""
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(xss, config, client, root)
        assert all("/escape" not in r.matched_at for r in results)
    finally:
        client.close()


# --- CSRF (RF-21) --------------------------------------------------------


def test_csrf_detects_form_without_token(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(csrf, config, client, root)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-CSRF-001"
        assert results[0].severity == "medium"
        assert results[0].matched_at.endswith("/contact")
    finally:
        client.close()


def test_csrf_secure_form_with_token_is_not_detected(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(csrf, config, client, root)
        assert all("/secure-form" not in r.matched_at for r in results)
    finally:
        client.close()


# --- SQLi (RF-22) --------------------------------------------------------


def test_sqli_detects_exposed_sql_error(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(sqli, config, client, root)
        assert len(results) == 1
        assert results[0].rule_id == "RULE-SQLI-001"
        assert results[0].severity == "high"
        assert "/search" in results[0].matched_at
        assert "sql syntax" in results[0].evidence_text.lower()
    finally:
        client.close()


def test_sqli_safe_search_is_not_detected(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(sqli, config, client, root)
        assert all("/safe-search" not in r.matched_at for r in results)
    finally:
        client.close()


# --- Fichiers sensibles --------------------------------------------------


def test_sensitive_files_detects_exposed_files(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(sensitive_files, config, client, root)
        assert len(results) == 4
        assert all(r.rule_id == "RULE-SENSITIVE-FILES-001" for r in results)
        exposed = {p for r in results for p in ("/.git/config", "/.env", "/backup.zip", "/dump.sql") if r.matched_at.endswith(p)}
        assert exposed == {"/.git/config", "/.env", "/backup.zip", "/dump.sql"}
    finally:
        client.close()


# --- Listing de répertoire ----------------------------------------------


def test_directory_listing_detects_exposed_index(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = directory_listing.run(config, client, root, {}, None, {})
        assert len(results) == 1
        assert results[0].rule_id == "RULE-LISTING-001"
        assert results[0].matched_at.endswith("/files/")
        assert results[0].severity == "medium"
    finally:
        client.close()


def test_directory_listing_root_is_not_a_listing(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = directory_listing.run(config, client, root, {}, None, {})
        assert all(r.matched_at.rstrip("/") != config.target.rstrip("/") for r in results)
    finally:
        client.close()


# --- CORS -----------------------------------------------------------------


def test_cors_detects_wildcard_and_reflected_origin(lab_server) -> None:
    client = create_http_client()
    config = _config(lab_server)
    try:
        root = fetch_root(client, config.target)
        results = _run_module(cors, config, client, root)
        assert len(results) == 2
        assert all(r.rule_id == "RULE-CORS-001" for r in results)
        exposed = {p for r in results for p in ("/cors-open", "/cors-echo") if r.matched_at.endswith(p)}
        assert exposed == {"/cors-open", "/cors-echo"}
        wildcard = next(r for r in results if r.matched_at.endswith("/cors-open"))
        assert "origine sauvage" in wildcard.evidence_text
    finally:
        client.close()


# --- TLS faible (lecture de l'observation de reconnaissance) -------------


def test_tls_weak_self_signed_certificate() -> None:
    observations = {
        "tls": {
            "issuer": "CN=lab",
            "subject": "CN=lab",
            "not_before": "20260801000000Z",
            "not_after": "20270801000000Z",
            "tls_version": "TLSv1.2",
            "self_signed": True,
        }
    }
    config = ScanConfig(target="https://lab.test/", authorized=True)
    results = run_tls(config, observations)
    assert any(r.title == "Certificat TLS auto-signé" for r in results)
    assert all(r.rule_id == "RULE-TLS-WEAK-001" for r in results)


def test_tls_weak_expired_certificate() -> None:
    past = (datetime.now(UTC) - timedelta(days=10)).strftime("%Y%m%d%H%M%S")
    observations = {
        "tls": {
            "not_after": f"{past}Z",
            "self_signed": False,
            "tls_version": "TLSv1.2",
        }
    }
    config = ScanConfig(target="https://lab.test/", authorized=True)
    results = run_tls(config, observations)
    assert any(r.title == "Certificat TLS expiré" and r.severity == "high" for r in results)


def test_tls_weak_old_protocol() -> None:
    observations = {
        "tls": {
            "not_before": "20260801000000Z",
            "not_after": "20270801000000Z",
            "tls_version": "TLSv1",
            "self_signed": False,
        }
    }
    config = ScanConfig(target="https://lab.test/", authorized=True)
    results = run_tls(config, observations)
    assert any("TLS désuet" in r.title and r.severity == "low" for r in results)


def test_tls_weak_healthy_certificate_produces_nothing() -> None:
    observations = {
        "tls": {
            "issuer": "CN=CA",
            "subject": "CN=lab",
            "not_before": "20260801000000Z",
            "not_after": "20270801000000Z",
            "tls_version": "TLSv1.3",
            "self_signed": False,
        }
    }
    config = ScanConfig(target="https://lab.test/", authorized=True)
    assert run_tls(config, observations) == []


def test_tls_weak_without_observation_produces_nothing() -> None:
    """Cible http (pas de sonde TLS) ou sonde en échec : aucun constat."""
    config = ScanConfig(target="http://lab.test/", authorized=True)
    assert run_tls(config, {}) == []
    assert run_tls(config, {"tls": {"error": "port fermé"}}) == []


# --- Intégration via l'orchestrateur -------------------------------------


def test_run_recon_scan_with_s8_tests_produces_findings(lab_server) -> None:
    """Les familles S8 produisent des Findings persistés, liés au scan, avec une
    preuve. La phase de re-vérification active (RF-23) renforce la confiance
    des constats reproductibles mais les laisse au statut ``Probable`` (le
    moteur ne confirme jamais, RF-12)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server, allowed_tests=ALL_S8_TESTS))

        by_rule: dict[str, int] = {}
        for finding in session.query(Finding).all():
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1

        assert by_rule["RULE-XSS-001"] == 1
        assert by_rule["RULE-CSRF-001"] == 1
        assert by_rule["RULE-SQLI-001"] == 1
        assert by_rule["RULE-SENSITIVE-FILES-001"] == 4
        assert by_rule["RULE-LISTING-001"] == 1
        assert by_rule["RULE-CORS-001"] == 2
        assert "RULE-TLS-WEAK-001" not in by_rule  # cible http : pas de TLS

        assert len(outcome.findings) == 10
        assert outcome.reproduced == 10
        for finding in session.query(Finding).all():
            assert finding.status == FindingStatus.PROBABLE
            assert finding.evidences
            assert any("Re-vérification" in e.content_text for e in finding.evidences)
            assert finding.scan_id == outcome.scan_id


def test_run_recon_scan_without_s8_tests_skips_detections(lab_server) -> None:
    """ES-02 : les familles S8 ne sont exécutées que si elles figurent dans le
    périmètre autorisé -- un scan sans elles ne produit aucun constat S8."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        outcome = run_recon_scan(
            session,
            _config(lab_server, allowed_tests=frozenset({"recon", "fingerprint"})),
        )
        assert session.query(Finding).count() == 0
        assert outcome.findings == []


def test_run_scan_detection_sonde_failure_is_traced_not_fatal(lab_server) -> None:
    """Une sonde S8 qui échoue sur le réseau est tracée dans les observations
    sans interrompre le scan ni les constats des autres familles."""
    import httpx

    engine = get_engine(":memory:")
    init_db(engine)

    def failing_network(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/echo":
            raise httpx.ConnectError("sonde bloquée")
        return httpx.Response(404, text="")

    client = httpx.Client(transport=httpx.MockTransport(failing_network), follow_redirects=True)
    try:
        with get_session(engine) as session:
            outcome = run_recon_scan(
                session,
                _config(lab_server, allowed_tests=frozenset({"recon", "xss"})),
                http_client=client,
            )
            scan = session.get(Scan, outcome.scan_id)
            observations = __import__("json").loads(scan.recon_json)
            assert any("sonde bloquée" in v for v in observations["sondes"].values())
            assert session.query(Finding).count() == 0
    finally:
        client.close()


def test_active_detections_persist_incrementally_before_deadline() -> None:
    """ES-05 : les constats de détection ACTIVES sont persistés au fil de l'eau.

    Si la durée maximale est atteinte au milieu des détections (entre deux
    familles), les constats déjà découverts restent en base -- au lieu d'être
    perdus. Ici la famille XSS (première, réfléchie par le faux serveur)
    persiste son constat avant que la famille CSRF, volontairement lente,
    ne déclenche `check_deadline`. Aucune ressource externe n'est contactée.
    """
    engine = get_engine(":memory:")
    init_db(engine)

    def handler(request: httpx.Request) -> httpx.Response:
        parsed = urlparse(str(request.url))
        q = parse_qs(parsed.query).get("q")
        if q:
            # Sonde XSS : on reflète la charge pour la faire détecter.
            return httpx.Response(200, text=f"<html>hello {q[0]}</html>")
        if parsed.path in {"/", "/contact", "/login", "/register", "/signup", "/profile"}:
            # Sonde CSRF volontairement lente : fait dépasser la durée maximale.
            import time

            time.sleep(2)
        return httpx.Response(200, text="<html>aucun formulaire</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    now = datetime.now(UTC)
    config = ScanConfig(
        target="http://127.0.0.1:1/",
        authorized=True,
        max_duration_seconds=1,
        allowed_tests=frozenset({"xss", "csrf"}),
    )
    root = RootResponse(
        status_code=200,
        headers={},
        body="<html/>",
        final_url=config.target,
        body_truncated=False,
    )
    try:
        with get_session(engine) as session:
            scan = Scan(
                scan_type=ScanType.ACTIVE_SCAN,
                source="tscan_engine",
                target=config.target,
                authorized=True,
                safe_mode=False,
                config_json=config.to_json(),
            )
            session.add(scan)
            session.flush()

            with pytest.raises(ScanConfigError, match="durée maximale"):
                run_active_detections(
                    session, scan, config, root, client, {}, now, pages={}
                )

            persisted = {
                f.rule_id for f in session.query(Finding).filter_by(scan_id=scan.id)
            }
            assert "RULE-XSS-001" in persisted
            assert "RULE-CSRF-001" not in persisted
    finally:
        client.close()


def test_detections_committed_live_visible_from_another_connection(tmp_path) -> None:
    """S11 : les constats commités au fil de l'eau sont lisibles depuis une
    AUTRE connexion PENDANT le scan, pas seulement à la fin.

    Le scan tourne dans un fil avec sa propre session (comme `workers.py`) ;
    l'interface, qui lit la base dans le fil principal (autre connexion), doit
    voir le constat XSS dès sa famille terminée -- alors même que la famille
    CSRF, volontairement lente, est encore en train d'exécuter (elle déclenchera
    `check_deadline`). Base fichier (WAL) : les deux connexions partagent le
    même fichier. Aucune ressource externe n'est contactée.
    """
    import threading
    import time

    db_path = tmp_path / "live.db"
    engine = get_engine(db_path)
    client = None
    try:
        init_db(engine)

        def handler(request: httpx.Request) -> httpx.Response:
            parsed = urlparse(str(request.url))
            q = parse_qs(parsed.query).get("q")
            if q:
                return httpx.Response(200, text=f"<html>hello {q[0]}</html>")
            if parsed.path in {"/", "/contact", "/login", "/register", "/signup", "/profile"}:
                time.sleep(2)
            return httpx.Response(200, text="<html>aucun formulaire</html>")

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        now = datetime.now(UTC)
        config = ScanConfig(
            target="http://127.0.0.1:1/",
            authorized=True,
            max_duration_seconds=1,
            allowed_tests=frozenset({"xss", "csrf"}),
        )
        root = RootResponse(
            status_code=200,
            headers={},
            body="<html/>",
            final_url=config.target,
            body_truncated=False,
        )

        def worker() -> None:
            with get_session(engine) as session:
                scan = Scan(
                    scan_type=ScanType.ACTIVE_SCAN,
                    source="tscan_engine",
                    target=config.target,
                    authorized=True,
                    safe_mode=False,
                    config_json=config.to_json(),
                )
                session.add(scan)
                session.flush()
                try:
                    run_active_detections(
                        session, scan, config, root, client, {}, now, pages={}
                    )
                except ScanConfigError:
                    pass  # durée maximale atteinte pendant CSRF : attendu

        scan_thread = threading.Thread(target=worker)
        scan_thread.start()

        # « L'interface » : autre connexion (fil principal) sur la même base.
        # Le rollback clôt l'instantané SQLite pour relire les derniers
        # commits du fil de scan, comme le fait la GUI avant chaque refresh.
        visible = False
        still_running_when_visible = None
        t0 = time.monotonic()
        with get_session(engine) as gui_session:
            while time.monotonic() - t0 < 5:
                gui_session.rollback()
                if (
                    gui_session.query(Finding)
                    .filter(Finding.rule_id == "RULE-XSS-001")
                    .count()
                    > 0
                ):
                    visible = True
                    still_running_when_visible = scan_thread.is_alive()
                    break
                time.sleep(0.05)

        scan_thread.join(timeout=10)
        assert visible, "le constat XSS devait déjà être visible pendant le scan"
        assert still_running_when_visible, (
            "le constat XSS devait être visible pendant le scan, pas seulement à sa fin"
        )
    finally:
        if client is not None:
            client.close()
        engine.dispose()
