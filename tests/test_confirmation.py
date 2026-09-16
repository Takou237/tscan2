"""Tests du bloc confirmation active non destructive (RF-23, semaines 9 et 11).

Vérifie que, à l'issue d'un scan actif, les constats reproductibles sont
renforcés (score plafonné à 0,85) mais restent au statut ``Probable`` : le
moteur ne confirme jamais — « Confirmée » est un verdict d'analyste (RF-12,
correctif de la semaine 11). Un fait contredit place le constat en
``Potentiel faux positif`` ; une sonde de re-vérification en échec laisse le
constat au statut ``Probable`` (jamais dégradé sur un problème réseau, ES-05).

La cible utilisée est le serveur de laboratoire local (fixture ``lab_server``) :
aucune ressource externe n'est contactée (ES-09).
"""

from __future__ import annotations

import json

import httpx

from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus, Scan
from tscan_core.rule_engine.loader import load_rules
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.orchestrator import run_recon_scan
from tscan_core.status import AUTOMATIC_ACTOR

ALL_FAMILIES = frozenset(
    {
        "recon",
        "fingerprint",
        "headers",
        "clickjacking",
        "bac",
        "xss",
        "csrf",
        "sqli",
        "sensitive-files",
        "directory-listing",
        "cors",
    }
)


def _config(lab_server, **overrides) -> ScanConfig:
    defaults = {
        "target": f"{lab_server.base_url}/",
        "authorized": True,
        "max_duration_seconds": 60,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def test_confirmation_reinforces_reproduced_findings_without_confirming(lab_server) -> None:
    """Sur le laboratoire, chaque constat attendu est reproductible : tous les
    constats du scan actif restent ``Probable`` avec un score renforcé
    (plafonné à 0,85), une preuve de re-vérification, et aucun ``StatusHistory``
    (le statut n'a pas changé : le moteur ne confirme jamais, RF-12)."""
    engine = get_engine(":memory:")
    init_db(engine)

    rules = {rule.id: rule for rule in load_rules()}

    with get_session(engine) as session:
        outcome = run_recon_scan(session, _config(lab_server, allowed_tests=ALL_FAMILIES))
        scan = session.get(Scan, outcome.scan_id)
        observations = json.loads(scan.recon_json)

        findings = session.query(Finding).all()
        assert len(findings) == 18  # en-têtes (6) + clickjacking (1) + BAC (1) + S8 (10)

        for finding in findings:
            # Le moteur ajuste la confiance mais ne confirme jamais (RF-12).
            assert finding.status == FindingStatus.PROBABLE
            base = rules[finding.rule_id].confidence_base
            assert finding.confidence_score == round(min(0.85, base + 0.10), 2)
            # Une preuve de re-vérification est ajoutée (en plus de la preuve initiale).
            assert finding.evidences
            assert any("Re-vérification" in e.content_text for e in finding.evidences)
            # Aucun changement de statut : pas de StatusHistory créée par le moteur.
            assert len(finding.status_history) == 0

        # Les compteurs d'observations (recon_json) reflètent les faits reproduits.
        assert observations["reproduced"] == 18
        assert "potential_false_positives" not in observations
        assert "probe_errors" not in observations
        assert outcome.reproduced == 18


def test_confirmation_contradicted_fact_flags_potential_false_positive(lab_server) -> None:
    """Un faux positif DÉTECTÉ par le scanner : la route /admin/ est exposée à
    la détection (200) mais ne l'est plus à la re-vérification (404). Comme la
    famille BAC est à re-vérification précise, le constat est placé en
    Potentiel faux positif pour revue analytique prioritaire (RF-23)."""
    engine = get_engine(":memory:")
    init_db(engine)

    calls = {"/admin/": 0}

    def flapping_network(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/":
            calls["/admin/"] += 1
            if calls["/admin/"] == 1:
                return httpx.Response(200, text="<html><body>admin</body></html>")
            return httpx.Response(404, text="<html><body>Non trouvé</body></html>")
        if request.url.path.startswith("/config/") or request.url.path == "/wp-admin/":
            return httpx.Response(404, text="")
        return httpx.Response(200, text="<html><body>ok</body></html>")

    client = httpx.Client(transport=httpx.MockTransport(flapping_network), follow_redirects=True)
    try:
        with get_session(engine) as session:
            outcome = run_recon_scan(
                session,
                _config(lab_server, allowed_tests=frozenset({"recon", "bac"})),
                http_client=client,
            )
            scan = session.get(Scan, outcome.scan_id)
            observations = json.loads(scan.recon_json)

            finding = session.query(Finding).one()
            assert finding.rule_id == "RULE-BAC-001"
            # Le fait décisif contredit -> Potentiel faux positif, score réduit.
            assert finding.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert finding.confidence_score == 0.50  # 0,65 - 0,15 (plancher 0,30)
            # La décision automatique est tracée (ES-06) pour revue humaine.
            assert finding.status_history[-1].new_status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert finding.status_history[-1].changed_by == AUTOMATIC_ACTOR
            assert any(
                "contradictoire" in e.content_text and "Re-vérification" in e.content_text
                for e in finding.evidences
            )

            assert observations["potential_false_positives"] == 1
            assert "reproduced" not in observations
            assert outcome.potential_false_positives == 1
    finally:
        client.close()


def test_confirmation_probe_failure_keeps_finding_probable(lab_server) -> None:
    """Une sonde de re-vérification qui échoue sur le réseau ne doit pas
    dégrader le constat : la détection initiale de la route /admin/ reste au
    statut ``Probable``, et l'échec est tracé dans les observations (ES-05)."""
    engine = get_engine(":memory:")
    init_db(engine)

    calls = {"/admin/": 0}

    def flaky_network(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/":
            calls["/admin/"] += 1
            if calls["/admin/"] > 1:
                raise httpx.ConnectError("sonde de re-vérification bloquée")
            return httpx.Response(200, text="<html><body>admin</body></html>")
        if request.url.path.startswith("/config/") or request.url.path == "/wp-admin/":
            return httpx.Response(404, text="")
        return httpx.Response(200, text="<html><body>ok</body></html>")

    client = httpx.Client(transport=httpx.MockTransport(flaky_network), follow_redirects=True)
    try:
        with get_session(engine) as session:
            outcome = run_recon_scan(
                session,
                _config(lab_server, allowed_tests=frozenset({"recon", "bac"})),
                http_client=client,
            )
            scan = session.get(Scan, outcome.scan_id)
            observations = json.loads(scan.recon_json)

            finding = session.query(Finding).one()
            assert finding.rule_id == "RULE-BAC-001"
            assert finding.matched_at.rstrip("/").endswith("/admin")
            assert finding.status == FindingStatus.PROBABLE
            assert "confirmations" in observations
            assert any("bloquée" in v for v in observations["confirmations"].values())
            assert observations["probe_errors"] == 1
            assert "reproduced" not in observations  # aucun constat reproduit
    finally:
        client.close()


def test_confirmation_is_idempotent_on_second_scan(lab_server) -> None:
    """Lancer le scan deux fois de suite ne doit produire aucune erreur : la
    re-vérification peut jouer sur chaque scan indépendamment."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        first = run_recon_scan(
            session, _config(lab_server, allowed_tests=frozenset({"recon", "bac"}))
        )
        second = run_recon_scan(
            session, _config(lab_server, allowed_tests=frozenset({"recon", "bac"}))
        )

        findings = session.query(Finding).all()
        assert len(findings) == 2
        assert [f.scan_id for f in findings] == [first.scan_id, second.scan_id]
        assert all(f.status == FindingStatus.PROBABLE for f in findings)


def test_confirmation_xss_contradiction_flags_potential_false_positive(lab_server) -> None:
    """Ré-observation précise d'une détection en CODE (XSS) : la charge qui a
    produit le constat (réflexion du nonce) ne se reproduit plus lors de la
    re-vérification -> le constat est placé en Potentiel faux positif (RF-23)."""
    engine = get_engine(":memory:")
    init_db(engine)

    counts = {"reflection": 0}

    from urllib.parse import parse_qs, urlparse

    def flapping_xss(request: httpx.Request) -> httpx.Response:
        qs = parse_qs(urlparse(str(request.url)).query)
        if "q" in qs and "data-tscan-xss=" in qs["q"][0]:
            counts["reflection"] += 1
            if counts["reflection"] == 1:
                return httpx.Response(200, text=f'<html><body>{qs["q"][0]}</body></html>')
            return httpx.Response(200, text="<html><body>reflété (échappé)</body></html>")
        if request.url.path.startswith("/config/") or request.url.path == "/wp-admin/":
            return httpx.Response(404, text="")
        if request.url.path == "/admin/":
            return httpx.Response(404, text="")
        return httpx.Response(200, text="<html><body>ok</body></html>")

    client = httpx.Client(transport=httpx.MockTransport(flapping_xss), follow_redirects=True)
    try:
        with get_session(engine) as session:
            outcome = run_recon_scan(
                session,
                _config(lab_server, allowed_tests=frozenset({"recon", "xss"})),
                http_client=client,
            )
            scan = session.get(Scan, outcome.scan_id)
            observations = json.loads(scan.recon_json)

            xss = [f for f in session.query(Finding).all() if f.rule_id == "RULE-XSS-001"]
            assert len(xss) == 1
            # Le probe_info (charge rejouable) a bien été persisté.
            assert xss[0].probe_json is not None
            assert json.loads(xss[0].probe_json)["signal_type"] == "body_contains"

            # La réflexion ne se reproduit pas -> Potentiel faux positif.
            assert xss[0].status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert observations["potential_false_positives"] == 1
            assert outcome.potential_false_positives == 1
    finally:
        client.close()
