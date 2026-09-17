"""Tests du moteur de checks déclaratifs (semaine 7b, RF-17, RF-20).

Les cas sont construits sur des règles minimales en mémoire (la charge des
fichiers YAML réels est couverte par test_rule_engine) et des réponses HTTP
simulées via `RootResponse`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tscan_core.recon.client import RootResponse
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.scan.checks import (
    CheckError,
    evaluate_rule_checks,
    is_path_exposed,
    validate_rule_checks,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _rule(checks: list[dict], category: str = "security_misconfiguration") -> RuleDefinition:
    return RuleDefinition(
        id=f"RULE-TEST-{category.upper()}-001",
        name="Règle de test",
        category=category,
        severity="medium",
        version="1.0.0",
        description="Règle construite pour le test.",
        checks=checks,
    )


def _response(
    status: int = 200,
    headers: dict[str, str] | None = None,
    url: str = "http://example.test/",
    request_url: str = "",
    body: str = "",
) -> RootResponse:
    return RootResponse(
        status_code=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        final_url=url,
        body_truncated=False,
        request_url=request_url,
    )


def test_header_absent_reports_missing_header() -> None:
    rule = _rule([{"id": "hsts", "type": "header_absent", "header": "Strict-Transport-Security"}])
    results = evaluate_rule_checks(rule, _response(headers={"Server": "nginx"}))

    assert len(results) == 1
    result = results[0]
    assert result.rule_id == rule.id
    assert result.severity == "medium"  # héritée de la règle
    assert "Strict-Transport-Security" in result.evidence_text
    assert result.matched_url == "http://example.test/"


def test_header_absent_silent_when_header_present() -> None:
    rule = _rule([{"id": "hsts", "type": "header_absent", "header": "Strict-Transport-Security"}])
    results = evaluate_rule_checks(
        rule, _response(headers={"Strict-Transport-Security": "max-age=31536000"})
    )

    assert results == []


def test_header_absent_is_case_insensitive() -> None:
    rule = _rule([{"id": "hsts", "type": "header_absent", "header": "strict-transport-security"}])
    results = evaluate_rule_checks(rule, _response(headers={"Strict-Transport-Security": "max-age=1"}))

    assert results == []


def test_clickjacking_reported_without_any_protection() -> None:
    rule = _rule([{"id": "cj", "type": "clickjacking"}])
    results = evaluate_rule_checks(rule, _response(headers={"Server": "nginx"}))

    assert len(results) == 1
    assert "X-Frame-Options" in results[0].evidence_text


def test_clickjacking_silent_with_x_frame_options() -> None:
    rule = _rule([{"id": "cj", "type": "clickjacking"}])
    results = evaluate_rule_checks(rule, _response(headers={"X-Frame-Options": "DENY"}))

    assert results == []


def test_clickjacking_silent_with_csp_frame_ancestors() -> None:
    rule = _rule([{"id": "cj", "type": "clickjacking"}])
    results = evaluate_rule_checks(
        rule,
        _response(headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"}),
    )

    assert results == []


def test_clickjacking_reported_with_csp_without_frame_ancestors() -> None:
    rule = _rule([{"id": "cj", "type": "clickjacking"}])
    results = evaluate_rule_checks(
        rule,
        _response(headers={"Content-Security-Policy": "default-src 'self'"}),
    )

    assert len(results) == 1


def test_path_status_reports_exposed_route() -> None:
    rule = _rule([{"id": "bac", "type": "path_status", "path": "/admin/"}], "broken_access_control")
    pages = {"/admin/": _response(status=200, url="http://example.test/admin/")}
    results = evaluate_rule_checks(rule, _response(), pages)

    assert len(results) == 1
    assert "200" in results[0].evidence_text
    assert results[0].severity == "medium"


def test_path_status_silent_when_redirect_targets_login_page() -> None:
    """WordPress répond 302 /wp-admin/ -> /wp-login.php pour PROTÉGER le
    panneau : une redirection vers une page d'authentification n'est pas une
    exposition (faux positif historique du check, corrigé semaine 12)."""
    rule = _rule(
        [{"id": "bac", "type": "path_status", "path": "/wp-admin/"}],
        "broken_access_control",
    )
    pages = {
        "/wp-admin/": _response(
            status=302,
            headers={"Location": "/wp-login.php?redirect_to=http%3A%2F%2Fexample.test%2Fwp-admin%2F"},
            url="http://example.test/wp-login.php?redirect_to=...",
            request_url="http://example.test/wp-admin/",
        )
    }
    results = evaluate_rule_checks(rule, _response(), pages)

    assert results == []


def test_path_status_silent_when_redirect_chain_lands_on_login() -> None:
    """Redirections déjà suivies par le client HTTP : la sonde reçoit un 200,
    mais c'est celui de la page de login, pas celui du panneau. Le check
    compare la ressource finale à la ressource demandée."""
    rule = _rule(
        [{"id": "bac", "type": "path_status", "path": "/admin/"}],
        "broken_access_control",
    )
    pages = {
        "/admin/": _response(
            status=200,
            url="http://example.test/login",
            request_url="http://example.test/admin/",
        )
    }
    results = evaluate_rule_checks(rule, _response(), pages)

    assert results == []


def test_path_status_reports_redirect_to_non_auth_resource() -> None:
    """Une redirection vers une ressource quelconque (pas une page de login)
    reste indicative d'exposition : comportement historique conservé."""
    rule = _rule(
        [{"id": "bac", "type": "path_status", "path": "/admin/"}],
        "broken_access_control",
    )
    pages = {
        "/admin/": _response(
            status=302,
            headers={"Location": "/dashboard"},
            url="http://example.test/dashboard",
            request_url="http://example.test/admin/",
        )
    }
    results = evaluate_rule_checks(rule, _response(), pages)

    assert len(results) == 1


def test_path_status_silent_when_protected() -> None:
    rule = _rule([{"id": "bac", "type": "path_status", "path": "/admin/"}], "broken_access_control")
    pages = {"/admin/": _response(status=403, url="http://example.test/admin/")}
    results = evaluate_rule_checks(rule, _response(), pages)

    assert results == []


def test_path_status_without_probe_is_silent() -> None:
    """Sonde non effectuée (échec réseau tracé par l'orchestrateur) : aucun
    constat ni erreur -- l'absence d'information n'est pas un constat."""
    rule = _rule([{"id": "bac", "type": "path_status", "path": "/admin/"}], "broken_access_control")
    results = evaluate_rule_checks(rule, _response())

    assert results == []


def test_is_path_exposed_soft404_calibration_blocks_finding() -> None:
    """Soft-404 : la cible répond 200 avec une page générique pour tout chemin.
    La sonde /admin/ (200) et la sentinelle (200, corps quasi identique) sont
    indiscernables → pas de constat (le statut ne prouve rien)."""
    body = "<html><body><h1>Bienvenue sur le site</h1></body></html>"
    probe = _response(
        status=200,
        url="http://example.test/admin/",
        request_url="http://example.test/admin/",
        body=body,
    )
    calibration = _response(status=200, url="http://example.test/tscan-calib-abc123", body=body)
    assert not is_path_exposed(probe, calibration, "abc123")


def test_is_path_exposed_distinct_body_not_blocked_by_calibration() -> None:
    """200 réel sur /admin/ : le corps du panneau diffère totalement de la
    sentinelle → le constat reste produit (la sentinelle ne masque rien)."""
    probe = _response(
        status=200,
        url="http://example.test/admin/",
        request_url="http://example.test/admin/",
        body="<html><body><h1>Panneau d'administration</h1><table><tr><td>Utilisateurs</td></tr></table></body></html>",
    )
    calibration = _response(
        status=404,
        url="http://example.test/tscan-calib-abc123",
        body="<html><body>404 introuvable</body></html>",
    )
    assert is_path_exposed(probe, calibration, "abc123")


def test_is_path_exposed_reflection_gap_blocks_finding() -> None:
    """Soft-404 réfléchissant : la page du contrôle contient le jeton du
    chemin-sentinelle (« introuvable tscan-calib-abc123 ») mais pas la sonde
    → le serveur fabrique des pages à la demande → pas de constat."""
    probe = _response(
        status=200,
        url="http://example.test/admin/",
        request_url="http://example.test/admin/",
        body="<html><body><h1>Accueil</h1><p>Contenu propre au site</p></body></html>",
    )
    calibration = _response(
        status=200,
        url="http://example.test/tscan-calib-abc123def456",
        body="<html><body><p>La page tscan-calib-abc123def456 n'existe pas</p></body></html>",
    )
    assert not is_path_exposed(probe, calibration, "abc123def456")


def test_is_path_exposed_without_calibration_keeps_status_only_verdict() -> None:
    """Sentinelle indisponible (échec réseau) : comportement historique —
    le statut seul décide, aucun constat n'est masqué."""
    probe = _response(
        status=200,
        url="http://example.test/admin/",
        request_url="http://example.test/admin/",
        body="<html><body>Panneau</body></html>",
    )
    assert is_path_exposed(probe, None, None)


def test_path_status_silent_on_soft404_target_end_to_end() -> None:
    """Bout en bout : sur une cible à soft-404 (200 générique partout), le
    check `path_status` ne produit AUCUN constat malgré un 200 sur /admin/."""
    generic = "<html><body><h1>Bienvenue</h1><p>page generique</p></body></html>"
    rule = _rule(
        [{"id": "bac", "type": "path_status", "path": "/admin/"}],
        "broken_access_control",
    )
    pages = {
        "/admin/": _response(
            status=200,
            url="http://example.test/admin/",
            request_url="http://example.test/admin/",
            body=generic,
        )
    }
    calibration = _response(status=200, url="http://example.test/tscan-calib-x9y8z7", body=generic)
    results = evaluate_rule_checks(rule, _response(), pages, calibration, "x9y8z7")
    assert results == []


def test_unknown_check_type_raises() -> None:
    rule = _rule([{"id": "zombie", "type": "deserialisation"}])
    with pytest.raises(CheckError, match="deserialisation"):
        validate_rule_checks(rule)


def test_malformed_checks_raise_during_validation() -> None:
    assert pytest.raises(CheckError, validate_rule_checks, _rule([{"id": "x", "type": "header_absent"}]))

    bad_path = _rule([{"id": "x", "type": "path_status", "path": "admin/"}], "broken_access_control")
    with pytest.raises(CheckError, match="path_status"):
        validate_rule_checks(bad_path)


def test_real_rule_files_pass_validation() -> None:
    """Les fichiers de règles du dépôt doivent passer la validation stricte."""
    from tscan_core.rule_engine.loader import load_rules

    rules = load_rules(RULES_DIR)
    for rule in rules:
        if rule.checks:
            validate_rule_checks(rule)
