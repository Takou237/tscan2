"""Tests du périmètre et des limites d'un scan actif (RF-24, ES-01 à ES-03)."""

from __future__ import annotations

import json

import pytest

from tscan_core.scan.config import (
    DEFAULT_ALLOWED_TESTS,
    TEST_TYPES,
    ScanConfig,
    ScanConfigError,
    validate_target,
)


def test_validate_target_accepts_http_and_https() -> None:
    assert validate_target("https://example.test").startswith("https://example.test")
    assert validate_target("http://127.0.0.1:8080").startswith("http://127.0.0.1:8080")


def test_validate_target_normalizes_host_and_path() -> None:
    assert validate_target("HTTPS://Example.Test") == "https://example.test/"
    assert validate_target("https://example.test:8443/some/path") == (
        "https://example.test:8443/some/path"
    )


def test_validate_target_rejects_unknown_scheme() -> None:
    with pytest.raises(ScanConfigError, match="http"):
        validate_target("ftp://example.test")


def test_validate_target_rejects_empty_and_hostless() -> None:
    with pytest.raises(ScanConfigError):
        validate_target("  ")
    with pytest.raises(ScanConfigError):
        validate_target("https://")


def test_scan_config_rejects_missing_authorization_by_default() -> None:
    config = ScanConfig(target="https://example.test", authorized=False)
    assert config.authorized is False  # ES-01 : vérifié par l'orchestrateur


def test_scan_config_safe_mode_default_on() -> None:
    config = ScanConfig(target="https://example.test", authorized=True)
    assert config.safe_mode is True  # ES-03


def test_scan_config_rejects_invalid_limits() -> None:
    with pytest.raises(ScanConfigError):
        ScanConfig(target="https://example.test", authorized=True, max_depth=0)
    with pytest.raises(ScanConfigError):
        ScanConfig(target="https://example.test", authorized=True, max_duration_seconds=0)


def test_scan_config_rejects_unknown_test_types() -> None:
    with pytest.raises(ScanConfigError, match="inconnus"):
        ScanConfig(
            target="https://example.test",
            authorized=True,
            allowed_tests=frozenset({"recon", "désérialisation"}),
        )


def test_scan_config_known_test_types_cover_week7_families() -> None:
    """Les noms des familles de détection des semaines 7-8 sont déjà
    déclarés, pour que la CLI les accepte dès leur implémentation."""
    assert {"recon", "fingerprint", "headers", "clickjacking", "bac", "components"} <= TEST_TYPES


def test_scan_config_default_allowed_tests() -> None:
    """Par défaut, un scan lance TOUTES les familles de détection non
    destructives (pas seulement reconnaissance + fingerprinting), pour que
    l'utilisateur obtienne réellement des résultats de sécurité, tout en
    restant encadré par le mode sécurisé GET-only (ES-03)."""
    assert DEFAULT_ALLOWED_TESTS == frozenset(TEST_TYPES)
    # Les familles qui produisent des constats de sécurité sont bien incluses.
    assert {
        "headers",
        "clickjacking",
        "bac",
        "components",
        "xss",
        "csrf",
        "sqli",
        "sensitive-files",
        "directory-listing",
        "cors",
        "tls",
    } <= DEFAULT_ALLOWED_TESTS


def test_scan_config_derives_hostname_and_port() -> None:
    config = ScanConfig(target="https://example.test:8443", authorized=True)
    assert config.hostname == "example.test"
    assert config.port == 8443
    assert ScanConfig(target="https://example.test", authorized=True).port == 443
    assert ScanConfig(target="http://example.test", authorized=True).port == 80


def test_scan_config_to_json_records_perimeter() -> None:
    config = ScanConfig(
        target="https://example.test",
        authorized=True,
        max_depth=3,
        max_duration_seconds=120,
        allowed_tests=frozenset({"recon", "fingerprint"}),
    )
    payload = json.loads(config.to_json())
    assert payload["target"] == "https://example.test/"
    assert payload["authorized"] is True
    assert payload["max_depth"] == 3
    assert payload["max_duration_seconds"] == 120
    assert payload["allowed_tests"] == ["fingerprint", "recon"]
    assert payload["safe_mode"] is True