"""Tests du fingerprinting passif des technologies (RF-16)."""

from __future__ import annotations

from tscan_core.recon.fingerprint import fingerprint_response, load_technologies

TECHNOLOGIES = load_technologies()


def _headers(**pairs: str) -> dict[str, str]:
    return {name.lower(): value for name, value in pairs.items()}


def test_detect_apache_with_version_from_server_header() -> None:
    matches = fingerprint_response(
        _headers(Server="Apache/2.4.53"),
        "",
        TECHNOLOGIES,
    )
    assert [m.name for m in matches] == ["apache"]
    assert matches[0].version == "2.4.53"
    assert matches[0].source == "header:Server"


def test_detect_nginx_without_version() -> None:
    matches = fingerprint_response(_headers(Server="nginx"), "", TECHNOLOGIES)
    assert matches[0].name == "nginx"
    assert matches[0].version is None


def test_header_matching_is_case_insensitive() -> None:
    matches = fingerprint_response(_headers(server="nginx/1.24.0"), "", TECHNOLOGIES)
    assert matches[0].name == "nginx"
    assert matches[0].version == "1.24.0"


def test_detect_tomcat_not_apache_on_coyote_header() -> None:
    """'Server: Apache-Coyote/1.1' est Tomcat, pas Apache : les patterns sont
    ancrés pour éviter cette confusion classique."""
    matches = fingerprint_response(_headers(Server="Apache-Coyote/1.1"), "", TECHNOLOGIES)
    assert [m.name for m in matches] == ["tomcat"]


def test_detect_wordpress_and_jquery_from_body() -> None:
    body = (
        '<meta name="generator" content="WordPress 6.4.2">'
        '<script src="/wp-content/themes/site/js/jquery-3.6.0.min.js"></script>'
    )
    matches = fingerprint_response({}, body, TECHNOLOGIES)
    names = {m.name for m in matches}
    assert {"wordpress", "jquery"} <= names

    wordpress = next(m for m in matches if m.name == "wordpress")
    assert wordpress.version == "6.4.2"
    assert wordpress.source == "body"

    jquery = next(m for m in matches if m.name == "jquery")
    assert jquery.version == "3.6.0"


def test_detect_php_from_x_powered_by() -> None:
    matches = fingerprint_response(_headers(**{"X-Powered-By": "PHP/7.4.33"}), "", TECHNOLOGIES)
    assert [m.name for m in matches] == ["php"]
    assert matches[0].version == "7.4.33"


def test_no_signature_no_detection() -> None:
    matches = fingerprint_response(
        _headers(Server="UndefinedServer/1.0"),
        "<html><body>rien ici</body></html>",
        TECHNOLOGIES,
    )
    assert matches == []


def test_one_detection_per_technology_even_with_multiple_matchers() -> None:
    body = (
        '<meta name="generator" content="WordPress 6.4.2">'
        "<script src='/wp-includes/js/jquery.min.js'></script>"
    )
    matches = fingerprint_response({}, body, TECHNOLOGIES)
    assert [m.name for m in matches].count("wordpress") == 1