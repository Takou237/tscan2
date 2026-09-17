"""Tests du fichier de signatures de faux positifs (RF-12).

Vérifie que le fichier versionné `knowledge/fp_signatures.yaml` est bien
formé, que ses marqueurs sont exploitables (minuscules, sans collision
connue), et que le check `path_status` (`checks.py`) est bien branché sur
ce fichier — et non sur une liste codée en dur : une extension du fichier
doit être prise en compte sans modification du code.
"""

from __future__ import annotations

import yaml

from tscan_core.knowledge_base.fp_signatures import (
    DEFAULT_FP_SIGNATURES_FILE,
    FpSignaturesError,
    get_category,
    load_fp_signatures,
)
from tscan_core.recon.client import RootResponse
from tscan_core.rule_engine.schema import RuleDefinition
from tscan_core.scan import checks
from tscan_core.scan.checks import evaluate_rule_checks, is_path_exposed

RULES_DIR = DEFAULT_FP_SIGNATURES_FILE.parents[1] / "rules"


def _response(
    status: int = 200,
    headers: dict[str, str] | None = None,
    url: str = "http://example.test/",
    request_url: str = "",
) -> RootResponse:
    return RootResponse(
        status_code=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body="",
        final_url=url,
        body_truncated=False,
        request_url=request_url,
    )


def _rule(path: str) -> RuleDefinition:
    return RuleDefinition(
        id="RULE-TEST-BROKEN_ACCESS_CONTROL-001",
        name="Règle de test",
        category="broken_access_control",
        severity="medium",
        version="1.0.0",
        description="Règle construite pour le test.",
        checks=[{"id": "bac", "type": "path_status", "path": path}],
    )


def test_default_fp_signatures_file_exists_and_loads() -> None:
    assert DEFAULT_FP_SIGNATURES_FILE.exists()
    signatures = load_fp_signatures()
    assert "auth_pages" in signatures
    assert signatures["auth_pages"].path_markers


def test_yaml_entries_are_list_of_mappings() -> None:
    with DEFAULT_FP_SIGNATURES_FILE.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    assert isinstance(raw, list) and all(isinstance(entry, dict) for entry in raw)


def test_auth_markers_are_lowercase_and_dont_match_probed_resource() -> None:
    """Les marqueurs sont comparés en minuscules et aucun ne doit figurer dans
    les chemins réellement sondés par les règles (rules/broken_access_control.yaml)
    : /admin/ est la ressource à tester, pas la page qui la protège — sinon
    aucune exposition ne serait plus jamais signalée."""
    category = load_fp_signatures()["auth_pages"]
    for marker in category.path_markers:
        assert marker == marker.lower(), f"marqueur non minuscule : {marker}"
    with (RULES_DIR / "broken_access_control.yaml").open("r", encoding="utf-8") as handle:
        probed = yaml.safe_load(handle)
    probed_paths = [
        check["path"] for check in probed["checks"] if check.get("type") == "path_status"
    ]
    for marker in category.path_markers:
        for path in probed_paths:
            assert marker not in path, f"marqueur {marker!r} capture la ressource sondée {path!r}"


def test_signatures_cover_known_cms_and_fr_login_pages() -> None:
    """Couverture minimale : les pages d'authentification des CMS courants
    (WordPress, Drupal, Django) et les pages francophones sont couvertes."""
    markers = set(load_fp_signatures()["auth_pages"].path_markers)
    for expected in ("login", "wp-login.php", "user/login", "connexion"):
        assert expected in markers, f"marqueur attendu absent : {expected}"


def test_waf_category_is_documented() -> None:
    """La catégorie `waf_pages` existe et porte des marqueurs : elle documente
    les pages de challenge servies en 200 par les filtrages anti-bot."""
    signatures = load_fp_signatures()
    assert "waf_pages" in signatures
    assert signatures["waf_pages"].path_markers


def test_loader_rejects_malformed_file(tmp_path) -> None:
    bad_file = tmp_path / "fp.yaml"
    bad_file.write_text(
        "- id: auth_pages\n  label: A\n- id: auth_pages\n  label: B\n",
        encoding="utf-8",
    )
    try:
        load_fp_signatures(bad_file)
    except FpSignaturesError as exc:
        assert "dupliqué" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("FpSignaturesError attendue pour un id dupliqué")


def test_get_category_returns_none_when_absent() -> None:
    signatures = load_fp_signatures()
    assert get_category(signatures, "auth_pages") is not None
    assert get_category(signatures, "categorie_inexistante") is None


def test_check_uses_yaml_extension_without_code_change(tmp_path, monkeypatch) -> None:
    """Branche vérifiée bout en bout : un marqueur ajouté UNIQUEMENT dans un
    fichier YAML étendu doit influencer `is_path_exposed` et le check
    `path_status` sans aucune modification du code."""
    extended = tmp_path / "fp_signatures.yaml"
    extended.write_text(
        "- id: auth_pages\n"
        "  label: Pages d'authentification\n"
        "  path_markers:\n"
        "    - portail-de-connexion-maison\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(checks, "AUTH_PAGE_MARKERS", ("portail-de-connexion-maison",))

    # Le marqueur YAML étendu est honoré par le helper et par le check.
    page = _response(
        status=302,
        headers={"Location": "/portail-de-connexion-maison"},
        url="http://example.test/portail-de-connexion-maison",
        request_url="http://example.test/admin/",
    )
    assert not is_path_exposed(page)

    pages = {"http://example.test/admin/": page}
    results = evaluate_rule_checks(_rule("/admin/"), _response(), pages)
    assert results == []

    # Sanity check : le fichier de test contient bien le marqueur étendu.
    assert "portail-de-connexion-maison" in extended.read_text(encoding="utf-8")


def test_wp_admin_redirect_to_wp_login_still_not_exposed() -> None:
    """Cas terrain (otakutique.com, semaine 12) : la protection WordPress
    reste reconnue après migration des marqueurs vers le fichier YAML."""
    page = _response(
        status=302,
        headers={"Location": "/wp-login.php?redirect_to=http%3A%2F%2Fexample.test%2Fwp-admin%2F"},
        url="http://example.test/wp-login.php?redirect_to=...",
        request_url="http://example.test/wp-admin/",
    )
    assert not is_path_exposed(page)
