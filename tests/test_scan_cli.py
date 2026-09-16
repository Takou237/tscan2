"""Tests de la commande CLI `scan` (RF-31, ES-01).

Utilise `typer.testing.CliRunner` : première suite de tests de la CLI elle-
même, sur la commande la plus sensible du point de vue sécurité.
"""

from __future__ import annotations

from typer.testing import CliRunner

from tscan_cli.main import app

runner = CliRunner()


def _error_output(result) -> str:
    # Typer redirige les messages d'erreur vers stderr, que CliRunner
    # sépare de stdout selon la version de Click : cumuler les deux rend
    # les assertions robustes quel que soit le comportement.
    return f"{result.stdout}{result.stderr}"


def test_scan_without_authorization_is_refused(lab_server) -> None:
    result = runner.invoke(app, ["scan", f"{lab_server.base_url}/"])
    assert result.exit_code == 1
    assert "ES-01" in _error_output(result)


def test_scan_with_authorization_succeeds(lab_server) -> None:
    result = runner.invoke(
        app,
        ["scan", f"{lab_server.base_url}/", "--authorized", "--max-duration", "30"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Scan actif #" in result.stdout
    assert "Technologies détectées" in result.stdout
    assert "Apache HTTP Server 2.4.53" in result.stdout
    assert "WordPress 6.4.2" in result.stdout


def test_scan_with_invalid_target_is_rejected(lab_server) -> None:
    result = runner.invoke(
        app,
        ["scan", "ftp://example.test", "--authorized"],
    )
    assert result.exit_code == 1
    assert "Schéma" in _error_output(result)


def test_scan_with_unknown_test_type_is_rejected(lab_server) -> None:
    result = runner.invoke(
        app,
        ["scan", f"{lab_server.base_url}/", "--authorized", "--tests", "recon,deserialisation"],
    )
    assert result.exit_code == 1
    assert "inconnus" in _error_output(result)


def test_scan_reports_declarative_findings(lab_server) -> None:
    """7b : la sortie CLI liste les constats de sécurité (en-têtes, clickjacking,
    BAC) avec leur sévérité, triés des plus critiques aux plus faibles."""
    result = runner.invoke(
        app,
        [
            "scan",
            f"{lab_server.base_url}/",
            "--authorized",
            "--max-duration",
            "30",
            "--tests",
            "recon,fingerprint,headers,clickjacking,bac",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "Résultats de sécurité (8)" in result.stdout
    assert "[medium]" in result.stdout  # clickjacking
    assert "[info]" in result.stdout  # en-têtes manquants
    assert "/admin/" in result.stdout  # constat BAC
    medium_index = result.stdout.index("[medium]")
    info_index = result.stdout.index("[info]")
    assert medium_index < info_index  # sévérité decroissante dans l'affichage


def test_scan_reports_active_detection_findings(lab_server) -> None:
    """8 : la sortie CLI liste les constats des détections actives (XSS, CSRF,
    SQLi, fichiers sensibles, listing, CORS) pour un périmètre complet."""
    result = runner.invoke(
        app,
        [
            "scan",
            f"{lab_server.base_url}/",
            "--authorized",
            "--max-duration",
            "60",
            "--tests",
            "recon,headers,clickjacking,bac,xss,csrf,sqli,sensitive-files,directory-listing,cors",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "Résultats de sécurité (18)" in result.stdout
    for needle in (
        "XSS réfléchi potentiel",
        "Formulaire POST sans jeton anti-CSRF",
        "Erreur SQL exposée : injection SQL error-based probable",
        "Fichier sensible exposé",
        "Listing de répertoire exposé",
        "Configuration CORS permissive",
        "/admin/",
    ):
        assert needle in result.stdout, needle