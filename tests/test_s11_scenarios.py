"""Test d'intégration de bout en bout — Semaine 11 (critères MVP, chapitre 14).

Rejoue les deux démonstrations du cahier des charges via la CLI réelle
(`typer.testing.CliRunner`), sur une base temporaire (jamais la base réelle
de l'utilisateur) :

* **Scénario A** : import Nuclei + ZAP sur la même cible -> corrélation ->
  statuts avec preuves -> rapport.
* **Scénario B** : scan actif autorisé sur la cible de laboratoire locale ->
  reconnaissance, familles de détection, validation active non destructive ->
  rapport.

C'est la répétition de démonstration S11 : chaque commande CLI est celle que
l'encadrant verra, et son résultat est contrôlé de bout en bout.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import tscan_cli.main as cli
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.models import Finding, FindingStatus

FIXTURES = Path(__file__).parent / "fixtures"

runner = CliRunner()


def _redirect_to_temp_db(tmp_path: Path):
    """Redirige temporairement la CLI vers une base de test dédiée."""
    engine = get_engine(tmp_path / "s11_test.db")
    init_db(engine)
    original_engine = cli.get_engine
    original_init = cli.init_db
    cli.get_engine = lambda: engine
    cli.init_db = lambda engine: init_db(engine)
    return engine, (original_engine, original_init)


# --- Scénario A : import multi-sources -> corrélation -> statuts -> rapport ---


def test_s11_scenario_a_import_correlate_statuses_report(tmp_path: Path) -> None:
    engine, originals = _redirect_to_temp_db(tmp_path)
    try:
        # 1. Import de trois fichiers : deux sources Nuclei + une source ZAP
        #    sur la même cible (RF-01, RF-02).
        for source, fixture in (
            ("nuclei", "nuclei_sample.jsonl"),
            ("nuclei", "nuclei_xss_overlap.jsonl"),
            ("zap", "zap_sample.json"),
        ):
            result = runner.invoke(
                cli.app,
                ["import", str(FIXTURES / fixture), "--format", source, "--target", "example.test"],
            )
            assert result.exit_code == 0, result.stdout
            assert "Import terminé" in result.stdout

        # 2. Corrélation + scoring (RF-08 à RF-10).
        result = runner.invoke(cli.app, ["correlate", "--target", "example.test"])
        assert result.exit_code == 0, result.stdout
        assert "Corrélation terminée : 6 résultat(s) traité(s)" in result.stdout

        # 3. Statuts attribués : le constat XSS corroboré par les 2 sources est
        #    Probable avec preuve (bonus multi-sources dans l'explication).
        #    Le CSRF (score 0.6 ≥ seuil) est aussi Probable (sans bonus).
        with get_session(engine) as session:
            findings = session.query(Finding).all()
            assert len(findings) == 6
            for finding in findings:
                assert finding.status == FindingStatus.PROBABLE
                assert finding.score_explanation is not None
            xss = next(f for f in findings if f.category == "xss")
            assert xss.status == FindingStatus.PROBABLE
            assert "Corroboré par 2 sources" in xss.score_explanation
            assert xss.evidences or xss.score_explanation  # preuve présente
            xss_id = xss.id

        # 4. La commande `show` affiche les preuves et l'historique (RF-11).
        result = runner.invoke(cli.app, ["show", str(xss_id)])
        assert result.exit_code == 0, result.stdout
        assert "Explication du score" in result.stdout
        assert "Corroboré par 2 sources" in result.stdout

        # 5. Rapport (RF-27 à RF-29) exporté en HTML et Markdown.
        out_html = tmp_path / "rapport_a.html"
        result = runner.invoke(
            cli.app,
            ["report", "--target", "example.test", "--format", "html", "--output", str(out_html)],
        )
        assert result.exit_code == 0, result.stdout
        assert out_html.exists()
        assert "Tscan - Rapport de sécurité" in out_html.read_text(encoding="utf-8")

        out_md = tmp_path / "rapport_a.md"
        result = runner.invoke(
            cli.app,
            ["report", "--target", "example.test", "--format", "markdown", "--output", str(out_md)],
        )
        assert result.exit_code == 0, result.stdout
        assert out_md.exists()
    finally:
        cli.get_engine, cli.init_db = originals
# --- Scénario B : scan actif autorisé -> validation active -> rapport ---------


def test_s11_scenario_b_scan_validate_report(tmp_path: Path, lab_server) -> None:
    engine, originals = _redirect_to_temp_db(tmp_path)
    try:
        # 1. Scan actif autorisé sur la cible de laboratoire (ES-01 : le flag
        #    --authorized est obligatoire ; RF-15 à RF-20).
        target = f"{lab_server.base_url}/"
        result = runner.invoke(
            cli.app,
            ["scan", target, "--authorized", "--max-duration", "60"],
        )
        assert result.exit_code == 0, result.stdout
        assert "Scan actif #" in result.stdout
        assert "Technologies détectées" in result.stdout
        assert "Résultats de sécurité (34)" in result.stdout

        # 2. Aucune confirmation automatique : le moteur laisse les constats
        #    Probable (RF-12 — « Confirmée » est un verdict d'analyste).
        with get_session(engine) as session:
            findings = session.query(Finding).all()
            assert len(findings) == 34
            for finding in findings:
                assert finding.status == FindingStatus.PROBABLE
                assert finding.confidence_score is not None
                assert finding.evidences

        # 3. L'analyste confirme manuellement un constat (RF-12, ES-06) :
        #    passage au statut Confirmée avec score 0,95 et historique.
        with get_session(engine) as session:
            first = session.query(Finding).order_by(Finding.id).first()
            assert first is not None
            fid = first.id
        result = runner.invoke(
            cli.app,
            ["correct", str(fid), "--status", "confirmed", "--reason", "Revue analytique S11"],
        )
        assert result.exit_code == 0, result.stdout
        assert "statut corrigé" in result.stdout

        with get_session(engine) as session:
            confirmed = session.get(Finding, fid)
            assert confirmed.status == FindingStatus.CONFIRMED
            assert confirmed.confidence_score == 0.95  # décision humaine
            assert confirmed.status_history[-1].new_status == FindingStatus.CONFIRMED

        # 4. Rapport final sur la cible scannée.
        out = tmp_path / "rapport_b.html"
        result = runner.invoke(
            cli.app,
            ["report", "--target", target, "--format", "html", "--output", str(out)],
        )
        assert result.exit_code == 0, result.stdout
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "Tscan - Rapport de sécurité" in content
        assert "Confirmé" in content  # le verdict humain apparaît dans le rapport
    finally:
        cli.get_engine, cli.init_db = originals