"""Tests du bloc reporting (semaine 9) : génération du rapport (RF-27),
recommandations et sources vérifiables (RF-28) et export HTML/Markdown (RF-29).
"""

from __future__ import annotations

from pathlib import Path

from tscan_core.correlation import run_correlation
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import import_file
from tscan_core.models import Finding, FindingStatus
from tscan_core.reporting import SEVERITY_ORDER, generate_report
from tscan_core.reporting.render_html import render_html
from tscan_core.reporting.render_markdown import render_markdown
from tscan_core.status import change_status

FIXTURES = Path(__file__).parent / "fixtures"


def _build_scenario(engine) -> None:
    """Importe deux sources sur la même cible et lance la corrélation, comme le
    scénario A : base minimale pour tester le rapport sans dépendre du réseau."""
    init_db(engine)
    with get_session(engine) as session:
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")
        run_correlation(session, target="example.test")


def test_report_contains_executive_summary_and_details() -> None:
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)

        assert report.total_findings == 5
        assert len(report.targets) == 1
        target = report.targets[0]
        assert target.target == "example.test"
        assert len(target.findings) == 5

        # Résumé exécutif : tous les compteurs de gravité sont présents, et le
        # total des compteurs égale le nombre de résultats.
        for severity in SEVERITY_ORDER + ["other"]:
            assert severity in target.severity_counts
        assert sum(target.severity_counts.values()) == 5
        assert sum(target.status_counts.values()) == 5


def test_report_orders_findings_by_severity() -> None:
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        severities = [f.severity for f in report.targets[0].findings]
        ranks = [SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 99 for s in severities]
        assert ranks == sorted(ranks)  # trié de la plus critique à la plus faible


def test_report_includes_recommendations_and_verifiable_sources() -> None:
    """RF-28 : chaque résultat porte une recommandation issue de sa règle et au
    moins une référence vérifiable (OWASP ou CWE MITRE)."""
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)

        for rf in report.targets[0].findings:
            assert rf.recommendation, f"recommandation manquante pour #{rf.id}"
            assert rf.references or rf.cwe_links, f"aucune source vérifiable pour #{rf.id}"

        # Le résultat XSS doit renvoyer vers la page OWASP XSS et vers sa CWE.
        xss = next(rf for rf in report.targets[0].findings if rf.category == "xss")
        assert any("owasp.org" in ref for ref in xss.references)
        assert any("CWE-79" in cwe for cwe in xss.cwe_ids)
        assert any("cwe.mitre.org" in link for link in xss.cwe_links)


def test_report_filter_by_target_and_status() -> None:
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session, target="example.test")
        assert report.total_findings == 5

        # On passe manuellement un constat en Confirmé (RF-12) pour tester
        # le filtrage par statut : ce constat sera exclu du rapport filtré
        # sur PROBABLE.
        first = session.query(Finding).first()
        change_status(
            session, first, FindingStatus.CONFIRMED, changed_by="analyste"
        )

        filtered = generate_report(
            session,
            target="example.test",
            statuses={FindingStatus.PROBABLE},
        )
        assert filtered.total_findings > 0
        assert filtered.total_findings < 5  # le constat Confirmé est exclu
        for target in filtered.targets:
            for rf in target.findings:
                assert rf.status == FindingStatus.PROBABLE


def test_report_empty_database_yields_no_findings() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        assert report.total_findings == 0
        assert report.targets == []
        assert sum(report.overall_severity_counts.values()) == 0
        assert sum(report.overall_status_counts.values()) == 0


def test_html_export_is_escaped() -> None:
    """La sortie HTML doit échapper les contenus issus d'une source importée :
    un titre contenant du HTML/JavaScript ne doit jamais être interprété."""
    engine = get_engine(":memory:")
    _build_scenario(engine)

    malicious_title = '<img src=x onerror="alert(1)">'
    with get_session(engine) as session:
        finding = session.query(Finding).first()
        finding.title = malicious_title
        session.commit()

        report = generate_report(session)
        html = render_html(report)

    assert "<img" not in html
    assert "&lt;img" in html  # la balise est échappée, pas interprétée
    assert "onerror" in html.replace("onerror", "onerror")  # l'attribut reste visible mais inerte


def test_html_export_is_standalone() -> None:
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        html = render_html(report)

    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "<style" in html  # CSS intégré : aucun fichier externe requis
    assert "Tscan - Rapport de sécurité" in html
    assert "Summary of Alerts" in html  # structure de rapport au format ZAP
    assert "example.test" in html


def test_html_alert_table_has_status_column() -> None:
    """La table « Alertes » (nom, niveau de risque, instances) comporte une
    colonne « Statut » avec des pastilles colorées par statut."""
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        html = render_html(report)

    # En-tête à 4 colonnes dont « Statut ».
    assert "Niveau de risque" in html
    assert ">Instances<" in html
    assert ">Statut<" in html
    # Au moins une pastille de statut rendue (span coloré inline).
    assert "background-color:" in html


def test_html_export_contains_status_per_instance() -> None:
    """Chaque instance dans le détail HTML doit comporter la ligne
    « Statut (verdict) » avec le label du statut du constat."""
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        html = render_html(report)

    assert "Statut (verdict)" in html
    assert "Probable" in html


def test_markdown_export_contains_sections() -> None:
    engine = get_engine(":memory:")
    _build_scenario(engine)

    with get_session(engine) as session:
        report = generate_report(session)
        md = render_markdown(report)

    assert "# Rapport de sécurité Tscan" in md
    assert "## Résumé" in md
    assert "## Cible : example.test" in md
    assert "Recommandation" in md
    assert "Sources vérifiables" in md
    assert "cwe.mitre.org" in md


def test_report_cli_writes_output_file(tmp_path: Path) -> None:
    """Intégration CLI : `tscan report --output` écrit bien le fichier demandé.

    La commande CLI lit la base par défaut via `get_engine()` : on redirige
    cette fonction et `init_db` vers une base temporaire pour ne pas toucher
    la base réelle de l'utilisateur.
    """
    from typer.testing import CliRunner

    import tscan_cli.main as cli

    db_path = tmp_path / "tscan_test.db"
    engine = get_engine(db_path)
    init_db(engine)
    with get_session(engine) as session:
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")

    original_engine = cli.get_engine
    original_init = cli.init_db
    cli.get_engine = lambda: engine
    cli.init_db = lambda engine: init_db(engine)
    try:
        out = tmp_path / "rapport.html"
        result = CliRunner().invoke(
            cli.app,
            ["report", "--target", "example.test", "--format", "html", "--output", str(out)],
        )
    finally:
        cli.get_engine = original_engine
        cli.init_db = original_init

    assert result.exit_code == 0, result.stdout
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Tscan - Rapport de sécurité" in content
    assert "Summary of Alerts" in content
    assert "example.test" in content


def test_end_to_end_import_correlate_scan_report(lab_server) -> None:
    """Scénario B réduit : le rapport agrège les résultats issus d'un import
    multi-sources corrélé ET d'un scan actif sur la cible de laboratoire."""
    from tscan_core.scan.config import ScanConfig
    from tscan_core.scan.orchestrator import run_recon_scan

    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        # 1. Import de deux sources externes sur une cible fictive.
        import_file(session, "nuclei", "example.test", FIXTURES / "nuclei_sample.jsonl")
        import_file(session, "zap", "example.test", FIXTURES / "zap_sample.json")

        # 2. Corrélation + scoring (statuts Probable / Potentiel faux positif).
        run_correlation(session, target="example.test")

        # 3. Scan actif sur le labo local (toutes les familles S7/S8).
        outcome = run_recon_scan(
            session,
            ScanConfig(
                target=f"{lab_server.base_url}/",
                authorized=True,
                max_duration_seconds=60,
                allowed_tests=frozenset(
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
                ),
            ),
        )
        assert outcome.scan_id is not None

        # 4. Rapport sur TOUTES les cibles : les deux origines y figurent.
        report = generate_report(session)
        assert report.total_findings == 5 + 18  # import + scan actif
        assert {t.target for t in report.targets} == {
            "example.test",
            f"{lab_server.base_url}/",
        }

        by_target = {t.target: t for t in report.targets}
        imported = by_target["example.test"]
        scanned = by_target[f"{lab_server.base_url}/"]

        # Résultats importés : score et statut fixés par la corrélation.
        for rf in imported.findings:
            assert rf.confidence_score is not None
            assert rf.recommendation
            assert rf.references or rf.cwe_links

        # Résultats de scan : statut Probable avec score renforcé par la
        # re-vérification (RF-23, plafonné à 0,85) — le moteur ne confirme
        # pas, « Confirmée » est un verdict d'analyste (RF-12).
        assert len(scanned.findings) == 18
        for rf in scanned.findings:
            assert rf.status == FindingStatus.PROBABLE
            assert rf.confidence_score is not None
            assert 0.5 <= rf.confidence_score <= 0.85
            assert rf.recommendation
            assert rf.references or rf.cwe_links

        # 5. Le rendu HTML couvre bien les deux cibles.
        html = render_html(report)
        assert "example.test" in html
        assert f"{lab_server.base_url}/".split("//")[1] in html