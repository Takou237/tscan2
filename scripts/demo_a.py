#!/usr/bin/env python3
"""Démonstration — Scénario A (chapitre 14, critère 1 du MVP).

Rejoue de bout en bout, sur une base TEMPORAIRE dédiée (jamais la base réelle),
la chaîne : import multi-sources (Nuclei + ZAP) → corrélation/scoring →
statuts avec preuves → correction manuelle d'analyste (RF-12) → rapport
HTML/Markdown.

Usage :
    python scripts/demo_a.py
    python scripts/demo_a.py --keep       # conserve la base dans %TEMP%
    python scripts/demo_a.py --out DIR    # écrit les artefacts dans DIR

Chaque étape affiche ce qu'elle fait, comme pendant la démonstration devant
l'encadrant. Le script échoue (code ≠ 0) si une vérification ne passe pas.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def main() -> int:
    parser = argparse.ArgumentParser(description="Démo Scénario A de Tscan")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Dossier de sortie (par défaut : dossier temporaire)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Si --out absent, ne pas supprimer la base temporaire à la fin",
    )
    args = parser.parse_args()

    workdir = args.out or Path(tempfile.mkdtemp(prefix="tscan_demo_a_"))
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = workdir / "demo_a.db"
    if db_path.exists():
        db_path.unlink()

    from tscan_core.correlation import run_correlation
    from tscan_core.db import get_engine, get_session, init_db
    from tscan_core.importers import import_file
    from tscan_core.models import Finding, FindingStatus
    from tscan_core.reporting import generate_report
    from tscan_core.reporting.render_html import render_html
    from tscan_core.reporting.render_markdown import render_markdown
    from tscan_core.status import correct_status_manually

    print("=" * 72)
    print("DÉMONSTRATION — SCÉNARIO A : import → corrélation → statuts → rapport")
    print("=" * 72)
    engine = get_engine(db_path)
    init_db(engine)

    with get_session(engine) as session:
        # -- 1. Import multi-sources ------------------------------------------
        print("\nÉtape 1 — Import de deux outils sur la même cible (exemple.test).")
        sources = [
            ("nuclei", "nuclei_sample.jsonl", "Nuclei (en-tête + composant + admin)"),
            ("nuclei", "nuclei_xss_overlap.jsonl", "Nuclei (XSS réfléchi)"),
            ("zap", "zap_sample.json", "OWASP ZAP (XSS + CSRF)"),
        ]
        total = 0
        for source, fixture, label in sources:
            scan = import_file(
                session, source=source, target="example.test", file_path=FIXTURES / fixture
            )
            total += len(scan.findings)
            print(f"    {label} : {len(scan.findings)} résultat(s) importé(s) (scan #{scan.id})")
        print(f"    => {total} résultats importés au total.")

        # -- 2. Corrélation + scoring -----------------------------------------
        print("\nÉtape 2 — Corrélation multi-sources et scoring de confiance (RF-08 à RF-10).")
        updated = run_correlation(session, target="example.test")
        print(f"    {len(updated)} résultat(s) corrélé(s) et scoré(s).")

        # -- 3. Statuts + preuves ----------------------------------------------
        print("\nÉtape 3 — Statuts attribués avec preuves (RF-07, RF-11).")
        findings = session.query(Finding).all()
        for finding in findings:
            score = f"{finding.confidence_score:.2f}" if finding.confidence_score else "--"
            has_evidence = "oui" if (finding.evidences or finding.score_explanation) else "non"
            print(
                f"    #{finding.id:<3} {finding.status.value:<25} score={score:<5} "
                f"{finding.severity:<7} {finding.category:<28} preuve: {has_evidence}"
            )

        xss = next(f for f in findings if f.category == "xss")
        assert "Corroboré par 2 sources" in xss.score_explanation
        print("    => le constat XSS est corroboré par 2 sources (explication via `tscan show`).")

        # -- 4. Correction manuelle (RF-12) ------------------------------------
        print("\nÉtape 4 — Décision d'analyste : confirmation manuelle du constat XSS (RF-12).")
        correct_status_manually(
            session,
            xss,
            FindingStatus.CONFIRMED,
            changed_by="demo_analyste",
            reason="Vérifié manuellement pendant la démonstration : réflexion reproductible.",
        )
        assert xss.status == FindingStatus.CONFIRMED and xss.confidence_score == 0.95
        print(f"    #{xss.id} -> Confirmé (score 0,95), historique tracé (ES-06).")

        # -- 5. Rapport ----------------------------------------------------
        print("\nÉtape 5 — Génération du rapport (RF-27 à RF-29), exports HTML et Markdown.")
        report = generate_report(session)
        out_html = workdir / "rapport_a.html"
        out_md = workdir / "rapport_a.md"
        out_html.write_text(render_html(report), encoding="utf-8")
        out_md.write_text(render_markdown(report), encoding="utf-8")
        print(f"    Rapport écrit : {out_html}")
        print(f"    Rapport écrit : {out_md} ({report.total_findings} résultat(s)).")

    print("\n✅ Scénario A terminé avec succès.")
    print(f"    Les artefacts sont dans : {workdir}")
    if not args.keep and args.out is None:
        print("    (base temporaire supprimée à la fin ; utilisez --keep ou --out pour la conserver)")
    return 0


if __name__ == "__main__":
    sys.exit(main())