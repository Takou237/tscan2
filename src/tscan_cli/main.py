"""Interface en ligne de commande de Tscan (RF-31).

Commandes disponibles à ce stade : `version`, `init-db`, `import`,
`correlate`, `list`, `show`, `correct`.
Les commandes `scan` et `report` seront ajoutées avec les blocs fonctionnels
correspondants (semaines 7-8 et 9 du planning).
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import Annotated

import typer

from tscan_core.correlation import run_correlation
from tscan_core.db import DEFAULT_DB_PATH, get_engine, get_session, init_db
from tscan_core.importers import SUPPORTED_FORMATS, UnsupportedFormatError, import_file
from tscan_core.importers.nuclei import NucleiParseError
from tscan_core.importers.zap import ZapParseError
from tscan_core.models import Finding, FindingStatus
from tscan_core.status import change_status

app = typer.Typer(
    name="tscan",
    help="Tscan --- analyse, corrélation et validation de vulnérabilités de sécurité.",
)


@app.command()
def version() -> None:
    """Affiche la version de Tscan."""
    typer.echo("Tscan 0.1.0 (semaines 5-6 -- corrélation, validation, scoring)")


@app.command("init-db")
def init_db_command() -> None:
    """Initialise la base de données locale (crée les tables si nécessaire)."""
    engine = get_engine()
    init_db(engine)
    typer.echo(f"Base de données initialisée : {DEFAULT_DB_PATH}")


@app.command("import")
def import_command(
    file: Annotated[Path, typer.Argument(help="Fichier de résultats à importer.")],
    format: Annotated[
        str, typer.Option("--format", "-f", help=f"Format source : {', '.join(SUPPORTED_FORMATS)}.")
    ],
    target: Annotated[
        str, typer.Option("--target", "-t", help="Libellé de la cible concernée par ce résultat.")
    ],
) -> None:
    """Importe un fichier de résultats externe (RF-01, RF-02)."""
    if not file.exists():
        typer.echo(f"Erreur : le fichier {file} n'existe pas.", err=True)
        raise typer.Exit(code=1)

    engine = get_engine()
    init_db(engine)

    try:
        with get_session(engine) as session:
            scan = import_file(session, source=format, target=target, file_path=file)
            count = len(scan.findings)
    except UnsupportedFormatError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (NucleiParseError, ZapParseError) as exc:
        typer.echo(f"Erreur d'analyse du fichier : {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Import terminé : {count} résultat(s) importé(s) depuis {format} (scan #{scan.id}).")


@app.command("correlate")
def correlate_command(
    target: Annotated[
        str | None, typer.Option("--target", "-t", help="Limiter la corrélation à cette cible.")
    ] = None,
) -> None:
    """Corrèle et score les résultats importés (RF-08, RF-09, RF-10)."""
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        updated = run_correlation(session, target=target)

        if not updated:
            typer.echo("Aucun résultat à corréler.")
            return

        probable = sum(1 for f in updated if f.status == FindingStatus.PROBABLE)
        potential_fp = len(updated) - probable
        typer.echo(
            f"Corrélation terminée : {len(updated)} résultat(s) traité(s) "
            f"({probable} probable(s), {potential_fp} potentiel(s) faux positif(s))."
        )


@app.command("list")
def list_command(
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    status: Annotated[str | None, typer.Option("--status", "-s", help="Filtrer par statut.")] = None,
) -> None:
    """Liste les résultats en base, avec filtres optionnels."""
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        query = session.query(Finding)
        if target is not None:
            query = query.join(Finding.scan).filter_by(target=target)
        if status is not None:
            query = query.filter_by(status=FindingStatus(status))
        findings = query.all()

        if not findings:
            typer.echo("Aucun résultat.")
            return

        for f in findings:
            score = f"{f.confidence_score:.2f}" if f.confidence_score is not None else "--"
            typer.echo(
                f"#{f.id:<4} [{f.status.value:<25}] score={score:<5} "
                f"{f.severity:<8} {f.category:<25} {f.title}"
            )


@app.command("show")
def show_command(finding_id: int) -> None:
    """Affiche le détail d'un résultat : preuves et explication du score (RF-11)."""
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            typer.echo(f"Erreur : aucun résultat avec l'identifiant {finding_id}.", err=True)
            raise typer.Exit(code=1)

        typer.echo(f"#{finding.id} -- {finding.title}")
        typer.echo(f"  Catégorie   : {finding.category}")
        typer.echo(f"  Gravité     : {finding.severity}")
        typer.echo(f"  Statut      : {finding.status.value}")
        typer.echo(f"  Score       : {finding.confidence_score}")
        typer.echo(f"  Cible       : {finding.scan.target} (source : {finding.scan.source})")
        typer.echo(f"  Emplacement : {finding.matched_at}")

        if finding.score_explanation:
            typer.echo("  Explication du score :")
            for line in json.loads(finding.score_explanation):
                typer.echo(f"    - {line}")

        if finding.status_history:
            typer.echo("  Historique des statuts :")
            for entry in finding.status_history:
                old = entry.old_status.value if entry.old_status else "(aucun)"
                typer.echo(f"    - {old} -> {entry.new_status.value} par {entry.changed_by}")


@app.command("correct")
def correct_command(
    finding_id: int,
    status: Annotated[str, typer.Option("--status", "-s", help="Nouveau statut à appliquer.")],
    reason: Annotated[str | None, typer.Option("--reason", "-r")] = None,
) -> None:
    """Corrige manuellement le statut d'un résultat, avec historique (RF-12)."""
    engine = get_engine()
    init_db(engine)

    try:
        new_status = FindingStatus(status)
    except ValueError as exc:
        valid = ", ".join(s.value for s in FindingStatus)
        typer.echo(f"Erreur : statut inconnu {status!r}. Statuts valides : {valid}.", err=True)
        raise typer.Exit(code=1) from exc

    with get_session(engine) as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            typer.echo(f"Erreur : aucun résultat avec l'identifiant {finding_id}.", err=True)
            raise typer.Exit(code=1)

        old_status = finding.status.value
        change_status(session, finding, new_status, changed_by=getpass.getuser(), reason=reason)

    typer.echo(f"Résultat #{finding_id} : statut corrigé de {old_status} vers {status}.")


if __name__ == "__main__":
    app()
