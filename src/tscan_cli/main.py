"""Interface en ligne de commande de Tscan (RF-31).

Commandes disponibles à ce stade : `version`, `init-db`, `import`.
Les commandes `scan` et `report` seront ajoutées avec les blocs fonctionnels
correspondants (semaines 7-8 et 9 du planning).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from tscan_core.db import DEFAULT_DB_PATH, get_engine, get_session, init_db
from tscan_core.importers import SUPPORTED_FORMATS, UnsupportedFormatError, import_file
from tscan_core.importers.nuclei import NucleiParseError
from tscan_core.importers.zap import ZapParseError

app = typer.Typer(
    name="tscan",
    help="Tscan --- analyse, corrélation et validation de vulnérabilités de sécurité.",
)


@app.command()
def version() -> None:
    """Affiche la version de Tscan."""
    typer.echo("Tscan 0.1.0 (semaine 4 -- bloc import & modèle pivot)")


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


if __name__ == "__main__":
    app()
