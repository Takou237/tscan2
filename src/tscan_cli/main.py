"""Interface en ligne de commande de Tscan (RF-31).

Squelette de la semaine 3 : seule la commande `init-db` est implémentée, pour
valider que la CLI peut effectivement piloter le cœur Tscan de bout en bout.
Les commandes `import`, `scan` et `report` seront ajoutées avec les blocs
fonctionnels correspondants (semaines 4, 7-8 et 9 du planning).
"""

from __future__ import annotations

import typer

from tscan_core.db import DEFAULT_DB_PATH, get_engine, init_db

app = typer.Typer(
    name="tscan",
    help="Tscan --- analyse, corrélation et validation de vulnérabilités de sécurité.",
)


@app.command()
def version() -> None:
    """Affiche la version de Tscan."""
    typer.echo("Tscan 0.1.0 (squelette de projet -- semaine 3)")


@app.command("init-db")
def init_db_command() -> None:
    """Initialise la base de données locale (crée les tables si nécessaire)."""
    engine = get_engine()
    init_db(engine)
    typer.echo(f"Base de données initialisée : {DEFAULT_DB_PATH}")


if __name__ == "__main__":
    app()
