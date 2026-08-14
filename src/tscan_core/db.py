"""Initialisation et accès à la base de données locale de Tscan (SQLite).

Conformément au chapitre 10 du cahier des charges, Tscan est une application
locale mono-utilisateur : SQLite est utilisé sans serveur à administrer, dans
un fichier unique facile à sauvegarder ou à déplacer.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from tscan_core.models import Base

DEFAULT_DB_PATH = Path.home() / ".tscan" / "tscan.db"


def get_engine(db_path: Path | str = DEFAULT_DB_PATH) -> Engine:
    """Crée le moteur SQLAlchemy pour le fichier de base indiqué.

    Le dossier parent est créé automatiquement s'il n'existe pas encore,
    pour que l'application fonctionne dès le premier lancement sans étape
    d'installation manuelle supplémentaire.

    Le cas particulier `":memory:"` (utilisé par les tests automatisés pour
    ne laisser aucune trace sur disque) est traité séparément.
    """
    if db_path == ":memory:":
        return create_engine("sqlite:///:memory:")

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}")


def init_db(engine: Engine) -> None:
    """Crée l'ensemble des tables définies dans `tscan_core.models` si elles
    n'existent pas déjà.

    Squelette de la semaine 3 : création directe des tables via SQLAlchemy.
    Un système de migrations (Alembic) pourra remplacer cette approche si le
    schéma évolue de façon incompatible en cours de projet ; ce choix n'est
    pas nécessaire tant que le schéma reste additif.
    """
    Base.metadata.create_all(engine)


def get_session(engine: Engine) -> Session:
    """Ouvre une session de travail sur le moteur donné."""
    return Session(engine)
