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
    # SQLite en mode WAL (journal anticipé) : un fil d'exécution (import, scan…
    # via `workers.py`) et l'interface, qui lisent la même base avec chacun sa
    # connexion, ne se bloquent plus mutuellement. L'interface voit alors les
    # constats commités au fil de l'eau par le scan en arrière-plan (S11).
    # `timeout` borne l'attente d'un verrou si une écriture traîne.
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 30})
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        connection.exec_driver_sql("PRAGMA busy_timeout=30000")
    return engine


def init_db(engine: Engine) -> None:
    """Crée l'ensemble des tables définies dans `tscan_core.models` si elles
    n'existent pas déjà, et applique les ajouts de colonnes additifs sur les
    tables existantes (migration minimale pour SQLite).

    Squelette de la semaine 3 : création directe des tables via SQLAlchemy.
    Un système de migrations (Alembic) pourra remplacer cette approche si le
    schéma évolue de façon incompatible en cours de projet ; tant que le
    schéma reste additif (ajout de colonnes, de tables), la fonction
    `_ensure_column` ci-dessous suffit -- une base créée par une ancienne
    version du logiciel reste utilisable sans manipulation manuelle.

    Depuis la semaine 11, `init_db` exécute aussi la migration de données
    `_migrate_legacy_engine_confirmations` : les constats « Confirmée » posés
    par l'ANCIEN moteur (avant le correctif RF-12) sont replacés en `Probable`.
    """
    Base.metadata.create_all(engine)
    _ensure_column(engine, "scans", "authorized", "BOOLEAN NOT NULL DEFAULT 0")
    _ensure_column(engine, "scans", "safe_mode", "BOOLEAN NOT NULL DEFAULT 1")
    _ensure_column(engine, "scans", "config_json", "TEXT")
    _ensure_column(engine, "scans", "recon_json", "TEXT")
    _ensure_column(engine, "findings", "check_id", "VARCHAR(128)")
    _ensure_column(engine, "findings", "probe_json", "TEXT")
    _migrate_legacy_engine_confirmations(engine)


def _ensure_column(engine: Engine, table: str, column: str, ddl: str) -> None:
    """Ajoute une colonne manquante à une table existante (SQLite).

    Vérifie l'existence de la colonne via le schéma réel de la base
    (`PRAGMA table_info`) avant tout ALTER : l'opération est idempotente, ce
    qui permet de l'exécuter à chaque démarrage sans état à maintenir.
    """
    with engine.connect() as connection:
        info = connection.exec_driver_sql(f"PRAGMA table_info({table})")
        existing = {row[1] for row in info}
        if column not in existing:
            connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            connection.commit()


def _migrate_legacy_engine_confirmations(engine: Engine) -> None:
    """Migration de données RF-12 (semaine 11) : nettoie les bases créées par
    l'ancienne version du moteur, qui auto-confirmait les constats reproductibles.

    Avant le correctif, la re-vérification active (RF-23) posait elle-même le
    statut `Confirmée` (score 0,90). Depuis, « Confirmée » est un verdict
    d'analyste uniquement (RF-12) : le moteur renforce au plus la confiance à
    0,85 en laissant le statut `Probable`. Les vieux constats restés en base
    avec un statut `Confirmée` venu du moteur (`StatusHistory.changed_by ==
    AUTOMATIC_ACTOR`) sont donc **rétrogradés en `Probable`** avec un score
    plafonné à 0,85, sans retirer l'historique (ES-06 : la trace reste).

    Une confirmation posée par un **humain** (`changed_by` ≠ moteur) n'est
    jamais touchée : elle reste le seul chemin légitime vers `Confirmée`.

    Idempotente par conception : après passage, aucun constat `tscan_engine`
    n'est plus `Confirmée`, donc une seconde exécution ne modifie rien.
    """
    from tscan_core.models import Finding, FindingStatus
    from tscan_core.status import AUTOMATIC_ACTOR, change_status

    with Session(engine) as session:
        candidates = (
            session.query(Finding)
            .filter(Finding.status == FindingStatus.CONFIRMED)
            .all()
        )
        for finding in candidates:
            # Dernière trace qui a mené à « Confirmée ».
            last_confirmation = next(
                (
                    entry
                    for entry in sorted(finding.status_history, key=lambda e: e.changed_at)
                    if entry.new_status == FindingStatus.CONFIRMED
                ),
                None,
            )
            if last_confirmation is None:
                continue  # Confirmée sans trace : ne pas deviner (donnée humaine)
            if last_confirmation.changed_by != AUTOMATIC_ACTOR:
                continue  # verdict humain : jamais retiré par une migration

            new_score = min(finding.confidence_score or 0.5, 0.85)
            change_status(
                session,
                finding,
                FindingStatus.PROBABLE,
                changed_by=AUTOMATIC_ACTOR,
                reason=(
                    "Migration RF-12 (semaine 11) : ancienne confirmation posée "
                    "par le moteur de scan (auto-confirmation historique) retirée ; "
                    "« Confirmée » est désormais un verdict d'analyste. Constat "
                    "replacé en Probable, score plafonné au niveau de re-vérification."
                ),
            )
            finding.confidence_score = round(new_score, 2)
            session.add(finding)
            session.commit()


def get_session(engine: Engine) -> Session:
    """Ouvre une session de travail sur le moteur donné."""
    return Session(engine)
