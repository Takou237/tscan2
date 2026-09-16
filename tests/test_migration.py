"""Tests de la migration minimale de schéma (ajout de colonnes additif).

Vérifie qu'une base créée par une ancienne version du logiciel (sans les
colonnes du bloc semaine 7) reste utilisable après `init_db` sans
manipulation manuelle : c'est la garantie apportée aux utilisateurs du MVP
sur leur base existante.
"""

from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from tscan_core.db import get_engine, init_db
from tscan_core.models import Base, Finding, FindingStatus, Scan, ScanType, StatusHistory
from tscan_core.status import AUTOMATIC_ACTOR, change_status

_LEGACY_SCANS_DDL = """
CREATE TABLE scans (
    id INTEGER NOT NULL PRIMARY KEY,
    scan_type VARCHAR(8) NOT NULL,
    source VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME
)
"""

_LEGACY_FINDINGS_DDL = """
CREATE TABLE findings (
    id INTEGER NOT NULL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    rule_id VARCHAR(64),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    external_id VARCHAR(128),
    matched_at VARCHAR(500),
    status VARCHAR(16) NOT NULL,
    confidence_score FLOAT,
    raw_result TEXT,
    score_explanation TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""


def _column_names(engine, table: str = "scans") -> set[str]:
    with engine.connect() as connection:
        info = connection.exec_driver_sql(f"PRAGMA table_info({table})")
        return {row[1] for row in info}


def test_init_db_adds_week7_columns_to_legacy_database() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text(_LEGACY_SCANS_DDL))
    assert {"authorized", "safe_mode", "config_json", "recon_json"}.isdisjoint(
        _column_names(engine)
    )

    init_db(engine)

    assert {"authorized", "safe_mode", "config_json", "recon_json"} <= _column_names(engine)


def test_init_db_is_idempotent_on_migrated_database() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text(_LEGACY_SCANS_DDL))

    init_db(engine)
    init_db(engine)  # pas de seconde erreur ni de colonne dupliquée

    assert {"authorized", "safe_mode", "config_json", "recon_json"} <= _column_names(engine)


def test_new_database_created_with_week7_columns() -> None:
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    assert {"authorized", "safe_mode", "config_json", "recon_json"} <= _column_names(engine)


def test_init_db_adds_check_id_to_legacy_findings() -> None:
    """Le champ `check_id` (bloc confirmation RF-23, semaine 9) doit être ajouté
    de façon additive à une base existante créée avant lui."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text(_LEGACY_FINDINGS_DDL))
    assert "check_id" not in _column_names(engine, "findings")

    init_db(engine)

    assert "check_id" in _column_names(engine, "findings")


def test_init_db_is_idempotent_for_findings_migration() -> None:
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    init_db(engine)
    assert "check_id" in _column_names(engine, "findings")


# --- Migration de données RF-12 (semaine 11) ---------------------------------


def _seed_legacy_confirmed(engine, changed_by: str, score: float = 0.90) -> int:
    """Crée une base « héritée » : tables sans migration + un constat Confirmée
    posé par l'acteur donné (moteur ou humain). Retourne l'id du Finding."""
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(scan_type=ScanType.ACTIVE_SCAN, source="tscan_engine", target="example.test")
        session.add(scan)
        session.flush()
        finding = Finding(
            scan_id=scan.id,
            title="En-tête Content-Security-Policy absent",
            category="security_misconfiguration",
            severity="info",
            status=FindingStatus.CONFIRMED,
            confidence_score=score,
        )
        session.add(finding)
        session.flush()
        change_status(
            session,
            finding,
            FindingStatus.CONFIRMED,
            changed_by=changed_by,
            reason="Ancien flux : re-vérification active (RF-23).",
        )
        finding.confidence_score = score
        session.add(finding)
        session.commit()
        return finding.id


def test_init_db_downgrades_legacy_engine_confirmations() -> None:
    """RF-12 (semaine 11) : une confirmation posée par l'ANCIEN moteur
    (`tscan_engine`) est replacée en Probable au démarrage, avec un score
    plafonné à 0,85, mais l'historique est conservé (ES-06)."""
    engine = get_engine(":memory:")
    fid = _seed_legacy_confirmed(engine, changed_by=AUTOMATIC_ACTOR, score=0.90)

    init_db(engine)

    with Session(engine) as session:
        finding = session.get(Finding, fid)
        assert finding.status == FindingStatus.PROBABLE
        assert finding.confidence_score <= 0.85
        history = (
            session.query(StatusHistory)
            .filter_by(finding_id=fid)
            .order_by(StatusHistory.changed_at)
            .all()
        )
        # La trace historique n'est jamais supprimée : l'ancienne confirmation
        # ET la rétrogradation sont visibles (ES-06).
        assert any(h.new_status == FindingStatus.CONFIRMED for h in history)
        assert any(
            h.new_status == FindingStatus.PROBABLE and "Migration RF-12" in (h.reason or "")
            for h in history
        )


def test_init_db_keeps_human_confirmations() -> None:
    """Une confirmation posée par un ANALYSTE est un verdict humain (RF-12) :
    elle n'est jamais retirée par la migration."""
    engine = get_engine(":memory:")
    fid = _seed_legacy_confirmed(engine, changed_by="analyste", score=0.95)

    init_db(engine)

    with Session(engine) as session:
        finding = session.get(Finding, fid)
        assert finding.status == FindingStatus.CONFIRMED
        assert finding.confidence_score == 0.95


def test_init_db_engine_downgrade_migration_is_idempotent() -> None:
    """Ré-exécuter `init_db` après la migration ne modifie plus rien (aucune
    nouvelle entrée d'historique) : la migration converge en un seul passage."""
    engine = get_engine(":memory:")
    fid = _seed_legacy_confirmed(engine, changed_by=AUTOMATIC_ACTOR, score=0.90)

    init_db(engine)
    with Session(engine) as session:
        count_after_first = session.query(StatusHistory).filter_by(finding_id=fid).count()

    init_db(engine)
    with Session(engine) as session:
        count_after_second = session.query(StatusHistory).filter_by(finding_id=fid).count()
        finding = session.get(Finding, fid)
        assert finding.status == FindingStatus.PROBABLE
        assert finding.confidence_score <= 0.85

    assert count_after_second == count_after_first