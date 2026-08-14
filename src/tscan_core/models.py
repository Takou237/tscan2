"""Modèles de données du cœur Tscan.

Ces modèles implémentent le modèle pivot décrit au chapitre 10 du cahier des
charges : tout résultat, qu'il provienne d'un import externe (Nuclei, ZAP) ou
du moteur de scan actif de Tscan, est représenté sous la forme d'un `Finding`
unique, indépendant de son format d'origine.

Statut du squelette (semaine 3) : structure des tables uniquement, aucune
logique métier. Les tables sont volontairement minimales et seront complétées
au fil des blocs fonctionnels suivants (semaines 4 à 8), conformément au
planning du chapitre 13, sans anticiper de fonctionnalités qui n'y sont pas
encore prévues (par exemple, l'historique détaillé des corrections de statut
sera ajouté avec le bloc corrélation/validation des semaines 5-6).
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Classe de base déclarative commune à tous les modèles Tscan."""


class ScanType(str, enum.Enum):
    """Origine d'un résultat : import d'un scanner externe, ou scan actif Tscan."""

    IMPORT = "import"
    ACTIVE_SCAN = "active_scan"


class FindingStatus(str, enum.Enum):
    """Statuts de validation définis au chapitre 1 / RF-07 du cahier des charges."""

    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POTENTIAL_FALSE_POSITIVE = "potential_false_positive"
    FALSE_POSITIVE = "false_positive"


class EvidenceType(str, enum.Enum):
    """Types de preuves pouvant être associées à un résultat (ES-08)."""

    REQUEST_RESPONSE = "request_response"
    SCREENSHOT = "screenshot"
    NOTE = "note"


class Scan(Base):
    """Un `Scan` représente un lot de résultats : soit un import externe
    (Nuclei, ZAP...), soit une exécution du moteur de scan actif de Tscan.

    Unifier ces deux origines dans une seule table permet à l'orchestrateur
    (chapitre 10) de traiter un import et un scan actif de façon homogène.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    """Origine précise : 'nuclei', 'zap', 'nessus', ou 'tscan_engine'."""

    target: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")

    def __repr__(self) -> str:  # pragma: no cover - confort de débogage
        return f"<Scan id={self.id} type={self.scan_type} source={self.source} target={self.target}>"


class Rule(Base):
    """Métadonnées d'une règle de détection/validation.

    Conformément à la décision d'architecture du chapitre 10, le contenu
    complet d'une règle (conditions, méthode de validation...) vit dans un
    fichier YAML versionné sous `rules/`. Cette table n'indexe que les
    métadonnées nécessaires pour relier un `Finding` à la règle qui l'a
    produit ou validé, sans dupliquer le contenu de la règle elle-même.
    """

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    """Identifiant de règle tel que défini dans le fichier YAML (ex: 'RULE-MISCONFIG-001')."""

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(String(255), nullable=False)

    findings: Mapped[list["Finding"]] = relationship(back_populates="rule")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Rule id={self.id} name={self.name!r}>"


class Finding(Base):
    """Modèle pivot : représentation normalisée d'un résultat de vulnérabilité,
    quelle que soit son origine (import externe ou scan actif Tscan).
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(ForeignKey("rules.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.UNVALIDATED, nullable=False
    )
    confidence_score: Mapped[float | None] = mapped_column(nullable=True)
    """Score de confiance (RF-10), calculé par le moteur de scoring. Absent tant
    que le résultat n'a pas encore été traité par le bloc corrélation/scoring."""

    raw_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Résultat brut d'origine, conservé sans modification (RF-05 / ES-07)."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    rule: Mapped["Rule | None"] = relationship(back_populates="findings")
    evidences: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding id={self.id} title={self.title!r} status={self.status}>"


class Evidence(Base):
    """Preuve associée à un `Finding` (ES-08).

    Conformément au chapitre 10, le contenu volumineux (capture, requête/
    réponse complète) est destiné à être stocké comme fichier référencé par
    son chemin plutôt que directement en base ; `content_path` porte cette
    référence. `content_text` permet de stocker une preuve courte directement
    en base lorsque cela reste raisonnable (ex : un en-tête HTTP manquant).
    """

    __tablename__ = "evidences"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)

    evidence_type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), nullable=False)
    content_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    finding: Mapped["Finding"] = relationship(back_populates="evidences")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Evidence id={self.id} type={self.evidence_type} finding_id={self.finding_id}>"
