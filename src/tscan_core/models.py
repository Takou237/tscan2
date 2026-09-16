"""Modèles de données du cœur Tscan.

Ces modèles implémentent le modèle pivot décrit au chapitre 10 du cahier des
charges : tout résultat, qu'il provienne d'un import externe (Nuclei, ZAP) ou
du moteur de scan actif de Tscan, est représenté sous la forme d'un `Finding`
unique, indépendant de son format d'origine.

Statut : structure de base posée en semaine 3, complétée en semaines 4
(champs external_id/matched_at pour l'import), 5-6 (score_explanation et
StatusHistory pour la corrélation, le scoring et la correction manuelle), 7
(CachedCve/KevEntry pour le cache de la base de connaissances, puis
authorized/safe_mode/config_json sur Scan et la table TechnologyDetection
pour le bloc reconnaissance de la semaine 7), conformément au planning du
chapitre 13.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


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

    authorized: Mapped[bool] = mapped_column(default=False, nullable=False)
    """Déclaration explicite d'autorisation sur la cible (ES-01), confirmée par
    l'utilisateur au lancement de tout scan actif. Toujours faux pour un
    import : l'exigence s'applique aux scans actifs uniquement."""

    safe_mode: Mapped[bool] = mapped_column(default=True, nullable=False)
    """Mode sécurisé (ES-03) : favorise les tests non destructifs. Actif par
    défaut pour tout scan actif, désactivable explicitement si nécessaire."""

    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Périmètre appliqué au scan (cible, profondeur, durée, tests autorisés),
    sérialisé en JSON (ES-05 : journalisation du périmètre de chaque scan
    actif). Conservé en texte plutôt que recalculé, comme le score."""

    recon_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Observations de la phase de reconnaissance (statut de la racine,
    URL finale, informations TLS, erreur éventuelle), sérialisées en JSON
    (RF-15). Distinct de `config_json` : le périmètre est défini avant le
    scan, les observations sont collectées pendant."""

    findings: Mapped[list[Finding]] = relationship(back_populates="scan")
    technologies: Mapped[list[TechnologyDetection]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

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

    findings: Mapped[list[Finding]] = relationship(back_populates="rule")

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

    check_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    """Identifiant du check précis (déclaratif) ayant produit le Finding, le
    cas échéant (ex : 'header-csp' dans la règle Security Misconfiguration,
    'bac-admin' dans la règle BAC). Ajouté à la semaine 9 pour identifier la
    sonde exacte lors de la confirmation active (RF-23) et pour le reporting."""

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    """Identifiant propre à l'outil source (ex: template-id Nuclei, pluginid
    ZAP). Conservé dès l'import car nécessaire à la corrélation multi-sources
    du bloc suivant (RF-09) : sans cet identifiant, il serait impossible de
    relier deux résultats désignant la même règle de détection d'origine."""

    matched_at: Mapped[str | None] = mapped_column(String(500), nullable=True)
    """URL ou endpoint précis où le résultat a été observé, lorsque l'outil
    source le fournit. Utile au reporting (RF-27) comme aux preuves (ES-08)."""

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.UNVALIDATED, nullable=False
    )
    confidence_score: Mapped[float | None] = mapped_column(nullable=True)
    """Score de confiance (RF-10), calculé par le moteur de scoring. Absent tant
    que le résultat n'a pas encore été traité par le bloc corrélation/scoring."""

    raw_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Résultat brut d'origine, conservé sans modification (RF-05 / ES-07)."""

    score_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Explication du score de confiance (RF-10), sérialisée en JSON : liste
    ordonnée des facteurs ayant contribué au score final (règle appliquée,
    corrélation multi-sources, pénalités de pré-filtrage). Conservée en
    texte plutôt que recalculée à l'affichage, pour que l'explication reste
    fidèle même si les règles évoluent ultérieurement."""

    probe_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Données de ré-observation précise d'un constat de détection active
    (RF-23) : la charge exacte et l'URL de re-sonde qui permettent de REJOUER
    la requête décisive et de vérifier si le signal caractéristique se
    reproduit. Sérialisées en JSON, conservées telles quelles à la re-
    vérification pour distinguer un vrai constat d'un faux positif."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    rule: Mapped[Rule | None] = relationship(back_populates="findings")
    evidences: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    status_history: Mapped[list[StatusHistory]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="StatusHistory.changed_at"
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

    finding: Mapped[Finding] = relationship(back_populates="evidences")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Evidence id={self.id} type={self.evidence_type} finding_id={self.finding_id}>"


class StatusHistory(Base):
    """Trace d'un changement de statut d'un `Finding` (RF-12 / ES-06).

    Une entrée est créée à chaque changement de statut, qu'il soit produit
    automatiquement par le moteur de scoring ou par une correction manuelle
    d'un analyste. `changed_by` vaut `"tscan_engine"` pour un changement
    automatique, ou un identifiant d'utilisateur pour une correction
    manuelle -- cette distinction permet de répondre, en cas de besoin, à la
    question « ce statut a-t-il jamais été revu par un humain ? ».
    """

    __tablename__ = "status_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)

    old_status: Mapped[FindingStatus | None] = mapped_column(Enum(FindingStatus), nullable=True)
    new_status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), nullable=False)
    changed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    finding: Mapped[Finding] = relationship(back_populates="status_history")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<StatusHistory finding_id={self.finding_id} "
            f"{self.old_status} -> {self.new_status} by {self.changed_by!r}>"
        )


class CachedCve(Base):
    """Résultat mis en cache d'une interrogation de la base de connaissances
    CVE/NVD (RF-33, RF-34, chapitre 10).

    Conformément au périmètre validé pour ce bloc, Tscan ne rapatrie pas
    l'intégralité de NVD : chaque ligne de cette table correspond à une
    interrogation déjà effectuée (`query`, par exemple "jquery 1.11.0"),
    conservée pour permettre une réutilisation hors-ligne ultérieure
    (RNF-14) sans réinterroger le réseau à chaque scan.
    """

    __tablename__ = "cached_cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    query: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Réponse brute de l'API NVD pour cette entrée, conservée par souci de
    traçabilité (même principe que ES-07 pour les résultats importés)."""

    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CachedCve query={self.query!r} cve_id={self.cve_id}>"


class KevEntry(Base):
    """Entrée du catalogue CISA KEV (vulnérabilités confirmées comme
    activement exploitées), synchronisée intégralement (RF-33, RF-34) --
    le flux est suffisamment petit pour ne pas justifier une interrogation
    à la demande, contrairement à NVD.
    """

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vulnerability_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_added: Mapped[str | None] = mapped_column(String(32), nullable=True)
    known_ransomware_use: Mapped[str | None] = mapped_column(String(32), nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<KevEntry cve_id={self.cve_id} name={self.vulnerability_name!r}>"


class TechnologyDetection(Base):
    """Technologie détectée sur une cible lors de la phase de reconnaissance
    (RF-15, RF-16).

    Chaque ligne correspond à une signature de fingerprinting qui a matché
    (en-tête HTTP ou contenu de page). `version` est extraite de la signature
    lorsqu'elle la porte (ex : "Server: Apache/2.4.53"). `cpe_alias` relie la
    technologie à la table d'alias CPE (`knowledge/cpe_aliases.yaml`) : c'est
    le point d'entrée de la détection des composants vulnérables connus
    (RF-18), qui interroge la base de connaissances par version.
    """

    __tablename__ = "technology_detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)

    technology_name: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpe_alias: Mapped[str | None] = mapped_column(String(64), nullable=True)

    source: Mapped[str] = mapped_column(String(128), nullable=False)
    """Origine de la preuve de détection (ex : 'header:Server', 'body')."""

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="technologies")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<TechnologyDetection id={self.id} name={self.technology_name!r} "
            f"version={self.version!r} scan_id={self.scan_id}>"
        )

