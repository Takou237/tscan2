"""Ré-observation active des résultats importés pour détecter les faux positifs.

Quand un scan externe (Nuclei, ZAP, Nessus/OpenVAS) est importé, ses constats
n'ont aucune validation active : ils proviennent d'un outil tiers et peuvent
contenir des **faux positifs**. Ce module rejoue le « cheminement déjà établi »
du scan actif de Tscan pour les confirmer ou les contredire :

1. **Recouvrement général** : les constats des scans actifs Tscan — celui que
   la ré-observation relance sur la même cible (**et** ceux des scans actifs
   complets déjà présents en base sur la même cible, qui corroborent des
   constats que la ré-observation bornée n'a pas recouverts) — sont reliés aux
   constats importés par catégorie + emplacement normalisé
   (`correlation.matcher`). Un constat importé **corroboré** par le scan actif
   sur la même vulnérabilité est reproduit : il n'est pas un faux positif. Les
   constats du scan de ré-observation qui dupliquent un constat déjà présent
   dans l'import sont retirés (pas de doublon en base) ; ceux des scans
   antérieurs ne sont jamais touchés.
2. **Ré-observation ciblée** : pour les constats importés non corroborés qui
   possèdent une URL (`matched_at`), une nouvelle requête HTTP vérifie si le
   fait décisif persiste (ressource toujours présente / statut attendu). Une
   ressource devenue injoignable ou introuvable (404/410) contredit le constat.
3. **Verdict** : un constat importé non reproduit est placé en
   « potentiel faux positif » (`POTENTIAL_FALSE_POSITIVE`) avec historique et
   explication de score, pour revue analytique prioritaire (RF-12) — jamais
   supprimé ni confirmé automatiquement.

Les résultats produits par le scan actif de Tscan lui-même (source
`tscan_engine`) sont déjà validés par la confirmation non destructive (RF-23)
et ne sont pas re-scorés ici.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlsplit

from sqlalchemy.orm import Session

from tscan_core.correlation.matcher import correlate, normalize_location
from tscan_core.models import (
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Scan,
    ScanType,
)
from tscan_core.recon.client import create_http_client, fetch_url
from tscan_core.scan.blocking import detect_target_blocking
from tscan_core.scan.config import ScanConfig, validate_target
from tscan_core.scan.orchestrator import ENGINE_SOURCE, run_recon_scan
from tscan_core.status import AUTOMATIC_ACTOR, change_status

# Cible jamais explorée en re-observation sans borne : le scan de ré-observation
# d'un lot importé explore un échantillon borné (comme le scan actif par défaut)
# pour garder une durée prévisible (ES-02).
REOBERVE_CRAWL_MAX_PAGES = 10

_NOT_REPRODUCED_REASON = (
    "Ré-observation active d'un constat importé : le fait décisif n'a pas été "
    "reproduit par la ré-observation. Constat placé en potentiel faux positif "
    "pour revue analytique (RF-12)."
)

# Catégories dont un emplacement (URL) est porteur d'un fait décisif rejouable :
# elles peuvent bénéficier de la ré-observation ciblée par URL. Les autres
# catégories s'appuient uniquement sur le recouvrement général.
_URL_REOBSERVABLE_CATEGORIES = {
    "xss",
    "sqli",
    "csrf",
    "broken_access_control",
    "vulnerable_component",
    "security_misconfiguration",
    "information_disclosure",
    "other",
}


@dataclass
class ReobserveOutcome:
    """Résumé de la ré-observation d'un lot importé."""

    import_scan_id: int
    active_scan_id: int
    total: int = 0
    reproduced: int = 0
    potential_false_positives: int = 0
    not_reproducible: int = 0
    # Constats importés placés en potentiel faux positif (URL + titre).
    flagged: list[dict] = field(default_factory=list)
    # La cible a refusé la ré-observation (racine en 401/403/429 ou crawl
    # quasi vide) : les comptes ci-dessus sont sous-estimés (corroboration
    # dégradée) et doivent être lus avec prudence. Les interfaces affichent
    # alors un avertissement explicite.
    blocked: bool = False
    blocked_reason: str = ""
    # Statut HTTP de la racine et nombre de pages crawlées par la
    # ré-observation (remontés aux interfaces pour le diagnostic).
    root_status_code: int | None = None
    pages_crawled: int | None = None


def reobserve_imported_scan(
    session: Session,
    import_scan_id: int,
    target: str | None = None,
    crawl_max_pages: int = REOBERVE_CRAWL_MAX_PAGES,
    on_event=None,
    on_request=None,
    http_client=None,
) -> ReobserveOutcome:
    """Ré-observed les constats d'un scan importé contre un scan actif Tscan.

    `import_scan_id` désigne le `Scan` de type `IMPORT` à ré-observer.
    `target` est l'URL de la cible ; si absent, elle est déduite de la cible
    du scan importé.

    `on_event` (progression) et `on_request` (journal « History » ZAP) sont
    des écouteurs facultatifs transmis au scan actif de ré-observation, pour
    afficher son déroulement dans les interfaces.

    Retourne un `ReobserveOutcome` résumant le nombre de constats reproduits
    et de potentiels faux positifs détectés.
    """
    import_scan = session.get(Scan, import_scan_id)
    if import_scan is None:
        raise ValueError(f"Scan importé introuvable : id={import_scan_id}")
    if import_scan.scan_type != ScanType.IMPORT:
        raise ValueError(
            f"Le scan #{import_scan_id} est de type {import_scan.scan_type.value}, "
            "pas un import."
        )

    target = target or import_scan.target
    target = validate_target(target)
    config = ScanConfig(
        target=target,
        authorized=True,  # ES-01 : fournir un import pour une cible = autorisation
        crawl_max_pages=crawl_max_pages,
        max_duration_seconds=None,
    )

    imported = _load_imported_findings(session, import_scan_id)

    # 1) Recouvrement général : scan actif Tscan sur la même cible.
    outcome = run_recon_scan(
        session,
        config,
        http_client=http_client,
        on_event=on_event,
        on_request=on_request,
        request_delay=0.0,
    )
    active_scan_id = outcome.scan_id

    # Détection d'un blocage de la cible (anti-bot/WAF) : une racine refusée
    # (401/403/429) ou une sonde racine en échec signifie que la ré-observation
    # est passée aveugle. Les comptes de corroboration restent valides en eux-
    # mêmes, mais ils sous-estiment la réalité (peu de constats produits pour
    # comparer) : on le signale explicitement aux interfaces au lieu de
    # présenter un bilan trompeusement « normal ».
    blocked, block_reasons = detect_target_blocking(outcome.recon_observations)
    blocked_reason = "; ".join(block_reasons)
    root_status = outcome.recon_observations.get("status_code")
    pages_crawled = (outcome.recon_observations.get("crawl_stats") or {}).get(
        "pages_found"
    )

    # Constats produits par le scan actif de ré-observation (source tscan_engine),
    # enrichis de ceux des scans actifs Tscan déjà présents en base sur la même
    # cible : un scan complet lancé au préalable corrobore les constats importés
    # que la ré-observation bornée n'a pas recouverts (workflow utilisateur :
    # « scanner la cible avant d'importer »).
    new_findings = _load_active_findings(session, active_scan_id)
    prior_engine = _load_prior_engine_findings(session, active_scan_id, target)

    # Corrélation catégorie + emplacement normalisé entre import et scan actif.
    corroborated_ids, duplicate_active_ids = _corroboration_sets(
        imported, new_findings + prior_engine
    )

    # Déduplication (demande utilisateur 26/09/2026) : un constat du scan de
    # ré-observation courant qui corrobore un constat déjà présent dans l'import
    # désigne la même vulnérabilité, déjà documentée par l'import. Le conserver
    # dupliquerait la ligne en base : il est retiré. Seuls les constats du scan
    # de ré-observation réellement nouveaux (non présents dans l'import) sont
    # conservés — les constats des scans actifs antérieurs ne sont jamais
    # touchés.
    for finding in new_findings:
        if finding.id in duplicate_active_ids:
            session.delete(finding)

    # Client réseau pour la ré-observation ciblée par URL des constats non
    # corroborés. Le client du scan actif n'est pas réutilisable ici (il peut
    # avoir été injecté pour les tests) : on en crée un dédié.
    client = http_client or create_http_client(verify_tls=config.verify_tls, request_delay=0.0)

    result = ReobserveOutcome(
        import_scan_id=import_scan_id,
        active_scan_id=active_scan_id,
        total=len(imported),
        blocked=blocked,
        blocked_reason=blocked_reason,
        root_status_code=root_status if isinstance(root_status, int) else None,
        pages_crawled=pages_crawled if isinstance(pages_crawled, int) else None,
    )

    for finding in imported:
        if blocked:
            # La cible bloque la ré-observation : ce contexte est porté par
            # chaque constat non corroboré pour que l'analyste voie en base
            # pourquoi le bilan est incomplet, sans ouvrir le recon_json.
            _add_note(
                session,
                finding,
                (
                    "Ré-observation dégradée : la cible a refusé le scan actif "
                    f"de ré-observation ({blocked_reason}). La corroboration "
                    "s'appuie surtout sur les scans actifs antérieurs — le "
                    "bilan est sous-estimé, à relire plus tard ou depuis une "
                    "autre adresse IP."
                ),
            )
        if finding.id in corroborated_ids:
            _reward_reproduced(session, finding)
            result.reproduced += 1
            continue

        # Non corroboré : ré-observation ciblée par URL si possible.
        contradicted = targeted_reobserve(session, finding, client)
        if contradicted:
            flag_potential_false_positive(session, finding)
            result.flagged.append(
                {"id": finding.id, "title": finding.title, "url": finding.matched_at}
            )
            result.potential_false_positives += 1
        else:
            result.not_reproducible += 1

    session.commit()
    return result


def _load_imported_findings(session: Session, import_scan_id: int) -> list[Finding]:
    return (
        session.query(Finding)
        .filter_by(scan_id=import_scan_id)
        .filter(Finding.status.notin_(
            [FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE]
        ))
        .all()
    )


def _load_active_findings(session: Session, active_scan_id: int) -> list[Finding]:
    return session.query(Finding).filter_by(scan_id=active_scan_id).all()


def _load_prior_engine_findings(
    session: Session, active_scan_id: int, target: str
) -> list[Finding]:
    """Constats des scans actifs Tscan déjà présents en base sur la même cible
    (tous les scans `tscan_engine` antérieurs, hors scan de ré-observation
    courant). Ils constituent une preuve de recouvrement supplémentaire : un
    scan complet lancé avant l'import corrobore des constats que la
    ré-observation bornée (10 pages) n'a pas couverts."""
    return (
        session.query(Finding)
        .join(Finding.scan)
        .filter(Scan.target == target)
        .filter(Scan.source == ENGINE_SOURCE)
        .filter(Scan.id != active_scan_id)
        .all()
    )


def _corroboration_sets(
    imported: list[Finding], new_findings: list[Finding]
) -> tuple[set[int], set[int]]:
    """Relie les constats importés et les constats du scan actif de
    ré-observation par vulnérabilité.

    Deux passes de rapprochement (demande utilisateur 27/09/2026) :
    1. **catégorie + emplacement normalisé** (`correlation.matcher`) : le scan
       actif et l'outil externe ont observé la même instance de la
       vulnérabilité (même URL) ;
    2. **catégorie + titre normalisé + même hôte** : les périmètres de crawl
       diffèrent, mais le site porte bien la même vulnérabilité (ex. en-têtes
       de sécurité absents observés par les deux outils sur des pages
       différentes).

    Retourne `(importés_corroborés, actifs_en_doublon)` :
    - les ids des constats importés corroborés par le scan actif (reproduits,
      donc non faux positifs) ;
    - les ids des constats actifs qui désignent une vulnérabilité déjà portée
      par un constat importé : ce sont des doublons de l'import, retirés par la
      ré-observation pour éviter de dupliquer la même vulnérabilité en base.
      Seuls les constats du scan de ré-observation courant sont concernés par
      le retrait ; les constats des scans actifs antérieurs ne sont jamais
      touchés."""
    if not imported or not new_findings:
        return set(), set()

    groups = correlate(imported + new_findings)
    new_ids = {f.id for f in new_findings}
    corroborated: set[int] = set()
    duplicate_active: set[int] = set()

    for group in groups:
        import_members = [f for f in group.findings if f.id not in new_ids]
        active_members = [f for f in group.findings if f.id in new_ids]
        # Multi-source dans le groupe ? Le scan actif corrobore les importés du
        # même groupe, et ses constats dupliquent une vulnérabilité déjà
        # documentée par l'import.
        if active_members and import_members:
            corroborated.update(f.id for f in import_members)
            duplicate_active.update(f.id for f in active_members)

    # Passe « titre » (demande utilisateur 27/09/2026) : le scan actif borné et
    # l'outil externe n'explorent pas les mêmes URL (périmètres de crawl
    # différents). Un constat actif de même catégorie + titre normalisé identique
    # + même hôte corrobore quand même un constat importé resté au bord : il
    # désigne la même vulnérabilité du site, observée sur une instance
    # différente. Complète la passe par emplacement ; ne diminue jamais rien.
    remaining_imports = [f for f in imported if f.id not in corroborated]
    if remaining_imports:
        by_title: dict[tuple[str, str], list[Finding]] = {}
        for active_finding in new_findings:
            bare = normalize_location(
                active_finding.matched_at,
                active_finding.scan.target if active_finding.scan is not None else "",
            )
            parts = urlsplit(bare)
            host = (
                f"{parts.scheme}://{parts.netloc}".lower()
                if parts.scheme and parts.netloc
                else ""
            )
            canonical = _canonical_title(_normalize_title(active_finding.title))
            by_title.setdefault((active_finding.category, host), []).append(
                (canonical, active_finding)
            )
        for imported_finding in remaining_imports:
            bare = normalize_location(
                imported_finding.matched_at,
                imported_finding.scan.target if imported_finding.scan is not None else "",
            )
            parts = urlsplit(bare)
            host = (
                f"{parts.scheme}://{parts.netloc}".lower()
                if parts.scheme and parts.netloc
                else ""
            )
            canonical = _canonical_title(_normalize_title(imported_finding.title))
            # Une catégorie import « other » (aucun indice fiable) est un joker :
            # le moteur n'émet jamais cette catégorie, on accepte alors n'importe
            # quelle catégorie du scan actif pour le même titre + hôte.
            candidate_keys = [(imported_finding.category, host)]
            if imported_finding.category == "other":
                active_categories = {key[0] for key in by_title if key[1] == host}
                candidate_keys = [(cat, host) for cat in active_categories]
            for key in candidate_keys:
                matches = [
                    active_finding
                    for (active_canonical, active_finding) in by_title.get(key, [])
                    if active_canonical == canonical
                ]
                if matches:
                    corroborated.add(imported_finding.id)
                    duplicate_active.update(f.id for f in matches)
                    break
    return corroborated, duplicate_active


def _normalize_title(title: str | None) -> str:
    """Titre ramené à une forme comparable (minuscules, sans accents, espaces
    uniques). Les lettres accentuées sont décomposées (NFKD) puis réduites à
    leur forme sans marque : « Requête » → « requete », forme attendue par la
    table de synonymes FR/EN du scanner (le rapport ZAP FR est accentué)."""
    if not title:
        return ""
    unaccented = "".join(
        c for c in unicodedata.normalize("NFKD", title) if not unicodedata.combining(c)
    )
    return re.sub(r"[^a-z0-9]+", " ", unaccented.lower()).strip()


# Synonymes de titres d'alerte ZAP (FR ↔ EN) : le rapport ZAP peut être
# fourni dans l'une ou l'autre langue selon la configuration de l'outil. La
# passe « titre » de la corroboration compare les titres normalisés ; sans
# cette table, une alerte FR (« Absence de Jetons Anti-CSRF ») ne rejoindrait
# jamais son équivalent EN du moteur (« Anti-CSRF Tokens Check ») alors qu'elle
# désigne la même vulnérabilité. Chaque entrée associe un titre normalisé
# (clé) à son équivalent canonique (valeur) ; la correspondance s'applique des
# deux côtés (import et scan actif) avant comparaison.
_TITLE_SYNONYMS: dict[str, str] = {
    "absence de jetons anti csrf": "anti csrf tokens check",
    "formulaire post sans jeton anti csrf": "anti csrf tokens check",
    "anti csrf tokens check": "anti csrf tokens check",
    "mauvaise configuration inter domaines": "cross domain misconfiguration",
    "configuration cors permissive": "cross domain misconfiguration",
    "cross domain misconfiguration": "cross domain misconfiguration",
    "incompatibilite de charset": "charset mismatch",
    "charset mismatch": "charset mismatch",
    "requete d authentification identifiee": "authentication request identified",
    "authentication request identified": "authentication request identified",
    "reponse de gestion de session identifiee": "session management response identified",
    "session management response identified": "session management response identified",
    "divulgation d informations sensibles dans l url": (
        "information disclosure sensitive information in url"
    ),
    "information disclosure sensitive information in url": (
        "information disclosure sensitive information in url"
    ),
    "en tete content type absent": "content type header missing",
    "content type header missing": "content type header missing",
    "le serveur web fuit des informations via l en tete x powered by http": (
        "server leaks information via x powered by http response header fields"
    ),
    "server leaks information via x powered by http response header fields": (
        "server leaks information via x powered by http response header fields"
    ),
}


def _canonical_title(normalized: str) -> str:
    """Ramène un titre normalisé à sa forme canonique (synonyme FR/EN)."""
    return _TITLE_SYNONYMS.get(normalized, normalized)


def _corroborated_import_ids(
    imported: list[Finding], new_findings: list[Finding]
) -> set[int]:
    """Retourne les ids des constats importés corroborés par le scan actif
    (catégorie + emplacement normalisé)."""
    corroborated, _ = _corroboration_sets(imported, new_findings)
    return corroborated


def targeted_reobserve(session: Session, finding: Finding, client) -> bool:
    """Ré-observed par URL un constat importé non corroboré.

    Utilisé par la ré-observation d'import (`reobserve_imported_scan`) et par
    la corrélation en mode `reobserve=True` (`correlation.service`).

    Retourne `True` si le fait décisif est CONTREDIT (faux positif probable) :
    la ressource n'est plus joignable ou a disparu (statut 404/410), ce qui
    invalide un constat qui supposait sa présence ou sa vulnérabilité.

    Retourne `False` si le constat ne peut pas être contredit de façon décisive
    par la liveness (il n'est donc pas marqué faux positif, on laisse l'analyste
    trancher).
    """
    url = finding.matched_at
    category = finding.category
    if not _is_reobservable_url(url) or category not in _URL_REOBSERVABLE_CATEGORIES:
        return False

    try:
        page = fetch_url(client, url)
    except Exception as exc:  # noqa: BLE001 - sonde réseau : on ne conclut pas au FP
        _add_note(
            session,
            finding,
            (
                "Ré-observation ciblée échouée (réseau) : le constat n'a pas pu être "
                f"repris sur {url} ({type(exc).__name__}). Constat laissé tel quel."
            ),
        )
        return False

    # Statuts d'inaccessibilité de la ressource : le fait décisif supposé ne
    # peut plus être observé → contradiction (faux positif probable).
    if page.status_code in (404, 410):
        return True

    # Statut 401/403/429 : la ressource a répondu, mais le serveur refuse la
    # requête (contrôle d'accès, filtrage anti-bot/WAF, rate limiting). Ce
    # n'est ni une preuve d'accessibilité, ni une preuve de disparition : la
    # sonde ne peut ni corroborer ni contredire le constat (le fait décisif
    # reste inobservable depuis cette adresse IP). Constat laissé tel quel,
    # avec une note explicite pour que l'analyste sache que la cible bloque
    # la sonde — le « -> 403 » ne doit pas être lu comme « accessible ».
    if page.status_code in (401, 403, 429):
        _add_note(
            session,
            finding,
            (
                "Ré-observation ciblée bloquée : la ressource a répondu "
                f"{page.status_code} (refus : contrôle d'accès, filtrage "
                "anti-bot/WAF ou rate limiting) sur "
                f"{url}. Le fait décisif n'est pas observable : le constat "
                "n'est ni corroboré ni contredit — revue analytique requise."
            ),
        )
        return False

    _add_note(
        session,
        finding,
        (
            "Ré-observation ciblée : la ressource est toujours accessible "
            f"({url} -> {page.status_code}). Le constat importé n'est pas contredit "
            "par la disponibilité."
        ),
    )
    return False


def _is_reobservable_url(url: str | None) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _reward_reproduced(session: Session, finding: Finding) -> None:
    """Corroboré par le scan actif : renforce la confiance, sans confirmer."""
    _add_note(
        session,
        finding,
        (
            "Ré-observation active : le constat importé a été corroboré par un "
            "constat du scan actif Tscan sur la même vulnérabilité (catégorie et "
            "emplacement). Faible probabilité de faux positif. Statut laissé tel "
            "quel — la confirmation relève de l'analyste (RF-12)."
        ),
    )


def flag_potential_false_positive(session: Session, finding: Finding) -> None:
    """Place un constat importé non reproduit en potentiel faux positif.

    Utilisé par la ré-observation d'import (`reobserve_imported_scan`) et par
    la corrélation en mode `reobserve=True` (`correlation.service`).
    """
    explanation = _load_explanation(finding)
    explanation.append(
        "Ré-observation active contradictoire : le fait décisif du constat "
        "importé n'a pas été reproduit (ni corroboré par le scan actif, ni "
        "re-observable par URL). Constat placé en potentiel faux positif pour "
        "revue analytique."
    )
    finding.score_explanation = json.dumps(explanation, ensure_ascii=False)
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=_NOT_REPRODUCED_REASON,
        )
    )
    change_status(
        session,
        finding,
        FindingStatus.POTENTIAL_FALSE_POSITIVE,
        changed_by=AUTOMATIC_ACTOR,
        reason=_NOT_REPRODUCED_REASON,
    )


def _add_note(session: Session, finding: Finding, text: str) -> None:
    session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType.NOTE,
            content_text=text,
        )
    )


def _load_explanation(finding: Finding) -> list[str]:
    if not finding.score_explanation:
        return []
    try:
        value = json.loads(finding.score_explanation)
        return value if isinstance(value, list) else [str(value)]
    except json.JSONDecodeError:
        return [finding.score_explanation]
