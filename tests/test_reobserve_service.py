"""Tests de la ré-observation active des constats importés (détection de faux
positifs via demande --rex au moment de l'import, RF-01/RF-02 + RF-23).

Le principe : un scan externe importé n'a aucune validation active ; on relance
un scan actif Tscan sur la même cible et on corrèle les constats importés avec
le scan actif (recouvrement général), puis on ré-observe par URL les constats
non corroborés (ré-observation ciblée). Un constat dont le fait décisif a
disparu (ressource introuvable 404/410) est placé en « potentiel faux positif »
pour revue analytique (RF-12) — jamais supprimé ni confirmé automatiquement.

Aucune ressource externe n'est contactée : un client HTTP simulé
(`httpx.MockTransport`) absorbe toutes les requêtes (ES-09).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tscan_core.correlation import run_correlation
from tscan_core.db import get_engine, get_session, init_db
from tscan_core.importers import import_file
from tscan_core.importers.reobserve_service import (
    _corroborated_import_ids,
    _corroboration_sets,
    _is_reobservable_url,
    reobserve_imported_scan,
)
from tscan_core.models import Finding, FindingStatus, Scan, ScanType

FIXTURES = Path(__file__).parent / "fixtures"


class _Site:
    """Mock transport d'un petit site cible, avec des endpoints contrôlables."""

    def __init__(self, admin_status: int = 200, dead_paths: set[str] | None = None) -> None:
        self.admin_status = admin_status
        self.dead_paths = dead_paths or set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/admin/":
            return httpx.Response(self.admin_status, text="<html><body>admin</body></html>")
        if path in self.dead_paths:
            return httpx.Response(404, text="<html><body>404</body></html>")
        # Tout le reste répond 200 pour que le scan actif se déroule normalement.
        return httpx.Response(200, text="<html><body>ok</body></html>")


def _imported_scan(session, target: str = "example.test"):
    """Crée un scan importé en base (3 constats nuclei) et retourne son id."""
    scan = import_file(
        session, source="nuclei", target=target, file_path=FIXTURES / "nuclei_sample.jsonl"
    )
    return scan


def test_reobserve_requires_an_import_scan(lab_server) -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        # Crée un scan actif (non-import) minimal via une importation est exclue ;
        # on fabrique un scan ACTIVE_SCAN directement.
        active = Scan(scan_type=ScanType.ACTIVE_SCAN, source="tscan_engine", target="example.test")
        session.add(active)
        session.commit()

        with pytest.raises(ValueError, match="pas un import"):
            reobserve_imported_scan(session, active.id)


def test_reobserve_flags_imported_finding_when_fact_is_gone(lab_server) -> None:
    """Endpoint /admin/ (constat importé « panel d'administration exposé ») :
    la détection active ne le trouve plus (404) et la ré-observation ciblée
    renvoie 404 → le constat importé est placé en potentiel faux positif."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(transport=httpx.MockTransport(_Site(admin_status=404)), follow_redirects=True)
    try:
        with get_session(engine) as session:
            scanned = _imported_scan(session, target="http://example.test")
            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )
            findings = session.query(Finding).filter_by(scan_id=scanned.id).all()

            admin = next(f for f in findings if f.category == "broken_access_control")
            assert admin.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert any(
                h.new_status == FindingStatus.POTENTIAL_FALSE_POSITIVE
                for h in admin.status_history
            )
            assert outcome.total == 3
            assert outcome.potential_false_positives >= 1
            assert any(f["url"] == "http://example.test/admin/" for f in outcome.flagged)
    finally:
        client.close()


def test_reobserve_does_not_flag_when_resource_still_present(lab_server) -> None:
    """Endpoint toujours accessible (200) et non corroboré : le constat importé
    n'est pas contredit par la disponibilité → on ne le marque pas faux positif
    (revue analytique laissée à l'analyste)."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(transport=httpx.MockTransport(_Site(admin_status=200)), follow_redirects=True)
    try:
        with get_session(engine) as session:
            scanned = _imported_scan(session, target="http://example.test")
            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )
            findings = session.query(Finding).filter_by(scan_id=scanned.id).all()
            admin = next(f for f in findings if f.category == "broken_access_control")
            # Pas de faux positif : ressource toujours présente.
            assert admin.status != FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert outcome.potential_false_positives == 0
    finally:
        client.close()


def test_is_reobservable_url() -> None:
    assert _is_reobservable_url("http://example.test/admin/") is True
    assert _is_reobservable_url("https://example.test/x") is True
    assert _is_reobservable_url("example.test") is False
    assert _is_reobservable_url(None) is False


def test_corroborated_import_ids_matches_category_and_location() -> None:
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scanned = _imported_scan(session, target="http://example.test")
        imported = session.query(Finding).filter_by(scan_id=scanned.id).all()

        # Scan actif de ré-observation : crée un constat sur le même endroit et
        # la même catégorie que l'un des importés (ex. fichier sensible jQuery).
        active = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="http://example.test",
        )
        session.add(active)
        session.commit()
        jquery = next(f for f in imported if "jquery" in (f.matched_at or ""))
        active_finding = Finding(
            scan_id=active.id,
            title="fichier sensible",
            category=jquery.category,
            severity="medium",
            matched_at=jquery.matched_at,
            status=FindingStatus.PROBABLE,
        )
        session.add(active_finding)
        session.commit()

        corroborated = _corroborated_import_ids(
            imported, session.query(Finding).filter_by(scan_id=active.id).all()
        )
        assert jquery.id in corroborated


def test_corroboration_sets_marks_duplicate_active_findings() -> None:
    """La ré-observation doit retirer les constats actifs qui dupliquent un
    constat déjà présent dans l'import (même vulnérabilité : catégorie +
    emplacement), tout en conservant les constats actifs réellement nouveaux
    (demande utilisateur 26/09/2026)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scanned = _imported_scan(session, target="http://example.test")
        imported = session.query(Finding).filter_by(scan_id=scanned.id).all()

        active = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="http://example.test",
        )
        session.add(active)
        session.commit()

        jquery = next(f for f in imported if "jquery" in (f.matched_at or ""))
        dup_active = Finding(
            scan_id=active.id,
            title="fichier sensible",
            category=jquery.category,
            severity="medium",
            matched_at=jquery.matched_at,
            status=FindingStatus.PROBABLE,
        )
        new_active = Finding(
            scan_id=active.id,
            title="XSS détecté par Tscan",
            category="xss",
            severity="high",
            matched_at="http://example.test/search",
            status=FindingStatus.PROBABLE,
        )
        session.add_all([dup_active, new_active])
        session.commit()

        corroborated, duplicates = _corroboration_sets(
            imported, session.query(Finding).filter_by(scan_id=active.id).all()
        )
        assert jquery.id in corroborated
        assert dup_active.id in duplicates
        assert new_active.id not in duplicates


def test_reobserve_drops_active_findings_duplicating_import(lab_server) -> None:
    """Invariante de la déduplication (demande utilisateur 26/09/2026) : après
    `reobserve_imported_scan`, aucun constat du scan actif de ré-observation ne
    duplique un constat de l'import — les corroborations en doublon sont
    retirées, seuls les constats actifs réellement nouveaux demeurent."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(
        transport=httpx.MockTransport(_Site(admin_status=404)), follow_redirects=True
    )
    try:
        with get_session(engine) as session:
            scanned = _imported_scan(session, target="http://example.test")
            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )
            imported = session.query(Finding).filter_by(scan_id=scanned.id).all()
            active_findings = session.query(Finding).filter_by(
                scan_id=outcome.active_scan_id
            ).all()

            _, duplicates = _corroboration_sets(imported, active_findings)
            assert duplicates == set()
    finally:
        client.close()


def test_reobserve_corroborates_with_prior_active_scan(lab_server) -> None:
    """Workflow « scanner la cible avant d'importer » : un constat d'un scan
    actif Tscan ANTÉRIEUR (même catégorie + emplacement normalisé) corrobore le
    constat importé correspondant, même quand la ré-observation bornée ne le
    recouvre pas.

    Régression (27/09/2026) : avant le correctif, `reobserve_imported_scan` ne
    tenait compte QUE des constats de son propre scan de ré-observation — un
    import completement corroboré par un scan actif lancé au préalable restait
    « non reproduit » (reproduced=0). L'import ciblé ici ne porte qu'un seul
    constat (jQuery) : une seule contre-référence, le scan antérieur, le rend
    décisif."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(
        transport=httpx.MockTransport(_Site(admin_status=200)), follow_redirects=True
    )
    try:
        with get_session(engine) as session:
            scanned = Scan(
                scan_type=ScanType.IMPORT,
                source="nuclei",
                target="http://example.test",
            )
            session.add(scanned)
            session.flush()
            jquery = Finding(
                scan_id=scanned.id,
                title="jQuery",
                category="vulnerable_component",
                severity="medium",
                matched_at="http://example.test/js/jquery-1.11.0.min.js",
                status=FindingStatus.PROBABLE,
            )
            session.add(jquery)
            session.commit()

            # Scan actif Tscan exécuté AVANT l'import, contenant déjà le constat
            # correspondant au fichier jQuery importé.
            prior = Scan(
                scan_type=ScanType.ACTIVE_SCAN,
                source="tscan_engine",
                target="http://example.test/",
            )
            session.add(prior)
            session.commit()
            prior_finding = Finding(
                scan_id=prior.id,
                title="fichier sensible",
                category=jquery.category,
                severity="medium",
                matched_at=jquery.matched_at,
                status=FindingStatus.PROBABLE,
            )
            session.add(prior_finding)
            session.commit()

            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )

            # Corroboré par le scan antérieur → reproduit, jamais flagué, jamais
            # contradictoire (la cible répond 200 : pas de potentiel faux positif).
            assert outcome.reproduced == 1
            assert outcome.not_reproducible == 0
            assert outcome.potential_false_positives == 0
            assert jquery.id not in {f["id"] for f in outcome.flagged}
            assert jquery.status != FindingStatus.POTENTIAL_FALSE_POSITIVE

            # Le constat du scan antérieur n'est ni supprimé, ni ré-scoré.
            assert session.get(Finding, prior_finding.id) is not None
            assert session.get(Finding, prior_finding.id).status == FindingStatus.PROBABLE
    finally:
        client.close()


def test_corroboration_title_pass_matches_category_title_and_host() -> None:
    """Passe titre de `_corroboration_sets` : un constat actif (avant ici —
    antérieur) de même catégorie + titre normalisé + hôte corrobore un constat
    importé dont l'URL diffère (la passe « catégorie + emplacement normalisé »
    ne suffisait pas : l'analyse de la base réelle ne corroborait que 3 alerte
    ZAP au lieu de 4)."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scanned = Scan(
            scan_type=ScanType.IMPORT,
            source="zap",
            target="http://example.test",
        )
        session.add(scanned)
        session.flush()
        imported = Finding(
            scan_id=scanned.id,
            title="Content Security Policy (CSP) Header Not Set",
            category="security_misconfiguration",
            severity="medium",
            matched_at="http://example.test/catalogue?page=1",
            status=FindingStatus.PROBABLE,
        )
        session.add(imported)
        session.commit()

        prior = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="http://example.test/",
        )
        session.add(prior)
        session.commit()
        prior_finding = Finding(
            scan_id=prior.id,
            title="Content Security Policy (CSP) Header Not Set",
            category="security_misconfiguration",
            severity="medium",
            matched_at="http://example.test/",
            status=FindingStatus.PROBABLE,
        )
        session.add(prior_finding)
        session.commit()

        corroborated, duplicates = _corroboration_sets(
            [imported],
            session.query(Finding).filter_by(scan_id=prior.id).all(),
        )

        # URL differentes → la passe exacte (catégorie + emplacement normalisé)
        # ne suffit pas ; le titre normalisé identique (« content security policy
        # csp header not set ») + hôte corrobore la même vulnérabilité du site.
        assert imported.id in corroborated
        assert prior_finding.id in duplicates


def test_corroboration_title_pass_tolerates_other_category_import() -> None:
    """Régression (11/09/2026) : les alertes de constat ZAP sans menace propre
    (« Requête d'authentification identifiée » 10111, « Réponse de gestion de
    session identifiée » 10112) sont catégorisées `other` à l'import (aucun
    mot-clé de menace du MVP). Le détecteur moteur émet la même vulnérabilité
    en `security_misconfiguration` : la passe titre doit corréler malgré la
    divergence de catégorie, le titre canonique étant identique."""
    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        scanned = Scan(
            scan_type=ScanType.IMPORT,
            source="zap",
            target="http://example.test",
        )
        session.add(scanned)
        session.flush()
        imported = Finding(
            scan_id=scanned.id,
            title="Requête d'authentification identifiée",
            category="other",
            severity="info",
            matched_at="http://example.test/",
            status=FindingStatus.PROBABLE,
        )
        session.add(imported)
        session.commit()

        active = Scan(
            scan_type=ScanType.ACTIVE_SCAN,
            source="tscan_engine",
            target="http://example.test/",
        )
        session.add(active)
        session.commit()
        active_finding = Finding(
            scan_id=active.id,
            title="Authentication Request Identified",
            category="security_misconfiguration",
            severity="info",
            matched_at="http://example.test/login",
            status=FindingStatus.PROBABLE,
        )
        session.add(active_finding)
        session.commit()

        corroborated, duplicates = _corroboration_sets(
            [imported],
            session.query(Finding).filter_by(scan_id=active.id).all(),
        )

        assert imported.id in corroborated
        assert active_finding.id in duplicates


def test_correlation_with_reobserve_flags_dead_url_as_potential_false_positive() -> None:
    """Régression (11/09/2026) : `run_correlation(..., reobserve=True)` déclenche
    une ré-observation ciblée par URL des constats importés non corroborés.

    Import des 3 constats nuclei (`/`, jQuery, `/admin/`) : le mock renvoie 404
    pour `/admin/`. La corrélation avec ré-observation doit placer le constat
    `broken_access_control` en « potentiel faux positif » (preuve de
    contradiction RF-23) avant tout scoring, et scorer les deux autres sans les
    flaguer. Le verdict acquis est ensuite protégé (jamais retiré)."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(
        transport=httpx.MockTransport(_Site(admin_status=404)),
        follow_redirects=True,
    )
    try:
        with get_session(engine) as session:
            scanned = _imported_scan(session, target="http://example.test")

            updated = run_correlation(
                session,
                target="http://example.test",
                reobserve=True,
                http_client=client,
            )
            findings = session.query(Finding).filter_by(scan_id=scanned.id).all()

            admin = next(f for f in findings if f.category == "broken_access_control")
            assert admin.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert admin in updated
            assert any(
                h.new_status == FindingStatus.POTENTIAL_FALSE_POSITIVE
                for h in admin.status_history
            )
            for finding in findings:
                if finding.category != "broken_access_control":
                    assert finding.status != FindingStatus.POTENTIAL_FALSE_POSITIVE

            # Re-corrélation : le verdict demeure (jamais retiré par un calcul).
            updated_again = run_correlation(
                session,
                target="http://example.test",
                reobserve=True,
                http_client=client,
            )
            assert admin.id not in [f.id for f in updated_again]
            assert session.get(Finding, admin.id).status == FindingStatus.POTENTIAL_FALSE_POSITIVE
    finally:
        client.close()


def test_import_task_accepts_rex_flag_and_returns_import_payload_without_rex() -> None:
    """La fabrique GUI `import_task` accepte le drapeau `rex` et, sans lui,
    retourne le résumé d'import (aucun scan de ré-observation n'est lancé)."""
    from tscan_gui.workers import import_task

    engine = get_engine(":memory:")
    init_db(engine)

    with get_session(engine) as session:
        run = import_task(
            FIXTURES / "nuclei_sample.jsonl", source="nuclei", target="example.test", rex=False
        )
        payload = run(session)
        assert payload["count"] == 3
        assert payload["source"] == "nuclei"
        assert "rex" not in payload


def test_correlation_never_erases_potential_false_positive_verdict() -> None:
    """Régression (11/09/2026) : la corrélation ne doit JAMAIS retirer un
    verdict `Potentiel faux positif` posé par la ré-observation (RF-12/RF-23).

    Avant le correctif, `run_correlation` ré-scorait les constats déjà placés
    en potentiel faux positif et les « récompensait » vers `Probable` dès que
    leur score statique de règle dépassait le seuil (0,55). Le verdict de
    contradiction issus de la ré-observation était ainsi perdu."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(
        transport=httpx.MockTransport(_Site(admin_status=404)), follow_redirects=True
    )
    try:
        with get_session(engine) as session:
            scanned = _imported_scan(session, target="http://example.test")
            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )
            assert outcome.potential_false_positives >= 1
            flagged_ids = {f["id"] for f in outcome.flagged}

            # La corrélation s'exécute sur la même base.
            updated = run_correlation(session, target="http://example.test")

            # Les constats flagués ne sont ni re-scorés, ni changés de statut.
            for finding in session.query(Finding).filter_by(scan_id=scanned.id).all():
                if finding.id in flagged_ids:
                    assert finding.id not in [f.id for f in updated]
                    assert finding.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
    finally:
        client.close()


def test_reobserve_flags_information_disclosure_finding_when_url_is_gone() -> None:
    """Régression (11/09/2026) : un constat `information_disclosure` (ex. page
    phpinfo, fichier sensible) dont l'URL renvoie 404 doit être flagué en
    potentiel faux positif. Avant le correctif, cette catégorie manquait dans
    `_URL_REOBSERVABLE_CATEGORIES` : la ré-observation ciblée restait sans
    effet et le faux positif n'était jamais signalé."""
    engine = get_engine(":memory:")
    init_db(engine)

    client = httpx.Client(
        transport=httpx.MockTransport(
            _Site(admin_status=200, dead_paths={"/info.php"})
        ),
        follow_redirects=True,
    )
    try:
        with get_session(engine) as session:
            import_file(
                session,
                source="nuclei",
                target="http://example.test",
                file_path=FIXTURES / "nuclei_phpinfo.jsonl",
            )
            scanned = (
                session.query(Scan).filter_by(scan_type=ScanType.IMPORT).order_by(Scan.id.desc()).first()
            )
            outcome = reobserve_imported_scan(
                session,
                scanned.id,
                target="http://example.test",
                http_client=client,
            )

            phpinfo = (
                session.query(Finding)
                .filter_by(scan_id=scanned.id, category="information_disclosure")
                .first()
            )
            assert phpinfo is not None
            assert phpinfo.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            assert any(f["url"].endswith("/info.php") for f in outcome.flagged)
    finally:
        client.close()
