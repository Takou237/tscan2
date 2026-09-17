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
from tscan_core.importers.reobserve_service import REOBERVE_CRAWL_MAX_PAGES, reobserve_imported_scan
from tscan_core.importers.zap import ZapParseError
from tscan_core.knowledge_base import UpdateManagerError, lookup_component, update_kev_catalog
from tscan_core.models import Finding, FindingStatus
from tscan_core.recon.client import ReconError
from tscan_core.reporting import SEVERITY_ORDER, generate_report
from tscan_core.reporting.render_html import render_html
from tscan_core.reporting.render_markdown import render_markdown
from tscan_core.scan.blocking import detect_target_blocking
from tscan_core.scan.config import ScanConfig, ScanConfigError
from tscan_core.scan.orchestrator import run_recon_scan
from tscan_core.status import correct_status_manually

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
    rex: Annotated[
        bool,
        typer.Option(
            "--rex",
            help="Après l'import, lance une ré-observation active sur la cible et corrèle "
            "les constats importés avec le scan actif pour détecter d'éventuels faux positifs "
            "(autorisation implicite, ES-01 : fournir un import pour une cible vaut autorisation).",
        ),
    ] = False,
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

    if rex:
        typer.echo(
            f"Ré-observation active (--rex) sur la cible {target!r} "
            f"(≤ {REOBERVE_CRAWL_MAX_PAGES} pages crawlées)…"
        )
        try:
            with get_session(engine) as session:
                outcome = reobserve_imported_scan(session, scan.id)
        except (ReconError, ScanConfigError) as exc:
            typer.echo(f"Ré-observation interrompue : {exc}", err=True)
            raise typer.Exit(code=1) from exc

        typer.echo(
            f"Ré-observation terminée (scan actif #{outcome.active_scan_id}) : "
            f"{outcome.total} constat(s) importé(s) — {outcome.reproduced} corroboré(s), "
            f"{outcome.potential_false_positives} potentiel(s) faux positif(s), "
            f"{outcome.not_reproducible} non concluant(s) (revue analytique requise, RF-12)."
        )
        if outcome.blocked:
            typer.echo(
                "⚠ AVERTISSEMENT : la cible a refusé la ré-observation active "
                f"({outcome.blocked_reason}). Le bilan est sous-estimé : peu de "
                "constats ont pu être produits pour comparer — réessayez plus "
                "tard ou depuis une autre adresse IP (ES-05).",
                err=True,
            )


@app.command("correlate")
def correlate_command(
    target: Annotated[
        str | None, typer.Option("--target", "-t", help="Limiter la corrélation à cette cible.")
    ] = None,
    rex: Annotated[
        bool,
        typer.Option(
            "--rex",
            help=(
                "Ré-observer par URL les constats importés non corroborés : une ressource "
                "introuvable (404/410) déclare le constat « potentiel faux positif » "
                "pendant la corrélation (RF-23). Best-effort : une panne réseau laisse "
                "les constats tel quels."
            ),
        ),
    ] = False,
) -> None:
    """Corrèle et score les résultats importés (RF-08, RF-09, RF-10)."""
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        updated = run_correlation(session, target=target, reobserve=rex)

        if not updated:
            typer.echo("Aucun résultat à corréler.")
            return

        if rex:
            pfp = sum(
                1 for f in updated if f.status == FindingStatus.POTENTIAL_FALSE_POSITIVE
            )
            typer.echo(
                f"Ré-observation ciblée : {pfp} potentiel(s) faux positif(s) détecté(s) "
                "(ressource introuvable sur la cible)."
            )
        probable = sum(1 for f in updated if f.status == FindingStatus.PROBABLE)
        typer.echo(
            f"Corrélation terminée : {len(updated)} résultat(s) traité(s) "
            f"({probable} probable(s), {len(updated) - probable} en attente de revue)."
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


def _warn_if_target_blocked(outcome) -> None:
    """Avertit quand la cible a refusé le scan (racine 401/403/429, échec de
    la sonde racine) : le bilan est incomplet, il ne faut pas le lire comme
    un site sain (recon_json = source de vérité du diagnostic)."""
    blocked, reasons = detect_target_blocking(outcome.recon_observations)
    if blocked:
        typer.echo(
            "⚠ AVERTISSEMENT : la cible semble bloquer le scanner ("
            + "; ".join(reasons)
            + "). Le bilan ci-dessus est incomplet — réessayez plus tard ou "
            "depuis une autre adresse IP (ES-05).",
            err=True,
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
        # Décision humaine (RF-12 / ES-06) : ajuste le statut ET le score de
        # confiance. La confirmation est un verdict d'analyste — jamais du
        # moteur de scan.
        correct_status_manually(
            session, finding, new_status, changed_by=getpass.getuser(), reason=reason
        )

    typer.echo(f"Résultat #{finding_id} : statut corrigé de {old_status} vers {status}.")


@app.command("scan")
def scan_command(
    target: Annotated[str, typer.Argument(help="Cible autorisée (URL http/https, ES-01).")],
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="Confirmation explicite que la cible est autorisée."),
    ] = False,
    max_duration: Annotated[
        int | None,
        typer.Option("--max-duration", "-d", help="Durée maximale du scan en secondes. Par défaut (omise) : aucun plafond — le scan s'arrête quand le crawl a épuisé les pages ou via Ctrl+C (parité OWASP ZAP)."),
    ] = None,
    max_depth: Annotated[
        int, typer.Option("--max-depth", help="Profondeur maximale de crawl (parité ZAP : par défaut, sans borne).")
    ] = 0,
    max_pages: Annotated[
        int | None,
        typer.Option("--max-pages", help="Nombre maximal de pages crawlées. Par défaut : 40 (durée prévisible). 0 = sans borne (crawl exhaustif, parité OWASP ZAP)."),
    ] = None,
    tests: Annotated[
        str | None,
        typer.Option("--tests", help="Restreindre aux types de test listés (séparés par des virgules). Sans cette option, toutes les détections non destructives sont exécutées."),
    ] = None,
    request_delay: Annotated[
        float,
        typer.Option("--delay", help="Délai en secondes entre chaque requête envoyée à la cible (limitation de débit, évite les timeouts)."),
    ] = 0.05,
) -> None:
    """Lance un scan actif autorisé (RF-15 à RF-23).

    Exige `--authorized` (ES-01) : sans confirmation explicite, aucun scan ne
    part. Par défaut, le scan lance la reconnaissance, le fingerprinting et
    TOUTES les familles de détection non destructives (en-têtes, clickjacking,
    BAC, composants, XSS, CSRF, SQLi, fichiers sensibles, listing, CORS, TLS).
    Le périmètre peut être restreint par `--tests` (ES-02) ; le mode sécurisé
    non destructif est la valeur par défaut (ES-03).

    Le crawl explore un échantillon borné de pages (40 max par défaut) pour
    garder une durée prévisible (ES-02) ; le scan peut être interrompu à tout
    moment par Ctrl+C (les constats déjà trouvés sont conservés).
    """
    engine = get_engine()
    init_db(engine)

    allowed_tests = None
    if tests is not None:
        allowed_tests = frozenset(part.strip() for part in tests.split(",") if part.strip())

    try:
        config_kwargs: dict = {
            "target": target,
            "authorized": authorized,
            "max_depth": max(1, max_depth) if max_depth and max_depth >= 1 else 1,
        }
        if max_duration is not None:
            config_kwargs["max_duration_seconds"] = max_duration
        if max_depth:
            # --max-depth borne la profondeur de crawl ; 0 (défaut) = sans borne.
            config_kwargs["crawl_max_depth"] = max_depth
        if max_pages is not None:
            # --max-pages borne le nombre de pages crawlées ; 0 = sans borne
            # (crawl exhaustif, parité ZAP) ; omis = défaut de 40.
            config_kwargs["crawl_max_pages"] = max_pages if max_pages > 0 else None
        if allowed_tests is not None:
            config_kwargs["allowed_tests"] = allowed_tests
        config = ScanConfig(**config_kwargs)
    except ScanConfigError as exc:
        typer.echo(f"Erreur : {exc}", err=True)
        raise typer.Exit(code=1) from exc

    # Interruption manuelle (Ctrl+C) : un gestionnaire de signal lève le
    # drapeau ScanInterrupt ; le scan s'arrête proprement aux points d'arrêt
    # (parité OWASP ZAP), quand le crawl n'a pas encore atteint l'épuisement.
    import signal

    from tscan_core.scan.interrupt import ScanInterrupt

    interrupt = ScanInterrupt()

    def _on_sigint(signum, frame):
        interrupt.stop()

    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _on_sigint)

    try:
        with get_session(engine) as session:
            try:
                outcome = run_recon_scan(
                    session,
                    config,
                    request_delay=max(0.0, request_delay),
                    interrupt=interrupt,
                )
            except ScanConfigError as exc:
                typer.echo(f"Erreur : {exc}", err=True)
                raise typer.Exit(code=1) from exc
            except ReconError as exc:
                typer.echo(f"Erreur de scan : {exc}", err=True)
                raise typer.Exit(code=1) from exc
    finally:
        signal.signal(signal.SIGINT, previous_sigint)

    if outcome.interrupted:
        typer.echo(
            f"Scan actif #{outcome.scan_id} interrompu par l'utilisateur après "
            f"{outcome.duration_seconds:.1f}s — {len(outcome.findings)} constat(s) "
            "déjà enregistré(s)."
        )
    else:
        typer.echo(
            f"Scan actif #{outcome.scan_id} terminé en {outcome.duration_seconds:.1f}s "
            f"sur {outcome.target}."
        )
    if outcome.findings:
        typer.echo(
            f"Re-vérification (RF-23) : {outcome.reproduced} constat(s) "
            f"reproductible(s), {outcome.potential_false_positives} potentiel(s) "
            "faux positif(s). Aucun constat n'est automatiquement Confirmé : "
            "la confirmation finale relève de la revue de l'analyste (RF-12)."
        )
    _warn_if_target_blocked(outcome)

    if outcome.technologies:
        typer.echo("Technologies détectées :")
        for tech in outcome.technologies:
            version = f" {tech.version}" if tech.version else ""
            typer.echo(f"  - {tech.label}{version}")

    if outcome.findings:
        ordered = sorted(
            outcome.findings,
            key=lambda f: _severity_rank(f.severity),
        )
        typer.echo(f"Résultats de sécurité ({len(outcome.findings)}) :")
        for finding in ordered:
            typer.echo(
                f"  [{finding.severity}] {finding.title}  ({finding.matched_at})"
            )
    else:
        typer.echo("Aucun résultat de sécurité détecté.")


@app.command("lookup-cve")
def lookup_cve_command(
    component: Annotated[str, typer.Argument(help="Composant (ex : 'jquery 1.11.0' ou une chaîne à chercher).")],
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Ne lire que le cache local (aucun appel réseau, ES-09)."),
    ] = False,
) -> None:
    """Recherche les CVE connues pour un composant (RF-18, RF-33).

    Interroge NVD à la demande et met le résultat en cache local (réutilisable
    hors-ligne ensuite). `--offline` ne lit que le cache, sans accéder au réseau.
    """
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        try:
            records = lookup_component(session, component, allow_network=not offline)
        except UpdateManagerError as exc:
            typer.echo(f"Erreur : {exc}", err=True)
            raise typer.Exit(code=1) from exc

    if not records:
        typer.echo(f"Aucune CVE connue pour {component!r}.")
        return

    typer.echo(f"{len(records)} CVE trouvée(s) pour {component!r} :")
    for record in records:
        severity = f" [{record.cvss_severity}]" if record.cvss_severity else ""
        score = f" (CVSS {record.cvss_score})" if record.cvss_score is not None else ""
        desc = (record.description or "")[:120]
        typer.echo(f"  - {record.cve_id}{severity}{score} : {desc}")


@app.command("update-kev")
def update_kev_command() -> None:
    """Synchronise intégralement le catalogue CISA KEV en local (RF-34).

    Action explicite (ES-09) : Tscan ne contacte jamais CISA automatiquement.
    """
    engine = get_engine()
    init_db(engine)

    with get_session(engine) as session:
        try:
            count = update_kev_catalog(session)
        except UpdateManagerError as exc:
            typer.echo(f"Erreur : {exc}", err=True)
            raise typer.Exit(code=1) from exc

    typer.echo(f"Catalogue CISA KEV synchronisé : {count} entrée(s) en local.")


@app.command("report")
def report_command(
    target: Annotated[
        str | None, typer.Option("--target", "-t", help="Limiter le rapport à cette cible.")
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Format d'export : 'html' ou 'markdown'."),
    ] = "html",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Fichier de sortie.")
    ] = None,
) -> None:
    """Génère un rapport de sécurité (RF-27 à RF-29), export HTML ou Markdown."""
    engine = get_engine()
    init_db(engine)

    fmt = (format or "html").lower()
    if fmt not in ("html", "markdown"):
        typer.echo(f"Erreur : format inconnu {format!r} (attendu 'html' ou 'markdown').", err=True)
        raise typer.Exit(code=1)

    with get_session(engine) as session:
        report = generate_report(session, target=target)

    rendered = render_html(report) if fmt == "html" else render_markdown(report)

    if output is None:
        typer.echo(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Rapport écrit dans {output} ({report.total_findings} résultat(s)).")


def _severity_rank(severity: str) -> int:
    """Ordre d'affichage d'une gravité, de la plus critique à la plus faible."""
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return len(SEVERITY_ORDER)


if __name__ == "__main__":
    app()
