# Tscan

Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité,
développée dans le cadre d'un stage à l'ANTIC.

Tscan importe et fiabilise les résultats de scanners externes (Nuclei, OWASP ZAP), et
exécute son propre moteur de scan actif ciblé sur le périmètre web, avec pour objectif
de réduire les faux positifs par corrélation et validation active non destructive.

## Statut du projet

🚧 **En cours de développement — semaines 1 à 10 livrées et vérifiées ; application desktop (semaine 10) corrigée et opérationnelle (27/08/2026) ; reste la semaine 11 (durcissement, empaquetage, démonstration).**

Le cahier des charges complet (contexte, objectifs, étude de l'existant, besoins,
architecture, technologies, planning) se trouve dans `docs/cahier_des_charges.pdf`.

Fonctionnalités disponibles à ce stade :
- Import de résultats Nuclei (JSONL), OWASP ZAP (JSON) et Nessus/OpenVAS (XML .nessus) vers le modèle pivot `Finding`
- Système de règles YAML versionnées (`rules/`), une par famille du MVP
- Pré-filtrage contextuel, corrélation multi-sources, scoring de confiance explicable
- Statuts automatiques (Probable / Potentiel faux positif) et correction manuelle avec historique
- **Scénario A démontrable en CLI** : import (x2 sources) → corrélation → statuts → preuves → correction
- **Base de connaissances CVE/NVD (à la demande, avec cache local) et CISA KEV (synchronisation complète)**,
  table de référence CWE minimale (`knowledge/`), commandes `tscan lookup-cve` / `tscan update-kev`
- **Scan actif autorisé** (`tscan scan --authorized`) : par défaut, le scan lance la reconnaissance (statut, TLS, technologies), le fingerprinting et **toutes les familles de détection non destructives** (en-têtes, clickjacking, BAC, composants, XSS, CSRF, SQLi, fichiers sensibles, listing, CORS, TLS). Périmètre restreignable par `--tests` (profondeur, durée, types — ES-01/ES-02), mode sécurisé GET-only par défaut (ES-03), journalisation systématique (ES-05).
- **Semaine 8 — détections actives non destructives (RF-19, RF-21, RF-22)** : XSS réfléchi,
  formulaires POST sans jeton CSRF, infection SQL error-based, fichiers sensibles exposés,
  listing de répertoire, configuration CORS permissive, certificat/protocole TLS faible.
  Sondes GET bénignes uniquement (ES-03), périmètre fermé par type de test (`--tests`),
  durée maximale bornée, constats au statut Probable.

- **Validation active non destructive (RF-23)** : chaque constat `Probable` du scan actif est soumis à une seconde observation non destructive ; le fait décisif « reproductible » **renforce le score de confiance** du constat (plafonné à **0,85**) mais le laisse au statut **Probable** — le moteur ne confirme jamais : **« Confirmée » est un verdict d'analyste** (RF-12), posé par la correction manuelle (`tscan correct`, fenêtre desktop) avec un score de **0,95**. Un fait **contredit** place le constat en **Potentiel faux positif** pour revue prioritaire ; une sonde en échec laisse le constat tel quel (ES-05).
- **Reporting (RF-27/28/29)** : générateur de rapport (résumé exécutif par gravité/statut + détails techniques, preuves, recommandations liées à des sources vérifiables OWASP/CWE) et commande `tscan report` avec export **HTML** et **Markdown**.
- **Scénarios A et B démontrables en CLI de bout en bout** (import → corrélation → scan → validation active → rapport).
- **Application desktop (semaine 10, opérationnelle au 27/08/2026)** : fenêtre principale `tscan_gui/main.py` (`MainWindow`) — liste des résultats filtrable (statut/gravité/cible/recherche, RF-11), détail avec preuves, score et historique (RF-12), correction manuelle de statut avec raison (ES-06), import depuis l'interface (RF-01), scan avec définition du périmètre (RF-24 / ES-01/02), corrélation, génération de rapport (HTML/Markdown). Les opérations longues (import, corrélation, scan, rapport) s'exécutent en arrière-plan (`tscan_gui/workers.py`, RNF-03), avec les dialogues `ImportDialog` / `ScanDialog` / `ReportDialog` (`tscan_gui/dialogs.py`). Logique de présentation testée sans écran (10 tests, `tests/test_gui_viewmodel.py`). Lancement : `python -m tscan_gui`.

Interface desktop : fenêtre fonctionnelle et testée en headless ; parcours manuels UC1→UC5 à valider sur un poste avec affichage (semaine 11). Fanion de démarrage rapide : le refactor S10 avait laissé `dialogs.py` syntaxiquement invalide et `main.py` manquant — corrigé (27/08/2026), avec ajout de `ReportDialog`.

## Correctifs et ajouts confirmés (début semaine 11, 28/08/2026)

- **Corrélation** : `run_correlation` **n'inclut plus les résultats du scan actif**
  (source `tscan_engine`) ni les résultats déjà **Confirmés** (RF-12/RF-23). Avant
  ce correctif, corréler après un scan rétrogradait les constats `Confirmée`
  (score 0,90 posé par la re-vérification active) vers `Probable` avec un score
  de règle 0,60-0,70 — incohérent avec le cahier des charges (la corrélation
  classe les résultats **importés** en attente de validation, elle ne retire
  jamais une confirmation acquise).
- **Progression de scan en temps réel** : le moteur de scan émet désormais des
  `ScanProgressEvent` (module `tscan_core.scan.progress`) à chaque étape
  observable (sondes GET, TLS, crawl, détections, re-vérifications RF-23).
  - Cœur : `run_recon_scan(..., on_event=...)` + crawl + détections + confirmation.
  - Desktop : nouveau panneau `ScanProgressPanel` sous la liste des résultats
    (barre de progression + journal des opérations, comme OWASP ZAP), alimenté via
    le signal `progress_emitted` de `workers.py` (`run(session, emit)`).
  - Tests : `tests/test_progress.py` (start→done, sondes GET individuelles,
    rétro-compatibilité sans écouteur).
- **Confirmation active : le moteur ne confirme plus (RF-12/RF-23, 28/08/2026)** :
  la re-vérification active ajuste la confiance des constats du scan actif sans
  jamais poser « Confirmée » : fait reproduit -> score renforcé plafonné à **0,85**,
  statut laissé `Probable` ; fait contredit (familles à re-vérification précise) ->
  statut `Potentiel faux positif` ; sonde en échec -> constat laissé tel quel (ES-05).
  La confirmation (score **0,95**), le potentiel faux positif (0,20) et le faux
  positif (0,00) sont désormais des **décisions humaines** portées par
  `correct_status_manually` (`tscan_core.status`), utilisée par `tscan correct` et
  par la fenêtre desktop (`MainWindow._correct_status`). Observabilité alignée :
  compteurs `reproduced` / `potential_false_positives` / `probe_errors`
  (progressions et message de fin). Corrélation cohérente (elle exclut
  `tscan_engine` et les verdicts humains). Tests mis à jour + 4 nouveaux dédiés à
  `correct_status_manually` : **suite complète de 227 tests verts**, `ruff` propre.
- **Migration des anciennes données (RF-12, 28/08/2026)** : les bases locales
  créées par l'ancien moteur portaient des constats `Confirmée` auto-posés par la
  re-vérification (score 0,90). `init_db` exécute désormais une migration de
  données idempotente (`db._migrate_legacy_engine_confirmations`) : tout constat
  `Confirmée` dont la dernière trace venait de `tscan_engine` est replacé en
  `Probable` (score plafonné 0,85) avec une entrée `StatusHistory` explicite.
  Une confirmation posée par un **analyste** n'est jamais touchée. Vérifié sur la
  base réelle : **15 anciens `Confirmée` moteur retirés** (106 constats tous
  `Probable`), 3 tests de régression de migration.
- **Faux positifs démontrés** : la re-vérification contredit désormais un fait
  non reproductible (familles à re-vérification précise) et place le constat en
  `Potentiel faux positif` (score réduit, historique tracé, ES-06). Nouveau test
  d'intégration `test_confirmation.py::test_confirmation_contradicted_fact_flags_potential_false_positive`
  avec un serveur simulé qui expose puis protège `/admin/`.

## Structure du dépôt

```
src/
  tscan_core/       Bibliothèque cœur partagée (import, corrélation, détection, reporting)
  tscan_cli/        Interface en ligne de commande (Typer)
  tscan_gui/        Application desktop (PySide6)
rules/              Règles de détection versionnées (YAML)
tests/              Tests automatisés (pytest)
docs/               Documentation du projet
```

## Installation (développement)

```bash
python3 -m venv .venv
source .venv/bin/activate      # sous Windows : .venv\Scripts\activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
```

## Contrôle de sécurité des dépendances (ES-12)

Vérification que les dépendances tierces de Tscan ne présentent pas de
vulnérabilité connue (source OSV / PyPA-advisory-db) :

```bash
pip install -e ".[dev]"          # fournit pip-audit
python scripts/audit_deps.py     # audit des dépendances installées
```

Cet audit fait partie de la checklist transverse de sécurité (ES-12) ; il doit
être rejoué à chaque modification de `pyproject.toml`.

## Licence

Non définie à ce stade (projet de stage, usage interne ANTIC).
