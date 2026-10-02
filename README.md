# Tscan

Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité,
développée dans le cadre d'un stage à l'ANTIC.

Tscan importe et fiabilise les résultats de scanners externes (Nuclei, OWASP ZAP,
Nessus/OpenVAS), et
exécute son propre moteur de scan actif ciblé sur le périmètre web, avec pour objectif
de réduire les faux positifs par corrélation et validation active non destructive.

## Statut du projet

✅ **Développement terminé — semaines 1 à 11 livrées et vérifiées (empaquetage PyInstaller + installeur Inno Setup produits le 28/09/2026) ; travaux de fin de stage : parité OWASP ZAP, démarche anti-faux-positifs complète (sentinelle anti soft-404 généralisée, analyse différentielle, re-vérification précise des en-têtes absents), publication sur GitHub, guide utilisateur, rapport de stage. État vérifié au 02/10/2026 : 343 tests verts, ruff propre, 54 règles YAML. Reste (logistique ANTIC) : tests manuels GUI UC1→UC5, installation testée sur machine « propre », répétition de la démonstration.**

Le cahier des charges complet (contexte, objectifs, étude de l'existant, besoins,
architecture, technologies, planning) se trouve dans `docs/cahier_des_charges.pdf`.

Fonctionnalités disponibles à ce stade :
- Import de résultats Nuclei (JSONL), OWASP ZAP (JSON) et Nessus/OpenVAS (XML .nessus) vers le modèle pivot `Finding`
- Système de règles YAML versionnées (`rules/`) — **54 règles** couvrant les familles du MVP et la parité passive OWASP ZAP
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
- **Scénarios A et B démontrables en CLI de bout en bout** (import → corrélation → scan → validation active → rapport) ; **validés sur cibles réelles autorisées** au 08/09/2026 (Scénario B sur `https://polytechnique.cm/` : 6 constats, re-vérification sans faux positif automatique, rapports HTML/Markdown générés).
- **Parité OWASP ZAP et fiabilisation (fin de stage)** : bundle de 17 règles passives aux titres exacts ZAP (`zap_passives.py` + `xss_attribute`), normalisation FR/EN des catégories avec table de synonymes, décompression Brotli (correctif d'un échec silencieux : 0 détection sur les serveurs LiteSpeed), bornes de volume des sondes (durée prévisible), message explicite en cas de blocage anti-bot.
- **Démarche anti-faux-positifs (RF-20)** : verdict sur la **destination** des redirections (302 `/wp-admin/` → page de connexion n'est plus lu comme un panneau exposé), **sentinelle anti soft-404** (contrôle négatif avant sondes de chemins), **signatures de faux positifs** déclaratives dans `knowledge/fp_signatures.yaml`. Mesuré sur la cible d'étude : le faux positif récurrent « panneau d'administration » a disparu (0 occurrence au scan #5 du 17/09/2026).
- **Machine anti-faux-positifs complète (fin de stage, P1→P7)** : **analyse différentielle SQLi** (baseline + charge de rupture + charge corrigée — un marqueur d'erreur n'est concluant que s'il disparaît avec la charge corrigée), **baseline XSS** (un nonce reflété aussi par la requête normale n'est pas un signal), **sentinelle anti soft-404 généralisée** (SQLi, XSS, fichiers sensibles, listing de répertoire — une réponse indiscernable du bruit de fond ne produit plus de constat), **section « Méthodologie anti-faux positifs » dans les rapports** (compteurs de sondes écartées, preuve que les contrôles ont tourné), et **re-vérification précise RF-23 des en-têtes absents et règles parité ZAP** (HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy, Modern Web App : un constat par page avec `probe_info` rejouable — fait reproduit → score renforcé, fait contredit → potentiel faux positif).
- **Publication** : dépôt GitHub `github.com/Takou237/tscan2` avec historique de commits et `.gitignore` protégeant les données de scan locales.
- **Application desktop (semaine 10, opérationnelle au 27/08/2026)** : fenêtre principale `tscan_gui/main.py` (`MainWindow`) — liste des résultats filtrable (statut/gravité/cible/recherche, RF-11), détail avec preuves, score et historique (RF-12), correction manuelle de statut avec raison (ES-06), import depuis l'interface (RF-01), scan avec définition du périmètre (RF-24 / ES-01/02), corrélation, génération de rapport (HTML/Markdown). Les opérations longues (import, corrélation, scan, rapport) s'exécutent en arrière-plan (`tscan_gui/workers.py`, RNF-03), avec les dialogues `ImportDialog` / `ScanDialog` / `ReportDialog` (`tscan_gui/dialogs.py`). Logique de présentation testée sans écran (10 tests, `tests/test_gui_viewmodel.py`). Lancement : `python -m tscan_gui`.

Interface desktop : fenêtre fonctionnelle et testée en headless ; parcours manuels UC1→UC5 à valider sur un poste avec affichage — procédure pas à pas dans `documentation/guide_test_manuel_gui.md`. Reste à livrer : tests manuels GUI et test d'installation de l'installeur sur machine « propre ».

## Empaquetage (PyInstaller, 28/09/2026)

Génération des exécutables Windows autonomes (one-file) :

```bash
.venv/Scripts/python.exe -m PyInstaller tscan.spec --noconfirm
```

Produits dans `dist/` :
- `tscan.exe` — CLI complète (~19 Mo)
- `tscan-gui.exe` — application desktop (~58 Mo)

Les règles de détection (`rules/`, 54 YAML) et la base de connaissances locale
(`knowledge/`) sont **embarquées dans les exécutables** et retrouvées à
l'exécution via `tscan_core.app_paths.data_root()` (compatible développement
et mode gelé PyInstaller). Le fichier `tscan.spec` est versionné pour
reproduire le build ; la CLI gélifiée a été vérifiée de bout en bout
(import Nuclei → corrélation → listage, règles chargées depuis le bundle).

Les deux exécutables portent l'icône `assets/tscan.ico` et les métadonnées
Windows (produit Tscan, version 0.1.0, éditeur ANTIC — `version_info.txt`,
visibles dans Propriétés > Détails).

### Installeur Windows (Inno Setup)

Le script `installer/tscan.iss` est prêt (installation par utilisateur sans
droits administrateur, raccourcis menu Démarrer et bureau, ajout optionnel de
la CLI au PATH, désinstalleur propre) et **déjà compilé le 28/09/2026** :
`installer/Output/tscan-0.1.0-setup.exe` (~95 Mo). Pour recompiler, une fois
[Inno Setup 6](https://jrsoftware.org/isdl.php) installé :

```bash
iscc installer/tscan.iss      # ou via l'IDE Inno Setup : Build > Compile
```

Sortie : `installer/Output/tscan-0.1.0-setup.exe`.

### Démonstrations (scénarios du MVP, chapitre 14)

Scripts prêts à exécuter devant témoin (Git Bash, à la racine du dépôt) :

```bash
bash scripts/demo_scenario_a.sh        # import Nuclei + ZAP → corrélation → statuts → rapport
bash scripts/demo_scenario_b.sh        # scan actif sur labo local → re-vérification → correction → rapport
bash scripts/demo_false_positives.sh   # rapport obsolète importé → ré-observation → taux de faux positifs détectés
```

Chaque script utilise une base de démonstration isolée (la vraie base
`~/.tscan/tscan.db` n'est jamais modifiée), démarre le serveur de laboratoire
local pour le scénario B, et marque une pause à chaque étape pour commenter.
Alternative : remplacer `TSCAN` par `./dist/tscan.exe` pour montrer
l'exécutable empaqueté.

## État de la suite de tests (02/10/2026)

**343 tests pytest verts** (exécutés intégralement le 02/10/2026, 3 min 35 s), `ruff` propre sur `src/` et `tests/`, audit des dépendances ES-12 vert. Les tests couvrent les parseurs d'import, la corrélation, le scoring, les règles, les détections (actives et passives), la machine anti-faux-positifs (sentinelle, analyse différentielle, tests qui forcent le faux positif), la confirmation/re-vérification, le reporting, la migration de données, la GUI (logique viewmodel) et les intégrations de bout en bout (scénarios A et B).

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

## Documentation

| Document | Contenu |
|---|---|
| [`docs/guide_utilisateur.md`](docs/guide_utilisateur.md) | **Guide utilisateur** : installation, commandes CLI, application desktop, parcours UC1→UC5, FAQ |
| [`docs/architecture.md`](docs/architecture.md) | **Architecture technique (version réalisée)** : couches, modèle de données, flux, découplage moteur/règles/connaissances, écarts vs prévisionnel |
| `docs/checklist_projet.md` | Avancement réel semaine par semaine (source de vérité) |
| `docs/cahier_des_charges.pdf` | Cahier des charges complet (besoins, architecture, exigences) |
| `docs/rapport_de_stage.tex` | Rapport de stage (LaTeX, compilable sur Overleaf/pdfLaTeX) |
| `../documentation/guide_test_manuel_gui.md` | Procédure de test manuel pas à pas de la GUI (UC1→UC5) |

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
