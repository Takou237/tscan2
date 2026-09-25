# Architecture technique — Tscan (version réalisée)

*Tscan 0.1.0 — État au 21/09/2026. Ce document décrit l'architecture **telle qu'elle est
réellement construite et vérifiée** dans le code, en regard du chapitre 10 (architecture
prévisionnelle) du cahier des charges. Les écarts assumés sont listés au chapitre 6.*

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Couches et paquets](#2-couches-et-paquets)
3. [Modèle de données](#3-modèle-de-données)
4. [Flux de données](#4-flux-de-données)
5. [Découplage moteur / règles / connaissances](#5-découplage-moteur--règles--connaissances)
6. [Écarts entre l'architecture prévisionnelle et la réalisation](#6-écarts-entre-larchitecture-prévisionnelle-et-la-réalisation)
7. [Sécurité architecturale](#7-sécurité-architecturale)
8. [Tests et qualité](#8-tests-et-qualité)

---

## 1. Vue d'ensemble

Les trois couches prévues au chapitre 10 du cahier des charges sont réalisées telles
quelles : deux clients de présentation indépendants, un cœur partagé, un stockage local
fichier. Le gestionnaire de mise à jour est bien le seul composant autorisé à appeler les
sources externes de connaissances.

```
+-----------------------------------------------------------------------+
|                             Présentation                              |
|   +----------------------------------+   +------------------------+   |
|   |        tscan_cli (Typer)         |   |  tscan_gui (PySide6)   |   |
|   |  11 commandes, scripts, démo     |   |  MainWindow, QThread   |   |
|   +----------------+-----------------+   +-----------+------------+   |
+--------------------|---------------------------------|-----------------+
                     |          import direct          |
                     v                                 v
+-----------------------------------------------------------------------+
|                    tscan_core (bibliothèque partagée)                 |
|                                                                       |
|  importers/        correlation/         scan/              reporting/ |
|  4 parseurs   -->  pré-filtre      -->  recon/détections --> générateur
|  -> Findings       matcher + scoring    re-vérification    HTML/MD    |
|                                                                       |
|  knowledge_base/   rule_engine/        recon/          status.py      |
|  NVD/KEV/CWE/CPE   54 règles YAML      client/crawl    statuts+scores |
|  cache local        (chargeur dyn.)    fingerprint                    |
+-----------------------------------------------------------------------+
                     |
                     v
+-----------------------------------------------------------------------+
|                            Stockage local                             |
|   SQLite (~/.tscan/tscan.db)   rules/*.yaml (54)   knowledge/*.yaml   |
|   8 tables : scans, findings, evidences, status_history,              |
|   rules, cached_cves, kev_entries, technology_detections              |
+-----------------------------------------------------------------------+
```

*Figure 1 : Architecture réalisée de Tscan.*

Le cœur totalise ~11 300 lignes de Python (75 fichiers), hors CLI et GUI.

## 2. Couches et paquets

### 2.1 `tscan_cli` — interface en ligne de commande

Un seul module (`main.py`, Typer) qui n'implémente **aucune logique métier** : chaque
commande ouvre une session SQLAlchemy, appelle une fonction du cœur et met en forme la
sortie. 11 commandes : `version`, `init-db`, `import`, `correlate`, `list`, `show`,
`correct`, `scan`, `lookup-cve`, `update-kev`, `report`. Le point d'entrée
`tscan = tscan_cli.main:app` est déclaré dans `pyproject.toml`.

### 2.2 `tscan_gui` — application desktop

Sept modules PySide6 :

| Module | Rôle |
|---|---|
| `main.py` | `MainWindow` : barre d'outils, filtres, table des constats, panneau de détail, onglets Progression / Historique des requêtes |
| `viewmodel.py` | Logique de présentation pure (filtres, tri, libellés) — testable sans écran |
| `widgets.py` | `FilterBar`, `FindingsTable`, `FindingDetailPanel`, `ScanProgressPanel` |
| `dialogs.py` | `ImportDialog`, `ScanDialog`, `CorrelateDialog`, `ReportDialog` — chaque dialogue expose `config_kwargs()` prêt pour la tâche |
| `workers.py` | `TaskWorker` (QThread) + fabriques `import_task`, `correlate_task`, `scan_task`, `report_task` — l'interface reste réactive (RNF-03) |
| `__main__.py` | Point d'entrée `python -m tscan_gui` |

La GUI consomme exactement les mêmes fonctions du cœur que la CLI (aucune logique
dupliquée, décision 10.2 respectée). La communication du temps réel se fait par le signal
Qt `progress_emitted` : le cœur de scan émet des `ScanProgressEvent` via le rappel
`on_event`, le worker les réémet vers `ScanProgressPanel` (barre + journal) et vers le
collecteur `RequestHistory` (chaque requête émise : ID, méthode, URL, code).

### 2.3 `tscan_core` — bibliothèque cœur

| Paquet | Contenu | Principaux points d'entrée |
|---|---|---|
| `importers/` | Parseurs Nuclei (JSONL), ZAP (JSON), Nessus/OpenVAS (XML), service d'import, service de ré-observation des imports | `import_file(session, source, target, path)` ; registre `_PARSERS` = `{"nuclei": parse_nuclei_jsonl, "zap": parse_zap_json, "nessus": parse_nessus_xml, "openvas": parse_nessus_xml}` |
| `correlation/` | Pré-filtrage contextuel, regroupement multi-sources, scoring explicable | `run_correlation(session, target, reobserve)` ; `matcher.correlate()` (2 passes : URL exacte, puis titre+catégorie+hôte avec synonymes FR↔EN) ; `scoring.score_finding()` |
| `scan/` | Orchestrateur du scan actif, configuration/périmètre, checks déclaratifs, confirmation active, interruption, progression, journal de requêtes | `run_recon_scan(session, config, ...)` ; `ScanConfig` (validation ES-01/02) ; `reverify_active_findings()` (RF-23) |
| `scan/detections/` | 23 modules de détection + `probe.py` (sondes bornées : `MAX_PROBE_PAGES = 12`, `MAX_PARAMS_PER_SCAN = 10`) | Chaque famille expose `run(config, client, root, ...) -> list[DetectionResult]` |
| `recon/` | Client HTTP borné (timeout, 3 redirections, pacing, rotation d'User-Agent, décompression Brotli), crawler, fingerprinting, TLS | `client.py`, `crawler.py`, `fingerprint.py`, `tls.py` |
| `rule_engine/` | Schéma de règle + chargeur dynamique + synchronisation en base | `load_rules()` lit tous les `rules/*.yaml` ; aucune règle codée en dur |
| `knowledge_base/` | NVD (à la demande + cache), CISA KEV (synchronisation), CWE, alias CPE, signatures de faux positifs, gestionnaire de mises à jour | `lookup_component()`, `update_kev_catalog()` ; garde-fous d'intégrité ES-11 (`kev_client.py`, `nvd_client.py`) |
| `reporting/` | Générateur de rapport + rendus HTML et Markdown | `generate_report(session, target)` ; `render_html()` / `render_markdown()` |
| racine | Modèles SQLAlchemy, initialisation/migrations de base, statuts et scores | `db.init_db()` (migrations additives idempotentes), `status.correct_status_manually()` |

## 3. Modèle de données

Base SQLite unique à `~/.tscan/tscan.db` (SQLAlchemy 2.0, `db.DEFAULT_DB_PATH`). Huit
tables, créées par `init_db()` avec migrations additives et idempotentes
(`_ensure_column`, `_migrate_legacy_engine_confirmations`) :

| Table | Rôle | Points notables |
|---|---|---|
| `scans` | Tout scan (import externe ou actif) | `ScanType` distingue import / `tscan_engine` / ré-observation ; config JSON, horodatages, autorisation tracée (ES-05) |
| `findings` | Le modèle pivot | Statut (`FindingStatus`), score + `score_explanation` (JSON : le détail des critères), `raw` (résultat brut conservé intact, ES-07), référence vers le scan |
| `evidences` | Preuves d'un constat | `content_text` pour les preuves courtes (en-tête manquant), `content_path` pour les contenus volumineux — conforme à la décision 10.5 |
| `status_history` | Trace de chaque changement de statut | `old_status`, `new_status`, `changed_by` (`tscan_engine` vs identifiant analyste), `reason`, horodatage (RF-12 / ES-06) |
| `rules` | Miroir des règles YAML en base | Synchronisé par `rule_engine.loader.sync_rules_to_db()` |
| `cached_cves` | Cache local NVD | Peuplé à la demande par `lookup-cve`, jamais pendant un scan (ES-09) |
| `kev_entries` | Catalogue CISA KEV synchronisé | Alimenté uniquement par `update-kev` (action explicite) |
| `technology_detections` | Technologies détectées par scan | Alimente le rapport et la corrélation de composants |

**Journal des requêtes (hors base).** Le journal des requêtes émises par un scan n'est
pas une table : `scan.request_log.RequestHistory` est un collecteur **en mémoire**
(thread-safe, vivant le temps du scan), branché sur le client HTTP par l'orchestrateur et
exposé en temps réel à l'interface (onglet « Historique des requêtes »). La traçabilité
durable du scan repose sur la table `scans` (config JSON, horodatages) et sur les
observations consignées en base (échecs de sondes, sentinelle, diagnostic de blocage —
ES-05).

**Le pivot `Finding`.** Tout résultat — importé (Nuclei/ZAP/Nessus/OpenVAS) ou produit
par le moteur de scan — converge vers ce modèle unique, ce qui rend la corrélation et le
scoring indépendants du format d'origine (décision 10.4 respectée).

**Sémantique des statuts (verrouillée semaine 11).** Le moteur pose `Probable` (import
corrélé ou scan actif) et `Potentiel faux positif` (fait décisif contredit à la
re-vérification). Il ne pose **jamais** `Confirmée` : le plafond automatique est 0,85.
Les verdicts `Confirmée` (0,95), `Potentiel faux positif` (0,20) et `Faux positif`
(0,00) sont des décisions humaines portées par `status.correct_status_manually()`, qui
ajuste statut, score et explication, et trace le tout dans `status_history`.

## 4. Flux de données

### 4.1 Scénario A — analyse d'un résultat externe

```
fichier externe (Nuclei/ZAP/Nessus/OpenVAS)
  -> importers.import_file()        parse, crée Scan (type import) + Findings
                                    (statut initial unvalidated, brut conservé)
  -> correlation.run_correlation()  pré-filtre contextuel -> regroupement
                                    multi-sources (2 passes + synonymes FR/EN)
                                    -> scoring explicable -> statuts Probable/PFP
  (option --rex) reobserve_service  ré-observation active de la cible :
                                    corrobore les imports, marque les non-reproduits
  -> status.correct_status_manually()  revue analyste (CLI/GUI)
  -> reporting.generate_report()    résumé exécutif + détail, HTML/Markdown
```

La corrélation **exclut** les constats du scan actif (`tscan_engine`) et les constats déjà
confirmés par un analyste : corrélér ne rétrograde jamais une confirmation acquise
(correctif semaine 11).

### 4.2 Scénario B — scan actif autorisé

```
ScanConfig (cible, autorisation ES-01, bornes ES-02, --tests)
  -> scan.orchestrator.run_recon_scan()
       1. reconnaissance     client borné, sonde TLS, sentinelle anti soft-404
                             (contrôle négatif aléatoire, tracé dans recon_json)
       2. fingerprinting     knowledge/technologies.yaml -> TechnologyDetection
       3. crawl borné        profondeur/pages plafonnées (défaut 40 pages)
       4. checks déclaratifs section checks: des règles (header_absent,
                             clickjacking, path_status) — verdicts guidés par
                             knowledge/fp_signatures.yaml et la destination réelle
                             des redirections
       5. détections actives run_active_detections() : familles filtrées par
                             allowed_tests, sondes GET bénignes (ES-03), volumes
                             plafonnés (probe.MAX_PROBE_PAGES, fuzzing.MAX_PARAMS),
                             **persistance au fil de l'eau** (commit par famille)
       6. re-vérification    confirmation.reverify_active_findings() (RF-23) :
                             fait reproduit -> score renforcé (≤ 0,85, statut
                             inchangé) ; fait contredit -> Potentiel faux positif ;
                             sonde en échec -> constat laissé tel quel (ES-05)
  -> ScanOutcome             bilan : constats, reproduits/PFP, technologies,
                             avertissement de blocage anti-bot (scan.blocking)
```

Les deux mécanismes d'arrêt (`interrupt.ScanInterrupt` pour Ctrl+C/« Arrêter »,
`check_deadline` pour la durée maximale) lèvent des interruptions **traitées comme une
clôture normale** : les constats déjà committés au fil de l'eau sont conservés.

## 5. Découplage moteur / règles / connaissances

Réalisation de la décision 10.3 :

- **Règles** : 54 fichiers YAML dans `rules/` (une par famille), structurés selon le
  schéma prévu — identifiant, nom, catégorie, gravité, version, dates, description,
  détection (mots-clés), méthode de validation, preuves attendues, recommandations
  sourcées, références. Le chargeur (`rule_engine.loader`) les lit au démarrage du scan
  et les synchronise en base. Ajouter une règle = ajouter un fichier YAML, sans toucher
  au code du moteur (RNF-10).
- **Connaissances** : tables YAML locales dans `knowledge/` (`technologies.yaml`,
  `cpe_aliases.yaml`, `cwe_reference.yaml`, `fp_signatures.yaml`) et cache en base
  (`cached_cves`, `kev_entries`). Alimentation exclusivement par le gestionnaire de mise
  à jour (`knowledge_base.update_manager`), seul composant à ouvrir le réseau vers NVD /
  CISA, avec garde-fous d'intégrité : taille maximale des réponses et validation du
  format CVE avant intégration (ES-11). Pendant un scan, le cœur ne lit que le cache
  local (ES-09).
- **Signatures de faux positifs** : les marqueurs de pages d'authentification ont quitté
  le code pour `knowledge/fp_signatures.yaml` — la table s'étend sans modification du
  moteur, avec un test anti-collisions garantissant qu'aucun marqueur ne capture une
  ressource réellement sondée.

## 6. Écarts entre l'architecture prévisionnelle et la réalisation

Écarts assumés, tous dans le sens de la simplicité ou de la robustesse :

1. **Preuves en base ET fichiers (10.5).** La table `evidences` porte les deux champs
   prévus (`content_text`, `content_path`) ; en pratique les preuves du MVP sont courtes
   et stockées en base. Le mécanisme fichiers reste disponible et le contrat est respecté.
2. **Étendue des détections.** Le périmètre prévisionnel (5 familles MVP + familles
   complémentaires) a été dépassé : 23 modules de détection et 54 règles, dont un bundle
   de parité passive OWASP ZAP. Les familles à risque prévues à la marge (SSTI, cmd
   injection, path traversal, open redirect, header injection, weak hash) sont implémentées
   en mode strictement bénin ; la sonde SSRF ne génère aucun réseau sortant (URL vers la
   boucle locale de la cible). ES-04 reste respecté : aucune action destructive n'existe
   dans le moteur.
3. **Crawl borné par défaut (40 pages) plutôt qu'exhaustif.** Choix de durée prévisible
   (ES-02) après mesure : un crawl exhaustif sur un CMS générait ~2 000 requêtes pour la
   seule famille SQLi. `--max-pages 0` restaure la parité ZAP (exhaustif) à la demande.
4. **Journal des requêtes temps réel.** La prévision ne mentionnait que la journalisation
   du scan ; la réalisation ajoute un flux d'événements temps réel (`ScanProgressEvent` ->
   `RequestHistory` -> GUI, journal mémoire par scan), parité avec l'onglet History de
   ZAP, sans table dédiée en base.
5. **Empaquetage non réalisé.** PyInstaller + Inno Setup (S11) restent à livrer ; l'aspect
   « installation » de l'architecture est le seul point en attente.

## 7. Sécurité architecturale

Traduction structurelle des exigences du chapitre 9 du cahier des charges :

- **ES-01** : `ScanConfig` refuse toute cible sans `authorized=True` — vérifié en CLI
  (option `--authorized`) comme en GUI (case obligatoire du `ScanDialog`) ; aucune
  requête n'est émise dans le cas contraire.
- **ES-02** : périmètre porté par `ScanConfig` (domaine, profondeur, durée, pages, types
  de test) et appliqué par l'orchestrateur à chaque étape.
- **ES-03** : mode sécurisé par défaut — sondes GET bénignes uniquement, charges à nonce,
  aucun module destructeur dans le code.
- **ES-05** : chaque scan est journalisé (table `scans` : config, horodatages, autorisation
  ; échecs de sondes consignés dans les observations) ; chaque requête émise est traçable
  en temps réel via le journal mémoire `RequestHistory`.
- **ES-06** : chaque changement de statut passe par `status.change_status()` qui crée
  l'entrée `status_history` — aucun chemin de code ne modifie un statut sans trace.
- **ES-07/08/09** : le brut d'origine est écrit une fois, jamais réécrit ; la base reste
  locale ; le réseau n'est ouvert que par les commandes explicites `lookup-cve` /
  `update-kev` (jamais pendant un scan).
- **ES-10** : la construction des requêtes de test passe par des helpers bornés du client
  (URL validée par `validate_target`, charges constantes à nonce, pas d'interpolation de
  données cible dans du code exécutable).
- **ES-12** : audit des dépendances (`pip-audit` + `scripts/audit_deps.py`), à rejouer à
  chaque évolution de `pyproject.toml`.

## 8. Tests et qualité

**322 tests pytest verts** (suite complète exécutée le 21/09/2026, 3 min 28 s), `ruff`
propre sur `src/` et `tests/`. Organisation :

- **Par module du cœur** : parseurs (`test_importer_*.py`), corrélation/matching
  (`test_correlation_matcher.py`, `test_prefilter.py`), scoring (`test_scoring.py`),
  règles (`test_rule_engine.py`, `test_scan_rules.py`, `test_checks.py`), détections
  (un fichier par famille : `test_detections.py`, `test_security_headers_detections.py`,
  `test_zap_passive_detections.py`, `test_waf.py`, `test_tls.py`, `test_cookies.py`…),
  confirmation (`test_confirmation.py`), orchestration (`test_orchestrator.py`,
  `test_interrupt.py`, `test_progress.py`), connaissances (`test_nvd_client.py`,
  `test_kev_client.py`, `test_cpe.py`, `test_fp_signatures.py`…).
- **Bout en bout** : `test_reporting.py::test_end_to_end_import_correlate_scan_report`
  (scénario A), `test_s11_scenarios.py` (scénarios A et B), `test_scenario_a_integration.py`,
  `test_scan_cli.py`, `test_zap_parity.py`.
- **GUI sans écran** : `test_gui_viewmodel.py` (filtres, tri, correction UC3) — la
  logique de présentation est testable headless par construction (viewmodel séparé des
  widgets).
- **Serveur de laboratoire local** : `tests/lab_server.py` (HTTP autonome) permet les
  tests d'intégration réseau sans aucune requête vers l'extérieur, y compris les scénarios
  d'arrêt (interruption manuelle, dépassement de durée) et le serveur qui « expose puis
  protège » `/admin/` pour démontrer la détection de faux positifs.
- **Régressions de données** : `test_migration.py` (migration idempotente des anciens
  « Confirmée » moteur), `test_offline.py` (fonctionnement hors-ligne).

**Dette technique connue** : quelques scripts d'analyse personnels non versionnés à la
racine et dans `tests/` (à nettoyer) ; l'empaquetage ; la mesure précision/rappel sur
corpus étiqueté (perspective post-stage, cf. rapport de stage ch. 13).

---

*Document généré le 21/09/2026 à partir de la lecture du code (`src/tscan_core`,
`src/tscan_cli`, `src/tscan_gui`, `rules/`, `knowledge/`) et de l'exécution vérifiée de
la suite de tests. Références RF-xx / ES-xx / RNF-xx : cahier des charges, chapitres 6, 7
et 9.*
