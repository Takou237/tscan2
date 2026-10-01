# Checklist complète — Projet Tscan

Cette checklist suit le planning du chapitre 13 du cahier des charges (11 semaines). Chaque case cochée doit correspondre à un critère réellement vérifié, pas supposé. Les références (RF-xx, RNF-xx, ES-xx) renvoient aux chapitres 6, 7 et 9 du cahier des charges.

---

## Suivi réel de l'avancement (au 21/08/2026)

- S1–S2 : terminées et validées.
- S3 : squelette technique opérationnel (venv, pyproject, ruff, pytest, modèles, base SQLite, CLI Typer, README). Dépôt Git, `.gitignore` et convention de commit **en attente de décision** (aucun commit avant fin du stage, par choix) — *résolu fin de stage : dépôt publié sur GitHub (`Takou237/tscan2`), historique de commits conventionnels, poussé au 21/09/2026* ; fenêtre PySide6 de la S3 **reportée à la S10**.
- S4 : import Nuclei/ZAP terminé, testé et vérifié manuellement en CLI.
- S5–S6 : corrélation, scoring, statuts et historique terminés ; Scénario A démontrable en CLI.
- Avant la S7 : bloc connaissances ajouté (CVE/NVD à la demande avec cache local, CISA KEV, références CWE, table d'alias CPE vérifiée contre l'API NVD) — commandes `tscan lookup-cve`, `tscan update-kev`.
- S7 : **terminée** — 7a (reconnaissance, fingerprinting, périmètre, journalisation) puis 7b (détections passives : en-têtes, clickjacking, BAC, composants vulnérables via cache CVE local) ; vérifiées sur labo local et cible réelle.
- S8 : **terminée** — détections actives non destructives (XSS, CSRF, SQLi error-based, fichiers sensibles, listing, CORS, TLS faible) + parseur Nessus/OpenVAS.
- Début **S9** : **confirmation active non destructive (RF-23) livrée** — chaque constat du scan actif est re-vérifié par une nouvelle requête non destructive. **Correctif semaine 11 (28/08/2026) : le moteur ne confirme plus** ; un fait reproduit renforce le score du constat (plafonné 0,85) mais le laisse `Probable` ; « Confirmée » (score 0,95) est un verdict d'analyste posé par `correct_status_manually` (RF-12). Un fait contredit place le constat en `Potentiel faux positif` ; les sondes en échec laissent le constat `Probable`. Reporting (RF-27-28-29) déjà implémenté et vérifié (générateur + export HTML/Markdown + commande CLI `tscan report`).
- S9 — **reporting et finalisation CLI : terminée et vérifiée au 21/08/2026**. Générateur de rapport (RF-27/28/29), exports HTML + Markdown, recommandations sourcées, commande `tscan report` ; tests d'intégration bout en bout (import → corrélation → scan → rapport, `test_reporting.py::test_end_to_end_import_correlate_scan_report`) ; revue d'architecture (conformité au chapitre 10) et revue de code effectuées. **Défaut corrigé** : plusieurs familles partageant une catégorie (ex. `security_misconfiguration`) faisaient écraser la règle au scoring → résolution de règle désambiguïsée (mots-clés de détection + score de base en repli, `scoring._resolve_rule`) avec 3 tests de régression. **Suite complète : 208 tests verts**, `ruff` propre sur `src/`.
- **Fin de stage (septembre 2026)** : **parité passive OWASP ZAP** (17 règles `zap_passives` aux titres exacts ZAP + XSS attribut), **normalisation FR/EN** des catégories (table de synonymes, matching par mot entier), **correctif Brotli** (cause racine d'un échec silencieux : 0 détection sur serveurs compressant en Brotli), **bornes de volume des sondes** (durée prévisible, ES-02), **démarche anti-faux-positifs sur RF-20** (verdict sur la destination des redirections, sentinelle anti soft-404, signatures déclaratives `knowledge/fp_signatures.yaml` — le faux positif récurrent « panneau d'administration accessible » est éliminé, mesuré au scan #5 du 17/09/2026), **avertissement explicite de blocage anti-bot** (ES-05). **Publication GitHub** : `github.com/Takou237/tscan2`, commits poussés au 21/09/2026. **Guide utilisateur rédigé** : `docs/guide_utilisateur.md` (installation, CLI, GUI, UC1→UC5, hors-ligne, FAQ), 21/09/2026. **État vérifié au 21/09/2026 : 322 tests verts (suite complète rejouée), ruff propre, 54 règles YAML.** Reste : tests manuels GUI UC1→UC5, empaquetage (PyInstaller/Inno Setup), script de démonstration scénario B, changelog.
- Transverse sécurité (bonus S9, 21/08/2026) : **ES-11** (validation d'intégrité des mises à jour KEV/NVD : taille max + format CVE) et **ES-12** (suivi des dépendances : `pip-audit` + `scripts/audit_deps.py`) **implémentés et vérifiés** — voir checklist ES ci-dessous.
- **Mécanismes anti-faux-positifs P1/P2/P5/P6 (01/10/2026)** — suite à l'analyse du rapport de scan du 01/10/2026 (13 constats, 0 faux positif détecté : le « 0 FP » était structurel — 12/13 constats étaient des en-têtes absents, non falsifiables, et la re-vérification RF-23 rejouait la même requête, donc **renforçait** un signal de bruit au lieu de le contredire) :
  - **P1 — Analyse différentielle (verdict à 3 requêtes) dans `sqli.py`** : chaque couple (page, paramètre) est évalué sur **requête normale** (baseline, valeur bénigne), **charge de rupture** (`' --` / `' #`) et **charge corrigée** (`''`, littéral SQL valide). Le marqueur d'erreur SQL n'est concluant que s'il est **absent de la baseline** et **disparait avec la charge corrigée** : un blog qui « parle » de SQL, une page de doc ou une erreur permanente ne produisent plus de constat. Le moteur **s'abstient et compte** l'abstention (RF-12). Le constat porte la trace différentielle complète (`probe_info["differential"]`).
  - **P1 — Baseline sur la réflexion XSS (`xss.py`)** : avant de poser un constat de réflexion de charge, la même page avec une valeur bénigne est sondée ; si le nonce y est également reflété (cache mal configuré, miroir qui renvoie la requête entière), la « réflexion » n'est pas un signal XSS — abstention comptée.
  - **P2 — Sentinelle anti soft-404 généralisée à toutes les familles actives** : nouveau module `scan/detections/sentinel.py` — une seule requête de calibration vers `/tscan-calib-<jeton>` par scan (cache mémoire réinitialisé par l'orchestrateur au début de chaque scan, jamais partagée entre deux scans ; observation persistée = `sentinelle_meta` JSON pur, sans objet non sérialisable et sans collision avec la clé `sentinelle` du BAC). Réutilise `_is_generic_response` de `checks.py` (même sémantique, pas de duplication). Branchée dans **`sqli`, `sensitive_files`, `directory_listing`, `xss`** : une réponse indiscernable du bruit de fond du serveur ne produit plus de constat quel que soit son contenu (faux « Index of », signature .env, marqueur SQL dans une page générique).
  - **P5 — Compteurs et bilan dans le rapport** : `observations["anti_fp"]` trace chaque sonde écartée (famille, URL, raison) et chaque verdict différentiel validé ; le générateur de rapport lit `recon_json` du dernier scan actif (`reporting/__init__.py::_last_scan_anti_fp`) et les rendus **HTML et Markdown affichent une section « Méthodologie anti-faux positifs »** (sentinelle exécutée, sondes écartées, analyses différentielles validées). Le rapport **prouve** que les contrôles ont tourné au lieu d'un « 0 FP » invérifiable.
  - **P6 — Tests qui forcent le faux positif** : labo enrichi (route `/static-error` : page statique contenant « SQL syntax error » ; **mode soft-404 activable** `enable_soft404()` : 200 générique réfléchissant la requête avec marqueurs SQL, « Index of » et signature DATABASE_URL pour tout chemin) + serveur miroir (écho global des chemins récents). Nouvelle suite `tests/test_anti_false_positives.py` (7 tests) : abstention sur marqueur statique, **constat conservé sur injection réelle** (`/search` : modèle réaliste corrigé — erreur sous rupture, absente de la baseline, disparissant avec `''`), soft-404 sans aucun constat sur les 3 familles, cache de calibration (une requête, jamais partagée entre tests), écho global XSS non signalé, structure des compteurs P5, échec réseau de la sentinelle non fatal. Suite `tests/test_reporting_anti_fp.py` (2 tests) : la section arrive jusqu'au HTML et au Markdown après un scan réel.
  - **Validation (01/10/2026)** : ruff propre sur `src/` et `tests/` ; **suite complète : 331 tests verts** (322 précédents + 7 `test_anti_false_positives.py` + 2 `test_reporting_anti_fp.py`, libellé du test CLI mis à jour vers le verdict différentiel). Les familles non re-vérifiables (parité ZAP, cf. rapport #8–#12 « fait non reproduit ») restent en note pour revue analytique : leur câblage à la re-vérification précise est un travail P7 (suivi).
- **P7 — Re-vérification précise des règles de parité ZAP (01/10/2026)** — répond au constat du rapport du 01/10 (#8, #12 : « fait non reproduit, constat laissé Probable » sur les règles parité ZAP, éternellement à 0,50–0,60 sans jamais être renforcées ni contredites) :
  - **Deux familles dédiées rejouables** : `permissions_policy.py` (RULE-PERMISSIONS-NOTSET-001, parité ZAP 10063, `probe_info` `header_absent`) et `modern_web_app.py` (RULE-MODERN-APP-001, parité ZAP 10101, `probe_info` `body_regex` portant la regex exacte) — un constat **par page** (au lieu d'un constat agrégé sur la racine), chaque constat portant l'URL rejouable en re-vérification.
  - **Déduplication** : le bundle agrégé `zap_passive.py` n'émet plus ces deux alertes (fin des doublons #7/#12 et #11 vus dans le rapport).
  - **Re-vérification précise RF-23** : nouveau signal `header_absent` dans `confirmation._recheck_special` (le fait est reproduit si l'en-tête est toujours absent de la réponse fraîche) ; `body_regex` déjà supporté. Les deux règles sont câblées dans `_PRECISE_RECHECK_RULE_IDS` + `_CODE_RUNNERS` : fait reproduit → score renforcé (plafond 0,85), fait contredit → potentiel faux positif — le verdict est maintenant exploitable au lieu d'une note « non reproduit » permanente.
  - **Nouveaux types de test** : `permissions-policy` et `modern-web-app` ajoutés à `TEST_TYPES`/`DEFAULT_ALLOWED_TESTS`/`_ACTIVE_DETECTION_TESTS` (activés par défaut, ES-02 : restreignables via `--tests`).
  - **Tests** : `tests/test_p7_precise_recheck.py` (7 tests : constat par page + probe_info, contre-exemples (en-tête présent, page non HTML, sans marqueur), déduplication zap_passive, scan bout en bout avec re-vérification précise (score > base, statut toujours Probable, RF-12), mode soft-404 sans constat « moderne ») ; `test_zap_passive_detections.py` ajusté (le bundle n'émet plus les 2 règles).
  - **Validation (01/10/2026)** : ruff propre sur `src/` et `tests/` ; **suite complète : 338 tests verts** (331 précédents + 7 `test_p7_precise_recheck.py`). Comptage du scénario B mis à jour : 34 → 37 constats sur le labo (Permissions-Policy émise par page, 4 pages crawlées sans l'en-tête, au lieu d'un constat agrégé).
  - **Reste (suivi)** : les autres règles parité ZAP (HSTS/XCTO/XFO/CSP en doublon `security-headers`/`csp` vs `zap_passive`, alertes HTML comme Suspicious Comments...) restent agrégées sans `probe_info` ; leur éclatement en modules dédiés suivra le même patron que P7 si l'analyste le juge utile.
- **S10 — application desktop : câblée et vérifiée au 23/08/2026 ; CORRIGÉE le 27/08/2026** — le refactor S10 avait laissé `dialogs.py` syntaxiquement invalide et `main.py` manquant ; `dialogs.py` réécrit (3 dialogues dont `ReportDialog` ajouté), `main.py`/`MainWindow` recréé, `__main__.py` ajouté. Vérifié : `ruff` propre, 10 tests `test_gui_viewmodel.py` verts, ouverture réelle de la fenêtre en headless (31 résultats chargés en base). `tscan_gui` reconstruit à partir des briques existantes (MainWindow, FilterBar, FindingsTable, FindingDetailPanel) + `workers.py` (opérations longues en QThread, RNF-03) : fenêtre avec liste filtrable (statut/gravité/cible/recherche), détail (preuves, score, historique), correction manuelle avec raison (RF-12, ES-06), import (`ImportDialog`), scan avec périmètre (`ScanDialog`, RF-24, ES-01/02), rapport (`ReportDialog`, HTML/Markdown). **Vérifié** : `ruff` propre sur `src/` et `tests/`, 10 tests de logique de présentation sans écran dans `tests/test_gui_viewmodel.py` (filtres, tri, détail, correction UC3), ouverture réelle de la fenêtre en mode headless. Reste à exécuter sur poste avec affichage les parcours manuels UC1→UC5 (fin S10 / S11).
- **Correctif comportemental (27/08/2026)** : le scan actif par défaut n'exécutait que la reconnaissance + le fingerprinting (`DEFAULT_ALLOWED_TESTS = {recon, fingerprint}`), d'où « 0 vulnérabilité » systématique (constat sur le scan de `https://owasp.org/www-project-juice-shop/`). Désormais `DEFAULT_ALLOWED_TESTS = TEST_TYPES` : un scan par défaut lance **toutes les familles de détection non destructives** (headers, clickjacking, BAC, components, XSS, CSRF, SQLi, fichiers sensibles, listing, CORS, TLS), toujours encadré par ES-02 (bornes durée/profondeur) et ES-03 (GET-only) ; `--tests` reste disponible pour restreindre. `test_scan_config_default_allowed_tests` mis à jour (6 tests CLI verts, 12 tests config verts).
- **Correctifs semaine 11 (28/08/2026)** : (1) **corrélation corrigée** — `run_correlation` n'inclut plus les résultats du scan actif (`tscan_engine`) ni les résultats déjà `Confirmée` (RF-12/RF-23) ; avancement sur arrivée, corréler après un scan rétrogradait les constats Confirmée (0,90) vers Probable (0,60-0,70). (2) **progression temps réel** — le moteur de scan émet des `ScanProgressEvent` (`tscan_core.scan.progress`, paramètre `on_event`) pour chaque sonde GET, TLS, crawl, détection et re-vérification ; nouveau panneau `ScanProgressPanel` sous la liste (barre + journal, comme OWASP ZAP), alimenté par le signal `progress_emitted` de `workers.py` (RNF-03). **Vérifié** : ruff propre sur `src/` et `tests/`, suite complète de 227 tests verte (3 nouveaux `test_progress.py` + 2 régressions corrélation dans `test_scenario_a_integration.py`). (3) **confirmation : le moteur ne confirme plus (RF-12/RF-23)** — la re-vérification active renforce la confiance des constats du scan actif (plafonné 0,85) sans changer le statut `Probable` ; fait contredit -> `Potentiel faux positif` ; sonde en échec -> constat laissé tel quel (ES-05). « Confirmée » (0,95), potentiel faux positif (0,20) et faux positif (0,00) deviennent des décisions humaines via `correct_status_manually` (`tscan_core.status`), câblée dans `tscan correct` et la GUI ; observations `reproduced` / `potential_false_positives` / `probe_errors`. Tests des blocs scan/confirmation/rapport refondus + 4 nouveaux dédiés à `correct_status_manually`. (4) **migration de données RF-12** — `init_db` rétrograde (idempotent) les anciens constats `Confirmée` posés par le moteur (`tscan_engine`) vers `Probable` (score plafonné 0,85), historique conservé (ES-06) ; une confirmation d'analyste n'est jamais touchée. Vérifié sur la base réelle : 15 anciens Confirmée moteur retirés (106 constats tous Probable), 3 tests de régression. (5) **faux positifs démontrés** — un fait contredit à la re-vérification (familles précises) passe en `Potentiel faux positif` (score réduit, historique) ; nouveau test `test_confirmation.py::test_confirmation_contradicted_fact_flags_potential_false_positive` (serveur qui expose puis protège `/admin/`).

---

## Phase déjà réalisée (S1–S2)

- [x] Étude de l'existant (scanners, plateformes d'agrégation, sources de connaissances, formats de rapport)
- [x] Définition du produit (vision, utilisateurs, MVP, périmètre)
- [x] Cahier des charges rédigé (16 chapitres) et validé
- [x] Architecture prévisionnelle validée (cœur partagé, découplage moteur/règles/connaissances, modèle pivot)
- [x] Pile technologique validée (Python, PySide6, Typer, SQLite/SQLAlchemy, httpx, YAML, PyInstaller, pytest)

---

## Semaine 3 — Mise en place du projet

**Dépôt et structure**
- [x] Créer le dépôt Git (nom, description, visibilité) — *publié fin de stage : `github.com/Takou237/tscan2`, commits poussés au 21/09/2026*
- [x] Définir la structure des dossiers (cœur, CLI, GUI, règles, tests, documentation)
- [x] `.gitignore` adapté à Python — *en place : venv, caches, build, bases `*.db` jamais versionnées*
- [x] README initial (présentation courte, statut du projet, installation prévue)
- [x] Convention de messages de commit définie et respectée dès le premier commit — *conventionnel (feat/fix/docs/chore/style), respectée sur tout l'historique*

**Environnement**
- [x] Environnement virtuel Python créé
- [x] Gestion des dépendances mise en place (`pyproject.toml`, installation editable)
- [x] Outils de qualité configurés (ruff + pytest)

**Squelette technique**
- [x] Squelette de la bibliothèque cœur (modules vides : import, corrélation, détection, règles, reporting, base de données)
- [x] Modèles de données initiaux (SQLAlchemy) : `Finding`, `Scan`, `Rule`, `Evidence`
- [x] Script ou migration d'initialisation de la base SQLite (init + migrations additifs)
- [x] Premier test automatisé qui passe (pytest configuré)
- [ ] Première fenêtre PySide6 minimale fonctionnelle — *reportée à la S10*

**Documentation**
- [x] README mis à jour avec l'état réel du squelette

---

## Semaine 4 — Bloc import & modèle pivot

- [x] Modèle de données `Finding` finalisé (champs, statuts RF-07)
- [x] Parseur Nuclei (JSONL) → `Finding` (RF-01)
- [x] Parseur ZAP (JSON) → `Finding` (RF-02)
- [x] Modèle pivot appliqué de façon homogène (RF-04)
- [x] Conservation du résultat brut d'origine (RF-05 / ES-07)
- [x] Statuts de validation initiaux posés (Confirmée / Probable / Potentiel faux positif / Faux positif)
- [x] Commande CLI d'import (`tscan import ...`)
- [x] Tests unitaires sur les deux parseurs, avec au moins un jeu de données réel par format
- [x] Vérification manuelle : import réel d'un résultat Nuclei et d'un résultat ZAP, listage via CLI

---

## Semaines 5–6 — Corrélation, validation, scoring

- [x] Pré-filtrage contextuel implémenté (service actif, version, cohérence) (RF-08)
- [x] Corrélation multi-sources sur une même cible (RF-09)
- [x] Format de règle YAML finalisé (identifiant, catégorie, gravité, conditions, méthode de validation, preuves attendues, recommandations, références, version)
- [x] Chargeur de règles dynamique (aucune règle codée en dur) (RF-13)
- [x] Au moins une règle écrite pour chacune des cinq familles du MVP
- [x] Moteur de scoring de confiance explicable (RF-10)
- [x] Consultation des preuves associées à un résultat (RF-11)
- [x] Correction manuelle d'un statut, avec historique conservé (RF-12)
- [x] Tests unitaires sur la corrélation et le scoring
- [x] **Jalon intermédiaire : Scénario A démontrable en CLI** (import → corrélation → statuts → preuves → sans rapport final à ce stade)

---

## Semaine 7 — Reconnaissance et détection (familles simples)

**Sous-bloc 7a — Reconnaissance et fingerprinting (fait)**
- [x] Module de reconnaissance web (headers, TLS, technologies de base) (RF-15) — `recon/client.py`, `recon/tls.py`
- [x] Fingerprinting technologies courantes (RF-16) — `recon/fingerprint.py` + `knowledge/technologies.yaml` (10 signatures)
- [x] Contrôle de périmètre implémenté dès ce stade : cible autorisée, profondeur, durée (RF-24 / ES-01, ES-02) — `scan/config.py` (validate_target, max-depth, max-duration, `--tests`)
- [x] Mode sécurisé par défaut activé (ES-03) — option `--insecure` requise pour le désactiver
- [x] Journalisation de chaque scan actif (cible, horodatage, périmètre) (ES-05) — table `Scan` (autorisation, mode sûr, config JSON, horodatages)
- [x] Tests sur une cible de test contrôlée et autorisée (labo local `tests/lab_server.py`) + vérification manuelle sur cible réelle

**Sous-bloc 7b — Détections passives (fait)**
- [x] Détection Security Misconfiguration (en-têtes manquants) (RF-17) — checks déclaratifs `header_absent`
- [x] Détection Clickjacking (absence X-Frame-Options / CSP frame-ancestors) (RF-17) — check déclaratif `clickjacking`
- [x] Détection composants vulnérables connus, via correspondance version → CVE (RF-18) — cache CVE local uniquement (aucun réseau pendant un scan, ES-09)
- [x] Détection Broken Access Control basique (RF-20) — checks `path_status` + sondes GET bénignes (ES-03)
- [x] Moteur de checks déclaratifs (section `checks:` des règles YAML) + tests par famille sur le labo local
- [x] Vérification manuelle CLI sur labo local (8 constats : BAC high, clickjacking medium, 6 en-têtes info)

---

## Semaine 8 — Détection (familles restantes) et validation active

- [x] Détection XSS réfléchi (RF-19) — module `detections/xss.py`, charge bénigne à nonce (ES-03)
- [x] Détection absence de protection CSRF (RF-21) — module `detections/csrf.py`, analyse passive des formulaires POST
- [x] Détection injection SQL error-based (RF-22) — module `detections/sqli.py`, charges `' --` / `' #` + marqueurs d'erreur
- [x] Familles complémentaires (choix utilisateur) : fichiers sensibles (`sensitive_files.py`), listing de répertoire (`directory_listing.py`), CORS permissif (`cors.py`), TLS faible (`tls_weak.py`)
- [x] Orchestrateur étendu : exécution des détections actives selon le périmètre (`--tests`), statut PROBABLE, preuves en `Evidence`, échec de sonde tracé (ES-05)
- [x] Import Nessus/OpenVAS (XML .nessus) — parseur `importers/nessus.py`, formats `nessus` et `openvas` enregistrés (RF-01)
- [x] **Confirmation active non destructive pour les cinq familles (RF-23)** — module `scan/confirmation.py` : chaque constat `Probable` du scan actif est soumis à une **seconde observation non destructive** (re-requête fraîche, périmètre fermé, bornée par la durée maximale). **Correctif semaine 11** : le fait reproduit renforce le score (plafonné 0,85) mais laisse le constat `Probable` — le moteur ne confirme pas ; « Confirmée » (0,95) est un verdict d'analyste (RF-12). Un fait contredit place le constat en `Potentiel faux positif` ; sonde en échec -> constat laissé `Probable` (jamais dégradé). *Livré en début de semaine 9, sémantique verrouillée en semaine 11.*
- [x] **Jalon de sécurité : Scénario B démontrable intégralement en CLI** — reconnaissance → 5 familles → validation active (RF-23) → scoring → rapport (`tscan report`). *Cadré en début de semaine 9 à la suite de la confirmation.*

---

## Semaine 9 — Reporting et finalisation CLI

- [x] Générateur de rapport (résumé exécutif + détails techniques) (RF-27)
- [x] Export HTML et Markdown (RF-29 ; le PDF reste hors périmètre MVP, « et/ou » satisfait)
- [x] Recommandations liées à des sources vérifiables (RF-28)
- [x] CLI complète et cohérente (import, scan, correction, rapport)
- [x] Tests d'intégration de bout en bout du cœur (import → corrélation → scan → rapport) — `test_reporting.py::test_end_to_end_import_correlate_scan_report`
- [x] Revue d'architecture (cohérence avec le chapitre 10, dette technique) — conformité validée
- [x] Revue de code (qualité, duplication, sécurité) — ruff propre, 204 tests verts

---

## Semaine 10 — Application desktop

- [x] Fenêtre principale : liste des résultats avec filtres (statut, gravité, cible) — `tscan_gui/main.py` (MainWindow + FilterBar + FindingsTable)
- [x] Vue détail d'un résultat : preuves, score, historique de statut — `tscan_gui/widgets.py` (`FindingDetailPanel`)
- [x] Correction manuelle d'un statut depuis l'interface (RF-12) — `main.py::_correct_status` via `status.change_status`, avec raison consignée (ES-06)
- [x] Lancement d'un import depuis l'interface — `ImportDialog` + `workers.import_task`
- [x] Lancement d'un scan depuis l'interface, avec définition du périmètre (RF-24) — `ScanDialog` (cible, profondeur, durée, types de test, auto-risation ES-01) + `workers.scan_task`
- [x] Génération de rapport depuis l'interface — `ReportDialog` + `workers.report_task` (HTML/Markdown)
- [x] Vérification que l'interface reste réactive pendant les opérations longues (RNF-03) — `tscan_gui/workers.py` (`TaskWorker` sur `QThread`)
- [x] Tests de la logique de présentation (viewmodel) sans écran — `tests/test_gui_viewmodel.py` (filtrages, tri, détail, cibles)
- [ ] Tests manuels de l'ensemble des parcours utilisateur (UC1 à UC5) — *à exécuter sur poste avec affichage*

---

## Semaine 11 — Intégration finale, durcissement, démonstration

**Tests et sécurité**
- [ ] Tests de bout en bout des scénarios A et B complets (CLI et desktop) — *CLI validés au 08/09/2026 (Scénario A sur imports réels, Scénario B sur `https://polytechnique.cm/` avec rapports HTML/Markdown) ; reste le desktop (UC1→UC5)*
- [ ] Revue de sécurité complète (voir checklist ES-01 à ES-12 ci-dessous)
- [ ] Vérification du fonctionnement hors-ligne des fonctions concernées (RNF-14, RNF-15)

**Empaquetage**
- [x] Génération de l'exécutable Windows (PyInstaller) — *réalisé le 28/09/2026 : fichier `tscan.spec` versionné, deux exécutables one-file `dist/tscan.exe` (CLI, 19 Mo) et `dist/tscan-gui.exe` (desktop, 58 Mo), règles `rules/` (54 YAML) et connaissances `knowledge/` embarquées et retrouvées via `tscan_core.app_paths.data_root()` (sys._MEIPASS). Nouveau module `app_paths.py` centralisant la résolution des chemins de données (5 modules adaptés, BNF-10 respecté). **Icône** (`assets/tscan.ico`) et **métadonnées de version Windows** (`version_info.txt` : produit Tscan 0.1.0, éditeur ANTIC) intégrées aux deux exécutables et vérifiées (propriétés > Détails). Vérifié : CLI `--help`, `version`, import Nuclei réel → corrélation (54 règles chargées depuis le bundle) → `list` corrects ; `tscan-gui.exe` démarre et se ferme proprement ; suite complète toujours verte (322 tests), ruff propre.*
- [ ] Installeur généré et testé (Inno Setup) — *script `installer/tscan.iss` rédigé le 28/09/2026 : installation par utilisateur sans élévation (`{localappdata}\Programs\Tscan`), raccourcis menu Démarrer (application + console CLI) et bureau optionnel, ajout/retrait au PATH utilisateur avec diffusion `WM_SETTINGCHANGE`, désinstalleur propre, interface française. Reste : installer Inno Setup 6, compiler (`ISCC.exe installer/tscan.iss`) et tester sur machine propre.*
- [ ] Installation testée sur une machine "propre" si possible

**Documentation**
- [x] Documentation utilisateur finalisée — *`docs/guide_utilisateur.md` (installation, CLI complète, application desktop, parcours UC1→UC5, hors-ligne, FAQ), rédigé le 21/09/2026, commandes vérifiées sur la version 0.1.0*
- [x] Documentation technique / architecture finalisée — *`docs/architecture.md` (version réalisée : couches, modèle de données, flux, découplage moteur/règles/connaissances, écarts vs prévisionnel) liée depuis le README ; rapport de stage rédigé (`docs/rapport_de_stage.md`, 704 lignes).*
- [x] README final à jour — *chiffres vérifiés (322 tests, 54 règles), état réel au 21/09/2026, section Documentation ajoutée ; sera re-précisé après empaquetage*
- [ ] Changelog à jour

**Démonstration**
- [x] Script de démonstration préparé (scénarios A et B) — *`scripts/demo_scenario_a.sh` et `scripts/demo_scenario_b.sh` créés le 28/09/2026 et rejoués de bout en bout : base de démonstration isolée (la vraie `~/.tscan/tscan.db` n'est jamais touchée), labo local auto-démarré/arrêté pour le scénario B (24 constats, re-vérification RF-23 sans faux positif), imports Nuclei+ZAP → corrélation → correction tracée → rapport HTML pour le scénario A (5 constats), pauses commentées à chaque étape, alternative exécutable `dist/tscan.exe` documentée dans l'en-tête.*
- [ ] Répétition complète de la démonstration
- [ ] Vérification de chaque critère de réussite du MVP (chapitre 14)
- [ ] Limites explicites du MVP formulées clairement pour l'encadrant (chapitre 15)
- [ ] Perspectives post-stage prêtes à être présentées (chapitre 16)

---

## Checklist transverse — Sécurité (à revalider à chaque bloc, pas seulement en fin de projet)

- [x] ES-01 — Cible confirmée explicitement avant tout scan actif
- [x] ES-02 — Périmètre limitable (domaine, profondeur, durée, types de tests)
- [x] ES-03 — Mode sécurisé (non destructif) activé par défaut
- [x] ES-04 — Familles à risque (SSRF, désérialisation...) bien exclues du moteur — *jamais implémentées (types de tests fermés)*
- [x] ES-05 — Journalisation systématique des scans actifs
- [x] ES-06 — Traçabilité des corrections manuelles de statut
- [x] ES-07 — Résultat brut d'origine conservé sans modification
- [x] ES-08 — Preuves stockées localement avec un niveau de protection adapté — *base SQLite locale de l'utilisateur, aucune transmission*
- [x] ES-09 — Aucune transmission de données à un tiers sans action explicite — *lookup-cve / update-kev = actions explicites ; scan hors ligne possible*
- [x] ES-10 — Entrées validées avant construction des requêtes de test
- [x] ES-11 — Intégrité vérifiée sur les données de mise à jour (règles, connaissances) — *garde-fou de taille (MAX_KEV_BYTES / MAX_NVD_BYTES) + validation du format CVE avant intégration, dans `kev_client.py` et `nvd_client.py` (tests dédiés), 21/08/2026*
- [x] ES-12 — Dépendances tierces suivies avec vigilance — *outil `pip-audit` ajouté en dev + script `scripts/audit_deps.py` ; audit vert (pip mis à jour 26.2.1), 21/08/2026*

---

## Checklist transverse — Qualité et documentation continue

- [x] Un test automatisé au minimum ajouté pour chaque nouveau module critique (**322 tests verts au 21/09/2026**, suite complète rejouée ; 208 au 21/08/2026)
- [x] Documentation mise à jour à chaque fin de bloc (checklist, README, prompt_maitre)
- [x] Commits réguliers, messages explicites — *repris fin de stage : dépôt publié sur `github.com/Takou237/tscan2`, commits conventionnels, poussés au 21/09/2026*
- [x] Comparaison avancement réel / planning effectuée chaque semaine (section « Suivi réel » ci-dessus)
- [ ] Tout retard signalé et arbitré selon la priorité qualité > quantité (chapitre 2) — *en suivi : Git/PySide6 arbitrés, rien de bloquant*

---

## Checklist finale avant présentation à l'ANTIC

- [ ] Cahier des charges à jour et cohérent avec le code livré
- [ ] Dépôt GitHub propre, README compréhensible par un tiers
- [ ] Scénario A exécuté sans erreur devant témoin
- [ ] Scénario B exécuté sans erreur devant témoin
- [ ] Rapport généré présentable à un non-technicien
- [ ] Application desktop installable sans intervention manuelle complexe
- [ ] Réponse claire et honnête préparée sur les limites du MVP
- [ ] Roadmap post-stage prête à être présentée
