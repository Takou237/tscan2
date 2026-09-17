# Rapport de stage — Développement de Tscan, plateforme d'analyse, de corrélation et de validation de vulnérabilités

> **Stage effectué à l'ANTIC (Agence Nationale des Technologies de l'Information et de la Communication), dans le cadre du cycle de formation en génie civil.**
> Période : [À COMPLÉTER — ex. 20/07/2026 → 18/09/2026]. Stagiaire : KEN DANIEL Takou. Encadrant : [À COMPLÉTER].

---

## Sommaire

1. [Introduction](#1-introduction)
2. [Organisation d'accueil](#2-organisation-daccueil)
3. [Contexte et problématique](#3-contexte-et-problématique)
4. [Objectifs et périmètre du stage](#4-objectifs-et-périmètre-du-stage)
5. [Étude de l'existant](#5-étude-de-lexistant)
6. [Choix méthodologiques](#6-choix-méthodologiques)
7. [Architecture technique](#7-architecture-technique)
8. [Réalisation : du squelette au moteur de scan actif](#8-réalisation--du-squelette-au-moteur-de-scan-actif)
9. [Validation expérimentale et mesure de corroboration](#9-validation-expérimentale-et-mesure-de-corroboration)
10. [Difficultés rencontrées et solutions](#10-difficultés-rencontrées-et-solutions)
11. [Sécurité, éthique et conformité](#11-sécurité-éthique-et-conformité)
12. [Limites du MVP](#12-limites-du-mvp)
13. [Perspectives post-stage](#13-perspectives-post-stage)
14. [Bilan personnel et professionnel](#14-bilan-personnel-et-professionnel)
15. [Conclusion](#15-conclusion)
16. [Références](#16-références)

---

## 1. Introduction

Ce rapport présente le travail réalisé au cours de mon stage à l'ANTIC, consacré au
développement de **Tscan** : une plateforme d'analyse, de corrélation et de validation de
vulnérabilités de sécurité pour applications web. Le stage couvre l'intégralité du cycle
produit — étude de l'existant, cahier des charges, architecture, développement, tests,
validation expérimentale — sur la base d'un cahier des charges de 16 chapitres et d'un
planning en 11 semaines.

La particularité du projet tient à son **double enjeu** : construire un outil opérationnel
(import multi-formats, scan actif non destructif, corrélation, reporting), et répondre à un
problème concret des équipes de sécurité : **les scanners produisent beaucoup de faux
positifs**, et la fiabilisation de leurs résultats exige des méthodes structurées. Tscan
attaque ce problème par trois leviers : le **pré-filtrage contextuel**, la **corrélation
multi-sources** et la **validation active non destructive** (ré-observation).

Le présent document décrit les choix techniques, les livrables, la validation expérimentale
mesurée sur cibles réelles et autorisées, ainsi que les limites assumées du produit au
terme du stage.

---

## 2. Organisation d'accueil

### 2.1 L'ANTIC

L'[ANTIC](https://www.antic.cm) (Agence Nationale des Technologies de l'Information et de la
Communication) est l'agence gouvernementale camerounaise chargée de la promotion et de la
sécurisation des technologies de l'information. Ses missions couvrent notamment
l'administration des ressources Internet du pays (domaine national « .cm », infrastructure
DNS et registre), le développement des usages numériques et la cyberdéfense nationale. Elle
héberge le **CERT/CCTAL**, l'équipe de réponse aux incidents de sécurité informatique du
Cameroun.

### 2.2 Mon rôle et mon encadrement

J'ai été accueilli au sein du [département/équipe — À COMPLÉTER] et encadré par
[À COMPLÉTER]. Mon travail a suivi la logique MVP (Minimum Viable Product) définie au
chapitre 5 du cahier des charges : livrer d'abord le cœur du produit, puis étendre par
blocs hebdomadaires testés et vérifiés. Les points d'avancement hebdomadaires ont été
consignés dans une checklist projet (`docs/checklist_projet.md`) comparant avancement réel
et planning, et le README reflète à tout instant l'état réel du dépôt.

---

## 3. Contexte et problématique

### 3.1 Le contexte

Les organisations sont soumises à une pression croissante : surface d'attaque web étendue,
composants tiers omniprésents (CMS, bibliothèques JavaScript), exigences de conformité.
Les scanners de vulnérabilités (Nuclei, OWASP ZAP, Nessus, OpenVAS) sont devenus
indispensables, mais leur sortie brute présente trois faiblesses :

- **formats hétérogènes** : chaque outil a son modèle de rapport, rendant difficile une vue
  consolidée ;
- **faux positifs** : une alerte détectée n'est pas toujours une vulnérabilité réelle — le
  filtrage manuel des alertes est le premier poste de charge des analystes ;
- **confiance non explicable** : un score 5/10 sans justification n'aide pas à prioriser.

### 3.2 La problématique

**Comment réduire le temps de tri des alertes et améliorer la fiabilité des constats, en
cross-checkant les résultats des scanners externes avec un moteur de validation interne ?**

Tscan répond par un modèle pivot unique (`Finding`), un pré-filtrage contextuel, une
corrélation multi-sources avec scoring de confiance **explicable**, et une **ré-observation
active** : chaque constat importé peut être re-validé par une seconde observation non
destructive exécutée par le moteur interne.

---

## 4. Objectifs et périmètre du stage

### 4.1 Objectif général

Concevoir et développer Tscan, plateforme d'analyse, de corrélation et de validation de
vulnérabilités web, conformément au cahier des charges (16 chapitres) et à son MVP
(chapitre 5), avec un niveau de qualité industrialisable : tests automatisés, style
vérifié, traçabilité des décisions (checklist + README reflétant l'état réel).

### 4.2 Objectifs spécifiques (par bloc hebdomadaire)

| Bloc | Objectif | État final |
|---|---|---|
| S1–S2 | Étude de l'existant, cahier des charges, architecture prévisionnelle | ✅ |
| S3 | Squelette technique (venv, pyproject, ruff, pytest, modèles, SQLite, CLI Typer) | ✅ |
| S4 | Import Nuclei/ZAP vers le modèle pivot `Finding` | ✅ |
| S5–S6 | Corrélation, scoring explicable, statuts, historique — scénario A en CLI | ✅ |
| + | Bloc connaissances CVE/NVD + CISA KEV + références CWE + alias CPE | ✅ |
| S7 | Reconnaissance (statut, TLS, technologies), périmètre, journalisation + détections passives | ✅ |
| S8 | Détections actives non destructives (XSS, CSRF, SQLi error-based…) + import Nessus/OpenVAS | ✅ |
| S9 | Confirmation active RF-23 + reporting (HTML/Markdown) + scénario B | ✅ |
| S10 | Application desktop PySide6 (liste filtrable, détail, correction, import/scan/rapport) | ✅ |
| S11 | Durcissement, empaquetage, démonstration | 🚧 en cours |

### 4.3 Périmètre du MVP

Le MVP couvre l'import des formats **Nuclei (JSONL), OWASP ZAP (JSON), Nessus/OpenVAS (XML)**,
la corrélation multi-sources sur cible commune, le scoring de confiance explicable, les
statuts avec correction manuelle et historique, un **moteur de scan actif autorisé et non
destructif**, la ré-observation (corroboration), le reporting HTML/Markdown, une CLI
complète et une application desktop. **Hors périmètre** : PDF, SSRF/désérialisation
(familles à risque, ES-04), gestion multi-utilisateurs, authentification applicative.

---

## 5. Étude de l'existant

Avant le développement, une étude de l'existant a été conduite sur quatre axes :

- **Scanners de vulnérabilités** : Nuclei (templating communautaire), OWASP ZAP (proxy
  d'analyse avec scanner actif), Nessus/OpenVAS (scanners infra). Aucun ne fait
  nativement de corrélation inter-outils avec fiabilisation.
- **Plateformes d'agrégation** (modèle « vuln management ») : se limitent souvent à la
  consolidation, sans validation active.
- **Sources de connaissances** : NVD/CVE, CISA KEV (catalogue des exploitations avérées),
  CWE pour la classification des faiblesses.
- **Formats de rapport** : JSONL (Nuclei), JSON (ZAP), XML `.nessus` (Nessus/OpenVAS).

**Conclusion** : il existe des outils excellents à chaque étage, mais **aucun chainon
mature qui corrèle plusieurs sources sur une même cible, score la confiance de façon
explicable, puis re-valide activement les constats importés**. C'est la niche que Tscan
occupe.

---

## 6. Choix méthodologiques

### 6.1 Démarche MVP incrémentale

Le développement a suivi une logique MVP : chaque bloc hebdomadaire livre des
fonctionnalités testées et vérifiées, consignées dans une checklist projet avec comparaison
avancement réel / planning. Le README reflète l'état réel du dépôt à chaque instant.

### 6.2 Assurance qualité

- **322 tests automatisés** (pytest), tous verts ;
- **ruff** (linting) propre sur `src/`, `tests/` et `rules/` ;
- **1 test automatisé minimum par module critique** ;
- audit des dépendances (`pip-audit` via `scripts/audit_deps.py`, ES-12) ;
- migration de données idempotente à l'initialisation de la base (RF-12).

### 6.3 Pile technologique

| Couche | Choix | Justification |
|---|---|---|
| Langage | Python ≥ 3.11 | Écosystème sécurité, httpx, rapidité de développement |
| Bibliothèque cœur | modules `tscan_core` | Partagée CLI + GUI, testable sans écran |
| CLI | Typer | Complétion, sous-commandes, ergonomie |
| Desktop | PySide6 | Qt pour Python, LGPL, opérations longues en QThread |
| Persistance | SQLite + SQLAlchemy | Base fichier unique, migrations additives, zéro infra |
| HTTP | httpx | Client borné (timeout, redirections limitées), brotli/gzip |
| Règles | YAML versionnés | Aucune règle codée en dur, chargeur dynamique |
| Tests | pytest + serveur labo local | Intégration sans réseau externe |
| Empaquetage | PyInstaller + Inno Setup | Exécutable Windows (S11) |

### 6.4 Structure du dépôt

```
src/
  tscan_core/       Bibliothèque cœur (import, corrélation, détection, reporting, scan)
  tscan_cli/        Interface en ligne de commande (Typer)
  tscan_gui/        Application desktop (PySide6)
rules/              54 règles de détection versionnées (YAML)
knowledge/          Technologies, alias CPE, référence CWE, signatures de faux positifs
tests/              322 tests pytest + labo local (lab_server.py) + fixtures réelles
docs/               Cahier des charges (PDF), checklist projet, rapport de stage
```

---

## 7. Architecture technique

### 7.1 Vue d'ensemble

```
                    ┌──────────────────────────────────────────────┐
                    │                tscan_gui (PySide6)           │
                    │  MainWindow · FilterBar · FindingsTable      │
                    │  FindingDetailPanel · Dialogs · Workers(QThread) │
                    └───────────────────────┬──────────────────────┘
                                            │
                    ┌───────────────────────┴──────────────────────┐
                    │                tscan_cli (Typer)             │
                    └───────────────────────┬──────────────────────┘
                                            │
┌──────────────┐   ┌───────────────────────┴───────────────────────────────┐
│ Importeurs   │──▶│                      tscan_core                       │
│ Nuclei/ZAP/  │   │  modèle pivot Finding → pré-filtrage → corrélation    │
│ Nessus/      │   │  → scoring → statuts/historique → reporting HTML/MD   │
│ OpenVAS      │   │                                                       │
└──────────────┘   │  ┌─────────────────┐   ┌──────────────────────────┐   │
                   │  │ Scan actif      │   │ Base de connaissances    │   │
                   │  │ recon → règles  │   │ NVD/CVE · KEV · CWE/CPE  │   │
                   │  │ → ré-observation│   │ (cache local, à la demande)│  │
                   │  └────────┬────────┘   └──────────────────────────┘   │
                   └───────────┼───────────────────────────────────────────┘
                               │
                  ┌────────────┴────────────┐
                  │  SQLite (Scans, Findings, │
                  │  Evidence, StatusHistory) │
                  └───────────────────────────┘
```

### 7.2 Le modèle pivot `Finding`

Tout résultat — importé ou produit par le scan actif — converge vers un modèle unique :
cible, emplacement (`matched_at`), catégorie, titre, gravité, statut, score de confiance,
preuves (`Evidence`), résultat brut conservé intact (ES-07), historique de statut
(`StatusHistory`, ES-06). C'est ce pivot qui rend la corrélation et le scoring possibles
entre sources hétérogènes.

### 7.3 Le moteur de règles (RF-13)

**Aucune règle codée en dur** : 54 règles YAML dans `rules/`, une par famille de détection,
chargées dynamiquement. Chaque règle déclare identifiant, catégorie, gravité, conditions,
méthode de validation, preuves attendues, recommandations sourcées (OWASP/CWE) et version.
Le moteur de checks déclaratifs (section `checks:`) exécute les vérifications passives
(`header_absent`, `clickjacking`, `path_status`…) ; les familles actives (XSS, SQLi…)
implémentent leurs sondes en Python, bornées par le module `probe.py`.

### 7.4 Le scan actif (RF-15→24, ES-01→05)

Le pipeline d'un scan actif autorisé :

1. **Reconnaissance** (RF-15) : requête racine via client HTTP borné (timeout, 3
   redirections max, pacing, rotation d'User-Agent), sonde TLS, fingerprinting (RF-16)
   des technologies (PHP, WordPress, jQuery…) via `knowledge/technologies.yaml` ;
2. **Crawl** borné (profondeur et pages plafonnées, pages HTML uniquement pour les sondes) ;
3. **Détections** selon le périmètre (`--tests`, RF-24) : 27 familles couvrant les en-têtes
   de sécurité, clickjacking, BAC, composants vulnérables (cache CVE local, ES-09), XSS
   réfléchi, CSRF, SQLi error-based, SSRF *non exécuté*, SSTI, fichiers sensibles, listing,
   CORS, TLS faible, cookies, WAF, CSP, SRI, inclusions cross-domain, timestamps,
   en-têtes passifs parité ZAP… — toutes **GET-only bénignes** (ES-03) ;
4. **Ré-observation** (RF-23) : re-vérification active de chaque constat `Probable` ;
   un fait reproduit **renforce la confiance (plafonné 0,85)** sans jamais changer le
   statut ; un fait contredit place le constat en `Potentiel faux positif` ; une sonde en
   échec laisse le constat tel quel (ES-05). **Le moteur ne confirme jamais** :
   « Confirmée » (0,95) est un verdict d'analyste (RF-12).

### 7.5 La corroboration (ré-observation des imports)

C'est la fonctionnalité au cœur de la problématique : réconcilier un **rapport importé**
(par ex. ZAP) avec une **observation fraîche** du moteur interne :

- **passe 1 — URL exacte** : catégorie + emplacement normalisé identiques ;
- **passe 2 — titre + catégorie + hôte** : même vulnérabilité, instance différente
  (l'URL précise diffère, la faiblesse est la même sur le même hôte) ;
- **table de synonymes FR↔EN** : les rapports ZAP en français (« Incompatibilité de
  charset ») rejoignent les titres du moteur (« Charset Mismatch ») ;
- **catégorie « other » en joker** : un titre sans indice fiable est rapproché par titre
  seul.

Le taux de corroboration mesuré sur le cas d'étude est présenté au chapitre 9.

### 7.6 La base de connaissances

Accès **à la demande, avec cache local** (aucun réseau pendant un scan, ES-09) :
NVD/CVE (requête CVE par CVE), CISA KEV (catalogue des vulnérabilités exploitées,
synchronisation complète via `tscan update-kev`), référence CWE minimale et table d'alias
CPE vérifiée contre l'API NVD. Garde-fous d'intégrité (ES-11) : taille maximale des
réponses + validation de format CVE avant intégration.

---

## 8. Réalisation : du squelette au moteur de scan actif

### 8.1 Semaines 3–4 : socle et modèle pivot

Mise en place du squelette (venv, `pyproject.toml`, ruff, pytest, modèles SQLAlchemy
`Finding`/`Scan`/`Rule`/`Evidence`, base SQLite à migrations additives, CLI Typer). Puis le
bloc import : parseurs **Nuclei (JSONL)** et **OWASP ZAP (JSON)** vers le modèle pivot, avec
conservation du résultat brut (ES-07) et tests sur jeux de données réels.

### 8.2 Semaines 5–6 : corrélation, scoring, statuts

Pré-filtrage contextuel (RF-08), corrélation multi-sources (RF-09), moteur de scoring
**explicable** (RF-10) — chaque score dérive de la règle appliquée, du bonus multi-sources
et de la re-vérification —, consultation des preuves (RF-11), correction manuelle avec
historique (RF-12). **Jalon : scénario A démontrable en CLI**.

### 8.3 Bloc connaissances (entre S6 et S7)

CVE/NVD à la demande avec cache local, CISA KEV, référence CWE, alias CPE — commandes
`tscan lookup-cve` et `tscan update-kev`.

### 8.4 Semaine 7 : reconnaissance et détections passives

Reconnaissance (client HTTP borné, TLS, fingerprinting), périmètre (cible autorisée,
profondeur, durée, types de test — RF-24/ES-01/02), journalisation systématique (ES-05),
mode sécurisé par défaut (ES-03). Détections passives : en-têtes de sécurité manquants,
clickjacking, composants vulnérables (correspondance version → CVE sur cache local),
broken access control basique. Vérification sur **labo local** puis sur cible réelle autorisée.

### 8.5 Semaine 8 : détections actives et validation active

XSS réfléchi (charge bénigne à nonce), formulaires POST sans jeton CSRF, SQLi error-based
(charges `' --`/`' #` + marqueurs d'erreur), plus quatre familles complémentaires : fichiers
sensibles, listing de répertoire, CORS permissif, TLS faible. Import Nessus/OpenVAS.
**Confirmation active RF-23** puis **jalon de sécurité : scénario B** (reconnaissance →
familles → validation → scoring → rapport).

### 8.6 Semaine 9 : reporting et finalisation CLI

Générateur de rapport (résumé exécutif par gravité/statut + détails techniques, preuves,
recommandations liées à des sources vérifiables OWASP/CWE — RF-27/28/29), exports **HTML et
Markdown**, commande `tscan report`, tests d'intégration bout en bout, revue d'architecture
et revue de code. **Défaut corrigé** au passage : la désambiguïsation des règles partageant
une catégorie (`scoring._resolve_rule`).

### 8.7 Semaine 10 : application desktop

Fenêtre principale (liste filtrable statut/gravité/cible/recherche — RF-11), vue détail
(preuves, score, historique), correction manuelle avec raison consignée (ES-06),
`ImportDialog`, `ScanDialog` (périmètre + autorisation), `ReportDialog` (HTML/Markdown).
Opérations longues en **QThread** (RNF-03) : l'interface reste réactive. Logique de
présentation testée sans écran (viewmodel). Un défaut de refactor (fichiers invalides) a été
corrigé le 27/08/2026, la fenêtre a été ouverte et vérifiée en headless.

### 8.8 Semaine 11 : durcissement et correctifs (en cours)

- **Corrélation cohérente** : `run_correlation` n'inclut plus les résultats du scan actif
  ni les constats déjà Confirmés — corrélter ne rétrograde plus une confirmation humaine ;
- **Progression temps réel** : événements de progression émis par le moteur
  (`tscan_core.scan.progress`), panneau dans la GUI (barre + journal, comme ZAP) ;
- **Migration des données** : les anciens `Confirmée` auto-posés par le moteur sont
  rétrogradés en `Probable` (idempotent, historique conservé) ;
- **Faux positifs démontrés** : test d'intégration avec serveur qui expose puis protège
  `/admin/` → constat en `Potentiel faux positif`.

### 8.9 Travaux de fin de stage (septembre 2026)

Cette dernière période a concentré l'effort sur la **fiabilisation et la performance du
moteur**, avec un cycle complet diagnostic → correctif → validation :

**Parité passive avec OWASP ZAP.** Analyse croisée des alertes ZAP réelles et des
constats du moteur : ajout d'un bundle de **16 règles passives** (`zap_passive.py`) aux
titres exacts ZAP (Content-Type Missing, Suspicious Comments, Modern Web Application,
Cache-control, Retrieved from Cache, Permissions-Policy, X-Frame-Options, Server Header
Leak, X-AspNet-Version, X-ChromeLogger-Data, X-Debug-Token, Reverse Tabnabbing, Weak
Authentication, Hash/Base64/Source Code Disclosure) et d'une règle **XSS attribut**
(RF : « User Controllable HTML Element Attribute (Potential XSS) », ZAP 10031). Câblage
complet : famille `zap-passives`, 17 règles YAML, comptages de tests mis à jour.

**Normalisation des catégories FR/EN.** Extension de `normalize_category` (mots-clés
timestamp, content-type, modern web app, cache, server header, weak auth, base64/hash/
source code disclosure, tabnabbing, x-aspnet/chromelogger/debug-token, auth request,
session management) ; correctif du matching par mot entier pour les sigles courts
(`rce` ne doit plus matcher « r**esou**rce ») ; **table de synonymes FR↔EN** pour la
passe titre de la corroboration. Correctif de régression : restauration du mapping Nessus
(`cve-`, `.env`) via seuil de sous-chaîne ≥ 4.

**Décompression Brotli — cause racine d'un échec silencieux.** Le client annonçait
`Accept-Encoding: gzip, deflate, br` sans le paquet `brotli` : sur les serveurs
compressant en Brotli (LiteSpeed), **tout le HTML analysé était un blob illisible** —
0 détection passive, crawl bloqué à 1 page. Correctif : `brotli` installé et ajouté aux
dépendances. Vérifié en conditions réelles : 39 scripts, 4 formulaires et 250 liens
soudain visibles sur une page WordPress ; détecteurs passant de 5 à 10 constats sur la
seule page racine, incluant exactement les alertes ZAP manquantes à la corroboration.

**Performance du scan actif (durée prévisible).** Le déblocage du crawl sur un CMS a
fait exploser le volume de sondes : 17 pages × 58 paramètres × 2 charges ≈ **2 000
requêtes** rien que pour la détection SQLi. Correctifs : fonction `probe_fetch` (1
tentative, timeout 5 s) adoptée par les familles volumineuses ; plafonnement du nombre de
paramètres sondés (`MAX_PARAMS_PER_SCAN = 10`, paramètre de recherche toujours couvert) ;
cadence réduite de la re-vérification ; arrêt anticipé des sondes big-redirect après
échecs consécutifs. Volume SQLi ramené à ~240 requêtes ; objectif de durée : ~5–15 min.

**Message d'erreur explicite en cas de blocage anti-bot.** Lorsqu'une cible dropperait les
connexions en silence (WAF/anti-bot), le message d'erreur distingue désormais ce cas d'une
panne réseau et invite à réessayer plus tard — retour utilisateur honnête, comme le
prévoit l'ES-05.

**Démarche anti-faux-positifs (sentinelle, signatures, cohérence).** Le faux positif
« panneau d'administration accessible sans authentification » observé sur la cible réelle
a servi de fil conducteur à un lot de fiabilisation du check `path_status` (RF-20) :

1. *Redirections vers une page de connexion.* La sonde suivait la redirection
   `302 /wp-admin/ → /wp-login.php` et ne regardait que le statut final (200) : le 200
   de la page de connexion était lu comme celui du panneau. Le verdict distingue
   désormais la destination (`Location`) et le trajet (URL finale ≠ URL demandée).
2. *Sentinelle anti « soft-404 » (contrôle négatif).* Certains serveurs répondent 200
   avec une page générique pour n'importe quel chemin. Avant les sondes de chemins, une
   requête vers un chemin inexistant aléatoire (`/tscan-calib-<jeton>`) établit le
   « bruit de fond » du serveur ; une réponse de sonde indiscernable du contrôle
   (réflexion du jeton, corps quasi identique) ne produit pas de constat — un 200 ne
   prouve plus rien. Le contrôle est partagé entre détection (orchestrateur) et
   re-vérification (RF-23), où il ajoute une note « fait décisif non démontrable »
   plutôt qu'une dégradation silencieuse.
3. *Signatures de faux positifs en connaissances.* Les marqueurs de pages
   d'authentification (WordPress, Drupal, Django, pages francophones `connexion`…) ont
   quitté le code pour `knowledge/fp_signatures.yaml`, au même principe que les règles
   YAML et les autres tables du dossier `knowledge/` : la table s'étend sans toucher au
   code, avec des consignes anti-collisions documentées (« auth » attraperait
   `/author/john-doe`) et un test qui garantit qu'aucun marqueur ne capture une
   ressource réellement sondée.

Le compromis retenu, fidèle au RF-12 : en cas de doute, le moteur **s'abstient et
documente** (note pour revue analytique) au lieu de conclure — il ne classe jamais un
constat en faux positif sur une simple incertitude de mesure.

**Publication du projet.** Le code a été publié sur GitHub
(`github.com/Takou237/tscan2`), avec historique de commits, `.gitignore` protégeant les
données de scan locales (bases `*.db` jamais versionnées) et exclusion des scripts
d'analyse personnels contenant des chemins locaux.

---

## 9. Validation expérimentale et mesure de corroboration

### 9.1 Protocole

Pour mesurer la capacité du moteur à **reproduire les constats d'un scanner tiers**, le
protocole suivant a été appliqué à un site réel autorisé (boutique WordPress/WooCommerce) :

1. **Import** d'un rapport ZAP réel (26 alertes) vers le modèle pivot ;
2. **Scan actif** Tscan sur la même cible (mêmes contraintes de bonté : GET-only) ;
3. **Corroboration** : rapprochement import ↔ moteur (passe URL exacte puis passe
   titre+catégorie+hôte avec synonymes FR/EN) ;
4. **Mesure** du taux : corroborés / alertes importées.

La cible a été scannée avec autorisation, à faible volume, en mode non destructif
(ES-01/02/03). Les constats importés non reproduits sont classés `non reproductible`
(revue analytique manuelle) ou `faux positif potentiel` lorsque la re-vérification contredit
explicitement le fait.

### 9.2 Résultats

| Étape | Taux de corroboration |
|---|---|
| Avant le lot de détecteurs (situation initiale, 16/26) | 61,5 % |
| Après parité ZAP + normalisation FR/EN (17/26 hors ligne) | 65,4 % |
| Après correctif Brotli + scan actif complet (20/26) | **76,9 %** |

**Analyse des non-corroborés restants (6/26)** : pour la moitié, l'alerte ZAP portait sur
des ressources que le moteur Tscan ne crawle volontairement pas (fichiers images
`.png`/`.jpg` ciblés par ZAP pour l'absence de CSP) ; pour les autres, le site a commencé à
**filtrer les connexions du scanner** en cours de scan (WAF anti-bot) — comportement
documenté au chapitre 10. Ces limites sont méthodologiquement significatives : **les deux
outils sont sujets au même blocage**, ce qui relativise l'écart constaté.

**Indicateurs qualité** : 322 tests verts, ruff propre, un test minimum par module critique,
migration de données vérifiée sur la base réelle. L'effet des correctifs anti-faux-positifs
de la semaine 12 est mesuré en 9.4.

### 9.3 Comparaison ZAP vs Tscan sur le cas d'étude

| Alerte ZAP importée | Tscan reproduit ? |
|---|---|
| En-têtes manquants (HSTS, XCTO, XFO, Permissions-Policy, CSP) | ✅ |
| Cookies sans HttpOnly/SameSite, Cookie Poisoning | ✅ |
| X-Powered-By divulgué, Timestamps Unix, Suspicious Comments, Modern Web App | ✅ |
| Cache-control / Retrieved from Cache | ✅ |
| Authentication / Session Management Identified | ✅ (règles passives parité ZAP) |
| Sub Resource Integrity Missing, Cross-Domain JS | ✅ (après correctif Brotli) |
| Absence de jetons Anti-CSRF | ✅ (formulaires POST analysés) |
| CSP Not Set sur image PNG, charset, XSS attribut, Sensitive Info in URL | ⚠️ partiel / non (hors périmètre de crawl ou blocage WAF) |

### 9.4 Effet des correctifs anti-faux-positifs (semaine 12)

Le lot de fiabilisation décrit en 8.9 (verdict sur la destination des redirections,
sentinelle anti soft-404, signatures déclaratives) a été mesuré sur la cible d'étude en
conditions réelles (17/09/2026, scan actif #5, autorisation inchangée, même adresse IP) :

| Observation | Campagnes avant correctifs | Scan #5 (après correctifs) |
|---|---|---|
| Constat « Panneau d'administration accessible sans authentification » | produit à chaque campagne (302 /wp-admin/ → wp-login.php suivie, 200 final) | **0** |
| Sentinelle anti soft-404 | absente | exécutée (1 requête), tracée dans `recon_json` |
| Avertissement « cible bloque le scanner » | absent (bilan présenté comme normal) | affiché (racine 403, crawl quasi vide) |
| Potentiels faux positifs automatiques | au moins 1 (panneau admin) | 0 |

**Analyse** : la cible restant bloquée (racine 403, crawl quasi vide — cf. 10.4), le scan #5
ne produit que des constats passifs sur la racine (10 constats, re-vérifiés : 3 reproduits,
0 contredit). La mesure de corroboration reste celle du tableau 9.2 ; l'apport démontré ici
est la **disparition du faux positif récurrent** et la transparence du bilan face au
blocage. La mesure complète (avec crawl et corroboration ZAP) sera refaite après levée du
filtrage anti-bot.

---

## 10. Difficultés rencontrées et solutions

### 10.1 Régression du matching de catégories (`rce` → « resource »)

La comparaison en sous-chaîne faisait matcher le sigle `rce` dans « r**esou**rce »,
recatégorisant les alertes « Sub Resource Integrity » en injection de commande.
**Solution** : matching par **mot entier** pour les sigles de 3 lettres, sous-chaîne
tolérée à partir de 4 caractères (`cve-`, `.env`) — validé par les suites importer Nessus
et ZAP.

### 10.2 Décompression Brotli non supportée

Décrit au §8.9 : cause racine d'un échec silencieux (corps illisible → 0 détection, crawl
à 1 page). Leçon : **vérifier la chaîne complète** (transport → décompression → parsing)
avant d'incriminer la logique métier.

### 10.3 Volume de sondes non borné sur les CMS

Le crawl débouchant soudain sur 40 pages × 58 paramètres, le volume de sondes explosait.
**Solution** : bornes explicites (`MAX_PROBE_PAGES`, `MAX_PARAMS_PER_SCAN`), sondes à coût
réduit, arrêt anticipé — la durée de scan redevient prévisible (ES-02).

### 10.4 Blocage anti-bot de la cible (limite de la mesure)

Après plusieurs campagnes de scan, le WAF du site d'étude a fini par **dropper
silencieusement les connexions de l'adresse IP du scanner par fenêtres temporelles** —
diagnostiqué par tests croisés (curl vs client interne, DNS, TCP, TLS). Les scans
lancés pendant une fenêtre de blocage échouent à la première requête racine
(`ReconError`), ce qui peut donner l'impression que « plus rien n'est détecté ».
**Solution** : message d'erreur explicite anti-bot, attente entre campagnes, et
documentation du phénomène comme **limite méthodologique** : ZAP lui-même y est exposé.

### 10.5 Sémantique des statuts (moteur vs analyste)

La re-vérification posait initialement des statuts « Confirmée » automatiques — en
contradiction avec la philosophie RF-12 (la confirmation est un **verdict humain**).
**Solution** : refonte RF-23 — le moteur renforce la confiance (plafond 0,85), l'analyste
seul confirme (0,95) ; migration idempotente des anciennes données.

---

## 11. Sécurité, éthique et conformité

Le scan actif d'un tiers sans autorisation est illégal et éthiquement inacceptable. Tscan
intègre des garde-fous systémiques (checklist ES-01→ES-12 du cahier des charges) :

- **ES-01** — cible confirmée explicitement avant tout scan actif (`--authorized`) ;
- **ES-02** — périmètre limitable : domaine, profondeur, durée maximale, types de tests ;
- **ES-03** — mode sécurisé par défaut : sondes **GET bénignes uniquement** (charges à
  nonce, marqueurs dédiés) ; familles destructives exclues par construction (ES-04) ;
- **ES-05** — journalisation systématique : chaque scan actif trace cible, horodatages,
  périmètre, chaque requête émise (`RequestHistory`), et les échecs de sondes ;
- **ES-06** — traçabilité des corrections manuelles (`StatusHistory` avec raison) ;
- **ES-07** — résultat brut d'origine conservé **sans modification** ;
- **ES-08/ES-09** — preuves stockées localement ; aucune transmission à un tiers sans
  action explicite (lookups CVE/KEV à la demande, scan possible hors ligne) ;
- **ES-10** — entrées validées avant construction des requêtes de test ;
- **ES-11** — intégrité des mises à jour de connaissances vérifiée (taille max, format
  CVE) ;
- **ES-12** — dépendances auditées (`pip-audit`).

Le protocole d'évaluation du chapitre 9 a respecté ces exigences : cible autorisée, volume
faible, mode non destructif, journalisation complète.

---

## 12. Limites du MVP

Les limites suivantes sont assumées et documentées pour l'encadrant (chapitre 15 du cahier
des charges) :

1. **Familles non couvertes** : SSRF, désérialisation, IDOR approfondi — exclues
   volontairement (ES-04, non destructivité) ;
2. **Périmètre de crawl** : Tscan ne sonde pas les ressources binaires (images, PDF) —
   certaines alertes ZAP sur ces ressources ne sont pas reproductibles par conception ;
3. **Blocage anti-bot** : un WAF peut dégrader ou empêcher la mesure (fenêtres de drop) ;
   le moteur le signale mais ne le contourne pas ;
4. **Le moteur ne confirme pas** : « Confirmée » reste un verdict d'analyste — la
   corroboration apporte une indication, pas une preuve ;
5. **Empaquetage** : l'exécutable Windows (PyInstaller/Inno Setup) reste à produire (S11) ;
6. **Tests manuels GUI UC1→UC5** : à exécuter sur poste avec affichage ;
7. **Re-vérification limitée** : elle ne re-vérifie pas les alertes ZAP actives dont la
   logique de détection n'est pas implémentée côté Tscan (ex. injection dans un
   formulaire soumis) ;
8. **Sentinelle et abstention** : le contrôle négatif anti soft-404 peut conduire à
   **s'abstenir** sur une exposition réelle si la ressource ressemble fortement à la page
   générique de la cible — compromis assumé (RF-12) : l'incertitude produit une note pour
   revue analytique, jamais un constat ni une classification silencieuse ;
9. **Corroboration « historique »** : la ré-observation d'un lot importé compte un scan
   Tscan antérieur sur la même cible comme preuve de recouvrement — corroboration différée,
   pas un rejeu en temps réel de chaque alerte.

---

## 13. Perspectives post-stage

- **Empaquetage final** : exécutable Windows + installeur (S11 en cours) ;
- **Élargissement de la parité ZAP** : normalisation des scopes HTTP, alertes de
  session plus fines, alertes de type « Content-Security-Policy » sur les sous-ressources ;
- **Corroboration inversée** : utiliser la ré-observation pour **prioriser** les alertes
  importées non reproduites plutôt que pour les classer d'emblée en faux positifs ;
- **Base de connaissances** : enrichissement automatique des recommandations via CWE et
  le catalogue KEV (priorisation des vulnérabilités exploitées activement) ;
- **CI/CD** : pipeline GitHub Actions (pytest + ruff à chaque push) ;
- **Distribution** : publication des règles en paquet versionné indépendant du code ;
- **Contrôle négatif généralisé** : étendre la sentinelle anti soft-404 aux familles de
  détection actives (fichiers sensibles, listing de répertoire, injections) dont les
  verdicts « 200 » restent exposés au même piège ;
- **Mesure précision / rappel** : corpus étiqueté (laboratoire + sites sains) pour chiffrer
  la précision du moteur avant/après correctifs et détecter objectivement les régressions ;
- **Statistiques de faux positifs par règle** : exploiter les verdicts d'analyste
  (`StatusHistory`, RF-12) pour produire un taux FP par règle et prioriser les
  améliorations — sans auto-ajustement automatique des scores, qui ferait dériver le
  moteur.

---

## 14. Bilan personnel et professionnel

### 14.1 Compétences développées

**Techniques** : architecture logicielle (découplage cœur/CLI/GUI, modèle pivot), sécurité
web appliquée (OWASP Top 10 en pratique, charges bénignes, non-destructivité), qualité
logicielle (322 tests, linting, migrations), Python avancé (SQLAlchemy, httpx, PySide6,
Typer), diagnostic réseau/TLS (DNS, TCP, TLS, encodages de transport).

**Méthodologiques** : gestion de projet MVP, documentation vivante (checklist + README
reflétant l'état réel), traçabilité des décisions, communication régulière avec
l'encadrant, rédaction du cahier des charges.

### 14.2 Apport pour un futur ingénieur en génie civil

Bien que le stage relève de l'informatique, les compétences transférables au génie civil
sont réelles : **rigueur méthodologique** (protocoles de mesure, validation expérimentale),
**démarche qualité** (tests = contrôles de conformité), gestion de projet structurée,
et culture de la **sécurité des systèmes d'information**, désormais transverse à tout
grand projet d'infrastructure (BIM, IoT sur chantiers, jumeaux numériques, systèmes
SCADA).

### 14.3 Difficultés personnelles et apprentissages

Le passage d'une logique « ça fonctionne » à une logique « ça fonctionne **et** c'est
testé, mesuré, tracé » a été l'apprentissage central. La gestion des échecs silencieux
(Brotli, blocage anti-bot) a appris à **déléguer le diagnostic à l'outil** (messages
explicites) plutôt qu'à l'utilisateur.

---

## 15. Conclusion

Le stage a permis de livrer **Tscan**, une plateforme fonctionnelle, testée et documentée
d'analyse, de corrélation et de validation de vulnérabilités web : import de 4 formats de
scanners, 54 règles YAML versionnées, 27 familles de détection non destructives, scoring
explicable, ré-observation avec corroboration mesurée (**76,9 %** sur le cas d'étude),
reporting HTML/Markdown, CLI complète et application desktop — le tout adossé à une
checklist de sécurité transverse (ES-01→ES-12) et à **322 tests automatisés**.

Au-delà de l'outil, le stage démontre qu'une **démarche d'ingénierie rigoureuse** — cahier
des charges, MVP incrémental, validation expérimentale, limites assumées — peut produire,
en 11 semaines, un système qui répond à une problématique réelle : la fiabilisation des
alertes de sécurité par corrélation et re-observation.

Les perspectives (empaquetage, CI/CD, élargissement de la parité ZAP, corroboration
inversée) tracent une feuille de route réaliste pour la suite du produit après le stage.

---

## 16. Références

1. Cahier des charges Tscan, 16 chapitres — `docs/cahier_des_charges.pdf` (projet).
2. OWASP Foundation. *OWASP Top 10:2021*. https://owasp.org/Top10/
3. OWASP ZAP. *Zed Attack Proxy — User Guide*. https://www.zaproxy.org/docs/
4. Nuclei (ProjectDiscovery). *Template-based vulnerability scanner*.
   https://docs.projectdiscovery.io/tools/nuclei/overview
5. Tenable. *Nessus*. https://www.tenable.com/products/nessus
6. Greenbone. *OpenVAS*. https://www.openvas.org/
7. NIST. *National Vulnerability Database (NVD)*. https://nvd.nist.gov/
8. CISA. *Known Exploited Vulnerabilities (KEV) Catalog*.
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog
9. MITRE. *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/
10. NIST. *Common Platform Enumeration (CPE)*. https://cpe.mitre.org/
11. pytest. *Framework de tests Python*. https://docs.pytest.org/
12. httpx. *HTTP client for Python*. https://www.python-httpx.org/
13. SQLAlchemy. https://www.sqlalchemy.org/
14. PySide6 / Qt for Python. https://doc.qt.io/qtforpython/
15. Typer. https://typer.tiangolo.com/
16. ruff. *Linter Python*. https://docs.astral.sh/ruff/
17. RFC 9110 — *HTTP Semantics*. https://www.rfc-editor.org/rfc/rfc9110
18. RFC 7946 — *Google Brotli (RFC 7932)*. https://www.rfc-editor.org/rfc/rfc7932

---

*Document généré le 16/09/2026. Les sections marquées `[À COMPLÉTER]` requièrent les
informations personnelles (période exacte, encadrant, service d'accueil) ainsi que la
validation finale par l'encadrant.*
