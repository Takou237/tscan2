# Guide utilisateur — Tscan

*Tscan 0.1.0 — Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité*

Ce guide s'adresse à l'analyste en cybersécurité qui utilise Tscan, soit en ligne de
commande (CLI), soit via l'application desktop. Il couvre l'installation, les deux
interfaces et les cinq parcours d'utilisation (UC1 à UC5).

> **Cadre d'utilisation — à lire avant tout scan.** Tscan est un outil de sécurité
> offensive à usage strictement autorisé. Aucun scan actif ne peut s'exécuter sans que
> vous confirmiez explicitement disposer de l'autorisation nécessaire sur la cible
> (exigence ES-01). Le mode sécurisé (sondes GET bénignes uniquement, ES-03) est actif
> par défaut et ne doit pas être désactivé sur une cible de production.

---

## Table des matières

1. [Installation](#1-installation)
2. [Concepts de base](#2-concepts-de-base)
3. [Interface en ligne de commande (CLI)](#3-interface-en-ligne-de-commande-cli)
4. [Application desktop (GUI)](#4-application-desktop-gui)
5. [Parcours d'utilisation (UC1 à UC5)](#5-parcours-dutilisation-uc1-à-uc5)
6. [Fonctionnement hors-ligne](#6-fonctionnement-hors-ligne)
7. [Questions fréquentes](#7-questions-fréquentes)

---

## 1. Installation

### 1.1 Prérequis

| Élément | Exigence |
|---|---|
| Système | Windows (fonctionne également sous Linux/macOS pour le développement) |
| Python | **3.11 ou supérieur** |
| Réseau | Internet uniquement pour les mises à jour de connaissances (CVE, KEV) ; Tscan fonctionne sinon hors-ligne |

### 1.2 Installation depuis les sources (mode développement)

```bash
# 1. Récupérer le projet
git clone https://github.com/Takou237/tscan2.git
cd tscan2

# 2. Créer et activer un environnement virtuel
python -m venv .venv
# Windows (invite de commandes) :
.venv\Scripts\activate
# Windows (Git Bash / Linux / macOS) :
source .venv/Scripts/activate     # adapté : .venv/bin/activate sous Linux/macOS

# 3. Installer Tscan et ses dépendances
pip install -e ".[dev]"
```

Vérification de l'installation :

```bash
tscan version
```

### 1.3 Dépendances installées

| Paquet | Rôle |
|---|---|
| SQLAlchemy ≥ 2.0 | Persistance locale (base SQLite) |
| Typer ≥ 0.12 | Interface en ligne de commande |
| httpx ≥ 0.27 | Requêtes HTTP bornées (timeout, redirections limitées) |
| brotli ≥ 1.1 | Décompression des réponses Brotli (indispensable aux détections passives) |
| beautifulsoup4 + lxml | Analyse HTML |
| PyYAML ≥ 6.0 | Chargement des règles de détection |
| PySide6 ≥ 6.7 | Application desktop |

Les dépendances de développement (`pytest`, `ruff`, `pip-audit`) ne sont utiles que pour
contribuer au code. L'audit des dépendances (exigence ES-12) se lance avec :

```bash
python scripts/audit_deps.py
```

### 1.4 Base de données locale

Tscan stocke toutes ses données dans **une base SQLite unique** à l'emplacement
`~/.tscan/tscan.db` (soit `C:\Users\<vous>\.tscan\tscan.db` sous Windows). Elle est
créée automatiquement au premier lancement ; vous pouvez aussi l'initialiser
explicitement :

```bash
tscan init-db
```

Cette base contient les constats (`Finding`), leurs preuves (`Evidence`), les scans
(`Scan`), l'historique des requêtes émises et l'historique des corrections de statut.
Elle ne quitte jamais votre poste : aucune donnée de scan n'est transmise à un tiers
sans action explicite de votre part (ES-08/ES-09).

> **Mise à jour silencieuse.** À l'ouverture d'une base créée par une version antérieure,
> Tscan applique automatiquement une migration : les anciens constats « Confirmée » posés
> par le moteur de scan sont replacés en « Probable » (score plafonné à 0,85), avec une
> trace conservée dans l'historique. Une confirmation posée par un analyste n'est jamais
> modifiée.

---

## 2. Concepts de base

### 2.1 Le constat (Finding)

Tout résultat — importé d'un scanner externe ou produit par un scan Tscan — est normalisé
dans un modèle unique, le **constat** : cible, emplacement (`matched_at`), catégorie,
titre, gravité, statut, score de confiance, preuves et résultat brut d'origine (conservé
sans modification, ES-07).

### 2.2 Statuts de validation

| Statut | Signification | Qui le pose |
|---|---|---|
| `unvalidated` | En attente de traitement | Système (à l'import) |
| `probable` | Vulnérabilité vraisemblable, à revue | Moteur (import corrélé ou scan actif) |
| `potential_false_positive` | Le fait décisif n'est plus reproduit : à vérifier en priorité | Moteur (ré-observation) |
| `confirmed` | Vulnérabilité confirmée | **Analyste uniquement** (RF-12) |
| `false_positive` | Écarté | Analyste uniquement |

**Principe fondamental : le moteur ne confirme jamais.** Une re-vérification qui reproduit
le fait décisif renforce le score de confiance (plafonné à 0,85) mais laisse le statut
`Probable`. Seul un analyste peut poser « Confirmée » (score 0,95), via `tscan correct` ou
l'application desktop. Chaque correction manuelle est tracée : ancien statut, nouveau
statut, auteur, date, raison (ES-06).

### 2.3 Score de confiance

Chaque constat porte un score entre 0,00 et 0,95 **accompagné de son explication** : la
liste des critères qui ont contribué au score (règle appliquée, corroboration
multi-sources, re-vérification). Consultable via `tscan show` ou le panneau de détail de
l'interface desktop.

### 2.4 Les deux scénarios d'usage

- **Scénario A** — Analyser les résultats d'un scanner externe : `import` → `correlate` →
  revue/correction → `report`.
- **Scénario B** — Scanner directement une cible autorisée : `scan` → re-vérification
  automatique → revue/correction → `report`.

---

## 3. Interface en ligne de commande (CLI)

La commande `tscan` est installée avec le projet. Toute commande accepte `--help` pour
afficher ses options.

### 3.1 `tscan version`

Affiche la version en cours.

### 3.2 `tscan init-db`

Initialise la base de données locale (crée les tables si nécessaire). Idempotent.

### 3.3 `tscan import` — importer un résultat externe (Scénario A)

```bash
tscan import CHEMIN_DU_FICHIER --format FORMAT --target "LIBELLÉ_CIBLE" [--rex]
```

| Option | Valeurs | Description |
|---|---|---|
| `--format`, `-f` | `nuclei`, `zap`, `nessus`, `openvas` | Format du fichier source (obligatoire) |
| `--target`, `-t` | texte libre | Libellé de la cible concernée (obligatoire) |
| `--rex` | fanion | Après l'import, lance une ré-observation active sur la cible et corrèle les constats importés avec le scan actif pour repérer d'éventuels faux positifs |

**Exemples :**

```bash
# Import simple d'un rapport ZAP
tscan import rapport-zap.json --format zap --target "https://www.exemple.cm/"

# Import Nuclei avec ré-observation active (détecte les faux positifs)
tscan import nuclei-results.jsonl --format nuclei --target "https://www.exemple.cm/" --rex
```

> **Autorisation implicite.** Fournir un import pour une cible et demander `--rex`
> vaut confirmation que vous êtes autorisé sur cette cible (ES-01) : la ré-observation
> envoie des requêtes au serveur.

À l'issue d'un import avec `--rex`, Tscan affiche le bilan de corroboration :
constats corroborés, potentiels faux positifs, non concluants (revue analytique requise).
Si la cible a refusé la ré-observation (WAF/anti-bot), un avertissement explicite est
affiché : le bilan est alors sous-estimé, il ne doit pas être lu comme « site sain ».

### 3.4 `tscan correlate` — corréler et scorer

```bash
tscan correlate [--target "CIBLE"] [--rex]
```

Croise les résultats importés portant sur une même cible, applique le pré-filtrage
contextuel, le scoring de confiance et les statuts. Sans `--target`, traite toutes les
cibles.

- `--rex` : ré-observation ciblée par URL des constats importés non corroborés — une
  ressource introuvable (404/410) place le constat en « potentiel faux positif ».
  Best-effort : une panne réseau laisse les constats tels quels.

La corrélation **ne touche jamais** les constats déjà confirmés par un analyste ni les
constats produits par le scan actif Tscan : corrélér ne rétrograde pas une confirmation
acquise.

### 3.5 `tscan list` — lister les constats

```bash
tscan list [--target "CIBLE"] [--status probable|confirmed|potential_false_positive|false_positive|unvalidated]
```

Affiche chaque constat : identifiant, statut, score, gravité, catégorie, titre.

### 3.6 `tscan show` — détail d'un constat

```bash
tscan show 42
```

Affiche : titre, catégorie, gravité, statut, score **avec son explication détaillée**,
cible, source, emplacement et historique des statuts (RF-11).

### 3.7 `tscan correct` — corriger un statut (verdict d'analyste)

```bash
tscan correct ID --status STATUT [--reason "JUSTIFICATION"]
```

**Exemple :**

```bash
tscan correct 42 --status confirmed --reason "Vérifié manuellement : exécution confirmée en laboratoire"
```

Le statut et le score sont mis à jour, la raison consignée dans l'historique avec le nom
d'utilisateur et l'horodatage (RF-12 / ES-06). Statuts valides : `confirmed`,
`probable`, `potential_false_positive`, `false_positive`, `unvalidated`.

### 3.8 `tscan scan` — scan actif autorisé (Scénario B)

```bash
tscan scan CIBLE --authorized [options]
```

| Option | Défaut | Description |
|---|---|---|
| `--authorized` | *(obligatoire)* | Confirmation explicite que la cible est autorisée (ES-01). Sans elle, aucune requête n'est envoyée. |
| `--max-duration`, `-d` | aucune limite | Durée maximale en secondes ; au-delà, le scan se clôture proprement en conservant les constats déjà trouvés. |
| `--max-depth` | 0 (sans borne) | Profondeur maximale du crawl. |
| `--max-pages` | 40 | Nombre maximal de pages crawlées (`0` = sans borne, parité OWASP ZAP). |
| `--tests` | toutes les familles | Restreint le périmètre, identifiants séparés par des virgules (liste ci-dessous). |
| `--delay` | 0,05 s | Délai entre chaque requête (limitation de débit, à augmenter sur une cible sensible). |

**Identifiants de types de test** (`--tests`) : `recon`, `fingerprint`, `headers`,
`clickjacking`, `bac`, `components`, `xss`, `csrf`, `sqli`, `sensitive-files`,
`directory-listing`, `cors`, `tls`, `cookies`, `waf`, `csp`, `sri`, `xdomain-js`,
`timestamp`, `security-headers`, `big-redirect`, `zap-passives`, `path-traversal`,
`open-redirect`, `cmd-injection`, `ssti`, `ssrf`, `header-injection`, `weak-hash`.

Par défaut, le scan exécute **toutes les familles non destructives** : reconnaissance
(statut, TLS, technologies), fingerprinting, en-têtes de sécurité, clickjacking, contrôle
d'accès (BAC), composants vulnérables (cache CVE local), XSS réfléchi, CSRF, SQLi
error-based, fichiers sensibles, listing de répertoire, CORS, TLS faible, cookies, WAF,
CSP, SRI, etc. Toutes les sondes sont **GET bénignes** (ES-03) ; les charges XSS/SQLi sont
des marqueurs inoffensifs ; la sonde SSRF ne génère aucun réseau sortant (URL vers la
propre boucle locale de la cible).

**Exemples :**

```bash
# Scan complet d'une cible autorisée
tscan scan https://www.exemple.cm/ --authorized

# Scan borné à 10 minutes, 20 pages, débit modéré
tscan scan https://www.exemple.cm/ --authorized --max-duration 600 --max-pages 20 --delay 0.2

# Scan rapide restreint à la configuration de sécurité
tscan scan https://www.exemple.cm/ --authorized --tests headers,clickjacking,cors,tls
```

**Interruptibilité.** `Ctrl+C` arrête le scan proprement : les constats déjà enregistrés
sont conservés, le bilan indique le nombre de constats sauvés. Un dépassement de la durée
maximale produit la même clôture sans perte.

**Interruption du pipeline d'un scan :** reconnaissance → crawl borné → détections par
famille → re-vérification active (RF-23) de chaque constat `Probable` → clôture. En fin
de scan : technologies détectées, résultats triés par gravité, bilan de re-vérification
(`X reproduits`, `Y potentiels faux positifs`) et avertissement éventuel si la cible a
bloqué le scanner.

### 3.9 `tscan lookup-cve` — rechercher les CVE d'un composant

```bash
tscan lookup-cve "jquery 1.11.0" [--offline]
```

Interroge NVD **à la demande** et met le résultat en cache local (réutilisable
hors-ligne ensuite). `--offline` ne lit que le cache, sans aucun appel réseau (ES-09).

### 3.10 `tscan update-kev` — synchroniser le catalogue CISA KEV

```bash
tscan update-kev
```

Télécharge intégralement le catalogue des vulnérabilités activement exploitées (CISA KEV)
vers le cache local. Action explicite : Tscan ne contacte jamais CISA automatiquement.

### 3.11 `tscan report` — générer un rapport

```bash
tscan report [--target "CIBLE"] [--format html|markdown] [--output CHEMIN]
```

**Exemples :**

```bash
# Rapport HTML pour toutes les cibles
tscan report --output rapport.html

# Rapport Markdown restreint à une cible
tscan report --target "https://www.exemple.cm/" --format markdown --output rapport.md
```

Sans `--output`, le rapport est affiché dans le terminal. Le rapport contient un résumé
exécutif (tableaux par gravité et par statut) puis le détail technique de chaque constat :
gravité, statut, score, emplacement, description, preuves et recommandations sourcées
(OWASP/CWE) — lisible par un analyste comme par un responsable informatique (RF-27 à
RF-29).

---

## 4. Application desktop (GUI)

### 4.1 Lancement

```bash
python -m tscan_gui
```

(depuis la racine du projet, environnement virtuel activé)

### 4.2 Fenêtre principale

La fenêtre se compose de :

- une **barre d'outils** : `Importer…`, `Scanner…`, `Corréler`, `Rapport…`, `Arrêter`
  (active pendant un scan), `Actualiser` ;
- une **barre de filtres** au-dessus de la liste : statut, gravité, cible (liste
  déroulante) et recherche texte — combinables (ET logique), effet immédiat (UC1) ;
- la **liste des constats** triée par gravité : cliquer sur une ligne ouvre le détail ;
- le **panneau de détail** (droite) : titre, gravité, statut, score de confiance avec
  explication, preuves, historique des corrections, et formulaire de correction manuelle
  avec raison obligatoire (UC2) ;
- deux **onglets en bas** : « Progression » (barre + journal des opérations en temps réel
  pendant un scan : sondes GET, TLS, crawl, détections, re-vérifications) et « Historique
  des requêtes » (chaque requête émise : ID, méthode, URL, code de réponse — ES-05).

Toutes les opérations longues (import, corrélation, scan, rapport) s'exécutent en
arrière-plan : la fenêtre reste réactive (RNF-03).

### 4.3 Les dialogues

**Importer… (UC3)** — Sélection du fichier, de la source (`nuclei`, `zap`, `nessus`,
`openvas`), de la cible concernée, et case à cocher « Lancer une ré-observation active »
(équivalent GUI de `--rex`). Une boîte confirme le nombre de constats importés ; la liste
se rafraîchit.

**Scanner… (UC4)** — Définition du périmètre : cible (URL http/https), case obligatoire
« Je confirme explicitement que cette cible est autorisée » (ES-01), durée maximale
(`0` = aucune limite), profondeur de crawl (`0` = aucune), types de test optionnels
(vide = toutes les détections). Le dialogue refuse de s'ouvrir sans cible et sans
autorisation : aucune requête n'est envoyée dans ce cas (ES-01). Pendant le scan, la
barre de progression et le journal avancent en temps réel ; le bouton « Arrêter » clôture
le scan proprement en conservant les constats déjà trouvés, comme un dépassement de durée.

**Corréler** — Cible optionnelle (vide = toutes) et case « Ré-observer les URLs des
constats importés » (cochée par défaut) : une ressource introuvable (404/410) place le
constat en « potentiel faux positif » pendant la corrélation.

**Rapport… (UC5)** — Fichier de sortie (parcourir), format HTML ou Markdown, cible
optionnelle (vide = toutes les cibles). Une boîte confirme la génération ; ouvrez le
fichier dans un navigateur pour vérifier le rendu.

### 4.4 Correction manuelle d'un statut (UC2)

Dans le panneau de détail d'un constat : choisir le nouveau statut (**Confirmé**, **Faux
positif**, **Potentiel faux positif**, **Probable**), saisir une **raison** (obligatoire),
valider. Le statut et le score changent immédiatement (Confirmé = 0,95, Faux positif =
0,00, Potentiel faux positif = 0,20), la raison est conservée dans l'historique et la
liste se rafraîchit. En base, l'auteur (`analyste_gui`), l'horodatage et la raison sont
tracés (ES-06).

---

## 5. Parcours d'utilisation (UC1 à UC5)

Cette section résume les cinq parcours de bout en bout. Pour une procédure pas à pas
avec résultats attendus, voir `documentation/guide_test_manuel_gui.md`.

| UC | Parcours | Par où passer |
|---|---|---|
| **UC1** | Consulter et filtrer les constats | Barre de filtres + panneau de détail |
| **UC2** | Corriger un statut manuellement | Panneau de détail → statut + raison |
| **UC3** | Importer un résultat externe (± ré-observation) | `Importer…` ou `tscan import` |
| **UC4** | Lancer un scan actif autorisé | `Scanner…` ou `tscan scan … --authorized` |
| **UC5** | Générer un rapport | `Rapport…` ou `tscan report` |

### Démonstration complète recommandée

**Scénario A (analyse d'un résultat externe) :**

```bash
tscan import zap-report.json --format zap --target "https://www.exemple.cm/"
tscan correlate --target "https://www.exemple.cm/" --rex
tscan list --target "https://www.exemple.cm/"
tscan show 12
tscan correct 12 --status confirmed --reason "Reproduit manuellement"
tscan report --target "https://www.exemple.cm/" --output rapport_a.html
```

**Scénario B (scan direct) :**

```bash
tscan scan https://www.exemple.cm/ --authorized --max-duration 600
tscan list --target "https://www.exemple.cm/"
tscan report --target "https://www.exemple.cm/" --format markdown --output rapport_b.md
```

Les deux scénarios sont également réalisables intégralement depuis l'interface desktop.

---

## 6. Fonctionnement hors-ligne (RNF-14/15)

| Fonction | Hors-ligne | Condition |
|---|---|---|
| Import, corrélation, correction, listage | ✅ | Aucune |
| Scan actif | ✅ | Aucune (détections sur composants via le cache CVE local) |
| Génération de rapport | ✅ | Aucune |
| `tscan lookup-cve` | ⚠️ partiel | Cache local uniquement avec `--offline` ; sinon NVD requis |
| `tscan update-kev` | ❌ | Connexion Internet requise |
| Détecter un composant dont le CVE n'est pas encore en cache | ❌ | Lancer `lookup-cve` une fois en ligne pour peupler le cache |

En l'absence de réseau, les fonctions concernées affichent un message explicite plutôt
que d'échouer silencieusement (RNF-15).

---

## 7. Questions fréquentes

**Le scan affiche « 0 vulnérabilité ». Ma cible est-elle saine ?**
Pas nécessairement. Vérifiez l'avertissement éventuel de blocage : si la cible a répondu
401/403/429 à la racine ou interrompu les connexions, le bilan est incomplet et Tscan le
signale explicitement (ES-05). Réessayez plus tard, depuis une autre adresse IP, ou avec
un débit plus faible (`--delay`).

**Pourquoi aucun constat n'est-il « Confirmé » après un scan ?**
C'est voulu : le moteur ne confirme jamais (RF-12). La re-vérification renforce le score
des constats reproduits (jusqu'à 0,85) mais laisse le statut `Probable`. La confirmation
est un verdict d'analyste, posé via `tscan correct` ou l'interface desktop.

**Un constat « Probable » est en réalité un faux positif. Que faire ?**
Corrigez-le : `tscan correct ID --status false_positive --reason "..."`. La décision est
tracée et le constat n'est plus re-signalé comme à traiter.

**Où sont stockées mes données ?**
Dans `~/.tscan/tscan.db` (SQLite), sur votre poste uniquement. Les bases `*.db` sont
exclues du dépôt Git ; aucune donnée de scan n'est transmise à un tiers sans action
explicite de votre part (ES-08/ES-09).

**Puis-je scanner un site sans autorisation ?**
Non. Tscan refuse tout scan sans confirmation explicite d'autorisation (ES-01), en CLI
comme en GUI. Scanner un système sans autorisation est illégal et contraire à l'usage
prévu de l'outil.

**Quels formats de fichiers puis-je importer ?**
Nuclei (JSONL), OWASP ZAP (JSON), Nessus et OpenVAS (XML `.nessus`). Le résultat brut
d'origine est conservé intact avec chaque constat (ES-07).

**L'interface se fige-t-elle pendant un scan ?**
Non : les opérations longues s'exécutent en arrière-plan (RNF-03) et la progression est
visible en temps réel dans l'onglet « Progression ».

---

*Guide utilisateur Tscan 0.1.0 — généré le 21/09/2026. Références RF-xx / ES-xx /
RNF-xx : cahier des charges, chapitres 6, 7 et 9. Toute commande documentée ici a été
vérifiée sur la version 0.1.0 du code.*
