# Manuel d'utilisation — Tscan

**Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité**

| | |
|---|---|
| Version du logiciel | 0.1.0 |
| Public | Utilisateurs et analystes en cybersécurité |
| Éditeur | ANTIC |
| Système | Windows |
| Date d'édition | Octobre 2026 |

---

> **À lire avant toute utilisation.**
> Tscan est un outil de sécurité **offensive**. Il ne doit être utilisé que sur des
> cibles pour lesquelles vous disposez d'une **autorisation écrite explicite**. Aucun
> scan actif ne peut démarrer sans que vous confirmiez cette autorisation : c'est un
> garde-fou volontaire du logiciel. Scanner un système sans autorisation est illégal.
>
> Le scan actif de Tscan est **non destructif** : il n'envoie que des requêtes GET
> bénignes et des marqueurs de test inoffensifs. Ne le détournez pas de cet usage.

---

## À propos de ce manuel

Ce manuel explique comment installer Tscan et s'en servir au quotidien. Il est organisé
en deux parties :

- **Partie I — Utilisation de l'application** : pour tous les utilisateurs, sans
  connaissances techniques. Tout se fait à la souris, dans la fenêtre de l'application.
  C'est la partie à lire en premier.
- **Partie II — Utilisation avancée (ligne de commande)** : pour les profils techniques
  qui souhaitent automatiser, scripter ou utiliser Tscan sans interface graphique.

Vous pouvez lire uniquement la partie qui vous concerne. La partie II suppose Tscan
déjà installé (voir 1). Des annexes (raccourcis, statuts, formats, dépannage, glossaire)
terminent le manuel.

---

## Sommaire

**Partie I — Utilisation de l'application**
1. Installer Tscan
2. Premier lancement et repérage de la fenêtre
3. Importer les résultats d'un scanner externe
4. Consulter et filtrer les constats
5. Comprendre un constat : gravité, statut, score
6. Corriger le statut d'un constat
7. Lancer un scan actif (cible autorisée)
8. Générer un rapport
9. Changer de thème (clair / sombre)

**Partie II — Utilisation avancée (ligne de commande)**
10. Préparer la ligne de commande
11. Vue d'ensemble des commandes
12. Importer puis corréler (scénario A)
13. Scanner une cible (scénario B)
14. Consulter, détailler et corriger
15. Générer un rapport
16. Base de connaissances CVE / KEV et usage hors-ligne

**Annexes**
- A. Raccourcis clavier
- B. Statuts et scores
- C. Types de test (option `--tests`)
- D. Où sont mes données
- E. Dépannage (questions fréquentes)
- F. Glossaire

---

# Partie I — Utilisation de l'application

## 1. Installer Tscan

### 1.1 Ce dont vous avez besoin

- Un poste **Windows**.
- Le fichier **`tscan-0.1.0-setup.exe`** fourni par l'ANTIC.
- **Aucune installation préalable** n'est nécessaire : Python et toutes les dépendances
  sont embarqués dans l'installeur.

### 1.2 Dérouler l'installation

1. Double-cliquez sur **`tscan-0.1.0-setup.exe`**.
2. Suivez l'assistant. L'installation se fait **pour votre utilisateur uniquement** :
   elle **ne demande pas de droits administrateur** et n'affiche pas d'écran de contrôle
   de comptes (UAC).
3. À l'écran des options, deux cases sont proposées :
   - **Créer une icône sur le Bureau** (facultatif) ;
   - **Ajouter la CLI (tscan.exe) au PATH utilisateur** (cochée par défaut) — laissez-la
     cochée si vous pensez utiliser un jour la ligne de commande (partie II).
4. Terminez : l'application se lance automatiquement.

Tscan est installé dans :

```
%localappdata%\Programs\Tscan
```

(soit `C:\Users\<vous>\AppData\Local\Programs\Tscan`), sans toucher aux fichiers système.

### 1.3 Ce que l'installation crée

Dans le **menu Démarrer**, un dossier **Tscan** contenant :

- **Tscan** — l'application à fenêtre (à utiliser au quotidien) ;
- **Tscan (invite de commandes)** — ouvre une console où la commande `tscan` est déjà
  disponible (pour la partie II) ;
- **Désinstaller Tscan**.

### 1.4 Désinstaller

Passez par **Paramètres Windows → Applications → Tscan → Désinstaller**, ou par
l'entrée **Désinstaller Tscan** du menu Démarrer. La désinstallation retire le programme
et nettoie l'entrée ajoutée au `PATH`. **Vos données de travail ne sont pas supprimées**
(voir annexe D).

---

## 2. Premier lancement et repérage de la fenêtre

Lancez **Tscan** depuis le menu Démarrer ou le raccourci Bureau. La fenêtre s'intitule
**« Tscan — Analyse de vulnérabilités »** et s'ouvre en **thème sombre**.

### 2.1 Les zones de la fenêtre

```
┌──────────────────────────────────────────────────────────────────────┐
│ Importer…  Scanner…  Corréler  Rapport…  │ Arrêter │ Actualiser │ Thème  │ ← barre d'outils
├──────────────────────────────────────────────────────────────────────┤
│ [Rechercher…]                    2 constats      [Réinitialiser]      │ ← barre de filtres
│ Statut : [Tous v]   Gravité : [Toutes v]   Cible : [Toutes v]         │
├──────────────────────────────────┬───────────────────────────────────┤
│ ID  Gravité Statut Catégorie …    │  Détail du résultat                │
│ ───────────────────────────────  │  (onglets : Nom et infos,          │
│ 12  Élevée  Probable xss  …       │   Description, Preuves,            │
│ 11  Moyenne Probable csp  …       │   Explication du score,            │
│ …                                │   Historique, Corriger le statut)  │
├──────────────────────────────────┴───────────────────────────────────┤
│ [ Progression ] [ Historique des requêtes ]                          │ ← onglets du bas
└──────────────────────────────────────────────────────────────────────┘
```

| Zone | À quoi elle sert |
|---|---|
| **Barre d'outils** (haut) | Les actions : importer, scanner, corréler, produire un rapport, arrêter un scan, actualiser, changer de thème |
| **Barre de filtres** | Rechercher et filtrer la liste par statut, gravité ou cible ; le compteur indique le nombre de lignes affichées |
| **Liste des constats** (gauche) | Tous vos résultats, triés par gravité. Cliquer sur une ligne ouvre son détail |
| **Panneau de détail** (droite) | Tout le détail du constat sélectionné, sur six onglets |
| **Onglets du bas** | Suivi d'un scan en direct (progression et historique des requêtes) |

### 2.2 La barre d'outils en un coup d'œil

| Bouton | Rôle | Raccourci |
|---|---|---|
| **Importer…** | Charger un fichier de résultats d'un scanner externe | `Ctrl+O` |
| **Scanner…** | Lancer un scan actif sur une cible autorisée | `Ctrl+N` |
| **Corréler** | Croiser et scorer les constats importés | `Ctrl+K` |
| **Rapport…** | Générer un rapport HTML ou Markdown | `Ctrl+R` |
| **Arrêter** | Interrompre le scan en cours (actif seulement pendant un scan) | `Ctrl+.` |
| **Actualiser** | Recharger la liste depuis la base | `F5` |
| **Thème clair / Thème sombre** | Basculer l'apparence | `Ctrl+T` |

> Une **infobulle** rappelle le rôle de chaque bouton lorsque vous laissez la souris
> dessus.

Au premier lancement, la liste est vide et affiche :
`Aucun constat en base. « Importer… » charge un résultat de scanner.`
C'est normal : commencez par importer des résultats (§3) ou lancer un scan (§7).

---

## 3. Importer les résultats d'un scanner externe

Tscan ne remplace pas vos outils de scan : il **récupère leurs rapports** pour les
normaliser, les recouper et les fiabiliser.

### 3.1 Formats acceptés

| Scanner | Format de fichier | Option « Source » à choisir |
|---|---|---|
| Nuclei | JSONL (`.jsonl`) | `nuclei` |
| OWASP ZAP | JSON (`.json`) | `zap` |
| Nessus | XML (`.nessus`) | `nessus` |
| OpenVAS / Greenbone | XML (`.nessus`) | `openvas` |

### 3.2 Procédure pas à pas

1. Cliquez sur **Importer…** (ou `Ctrl+O`).
2. **Fichier** : cliquez sur **Parcourir…** et sélectionnez le fichier de résultats.
3. **Source** : choisissez le scanner qui a produit le fichier.
4. **Cible concernée** : saisissez le libellé de la cible, par exemple
   `https://www.exemple.cm/`. C'est le nom sous lequel ces résultats seront regroupés ;
   réutilisez **exactement la même écriture** d'un import à l'autre pour une même cible.
5. **Ré-observation active** (facultatif) : cochez cette case si vous voulez que Tscan
   **vérifie immédiatement** sur la cible, par ses propres requêtes, si les vulnérabilités
   signalées sont toujours présentes. Voir l'encadré ci-dessous.
6. Cliquez sur **OK**.

Un message confirme l'import, par exemple :

```
Import terminé : 3 résultat(s) importé(s) depuis nuclei (scan #1).
```

La liste se rafraîchit et les résultats apparaissent.

> **La ré-observation envoie de vraies requêtes à la cible.** En cochant
> « Ré-observation active », vous confirmez implicitement être autorisé sur cette cible.
> Ne l'utilisez jamais sur une cible pour laquelle vous n'avez pas d'autorisation.
>
> Sans ré-observation, l'import est une simple lecture de fichier : **aucune requête
> réseau n'est émise**.

### 3.3 Champs obligatoires

Le dialogue **refuse de valider** tant qu'il manque un fichier ou une cible, et affiche
« Champ requis ». C'est volontaire : un import sans cible ne pourrait pas être corrélé.

### 3.4 Et ensuite ?

Un import brut ne calcule ni score ni statut définitif. Pour les obtenir, lancez une
**corrélation** : bouton **Corréler** (`Ctrl+K`), puis **OK** (laissez la cible vide pour
traiter toutes les cibles). C'est l'étape qui **scora** et **statue** chaque constat (voir
§5).

---

## 4. Consulter et filtrer les constats

### 4.1 Lire la liste

La liste affiche une ligne par vulnérabilité, triée de la plus grave à la moins grave :

| Colonne | Contenu |
|---|---|
| **ID** | Identifiant interne du constat |
| **Gravité** | Pastille colorée + libellé (Critique, Élevée, Moyenne, Faible, Information) |
| **Statut** | État de validation (voir §5) |
| **Catégorie** | Famille technique (ex. `xss`, `csp`, `information_disclosure`) |
| **Titre** | Intitulé lisible de la vulnérabilité |
| **Instances** | Nombre de fois où la vulnérabilité a été trouvée sur la cible |
| **Cible** | La cible concernée |
| **URL** | Emplacement (ou la dernière partie de l'URL) |
| **Score** | Score de confiance de 0,00 à 0,95 (`--` si non calculé) |

**Trier** : cliquez sur un en-tête de colonne. Les colonnes ID, Instances, Score et
Gravité trient sur leur **valeur réelle** (10 vient après 9, Critique avant Élevée) et non
sur l'ordre alphabétique.

### 4.2 Filtrer et rechercher

- **Rechercher** : un mot dans le titre, la catégorie ou l'URL.
- **Statut / Gravité / Cible** : listes déroulantes. La valeur `Tous` / `Toutes`
  désactive le filtre.

Les filtres **se combinent** (ET logique) : par exemple *Statut = Probable* **et**
*Gravité = Élevée* ne montre que les lignes qui remplissent les deux conditions.

Le **compteur** (à droite de la recherche) indique le nombre de lignes affichées, par
exemple `2 constats`. S'il tombe à `0 constat`, la table affiche
`Aucun constat ne correspond aux filtres actifs.`

Le bouton **Réinitialiser** remet tous les filtres à zéro et réaffiche toute la base.

### 4.3 Ouvrir un constat

Cliquez sur une ligne : le **panneau de détail** (à droite) s'ouvre sur six onglets :

| Onglet | Contenu |
|---|---|
| **Nom et infos** | Titre, gravité, statut, score, catégorie, cible, source, emplacement |
| **Description** | Ce que la vulnérabilité signifie |
| **Preuves** | Éléments collectés (en-têtes, extraits de réponse…) séparés par `---` |
| **Explication du score** | Les critères qui ont mené au score, ligne par ligne |
| **Historique de statut** | Tous les changements de statut, avec auteur, date et raison |
| **Corriger le statut** | Le formulaire pour valider le constat (voir §6) |

Vous pouvez naviguer entre les onglets avec les **flèches gauche/droite** du clavier
lorsque la barre d'onglets a le focus.

---

## 5. Comprendre un constat : gravité, statut, score

Trois informations résument un constat.

### 5.1 La gravité

La gravité décrit l'**impact potentiel**, pas la certitude. De la plus forte à la plus
faible : **Critique**, **Élevée**, **Moyenne**, **Faible**, **Information**.

### 5.2 Le statut de validation

| Statut affiché | Signification |
|---|---|
| **Non validé** | Rien n'a encore été décidé (constat tout juste importé) |
| **Probable** | Vulnérabilité vraisemblable, à confirmer par un analyste |
| **Potentiel faux positif** | Le fait décisif n'a pas été reproduit : **à vérifier en priorité** |
| **Confirmé** | Vulnérabilité confirmée (décision humaine) |
| **Faux positif** | Constat écarté (décision humaine) |

> **Règle d'or de Tscan : le logiciel ne confirme jamais une vulnérabilité.**
> Après un scan, aucun constat n'est automatiquement « Confirmé ». Le moteur peut
> seulement *renforcer* un score ou *lever un doute*. Les verdicts **Confirmé** et
> **Faux positif** sont toujours posés par un humain (§6). C'est ce qui distingue Tscan
> d'un scanner qui crie au loup.

### 5.3 Le score de confiance

Le score va de **0,00** (aucune confiance) à **0,95** (certitude maximale) et **s'accompagne
toujours de son explication** (onglet *Explication du score*). Un score élevé n'est pas une
confirmation : c'est un indice. Un constat « Probable » bien scoré mérite simplement votre
attention en premier.

---

## 6. Corriger le statut d'un constat

C'est l'action la plus importante de l'analyste.

1. Sélectionnez le constat dans la liste.
2. Ouvrez l'onglet **Corriger le statut** du panneau de détail.
3. Choisissez le **Nouveau statut** (Confirmé, Faux positif, Potentiel faux positif,
   Probable, Non validé).
4. Saisissez une **Raison** (fortement recommandé, par exemple
   « Reproduit manuellement sur la page d'accueil »).
5. Cliquez sur **Appliquer**.

Effets immédiats :

- la colonne **Statut** de la ligne est mise à jour ;
- la colonne **Score** est ajustée (Confirmé = 0,95 ; Faux positif = 0,00 ; Potentiel
  faux positif = 0,20) ;
- une **nouvelle entrée** est ajoutée à l'historique avec votre nom, la date et la raison.
  Les changements précédents **ne sont jamais effacés** : l'historique est un journal
  d'audit complet.

---

## 7. Lancer un scan actif (cible autorisée)

Tscan peut aussi analyser une cible **par lui-même**, sans rapport externe.

> **Autorisation obligatoire.** Vous devez disposer d'une autorisation explicite sur la
> cible. Tscan refuse tout scan sans confirmation (ES-01).

### 7.1 Configurer le scan

1. Cliquez sur **Scanner…** (ou `Ctrl+N`).
2. **Cible (autorisée, http/https)** : l'adresse à analyser, par exemple
   `https://www.exemple.cm/`.
3. Cochez **« Je confirme explicitement que cette cible est autorisée »**. Sans cette
   case, le bouton **OK** est refusé (message *« Autorisation requise (ES-01) »*) et
   **aucune requête n'est envoyée**.
4. **Durée maximale** : `0` = aucune limite (valeur par défaut). Sinon, indiquez une durée
   en secondes ; à l'expiration, le scan se termine proprement en gardant ce qu'il a trouvé.
5. **Profondeur de crawl** : `0` = aucune limite (valeur par défaut).
6. **Types de test** : laissez vide pour exécuter **toutes** les détections non
   destructives, ou restreignez (voir annexe C).
7. Cliquez sur **OK**.

### 7.2 Suivre le déroulement

Pendant le scan, la fenêtre reste **entièrement utilisable** (vous pouvez filtrer, ouvrir
un constat, redimensionner…). Les constats **apparaissent au fur et à mesure**.

En bas de la fenêtre, deux onglets se remplissent en direct :

- **Progression** : une barre d'avancement, l'étape en cours (GET, crawl, détection…)
  et un journal d'opérations ;
- **Historique des requêtes** : chaque requête émise (numéro, horodatages, méthode, URL,
  code de réponse).

### 7.3 Interrompre un scan

Le bouton **Arrêter** (`Ctrl+.`) n'est actif que pendant un scan. Il arrête le scan
**proprement** : les constats **déjà trouvés sont conservés**.

### 7.4 À la fin du scan

Une boîte de bilan indique le nombre de constats relevés et la cible. Deux cas notables :

- **La cible a bloqué le scanner** (pare-feu applicatif, protection anti-robot) : un
  avertissement explicite est ajouté :
  `⚠ AVERTISSEMENT : la cible semble bloquer le scanner (…). Le bilan est incomplet…`
  Dans ce cas, **ne concluez pas que le site est sain** : réessayez plus tard, depuis une
  autre adresse IP.
- **Aucun constat** : le message l'indique. Vérifiez d'abord l'absence d'avertissement de
  blocage avant de conclure.

Rappel : les constats issus du scan sont au mieux « Probable ». À vous de les valider
(§6).

---

## 8. Générer un rapport

1. Cliquez sur **Rapport…** (ou `Ctrl+R`).
2. **Fichier de sortie** : cliquez sur **Parcourir…** et choisissez l'emplacement (par
   exemple `rapport.html`).
3. **Format** : **HTML** (recommandé, mise en page complète, s'ouvre dans un navigateur)
   ou **Markdown** (texte structuré, réutilisable).
4. **Cible** : laissez vide pour toutes les cibles, ou saisissez une cible précise.
5. Cliquez sur **OK**.

Un message confirme le chemin et le nombre de constats. Ouvrez ensuite le fichier dans
votre navigateur.

Le rapport comprend :

- un **résumé chiffré** (nombre de constats par gravité et par statut) ;
- le **détail de chaque constat** : description, preuves, explication du score,
  recommandations sourcées (OWASP / CWE) ;
- une section **« Méthodologie anti-faux-positifs »** qui montre les contrôles exécutés.

---

## 9. Changer de thème (clair / sombre)

Cliquez sur **Thème clair** (ou `Ctrl+T`) dans la barre d'outils. L'interface bascule
**immédiatement**, sans redémarrer. Le bouton annonce toujours le thème **vers lequel**
vous allez basculer. Votre choix est **mémorisé** et réappliqué au prochain lancement.
La taille de la fenêtre et la position du séparateur liste/détail sont, elles aussi,
conservées.

---

# Partie II — Utilisation avancée (ligne de commande)

> Cette partie s'adresse aux utilisateurs à l'aise avec une console. Tout ce qui suit
> suppose Tscan installé (§1). Si vous avez coché l'ajout au `PATH` pendant l'installation,
> la commande `tscan` est directement disponible dans une **nouvelle** console.

## 10. Préparer la ligne de commande

### 10.1 Ouvrir une console prête

Depuis le **menu Démarrer**, ouvrez **Tscan (invite de commandes)** : la console s'ouvre
dans le dossier d'installation et la commande `tscan` est disponible.

### 10.2 Vérifier que tout fonctionne

```bash
tscan version
```

doit afficher la version du logiciel. Toute commande accepte `--help` :

```bash
tscan --help
tscan scan --help
```

### 10.3 Depuis les sources (développeurs uniquement)

Si vous travaillez depuis le code source plutôt que depuis l'installeur :

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
tscan version
```

---

## 11. Vue d'ensemble des commandes

| Commande | Rôle |
|---|---|
| `tscan version` | Afficher la version |
| `tscan init-db` | Initialiser la base de données locale (créée automatiquement au besoin) |
| `tscan import FICHIER` | Importer un rapport externe |
| `tscan correlate` | Corréler et scorer les constats importés |
| `tscan list` | Lister les constats |
| `tscan show ID` | Afficher le détail d'un constat |
| `tscan correct ID` | Corriger manuellement le statut d'un constat |
| `tscan scan CIBLE` | Lancer un scan actif autorisé |
| `tscan lookup-cve` | Rechercher les CVE connues d'un composant (réseau) |
| `tscan update-kev` | Synchroniser le catalogue CISA KEV (réseau) |
| `tscan report` | Générer un rapport |

Les deux seules commandes qui accèdent au réseau de leur propre initiative sont
`lookup-cve` (réseau NVD) et `update-kev` (§16). Tout le reste fonctionne **hors-ligne**.

---

## 12. Importer puis corréler (scénario A)

Le scénario typique : vous avez des rapports de scanners externes et vous voulez les
recouper.

```bash
# 1. Importer un rapport ZAP
tscan import rapport-zap.json --format zap --target "https://www.exemple.cm/"

# 2. (Facultatif) Importer un second rapport pour la même cible
tscan import nuclei.jsonl --format nuclei --target "https://www.exemple.cm/"

# 3. Corréler et scorer les constats de cette cible
tscan correlate --target "https://www.exemple.cm/"

# 4. Lister les constats obtenus
tscan list --target "https://www.exemple.cm/"
```

| Option de `import` | Description |
|---|---|
| `--format`, `-f` | `nuclei`, `zap`, `nessus` ou `openvas` (obligatoire) |
| `--target`, `-t` | Libellé de la cible (obligatoire) |
| `--rex` | Après l'import, lancer une **ré-observation active** sur la cible (envoie des requêtes ; confirme implicitement l'autorisation) |

| Option de `correlate` | Description |
|---|---|
| `--target`, `-t` | Limiter la corrélation à une cible (par défaut : toutes) |
| `--rex` | Ré-observer les URLs des constats importés : une ressource introuvable (404/410) place le constat en « potentiel faux positif » |

> La corrélation ne touche **jamais** un constat déjà **Confirmé** par un analyste, ni les
> constats produits par le scan actif de Tscan : elle ne rétrograde pas une décision
> acquise.

---

## 13. Scanner une cible (scénario B)

```bash
tscan scan https://www.exemple.cm/ --authorized
```

| Option | Défaut | Description |
|---|---|---|
| `--authorized` | *(obligatoire)* | Confirme explicitement que la cible est autorisée. Sans elle, aucune requête n'est émise |
| `--max-duration`, `-d` | aucune limite | Durée maximale en secondes |
| `--max-depth` | 0 (sans borne) | Profondeur maximale du crawl |
| `--max-pages` | 40 | Nombre maximal de pages crawlées (`0` = sans borne) |
| `--tests` | toutes | Restreint les familles de détection (annexe C) |
| `--delay` | 0,05 s | Délai entre deux requêtes (à augmenter sur une cible sensible) |

**Exemples :**

```bash
# Scan complet d'une cible autorisée
tscan scan https://www.exemple.cm/ --authorized

# Scan borné à 10 minutes, 20 pages, débit modéré
tscan scan https://www.exemple.cm/ --authorized --max-duration 600 --max-pages 20 --delay 0.2

# Scan restreint à la configuration de sécurité
tscan scan https://www.exemple.cm/ --authorized --tests headers,clickjacking,cors,tls
```

`Ctrl+C` interrompt le scan proprement : les constats déjà enregistrés sont conservés.

---

## 14. Consulter, détailler et corriger

```bash
# Lister (filtres optionnels)
tscan list
tscan list --target "https://www.exemple.cm/" --status probable

# Détail d'un constat (avec explication du score et historique)
tscan show 12

# Corriger manuellement le statut (verdict d'analyste)
tscan correct 12 --status confirmed --reason "Reproduit manuellement en laboratoire"
tscan correct 13 --status false_positive --reason "Page de connexion, pas un panneau exposé"
```

Statuts acceptés par `--status` : `unvalidated`, `probable`, `potential_false_positive`,
`confirmed`, `false_positive`. Le nom d'utilisateur et la date sont enregistrés
automatiquement dans l'historique.

---

## 15. Générer un rapport

```bash
# Rapport HTML pour toutes les cibles
tscan report --output rapport.html

# Rapport Markdown restreint à une cible
tscan report --target "https://www.exemple.cm/" --format markdown --output rapport.md
```

| Option | Défaut | Description |
|---|---|---|
| `--target`, `-t` | toutes | Limiter le rapport à une cible |
| `--format`, `-f` | `html` | `html` ou `markdown` |
| `--output`, `-o` | (affiché à l'écran) | Fichier de sortie |

---

## 16. Base de connaissances CVE / KEV et usage hors-ligne

Tscan peut enrichir ses constats avec les vulnérabilités connues des composants
détectés. Ces données sont **téléchargées à la demande** et **mises en cache
localement**, ce qui permet ensuite de travailler hors-ligne.

```bash
# Rechercher les CVE connues d'un composant (interroge NVD puis met en cache)
tscan lookup-cve "jquery 1.11.0"

# Sans réseau : relire uniquement le cache local
tscan lookup-cve "jquery 1.11.0" --offline

# Synchroniser le catalogue CISA KEV (vulnérabilités activement exploitées)
tscan update-kev
```

> **Vie privée.** Tscan n'envoie **jamais** vos données de scan à un tiers. Les seuls
> échanges réseau sont ceux de `lookup-cve` et `update-kev`, déclenchés explicitement par
> vous.

---

# Annexes

## A. Raccourcis clavier

| Action | Raccourci |
|---|---|
| Importer… | `Ctrl+O` |
| Scanner… | `Ctrl+N` |
| Corréler | `Ctrl+K` |
| Rapport… | `Ctrl+R` |
| Arrêter le scan | `Ctrl+.` (actif pendant un scan) |
| Actualiser | `F5` |
| Basculer le thème | `Ctrl+T` |

## B. Statuts et scores

| Statut | Score associé | Qui le pose |
|---|---|---|
| Non validé | — | Le logiciel, à l'import |
| Probable | selon la règle et la corroboration | Le logiciel (import corrélé ou scan) |
| Potentiel faux positif | 0,20 | Le logiciel (ré-observation) ou vous |
| Confirmé | 0,95 | **Vous uniquement** |
| Faux positif | 0,00 | **Vous uniquement** |

Après une re-vérification, un constat « reproduit » voit son score renforcé (plafonné à
0,85) mais **reste « Probable »**. Un constat « contredit » passe en « Potentiel faux
positif ».

## C. Types de test (option `--tests`)

Valeurs acceptées pour restreindre un scan (séparées par des virgules) :

```
recon, fingerprint, headers, clickjacking, bac, components, xss, csrf, sqli,
sensitive-files, directory-listing, cors, tls, cookies, waf, csp, sri, xdomain-js,
timestamp, security-headers, big-redirect, permissions-policy, modern-web-app,
header-notset, zap-passives, path-traversal, open-redirect, cmd-injection, ssti,
ssrf, header-injection, weak-hash
```

Sans `--tests`, **toutes** les familles non destructives sont exécutées. Un type
inconnu est refusé avec la liste des types valides.

## D. Où sont mes données

| Élément | Emplacement |
|---|---|
| Base de données (constats, preuves, historique) | `%USERPROFILE%\.tscan\tscan.db` |
| Préférences d'interface (thème, taille de fenêtre) | Paramètres utilisateur Windows (QSettings) |
| Règles et base de connaissances | Embarquées dans l'application |

- Toutes les données restent **sur votre poste**. Aucune donnée de scan n'est transmise à
  un tiers sans votre action explicite.
- Pour **sauvegarder**, copiez le fichier `tscan.db`.
- **La désinstallation ne supprime pas** `%USERPROFILE%\.tscan` : supprimez ce dossier
  manuellement si vous voulez effacer définitivement vos données.

## E. Dépannage (questions fréquentes)

**Le scan affiche « 0 constat » : ma cible est-elle vraiment saine ?**
Pas nécessairement. Si un avertissement de blocage s'affiche, la cible a refusé le
scanner : le bilan est incomplet. Réessayez plus tard, depuis une autre adresse IP, ou avec
un débit plus faible (`--delay`).

**Pourquoi aucun constat n'est-il « Confirmé » après un scan ?**
C'est volontaire. Le logiciel ne confirme jamais : la confirmation est votre décision
(§6). Un constat bien re-vérifié reste « Probable » avec un score renforcé.

**Un constat est en réalité un faux positif. Que faire ?**
Corrigez-le en « Faux positif » avec une raison (§6 ou `tscan correct`). Il ne sera plus
présenté comme à traiter, et la décision restera tracée.

**Le bouton « Corriger le statut » ne change rien.**
Vérifiez qu'un constat est bien sélectionné dans la liste avant d'appliquer.

**La case d'autorisation bloque le scan.**
C'est un garde-fou. Confirmez explicitement être autorisé sur la cible avant de scanner.

**Où trouver le rapport que je viens de générer ?**
À l'emplacement exact indiqué dans la boîte de confirmation (chemin complet). Ouvrez le
fichier `.html` dans un navigateur ou `.md` dans un éditeur de texte.

**Puis-je travailler sans Internet ?**
Oui, pour tout sauf `lookup-cve` et `update-kev` (§16). Import, scan, corrélation,
rapports fonctionnent hors-ligne.

**J'ai installé, mais la commande `tscan` n'est pas reconnue.**
Fermez et rouvrez la console (le `PATH` n'est pris en compte que par les nouvelles
fenêtres), ou passez par le raccourci **Tscan (invite de commandes)**.

## F. Glossaire

- **Constat (Finding)** — Un résultat de sécurité : une vulnérabilité constatée à un
  endroit précis d'une cible.
- **Cible** — Le système analysé (généralement un site web).
- **Crawl** — Exploration automatique des pages d'un site par Tscan pour y chercher des
  vulnérabilités.
- **Ré-observation / re-vérification** — Fait de re-tester un constat pour confirmer ou
  infirmer qu'il est toujours présent.
- **Corrélation** — Recoupement de constats issus de plusieurs sources, avec calcul d'un
  score de confiance.
- **Faux positif** — Un constat qui, après vérification, n'est pas une vraie
  vulnérabilité.
- **CVE** — Référence internationale d'une vulnérabilité connue.
- **CISA KEV** — Catalogue des vulnérabilités réellement exploitées.
- **OWASP** — Organisation de référence en sécurité des applications web.

---

*Manuel d'utilisation Tscan 0.1.0 — ANTIC. Pour un complément technique (architecture,
exigences), voir `docs/architecture.md` et `docs/guide_utilisateur.md`. Pour la procédure
de recette de l'interface, voir `documentation/guide_test_manuel_gui.md`.*
