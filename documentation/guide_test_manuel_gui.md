# Guide de test manuel de l'application desktop Tscan (UC1 → UC5)

Procédure pas à pas pour valider l'interface graphique sur un poste **avec
affichage**. Elle complète `docs/guide_utilisateur.md` (qui *décrit* l'interface)
en donnant pour chaque parcours : les manipulations exactes, le résultat attendu
et le critère de réussite.

Ce guide est référencé par :

- `docs/guide_utilisateur.md` §5 (parcours UC1 → UC5) ;
- `src/../tests/lab_server.py` (bloc `__main__`, lancement autonome du labo) ;
- `README.md` (état de S10/S11).

---

## 1. Objet et périmètre

| Parcours | Intitulé | Où il passe |
|---|---|---|
| **UC1** | Consulter et filtrer les constats | Barre de filtres + panneau de détail |
| **UC2** | Corriger un statut manuellement | Panneau de détail → statut + raison |
| **UC3** | Importer un résultat externe | `Importer…` (+ ré-observation active) |
| **UC4** | Lancer un scan actif autorisé | `Scanner…` + onglets Progression / Historique |
| **UC5** | Générer un rapport | `Rapport…` |

Hors périmètre : la logique métier est déjà couverte par les 348 tests pytest
(`tests/test_gui_viewmodel.py` teste les filtres, le tri et la correction sans
écran). Ce guide valide ce qu'un test automatisé ne peut pas voir : **le rendu
réel à l'écran, la réactivité de la fenêtre pendant une opération longue, et la
cohérence des messages affichés**.

**Durée indicative : 30 à 45 minutes.**

---

## 2. Prérequis

- [ ] Un poste Windows **avec affichage** (un simple RDP vers la machine de dev
      suffit ; un bureau à distance sans session graphique ne convient pas).
- [ ] Le dépôt et l'environnement virtuel `.venv` présents.
- [ ] Aucun scan en cours sur une autre instance.

### 2.1 Isolation de la base (à faire impérativement)

L'interface lit la base locale `%USERPROFILE%\.tscan\tscan.db`. Pour ne pas
mélanger les constats d'un essai précédent — et ne pas salir la base de travail
—, rediriger `USERPROFILE` vers un dossier de recette jetable **avant** de
lancer l'application :

```powershell
# PowerShell, depuis la racine du dépôt
$env:USERPROFILE = "$PWD\.tscan_recette"
.venv\Scripts\python.exe -m tscan_gui
```

> Sous Git Bash : `export USERPROFILE="$(cygpath -w "$PWD/.tscan_recette")"`
> (même mécanisme que `scripts/demo_scenario_b.sh`).

Le dossier `.tscan_recette/` est un artefact local de recette : il ne doit pas
être commité.

### 2.2 Démarrage du laboratoire (cible autorisée, obligatoire pour UC4 et UC3)

Dans **un second terminal**, depuis la racine du dépôt :

```powershell
.venv\Scripts\python.exe tests\lab_server.py
```

Sortie attendue :

```
Laboratoire Tscan démarre : http://127.0.0.1:51234/  (Ctrl+C pour arrêter)
```

**Noter le port affiché** : il sert de cible pour UC4. Arrêt : `Ctrl+C`.

> Le laboratoire est un serveur HTTP local qui sert des pages volontairement
> vulnérables (en-têtes absents, XSS, CSRF, SQLi, fichiers sensibles…). Il n'y a
> **aucun accès réseau sortant** : c'est la cible autorisée du cahier des charges.

---

## 3. Convention de restitution

Pour chaque étape, cocher une seule case :

- **[OK]** — le résultat observé est exactement celui attendu ;
- **[ÉCART]** — différence constatée : noter l'attendu, l'obtenu, et ouvrir un
  rapport de boguet.

En fin de document (§7), reporter le verdict par parcours. **Un écart n'invalide
pas la recette** tant qu'il est documenté : c'est l'inventaire des boguet réels
qui compte, pas un tableau tout vert.

---

## 4. UC1 — Consulter et filtrer les constats

### 4.1 Préparation (import initial)

Il faut des constats à filtrer. Utiliser la fixture hors ligne (aucun réseau) :

1. `Importer…` → **Parcourir…** → `tests/fixtures/nuclei_sample.jsonl`
2. **Source** : `nuclei`
3. **Cible concernée** : `http://example.test`
4. **Lancer une ré-observation active** : **décochée** (on testera ce mode en UC3)
5. `OK`

**Attendu** : une boîte de dialogue « Tscan » affiche

```
Import terminé : 3 résultat(s) importé(s) depuis nuclei (scan #1).
```

puis la liste affiche **3 lignes** (le `n°` du scan varie selon votre base).

### 4.2 Lecture d'un constat

Cliquer sur une ligne (par exemple *Exposed Administration Panel*).

**Attendu** dans le panneau de détail :

| Zone | Contenu attendu |
|---|---|
| Titre | `#N — Exposed Administration Panel` |
| Métadonnées | Gravité, Statut, Score, Catégorie, Cible, Source |
| Description | le texte d'information de la finding |
| Preuves | bloc(s) de preuve séparés par `---` |
| Explication du score | justification du score de confiance |
| Historique de statut | `(aucun historique)` au premier import |

**Critère de réussite** : les 5 zones sont remplies et le titre commence par `#N`.

### 4.3 Tri

Cliquer successivement sur les en-têtes **Gravité**, **Score**, **Titre**.

**Attendu** : les lignes sont réordonnées. **La couleur de fond de la cellule
Gravité reste attachée à son constat** (elle suit la ligne, pas le tri).

**Critère** : le tri réordonne sans qu'aucune ligne ne change de gravité.

### 4.4 Filtres

| Action | Attendu |
|---|---|
| **Statut** → `Non validé` | seules les lignes non validées restent |
| **Gravité** → `high` | seule la ligne *Administration Panel* reste |
| **Rechercher** : `csp` | seule la ligne CSP reste |
| **Cible** → `Toutes` | inchangé |

Les filtres sont **combinés en ET logique** : `Statut = Non validé` **et**
`Gravité = high` donne la ligne d'administration.

Puis `Réinitialiser` : **toutes** les lignes reviennent, les 4 filtres sont remis
à leur valeur par défaut.

**Critère** : les 4 filtres agissent indépendamment, se combinent, et
`Réinitialiser` restaure l'état initial.

---

## 5. UC2 — Corriger un statut manuellement

Le moteur **ne confirme jamais** seul : la décision finale appartient à
l'analyste (RF-12). C'est le cœur du parcours à valider.

1. Sélectionner un constat (par exemple la ligne *Administration Panel*,
   gravité `high`).
2. Dans `Corriger le statut`, choisir **`Confirmé`**.
3. Saisir une raison, par exemple : `Reproduit manuellement sur la page d'accueil`
   (champ **Raison**, sous le bouton `Appliquer`).
4. `Appliquer`.

**Attendu** :

- la colonne **Statut** de la ligne passe à `Confirmé` ;
- la colonne **Score** passe à `0.95` ;
- le panneau **Explication du score** et **Historique de statut** se mettent à
  jour ; l'historique contient une entrée mentionnant la raison et l'auteur.

### 5.1 Tracer d'audit (ES-06)

Répéter avec `Faux positif` et une raison differente.

**Attendu** : score `0.00`, et **l'historique conserve les deux changements**
(il ne réécrit pas le précédent).

**Critère de réussite** : statut + score + historique + raison sont tous
cohérents, et la validation est attribuée à l'analyste.

---

## 6. UC3 — Importer un résultat externe

### 6.1 Import simple

Comme en §4.1, mais **sans** ré-observation.

**Attendu** : confirmation du nombre de constats, liste rafraîchie, cibles de la
liste déroulante **Cible** mises à jour.

### 6.2 Import avec ré-observation active (détection de faux positifs)

1. `Importer…` → `tests/fixtures/nuclei_lab_vfp.jsonl`
2. **Source** : `nuclei`
3. **Cible concernée** : l'URL du laboratoire notée en §2.2
   (`http://127.0.0.1:<port>/`)
4. **Lancer une ré-observation active** : **cochée**
5. `OK`

**Attendu** : après l'import, le bilan s'affiche sur **deux lignes** :

```
Import terminé : N résultat(s) importé(s) depuis nuclei (scan #N).
Ré-observation (scan actif #N) : X constat(s) importé(s) — Y corroboré(s),
Z potentiel(s) faux positif(s), W non concluant(s) (revue analytique, RF-12).
```

Puis filtrer sur **Statut = `Potentiel faux positif`** : les constats dont la
ressource n'existe plus sur la cible doivent y figurer.

**Critère de réussite** : les compteurs Y / Z / W s'affichent et au moins un
constat bascule en `Potentiel faux positif`.

> Si le laboratoire est arrêté, l'import aboutit quand même mais la
> ré-observation ne peut rien conclure : les compteurs restent à 0 et les
> constats ne changent pas de statut. C'est le comportement attendu d'un mode
> « best-effort » en l'absence de réseau — le noter tel quel, pas comme un échec.

### 6.3 Contrôle d'erreur attendu

Cliquer `OK` sans fichier, puis `OK` sans cible.

**Attendu** : deux boîtes « Champ requis » — *« Sélectionnez un fichier à
importer. »* puis *« Indiquez la cible concernée. »* — et le dialogue reste
ouvert (aucune requête émise).

### 6.4 Corréler les résultats importés

Action à ne pas sauter : c'est elle qui attribue un score et un statut à chaque
constat importé.

1. `Corréler`
2. **Cible** : laisser vide (toutes les cibles)
3. **Ré-observer les URLs des constats importés** : laisser **cochée**
   (cochée par défaut)
4. `OK`

**Attendu** :

```
Corrélation terminée.
N constat(s) corrélé(s) — X probable(s), Y potentiel(s) faux positif(s).
```

Les constats sans corroboration suffisante restent **Probable** : c'est
voulu (le moteur ne confirme jamais seul, RF-12). Les ressources introuvables
(404/410) basculent en **Potentiel faux positif**.

**Critère de réussite** : les compteurs du bilan correspondent à ce qu'on observe
dans la liste en filtrant par statut.

---

## 7. UC4 — Lancer un scan actif autorisé

### 7.1 Refus sans autorisation (ES-01) — à tester en premier

1. `Scanner…`
2. **Cible** : l'URL du laboratoire
3. Laisser **« Je confirme explicitement que cette cible est autorisée »**
   décochée
4. `OK`

**Attendu** : boîte *« Autorisation requise (ES-01) »*, le dialogue reste ouvert,
**aucune requête n'est partie** (l'onglet *Historique des requêtes* est vide).

### 7.2 Scan autorisé

1. Cocher la case d'autorisation
2. **Durée maximale** : `30` (secondes) — pour ne pas attendre
3. **Profondeur de crawl** : `0` (aucune limite)
4. **Types de test** : laisser vide (toutes les détections)
5. `OK`

**Pendant le scan**, observer :

| Onglet | Attendu |
|---|---|
| **Progression** | barre qui avance, journal qui se remplit (`GET /…`, crawl, détections…) |
| **Historique des requêtes** | une ligne par requête : ID, Envoyé, Reçu, Méthode, URL, Code, Raison |

Et **dans la liste du haut** : les constats doivent **apparaître au fil de l'eau**
(la liste se remplit sans attendre la fin du scan).

**Réactivité (RNF-03)** — pendant que le scan tourne : redimensionner la
fenêtre, cliquer sur une ligne déjà affichée, changer un filtre.

**Attendu** : la fenêtre reste fluide, le scan ne se bloque pas.

**Attendu** : la boîte de bilan affiche le nombre de constats relevés et la cible :

```
Scan terminé.
N constat(s) relevé(s) sur http://127.0.0.1:<port>/.
```

Si la cible refuse le scan (racine en 401/403/429, sonde racine bloquée), un
avertissement est **ajouté** sous ces lignes :

```
⚠ AVERTISSEMENT : la cible semble bloquer le scanner (<raisons>).
Le bilan est incomplet — réessayez plus tard ou depuis une autre adresse IP.
```

**Critère de réussite** : le bilan indique le nombre de constats et la cible ; un
blocage éventuel est signalé explicitement et non masqué par un résumé normal.

### 7.3 Arrêt manuel

Si le scan n'est pas terminé : `Arrêter` (actif seulement pendant un scan).

**Attendu** : le journal affiche `Arrêt demandé — fin propre du scan…`, le scan se
termine proprement, **les constats déjà trouvés sont conservés** (comme un
dépassement de durée). La boîte de bilan s'affiche et contient le nombre de
constats trouvés ainsi que la trace de l'arrêt :

```
Scan terminé.
N constat(s) relevé(s) sur http://127.0.0.1:<port>/.
Arrêt manuel : les constats déjà trouvés sont conservés.
```

Le bouton `Arrêter` redevient inactif. Sans arrêt manuel, la troisième ligne est
absente.

### 7.4 Avertissement de blocage

Point de robustesse : si la cible bloque le scanner, la boîte de bilan doit
ajouter un avertissement explicite plutôt qu'un résumé normal. À vérifier si
lportunity se présente ; **sinon, noter « non observé »** plutôt que coché.

---

## 8. UC5 — Générer un rapport

1. `Rapport…`
2. **Parcourir…** → choisir `rapport_recette.html` dans un dossier de travail
3. **Format** : `HTML`
4. **Cible** : laisser vide (toutes les cibles)
5. `OK`

**Attendu** : la boîte de bilan affiche le chemin et le nombre de constats :

```
Rapport généré.
N constat(s) dans le rapport, écrit dans <chemin choisi>\rapport_recette.html.
```

puis le fichier existe à l'emplacement choisi.

**Vérifier le rendu** : ouvrir le fichier dans un navigateur et contrôler que le
rapport contient bien :

- [ ] un résumé chiffré (nombre de constats par statut et par gravité) ;
- [ ] le tableau des constats, trié ;
- [ ] pour chaque constat : sa description, ses **preuves**, l'**explication du
      score** et les **recommandations sourcées** (référence OWASP / CWE) ;
- [ ] la section **« Méthodologie anti faux positifs »** (compteurs de sondes
      écartées) ;
- [ ] l'identifiant de scan et la cible en en-tête.

Répéter une fois en **Markdown** pour vérifier le second format.

**Critère de réussite** : le HTML s'ouvre sans erreur et contient les 5 éléments
ci-dessus.

---

## 9. Robustesse de l'interface

À vérifier en fin de recette, ces points ont été corrigés en septembre 2026 et
doivent rester acquis :

| # | Test | Attendu |
|---|---|---|
| R1 | Réduire la fenêtre en dessous de 700×380 | Des barres de défilement apparaissent ; **aucun panneau ne disparaît** |
| R2 | Lancer un second scan depuis un PC portable en Wi-Fi qui se déconnecte | Échec affiché proprement (« Échec du scan — voir le journal. »), pas de fenêtre figée |
| R3 | Fermer l'application pendant un scan | Les constats déjà enregistrés en base sont conservés |
| R4 | Ouvrir la fenêtre avec une base vide | Liste vide, aucun message d'erreur, application utilisable |

---

## 10. Verdict — tableau à remplir

| Parcours | Verdict | Constat / ticket |
|---|---|---|
| UC1 — Consulter et filtrer | ☐ OK ☐ ÉCART | |
| UC2 — Corriger un statut | ☐ OK ☐ ÉCART | |
| UC3 — Importer (+ ré-observation) | ☐ OK ☐ ÉCART | |
| — Corréler | ☐ OK ☐ ÉCART | |
| UC4 — Scan actif autorisé | ☐ OK ☐ ÉCART | |
| UC5 — Générer un rapport | ☐ OK ☐ ÉCART | |
| R1 — Fenêtre réduite | ☐ OK ☐ ÉCART | |
| R2 — Perte de réseau | ☐ OK ☐ ÉCART | |
| R3 — Fermeture pendant scan | ☐ OK ☐ ÉCART | |
| R4 — Base vide | ☐ OK ☐ ÉCART | |

**Recette effectuée le** : ____/____/2026 — **Par** : ______________

**Conclusion** : ☐ recette conforme ☐ recette conforme avec réserves
(liste ci-dessous) ☐ recette non conforme

---

## 11. Nettoyage

```powershell
# Arrêter le laboratoire (Ctrl+C dans son terminal), puis supprimer les
# artefacts de recette (base isolée + rapport) :
Remove-Item -Recurse -Force .tscan_recette
Remove-Item -Force rapport_recette.html, rapport_recette.md -ErrorAction SilentlyContinue
```

Ne pas toucher à `%USERPROFILE%\.tscan\tscan.db` (la base de travail) : la
recette s'est faite dans la base isolée de §2.1.