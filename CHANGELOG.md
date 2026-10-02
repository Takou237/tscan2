# Changelog

Toutes les modifications notables de **Tscan**.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnement sémantique. Les entrées sont regroupées par jalon de stage :
chaque item est traçable dans l'historique Git (`git log --oneline`).

Version courante : **0.1.0** — première version complète du MVP.

---

## [0.1.0] — 2026-10-02

Version complète du MVP : import multi-formats, corrélation, scan actif,
scoring explicable, ré-observation anti-faux-positifs, reporting et application
desktop, avec exécutable Windows et installeur.

**État vérifié au 02/10/2026** : 348 tests pytest verts (3 min 52 s), `ruff`
propre sur `src/` et `tests/`, 54 règles YAML, 31 modules de détection.

### Ajouté — Socle (semaines 3 à 6)

- Squelette du projet, environnement virtuel, outillage `ruff`/`pytest` (`631553c`).
- Bloc import et modèle pivot : lecture des rapports externes, normalisation en
  constats dénormalisés, agrégation par vulnérabilité (`73e4c7e`).
- Corrélation, validation, scoring et moteur de règles : chargement déclaratif
  des règles YAML, résolution de règles, scoring explicable (`f4e4742`).
- Base de données, migrations et modèle de traçabilité (auteur, horodatage,
  raison de chaque changement de statut).

### Ajouté — Détection (semaines 7 à 11)

- Scan actif : reconnaissance, crawl borné, TLS, 27 familles de détection non
  destructives, historique des requêtes temps réel (`72c6f70`).
- Import multi-formats : Nuclei, ZAP, Nessus, OpenVAS.
- Corroboration avec OWASP ZAP : règles passives aux titres ZAP exacts.
- Reporting HTML et Markdown : résumé chiffré, preuves, explications de score,
  recommandations sourcées OWASP/CWE (`72c6f70`).
- Application desktop PySide6 : liste filtrable, détail, correction manuelle,
  import, scan, corrélation, rapport, panneaux « Progression » et « History ».

### Ajouté — Empaquetage (28/09/2026)

- Deux exécutables Windows one-file : `tscan.exe` (CLI) et `tscan-gui.exe`
  (desktop), règles et connaissances embarquées (`9b746d5`).
- Script d'installation Inno Setup : installation par utilisateur sans
  élévation, raccourcis, PATH, désinstalleur, interface française.
- Icône et métadonnées de version Windows.

### Ajouté — Démarche anti-faux-positifs (semaine 12, P1→P7)

- Verdict sur la destination des redirections (RF-20) : un `302 /wp-admin/`
  vers une page de connexion n'est plus lu comme un panneau exposé (`f6ff426`).
- Signatures de faux positifs déclaratives (`knowledge/fp_signatures.yaml`).
- **Analyse différentielle SQLi** : un marqueur d'erreur n'est concluant que
  s'il disparaît avec la charge de rupture corrigée (`f5b197e`).
- **Baseline XSS** : un nonce aussi reflété par la requête normale n'est pas un
  signal (`f5b197e`).
- **Sentinelle anti soft-404 généralisée** aux injections SQL/XSS, fichiers
  sensibles et listing de répertoire : une réponse indiscernable du bruit de
  fond ne produit plus de constat (`f5b197e`).
- **Section « Méthodologie anti faux positifs »** dans les rapports : compteurs
  de sondes écartées, preuve que les contrôles ont tourné (`f5b197e`).
- **Re-vérification précise RF-23** des règles parité ZAP et **en-têtes de
  sécurité absents émis par page** avec `probe_info` rejouable : fait reproduit →
  score renforcé, fait contredit → potentiel faux positif (`338df8e`, `cdd483f`).
- Déduplication : `security_headers` et `zap_passive` n'émettent plus les
  constats repris par la nouvelle famille `header_notset` (`cdd483f`).
- Scripts de démonstration rejouables devant témoin : scénarios A et B
  (`03fb3d6`), anti-faux-positifs (`5e652e1`).

### Corrigé

- **Encodage CLI sous Windows** : `stdout`/`stderr` forcés en UTF-8, sinon tout
  caractère hors cp1252 (`≤`, `→`) faisait planter la CLI dès que la sortie était
  redirigée — le cas d'un script ou d'un rapport exporté (`ae1024b`).
- **Bilan des actions longues dans la GUI** : l'import affichait le `dict`
  Python brut (`{'scan_id': 1, 'count': 3, …}`) et les autres actions
  n'affichaient que « Opération terminée. » ; les indicateurs (nombre de
  constats, compteurs par statut, chemin du rapport) sont désormais résumés en
  français.
- Correctif Brotli : cause racine d'un échec silencieux (aucune détection sur
  serveur compressé en Brotli).
- Normalisation FR/EN des catégories (table de synonymes, correspondance par
  mot entier).
- Bornes de volume des sondes : durée de scan prévisible (ES-02).
- Avertissement explicite quand la cible bloque le scanner (anti-bot/WAF), au
  lieu d'un résumé trompeusement normal.
- `HWND_BROADCAST` redéclaré à tort dans le script Inno Setup (`6df298c`).

### Documentation

- Cahier des charges, guide utilisateur (installation, CLI, GUI, UC1→UC5,
  hors-ligne, FAQ) (`79d9fed`).
- Architecture réalisée : 5 écarts assumés et justifiés (`77b7951`).
- Checklist projet tenue à jour par jalon.
- **Guide de test manuel de l'interface** (parcours UC1→UC5, résultats attendus,
  tableau de verdict) : `documentation/guide_test_manuel_gui.md`.
- Rapport de stage en Markdown et en **LaTeX** (compilable pdfLaTeX/Overleaf) :
  `docs/rapport_de_stage.md`, `docs/rapport_de_stage.tex` (`2bce492`).
- Chiffres et états réels harmonisés entre README, checklist, architecture et
  rapport (348 tests, 54 règles, empaquetage produit le 28/09/2026).

### Reste à faire

- Exécution des tests manuels GUI UC1→UC5 sur poste avec affichage (procédure
  rédigée, recette à réaliser).
- Recette d'installation de `tscan-0.1.0-setup.exe` sur une machine « propre ».
- Vérification du fonctionnement hors-ligne (RNF-14/15) sur poste.

---

## Versions antérieures

Aucun numéro de version publié : le projet a été développé étape par étape par des
commits datés plutôt que par des versions. L'historique complet est consultable
par `git log --reverse --oneline`.