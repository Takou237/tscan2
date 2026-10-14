# Changelog

Toutes les modifications notables de **Tscan**.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnement sémantique. Les entrées sont regroupées par jalon de stage :
chaque item est traçable dans l'historique Git (`git log --oneline`).

Version courante : **0.1.0** — première version complète du MVP.

---

## [Unreleased]

### Corrigé — Réduction du bruit de détection (14/10/2026)

Audit du bruit du scan actif : sur une cible saine, 15 constats étaient tous des
faux positifs d'en-têtes « absent ». Deux causes racines corrigées :

- **Sondes de chemins analysées comme des pages** : la table `pages` mêlait les
  pages réellement servies et les sondes de chemins (BAC `path_status`) qui
  répondent 403/404. Les modules d'analyse passive (en-têtes, CSP,
  Permissions-Policy, parité ZAP, SRI, timestamps, `modern-web-app`) itèrent
  désormais `served_pages` (statut 2xx uniquement, cf.
  `scan/detections/page_scope.py`) : plus de constat « en-tête absent » sur une
  page d'erreur issue d'une sonde interne.
- **Doublons d'en-têtes** : `RULE-MISCONFIG-001` (déclaratif, racine) et les
  familles dédiées (`RULE-*-NOTSET`, par page, rejouables) signalaient le même
  en-tête. `superseded_headers` (`scan/checks.py`) retire le check déclaratif
  quand la famille dédiée est active : un seul constat par en-tête.

**Effet mesuré** : cible saine → 15 faux positifs → **2 constats** (tous deux
légitimes) ; scénario B sur le labo → 46 → **33 constats** (MISCONFIG-001 : 6 → 1).

**Tests** : `tests/test_noise_reduction.py` (9 tests : filtre `served_pages`,
dé-duplication, intégration orchestrateur) ; `test_s11_scenarios.py` recalibré
(46 → 33). Suite complète : **387 tests verts**, `ruff` propre.

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

### Repackaging (13/10/2026)

Les livrables Windows ont été reconstruits pour embarquer les modifications
récentes (habillage graphique clair/sombre de la GUI du 08/10, pastilles
corrigées sur fond sombre — retour du 09/10, regroupement des instances par
vulnérabilité, retrait d'un import inutilisé dans `widgets.py`) :

- Exécutables reconstruits (PyInstaller 6.22.3, `--clean --noconfirm`) :
  `dist/tscan.exe` (27,0 Mo) et `dist/tscan-gui.exe` (67,4 Mo).
- Recette re-vérifiée sur le bundle : `version`, `--help`, puis, dans un
  répertoire `USERPROFILE` isolé (technique des scripts de démonstration,
  la vraie base `~/.tscan/tscan.db` n'est jamais touchée), `init-db` →
  import Nuclei réel (3 constats) → corrélation (règles du bundle chargées)
  → `list` corrects ; `tscan-gui.exe` démarre (offscreen) et se ferme
  proprement.
- Installeur recompilé (`ISCC.exe installer/tscan.iss`) :
  `installer/Output/tscan-0.1.0-setup.exe` (95,5 Mo).

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
- **Sondes écartées exposées (14/10/2026)** : chaque sonde écartée par un
  contrôle anti-faux-positifs (sentinelle P2, verdicts différentiels P1) devient
  un constat au statut **Potentiel faux positif** — règle de la famille, preuve
  par raison exécutée et historique de statut — au lieu d'un simple compteur :
  l'analyste voit ce que le moteur a volontairement écarté (RF-12).
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
- **Sur-suppression de la sentinelle anti soft-404 (14/10/2026)** : l'indice fondé
  sur la seule réflexion du jeton classait *toute* page 200 comme générique dès
  que le serveur ré-écho le chemin demandé (404 habillé, CMS), supprimant à la
  fois de vrais et de faux positifs. Une réponse n'est désormais écartée que si
  elle est **indiscernable du contrôle** (jeton-sentinelle et chemin demandé
  retirés des deux corps, mots principaux communs et longueur comparable) ; un
  serveur qui ré-écho le chemin dans une page par ailleurs propre à la ressource
  sondée conserve son constat. Suite portée à **377 tests verts**, `ruff` propre.

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