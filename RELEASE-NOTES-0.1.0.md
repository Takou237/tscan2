# Tscan 0.1.0 — Notes de version

*Livraison du 13/10/2026 — installateur `tscan-0.1.0-setup.exe` (95,5 Mo).*

Tscan analyse les vulnérabilités d'un site web : il importe les résultats de
scanners externes, les corrèle avec un scoring de confiance explicable, mène ses
propres scans actifs **non destructifs** et produit des rapports HTML/Markdown.

L'installeur embarque tout ce qu'il faut : Python n'est pas requis sur la
machine.

---

## Contenu de la livraison

| Fichier | Rôle |
|---|---|
| `tscan.exe` (27,0 Mo) | Interface en ligne de commande (11 commandes) |
| `tscan-gui.exe` (67,4 Mo) | Application desktop PySide6 |
| `rules/`, `knowledge/` | 54 règles YAML et base de connaissances **embarquées** dans les deux exécutables |

## Installation

1. Exécuter `tscan-0.1.0-setup.exe`.
2. Installation **par utilisateur, sans élévation** : les programmes vont dans
   `%localappdata%\Programs\Tscan`.
3. Raccourcis créés dans le menu Démarrer (application + console CLI) et sur le
   bureau (optionnel). La variable `PATH` utilisateur est mise à jour
   automatiquement : la commande `tscan` est disponible immédiatement (les
   fenêtres de terminal **ouvertes avant** l'installation doivent être rouvertes).

## Ce que la version 0.1.0 fait

- **Import multi-formats** : Nuclei (JSONL), ZAP (JSON), Nessus/OpenVAS (XML) ;
  le résultat brut d'origine est conservé intact.
- **Corrélation et scoring explicable** : constats regroupés par vulnérabilité
  (instances comptées), score 0–1 accompagné de son explication ligne par ligne.
- **Scan actif borné et non destructif** (après confirmation explicite de
  l'autorisation) : reconnaissance, fingerprinting technologies, crawl plafonné,
  31 familles de détection (en-têtes de sécurité, clickjacking, contrôle
  d'accès défaillant, XSS, CSRF, SQLi *error-based* en analyse différentielle,
  fichiers sensibles, listing, TLS faible…), sondes GET bénignes uniquement.
- **Machine anti-faux positifs (P1→P7)** : analyse différentielle SQLi,
  baseline XSS, sentinelle anti soft-404, verdict à la re-vérification
  précise (fait reproduit → score renforcé, fait contredit → potentiel faux
  positif). Le rapport démontre les contrôles exécutés (section
  « Méthodologie anti-faux positifs »).
- **Application desktop** : liste filtrable (statut/gravité/cible/recherche),
  détail complet (preuves, explication du score, historique des statuts),
  correction manuelle avec raison tracée, import, scan avec périmètre, bouton
  « Arrêter », corrélation, rapport. Suivi **temps réel** du scan : panneau de
  progression + historique des requêtes HTTP (type « History » de ZAP).
- **Thème clair / sombre** (sombre par défaut, bascule `Ctrl+T`, choix
  mémorisé).
- **Rapports** HTML et Markdown : résumé exécutif, recommandations sourcées
  OWASP/CWE.
- **Cœur partagé** CLI/GUI : aucune logique dupliquée entre les deux interfaces.
- **Hors ligne** : tout fonctionne sans réseau, sauf les commandes explicites
  `tscan lookup-cve` et `tscan update-kev` (cache local NVD/CISA-KEV).

## Usage rapide (CLI)

```text
tscan import  fichier.jsonl --format nuclei --target "https://exemple.test/"
tscan correlate
tscan list
tscan scan    https://exemple.test/ --authorized   # cible autorisée obligatoire
tscan report  --format html -o  rapport.html
```

Raccourcis GUI : `Ctrl+O` importer, `Ctrl+N` scanner, `Ctrl+K` corréler,
`Ctrl+R` rapport, `Ctrl+.` arrêter le scan, `F5` actualiser, `Ctrl+T` thème.

## Vérifications effectuées sur cette version (13/10/2026)

- Suite de tests `pytest` verte, `ruff` propre sur `src/` et `tests/`.
- Exécutables : `tscan version`, `--help`, recette complète dans un
  environnement isolé (la base `~/.tscan/tscan.db` de l'utilisateur n'est pas
  touchée par ces vérifications) : `init-db` → import Nuclei réel (3 constats)
  → corrélation (54 règles du bundle chargées) → `list` corrects.
- GUI : démarrage et fermeture propres vérifiés en mode offscreen.

## Limites connues

- La fenêtre de la GUI n'a pas été testée sur un affichage réel ici : les
  parcours manuels UC1→UC5 restent à exécuter (procédure dans
  `documentation/guide_test_manuel_gui.md`).
- L'installeur n'a pas encore été installé sur une machine « propre ».
- Aucun module destructif (SSTI actif, désérialisation…) n'est implémenté
  volontairement : les types de tests à risque sont exclus du moteur.
- Scans actifs possiblement bloqués par un WAF/anti-bot : un avertissement
  explicite est affiché, le bilan est signalé incomplet.

## Protection des données

Tout est stocké localement (`~/.tscan/tscan.db`, SQLite). Aucune transmission
vers un tiers n'a lieu sans action explicite de l'utilisateur ; les requêtes de
mise à jour (NVD / CISA-KEV) ne sont déclenchées que par les commandes dédiées.

*Détail complet des changements : voir `CHANGELOG.md`. Historique : `git log --oneline`.*
