# Checklist complète — Projet Tscan

Cette checklist suit le planning du chapitre 13 du cahier des charges (11 semaines). Chaque case cochée doit correspondre à un critère réellement vérifié, pas supposé. Les références (RF-xx, RNF-xx, ES-xx) renvoient aux chapitres 6, 7 et 9 du cahier des charges.

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
- [ ] Créer le dépôt Git (nom, description, visibilité)
- [ ] Définir la structure des dossiers (cœur, CLI, GUI, règles, tests, documentation)
- [ ] `.gitignore` adapté à Python
- [ ] README initial (présentation courte, statut du projet, installation prévue)
- [ ] Convention de messages de commit définie et respectée dès le premier commit

**Environnement**
- [ ] Environnement virtuel Python créé
- [ ] Gestion des dépendances mise en place (`pyproject.toml` ou `requirements.txt`)
- [ ] Outils de qualité configurés (formatage, linting)

**Squelette technique**
- [ ] Squelette de la bibliothèque cœur (modules vides : import, corrélation, détection, règles, reporting, base de données)
- [ ] Modèles de données initiaux (SQLAlchemy) : `Finding`, `Scan`, `Rule`, `Evidence`
- [ ] Script ou migration d'initialisation de la base SQLite
- [ ] Premier test automatisé qui passe (pytest configuré)
- [ ] Première fenêtre PySide6 minimale fonctionnelle (pour lisser la courbe d'apprentissage dès le début, comme prévu au chapitre 13)

**Documentation**
- [ ] README mis à jour avec l'état réel du squelette

---

## Semaine 4 — Bloc import & modèle pivot

- [ ] Modèle de données `Finding` finalisé (champs, statuts RF-07)
- [ ] Parseur Nuclei (JSONL) → `Finding` (RF-01)
- [ ] Parseur ZAP (JSON) → `Finding` (RF-02)
- [ ] Modèle pivot appliqué de façon homogène (RF-04)
- [ ] Conservation du résultat brut d'origine (RF-05 / ES-07)
- [ ] Statuts de validation initiaux posés (Confirmée / Probable / Potentiel faux positif / Faux positif)
- [ ] Commande CLI d'import (`tscan import ...`)
- [ ] Tests unitaires sur les deux parseurs, avec au moins un jeu de données réel par format
- [ ] Vérification manuelle : import réel d'un résultat Nuclei et d'un résultat ZAP, listage via CLI

---

## Semaines 5–6 — Corrélation, validation, scoring

- [ ] Pré-filtrage contextuel implémenté (service actif, version, cohérence) (RF-08)
- [ ] Corrélation multi-sources sur une même cible (RF-09)
- [ ] Format de règle YAML finalisé (identifiant, catégorie, gravité, conditions, méthode de validation, preuves attendues, recommandations, références, version)
- [ ] Chargeur de règles dynamique (aucune règle codée en dur) (RF-13)
- [ ] Au moins une règle écrite pour chacune des cinq familles du MVP
- [ ] Moteur de scoring de confiance explicable (RF-10)
- [ ] Consultation des preuves associées à un résultat (RF-11)
- [ ] Correction manuelle d'un statut, avec historique conservé (RF-12)
- [ ] Tests unitaires sur la corrélation et le scoring
- [ ] **Jalon intermédiaire : Scénario A démontrable en CLI** (import → corrélation → statuts → preuves → sans rapport final à ce stade)

---

## Semaine 7 — Reconnaissance et détection (familles simples)

- [ ] Module de reconnaissance web (headers, TLS, technologies de base) (RF-15)
- [ ] Fingerprinting technologies courantes (RF-16)
- [ ] Détection Security Misconfiguration + Clickjacking (RF-17)
- [ ] Détection composants vulnérables connus, via correspondance version → CVE (RF-18)
- [ ] Détection Broken Access Control basique (RF-20)
- [ ] Contrôle de périmètre implémenté dès ce stade : cible autorisée, profondeur, durée (RF-24 / ES-01, ES-02)
- [ ] Mode sécurisé par défaut activé (ES-03)
- [ ] Tests sur une cible de test contrôlée et autorisée (environnement de laboratoire local)

---

## Semaine 8 — Détection (familles restantes) et validation active

- [ ] Détection XSS réfléchi (RF-19)
- [ ] Détection absence de protection CSRF (RF-21)
- [ ] Confirmation active non destructive pour les cinq familles (RF-23)
- [ ] (Bonus, si avancement le permet) Détection injection SQL error-based (RF-22)
- [ ] Journalisation de chaque scan actif (cible, horodatage, périmètre) (ES-05)
- [ ] Tests sur cible de test contrôlée pour chaque famille
- [ ] **Jalon de sécurité : Scénario B démontrable intégralement en CLI**

---

## Semaine 9 — Reporting et finalisation CLI

- [ ] Générateur de rapport (résumé exécutif + détails techniques) (RF-27)
- [ ] Export PDF et/ou HTML (RF-29)
- [ ] Recommandations liées à des sources vérifiables (RF-28)
- [ ] CLI complète et cohérente (import, scan, correction, rapport)
- [ ] Tests d'intégration de bout en bout du cœur (import → corrélation → scan → rapport)
- [ ] Revue d'architecture (cohérence avec le chapitre 10, dette technique)
- [ ] Revue de code (qualité, duplication, sécurité)

---

## Semaine 10 — Application desktop

- [ ] Fenêtre principale : liste des résultats avec filtres (statut, gravité, cible)
- [ ] Vue détail d'un résultat : preuves, score, historique de statut
- [ ] Correction manuelle d'un statut depuis l'interface (RF-12)
- [ ] Lancement d'un import depuis l'interface
- [ ] Lancement d'un scan depuis l'interface, avec définition du périmètre (RF-24)
- [ ] Génération de rapport depuis l'interface
- [ ] Vérification que l'interface reste réactive pendant les opérations longues (RNF-03)
- [ ] Tests manuels de l'ensemble des parcours utilisateur (UC1 à UC5)

---

## Semaine 11 — Intégration finale, durcissement, démonstration

**Tests et sécurité**
- [ ] Tests de bout en bout des scénarios A et B complets (CLI et desktop)
- [ ] Revue de sécurité complète (voir checklist ES-01 à ES-12 ci-dessous)
- [ ] Vérification du fonctionnement hors-ligne des fonctions concernées (RNF-14, RNF-15)

**Empaquetage**
- [ ] Génération de l'exécutable Windows (PyInstaller)
- [ ] Installeur généré et testé (Inno Setup)
- [ ] Installation testée sur une machine "propre" si possible

**Documentation**
- [ ] Documentation utilisateur finalisée
- [ ] Documentation technique / architecture finalisée
- [ ] README final à jour
- [ ] Changelog à jour

**Démonstration**
- [ ] Script de démonstration préparé (scénarios A et B)
- [ ] Répétition complète de la démonstration
- [ ] Vérification de chaque critère de réussite du MVP (chapitre 14)
- [ ] Limites explicites du MVP formulées clairement pour l'encadrant (chapitre 15)
- [ ] Perspectives post-stage prêtes à être présentées (chapitre 16)

---

## Checklist transverse — Sécurité (à revalider à chaque bloc, pas seulement en fin de projet)

- [ ] ES-01 — Cible confirmée explicitement avant tout scan actif
- [ ] ES-02 — Périmètre limitable (domaine, profondeur, durée, types de tests)
- [ ] ES-03 — Mode sécurisé (non destructif) activé par défaut
- [ ] ES-04 — Familles à risque (SSRF, désérialisation...) bien exclues du moteur
- [ ] ES-05 — Journalisation systématique des scans actifs
- [ ] ES-06 — Traçabilité des corrections manuelles de statut
- [ ] ES-07 — Résultat brut d'origine conservé sans modification
- [ ] ES-08 — Preuves stockées localement avec un niveau de protection adapté
- [ ] ES-09 — Aucune transmission de données à un tiers sans action explicite
- [ ] ES-10 — Entrées validées avant construction des requêtes de test
- [ ] ES-11 — Intégrité vérifiée sur les données de mise à jour (règles, connaissances)
- [ ] ES-12 — Dépendances tierces suivies avec vigilance

---

## Checklist transverse — Qualité et documentation continue

- [ ] Un test automatisé au minimum ajouté pour chaque nouveau module critique
- [ ] Documentation mise à jour à chaque fin de bloc, pas seulement en semaine 11
- [ ] Commits réguliers, messages explicites
- [ ] Comparaison avancement réel / planning effectuée chaque semaine (chapitre 13)
- [ ] Tout retard signalé et arbitré selon la priorité qualité > quantité (chapitre 2)

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
