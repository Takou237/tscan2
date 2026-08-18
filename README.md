# Tscan

Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité,
développée dans le cadre d'un stage à l'ANTIC.

Tscan importe et fiabilise les résultats de scanners externes (Nuclei, OWASP ZAP), et
exécute son propre moteur de scan actif ciblé sur le périmètre web, avec pour objectif
de réduire les faux positifs par corrélation et validation active non destructive.

## Statut du projet

🚧 **En cours de développement — semaines 5-6 du planning (corrélation, validation, scoring).**

Le cahier des charges complet (contexte, objectifs, étude de l'existant, besoins,
architecture, technologies, planning) se trouve dans `docs/cahier_des_charges.pdf`.

Fonctionnalités disponibles à ce stade :
- Import de résultats Nuclei (JSONL) et OWASP ZAP (JSON) vers le modèle pivot `Finding`
- Système de règles YAML versionnées (`rules/`), une par famille du MVP
- Pré-filtrage contextuel, corrélation multi-sources, scoring de confiance explicable
- Statuts automatiques (Probable / Potentiel faux positif) et correction manuelle avec historique
- **Scénario A démontrable en CLI** : `tscan import` (x2 sources) → `tscan correlate` → `tscan list` / `tscan show` → `tscan correct`

Pas encore implémenté : reconnaissance et scan actif, validation active non
destructive, reporting, interface desktop (blocs des semaines suivantes).

## Structure du dépôt

```
src/
  tscan_core/       Bibliothèque cœur partagée (import, corrélation, détection, reporting)
  tscan_cli/        Interface en ligne de commande (Typer)
  tscan_gui/        Application desktop (PySide6)
rules/              Règles de détection versionnées (YAML)
tests/              Tests automatisés (pytest)
docs/               Documentation du projet
```

## Installation (développement)

```bash
python3 -m venv .venv
source .venv/bin/activate      # sous Windows : .venv\Scripts\activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
```

## Licence

Non définie à ce stade (projet de stage, usage interne ANTIC).
