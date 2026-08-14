# Tscan

Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité,
développée dans le cadre d'un stage à l'ANTIC.

Tscan importe et fiabilise les résultats de scanners externes (Nuclei, OWASP ZAP), et
exécute son propre moteur de scan actif ciblé sur le périmètre web, avec pour objectif
de réduire les faux positifs par corrélation et validation active non destructive.

## Statut du projet

🚧 **En cours de développement — semaine 3 du planning (mise en place du projet).**

Le cahier des charges complet (contexte, objectifs, étude de l'existant, besoins,
architecture, technologies, planning) se trouve dans `docs/cahier_des_charges.pdf`.

À ce stade, seul le squelette du projet est en place : structure des modules, modèles
de données, base de tests, première fenêtre de l'application desktop. Aucune
fonctionnalité d'import, de corrélation ou de scan n'est encore implémentée.

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
