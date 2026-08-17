# Tscan

Plateforme d'analyse, de corrélation et de validation de vulnérabilités de sécurité,
développée dans le cadre d'un stage à l'ANTIC.

Tscan importe et fiabilise les résultats de scanners externes (Nuclei, OWASP ZAP), et
exécute son propre moteur de scan actif ciblé sur le périmètre web, avec pour objectif
de réduire les faux positifs par corrélation et validation active non destructive.

## Statut du projet

🚧 **En cours de développement — semaine 4 du planning (bloc import & modèle pivot).**

Le cahier des charges complet (contexte, objectifs, étude de l'existant, besoins,
architecture, technologies, planning) se trouve dans `docs/cahier_des_charges.pdf`.

Fonctionnalités disponibles à ce stade :
- Import de résultats Nuclei (JSONL) et OWASP ZAP (JSON) vers le modèle pivot `Finding`
- Conservation du résultat brut d'origine, rattachement à un `Scan`
- Commande CLI `tscan import <fichier> --format nuclei|zap --target <cible>`

Pas encore implémenté : corrélation, scoring, moteur de règles, scan actif,
reporting, interface desktop (blocs des semaines suivantes).

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
