#!/usr/bin/env bash
# ============================================================================
# Démonstration Scénario A — Tscan devant l'encadrant (ANTIC)
# ============================================================================
# Contenu du scénario (chapitre 14 du cahier des charges) :
#   « Import d'un résultat Nuclei et ZAP sur une même cible, corrélation,
#    attribution de statuts avec preuves, et génération de rapport. »
#
# Aucun réseau : les fichiers de démonstration (tests/fixtures/) portent sur
# la cible fictive http://example.test. La base est isolée dans /tmp : votre
# vraie base ~/.tscan/tscan.db n'est jamais touchée.
#
# Utilisation (Git Bash, à la racine du dépôt tscan/) :
#   bash scripts/demo_scenario_a.sh
#
# Alternative devant témoin : remplacer TSCAN par "./dist/tscan.exe".
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

# --- Configuration -----------------------------------------------------------
PYTHON=".venv/Scripts/python.exe"
TSCAN="$PYTHON -m tscan_cli.main"
DEMO_HOME="/tmp/tscan_demo_home_a"
CIBLE="http://example.test"
RAPPORT="rapport_demo_a.html"

mkdir -p "$DEMO_HOME"
export USERPROFILE="$(cygpath -w "$DEMO_HOME")"   # base isolée : $DEMO_HOME/.tscan/tscan.db

# --- Utilitaires -------------------------------------------------------------
pause() {
    echo ""
    read -r -p "—— Appuyez sur Entrée pour continuer ——" _
    echo ""
}

titre() {
    echo ""
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
}

# --- Étape 1 : base locale ----------------------------------------------------
titre "Étape 1 — Initialisation de la base locale"
$TSCAN init-db
echo "Base de démonstration isolée : $(cygpath -w "$DEMO_HOME")/.tscan/tscan.db"
pause

# --- Étape 2 : import Nuclei ---------------------------------------------------
titre "Étape 2 — Import d'un résultat Nuclei (JSONL) — RF-01"
echo "Commande : tscan import tests/fixtures/nuclei_sample.jsonl -f nuclei --target $CIBLE"
$TSCAN import tests/fixtures/nuclei_sample.jsonl -f nuclei --target "$CIBLE"
pause

# --- Étape 3 : import ZAP -------------------------------------------------------
titre "Étape 3 — Import d'un résultat OWASP ZAP (JSON) — RF-02"
echo "Commande : tscan import tests/fixtures/zap_sample.json -f zap --target $CIBLE"
$TSCAN import tests/fixtures/zap_sample.json -f zap --target "$CIBLE"
echo ""
echo "→ Deux sources différentes sur la même cible : matière à corrélation (RF-09)."
pause

# --- Étape 4 : corrélation et scoring -------------------------------------------
titre "Étape 4 — Corrélation multi-sources et scoring de confiance (RF-08/09/10)"
echo "Commande : tscan correlate"
$TSCAN correlate
echo ""
echo "→ Chaque constat reçoit un statut (Probable / en attente de revue) et un"
echo "  score explicable ; le croisement des sources renforce la confiance"
echo "  (bonus multi-source). Le moteur ne pose jamais « Confirmée » (RF-12)."
pause

# --- Étape 5 : consultation -------------------------------------------------------
titre "Étape 5 — Consultation : liste, preuves et explication du score (RF-11)"
$TSCAN list --target "$CIBLE"
echo ""
$TSCAN show 1 || echo "(adapter l'identifiant affiché ci-dessus)"
pause

# --- Étape 6 : verdict d'analyste ---------------------------------------------------
titre "Étape 6 — Correction manuelle d'un statut, avec historique (RF-12 / ES-06)"
echo "Commande : tscan correct 1 -s confirmed -r \"Vérifié par l'analyste devant témoin\""
$TSCAN correct 1 -s confirmed -r "Vérifié par l'analyste devant témoin" \
    || echo "(constat 1 absent — adapter l'identifiant)"
echo ""
$TSCAN show 1 || true
pause

# --- Étape 7 : rapport -----------------------------------------------------------------
titre "Étape 7 — Rapport de sécurité HTML (RF-27/28/29)"
$TSCAN report --target "$CIBLE" --format html --output "$RAPPORT"
echo ""
echo "Rapport généré : $(pwd)/$RAPPORT — l'ouvrir dans le navigateur devant l'encadrant."
pause

# --- Clôture ------------------------------------------------------------------------------
titre "Démonstration terminée"
echo "Récapitulatif du scénario A démontré :"
echo "  1. Import de deux formats hétérogènes (Nuclei JSONL, ZAP JSON) sur une même cible"
echo "  2. Normalisation dans le modèle pivot Finding, brut conservé (ES-07)"
echo "  3. Corrélation multi-sources avec bonus de confiance (RF-09/10)"
echo "  4. Statuts automatiques sans verdict humain automatique (RF-12)"
echo "  5. Preuves et explication du score consultables (RF-11)"
echo "  6. Correction d'analyste tracée (ES-06)"
echo "  7. Rapport HTML professionnel (résumé exécutif + détail sourcé)"
echo ""
echo "Base de démonstration (jetable) : $DEMO_HOME/.tscan/tscan.db"
