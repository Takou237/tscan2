#!/usr/bin/env bash
# ============================================================================
# Démonstration Scénario B — Tscan devant l'encadrant (ANTIC)
# ============================================================================
# Contenu du scénario (chapitre 14 du cahier des charges) :
#   « Lancement d'un scan direct sur une cible web autorisée (reconnaissance,
#    familles de détection, validation active, scoring, rapport). »
#
# La cible utilisée est le serveur de laboratoire local (tests/lab_server.py) :
# aucune requête ne sort de la machine (ES-01/ES-09), la démonstration est
# reproductible et indépendante du réseau. Pour une cible internet autorisée,
# remplacer $CIBLE par l'URL réelle (ex. https://polytechnique.cm/).
#
# Utilisation (depuis Git Bash, à la racine du dépôt tscan/) :
#   bash scripts/demo_scenario_b.sh
#
# Le script :
#   - isole la base de démonstration (USERPROFILE redirigé vers /tmp) :
#     votre vraie base ~/.tscan/tscan.db n'est jamais touchée ;
#   - démarre et arrête automatiquement le serveur de laboratoire ;
#   - s'arrête entre chaque étape (Appuyez sur Entrée) pour commenter ;
#   - produit rapport_demo_b.html dans le dossier courant.
#
# Alternative devant témoin : montrer l'exécutable empaqueté (28/09) en
# remplaçant TSCAN="python -m tscan_cli.main" par
# TSCAN="./dist/tscan.exe" — le déroulé est identique.
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

# --- Configuration -----------------------------------------------------------
PYTHON=".venv/Scripts/python.exe"
TSCAN="$PYTHON -m tscan_cli.main"
DEMO_HOME="/tmp/tscan_demo_home"
MAX_DURATION=120          # borne ES-02 : durée maximale du scan (secondes)
RAPPORT="rapport_demo_b.html"

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

# Arrêt garanti du serveur de laboratoire, même en cas d'interruption (Ctrl+C).
LAB_PID=""
nettoyage() {
    if [ -n "$LAB_PID" ] && kill -0 "$LAB_PID" 2>/dev/null; then
        kill "$LAB_PID" 2>/dev/null || true
    fi
}
trap nettoyage EXIT INT TERM

# --- Démarrage du serveur de laboratoire -------------------------------------
titre "Démarrage du serveur de laboratoire local (cible autorisée)"

"$PYTHON" tests/lab_server.py > /tmp/tscan_lab.log 2>&1 &
LAB_PID=$!
sleep 2
CIBLE="$(grep -oE 'http://127\.0\.0\.1:[0-9]+' /tmp/tscan_lab.log | head -1)"
if [ -n "$CIBLE" ]; then
    # Normalisation avec slash final : les constats en base portent la cible
    # sous la forme http://127.0.0.1:<port>/ — les filtres list/report
    # comparent exactement cette valeur.
    CIBLE="${CIBLE%/}/"
fi
if [ -z "$CIBLE" ]; then
    echo "ERREUR : le serveur de laboratoire n'a pas démarré. Log :"
    cat /tmp/tscan_lab.log
    exit 1
fi
echo "Serveur démarré (PID $LAB_PID) : $CIBLE"
echo "Base de démonstration isolée : $(cygpath -w "$DEMO_HOME")/.tscan/tscan.db"
pause

# --- Étape 1 : initialisation de la base -------------------------------------
titre "Étape 1 — Initialisation de la base locale (traçabilité ES-05)"
$TSCAN init-db
pause

# --- Étape 2 : scan actif autorisé -------------------------------------------
titre "Étape 2 — Scan actif autorisé (ES-01 : --authorized, ES-02 : durée bornée)"
echo "Commande : tscan scan $CIBLE --authorized --max-duration $MAX_DURATION"
echo "(reconnaissance, fingerprinting, toutes les familles de détection non"
echo " destructives, re-vérification active RF-23 — sondes GET bénignes ES-03)"
$TSCAN scan "$CIBLE" --authorized --max-duration "$MAX_DURATION"
pause

# --- Étape 3 : consultation des constats --------------------------------------
titre "Étape 3 — Résultats : constats au statut Probable (le moteur ne confirme pas, RF-12)"
$TSCAN list --target "$CIBLE"
echo ""
echo "Le détail d'un constat montre la preuve et l'explication du score :"
$TSCAN show 1 || echo "(aucun constat — ajuster l'identifiant affiché ci-dessus)"
pause

# --- Étape 4 : verdict d'analyste ---------------------------------------------
titre "Étape 4 — Correction manuelle : « Confirmée » est un verdict d'analyste (RF-12)"
echo "Commande : tscan correct 1 -s confirmed -r \"Vérifié par l'analyste devant témoin\""
$TSCAN correct 1 -s confirmed -r "Vérifié par l'analyste devant témoin" \
    || echo "(constat 1 absent — adapter l'identifiant)"
echo ""
$TSCAN show 1 || true
echo "→ Historique tracé (ES-06) : statut automatique initial, verdict posé, auteur, date."
pause

# --- Étape 5 : rapport ---------------------------------------------------------
titre "Étape 5 — Rapport de sécurité (RF-27/28/29 : résumé exécutif + détail sourcé)"
$TSCAN report --target "$CIBLE" --format html --output "$RAPPORT"
echo ""
echo "Rapport généré : $(pwd)/$RAPPORT — l'ouvrir dans le navigateur devant l'encadrant."
pause

# --- Clôture -------------------------------------------------------------------
titre "Démonstration terminée"
echo "Livrables de la séance :"
echo "  - Rapport HTML : $RAPPORT"
echo "  - Base de démonstration (jetable) : $DEMO_HOME/.tscan/tscan.db"
echo ""
echo "Récapitulatif du scénario B démontré :"
echo "  1. Cible autorisée confirmée explicitement (--authorized, ES-01)"
echo "  2. Reconnaissance + fingerprinting + familles de détection non destructives"
echo "  3. Re-vérification active (RF-23) : fait reproduit -> score renforcé (max 0,85),"
echo "     statut laissé Probable ; le moteur ne confirme jamais (RF-12)"
echo "  4. Scoring de confiance explicable (preuves + détail du calcul)"
echo "  5. Verdict d'analyste tracé (Confirmée = 0,95, ES-06)"
echo "  6. Rapport HTML professionnel avec recommandations sourcées"
echo ""
echo "Arrêt du serveur de laboratoire…"
nettoyage
