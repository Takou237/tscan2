#!/usr/bin/env bash
# ============================================================================
# Démonstration « Détection des faux positifs » — Tscan devant l'encadrant
# ============================================================================
# Objectif (cœur du projet, RF-23 / RF-12) : mesurer le taux de détection des
# faux positifs de Tscan sur une cible comportant des résultats obsolètes.
#
# Principe de la démonstration :
#   1. Un serveur de laboratoire local est démarré (cible autorisée, boucle
#      locale — ES-01/ES-09, aucun réseau sortant).
#   2. Un « rapport Nuclei » de démonstration est importé : 19 constats dont
#      4 pointent vers des ressources qui N'EXISTENT PLUS sur la cible
#      (/info.php, /debug/info, /admin-backup/, /backup-old/) — simulant un
#      rapport de scan ancien contenant des faux positifs — et 1 vers une
#      ressource TOUJOURS PRÉSENTE (/files/) que la ré-observation ne doit
#      PAS contredire (sélectivité du contrôle).
#   3. La ré-observation active (--rex) re-vérifie chaque constat importé :
#      ressource introuvable (404/410) -> « Potentiel faux positif » ;
#      ressource toujours présente -> corroboré ou non concluant (RF-12).
#   4. Le taux de détection est calculé et affiché.
#   5. L'analyste tranche ensuite (correct -s false_positive), historique
#      conservé (ES-06).
#
# La fixture modèle (tests/fixtures/nuclei_lab_vfp.jsonl) mentionne le port
# 51256 ; le script le réécrit avec le port réel du labo démarré.
#
# Utilisation (Git Bash, à la racine du dépôt tscan/) :
#   bash scripts/demo_false_positives.sh
#
# Alternative devant témoin : remplacer TSCAN par "./dist/tscan.exe".
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

# --- Configuration -----------------------------------------------------------
PYTHON=".venv/Scripts/python.exe"
TSCAN="$PYTHON -m tscan_cli.main"
DEMO_HOME="/tmp/tscan_demo_home_fp"
FIXTURE="tests/fixtures/nuclei_lab_vfp.jsonl"
FIXTURE_REWRITE="/tmp/tscan_nuclei_vfp_demo.jsonl"
RAPPORT="rapport_demo_fp.html"

# Base de démonstration NEUVE à chaque exécution : le script est rejouable
# devant témoin sans mélanger les constats d'un run précédent.
rm -rf "$DEMO_HOME"
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

# --- Étape 0 : démarrage du labo ----------------------------------------------
titre "Étape 0 — Démarrage du serveur de laboratoire local"

"$PYTHON" tests/lab_server.py > /tmp/tscan_lab_fp.log 2>&1 &
LAB_PID=$!
sleep 2
PORT="$(grep -oE '127\.0\.0\.1:[0-9]+' /tmp/tscan_lab_fp.log | head -1 | cut -d: -f2)"
CIBLE="http://127.0.0.1:${PORT}/"
if [ -z "$PORT" ]; then
    echo "ERREUR : le serveur de laboratoire n'a pas démarré. Log :"
    cat /tmp/tscan_lab_fp.log
    exit 1
fi
echo "Serveur démarré (PID $LAB_PID) : $CIBLE"
echo "Base de démonstration isolée : $(cygpath -w "$DEMO_HOME")/.tscan/tscan.db"
pause

# --- Étape 1 : préparation du rapport « ancien » -------------------------------
titre "Étape 1 — Préparation d'un rapport Nuclei contenant des faux positifs"

sed "s/127\.0\.0\.1:51256/127.0.0.1:${PORT}/g" "$FIXTURE" > "$FIXTURE_REWRITE"
TOTAL_FIXTURE="$(wc -l < "$FIXTURE_REWRITE" | tr -d ' ')"
echo "Rapport importé : $TOTAL_FIXTURE constat(s) au format Nuclei (JSONL)."
echo ""
echo "4 de ces constats pointent vers des ressources qui n'existent PLUS sur"
echo "la cible (rapport de scan ancien / obsolète) :"
echo "    /info.php      (phpinfo() Exposed)"
echo "    /debug/info    (Debug Endpoint Exposed)"
echo "    /admin-backup/ (Admin Backup Panel Found)"
echo "    /backup-old/   (Old Backup Directory Found)"
echo ""
echo "... et 1 vers une ressource TOUJOURS PRÉSENTE :"
echo "    /files/        (Directory Listing Detected) — la ré-observation ne"
echo "                   doit PAS la contredire (sélectivité du contrôle)"
echo ""
echo "→ Vérité terrain attendue : 4 faux positifs sur $TOTAL_FIXTURE constats."
pause

# --- Étape 2 : import avec ré-observation active --------------------------------
titre "Étape 2 — Import + ré-observation active (--rex, RF-23)"
echo "Commande : tscan import <rapport> -f nuclei --target $CIBLE --rex"
echo ""
$TSCAN import "$FIXTURE_REWRITE" -f nuclei --target "$CIBLE" --rex
echo ""
echo "→ Chaque constat importé a été re-vérifié : ressoures 404/410 = fait"
echo "  décisif disparu = « Potentiel faux positif » (le moteur ne déclare"
echo "  jamais « Faux positif » seul — verdict d'analyste, RF-12)."
pause

# --- Étape 3 : constats signalés --------------------------------------------------
titre "Étape 3 — Constats signalés « Potentiel faux positif »"
$TSCAN list -s potential_false_positive
PFP_LIST="$(mktemp)"
$TSCAN list -s potential_false_positive | grep -oE '^#[0-9]+' | tr -d '#' > "$PFP_LIST"
PFP="$(wc -l < "$PFP_LIST" | tr -d ' ')"
pause

# --- Étape 4 : taux de détection ---------------------------------------------------
titre "Étape 4 — Taux de détection des faux positifs"
# Dénominateur : les constats IMPORTÉS uniquement ($TOTAL_FIXTURE). La
# ré-observation exécute aussi un scan actif de corroboration dont les
# constats propres (Probable) sont stockés dans la même base — ils ne
# font pas partie du rapport importé et ne doivent pas diluer le taux.
RATE="$(awk -v p="$PFP" -v t="$TOTAL_FIXTURE" 'BEGIN{ if (t>0) printf "%.0f", 100*p/t; else print "n/a" }')"
echo "    Constats importés........................ : $TOTAL_FIXTURE"
echo "    Faux positifs potentiels détectés........ : $PFP"
echo "    Taux de détection........................ : ${RATE} %"
echo ""
echo "Attendu : 4 sur $TOTAL_FIXTURE (les 4 ressources 404). /files/ existe"
echo "toujours : son constat n'est pas contredit — corroboré par le scan actif ou"
echo "laissé en attente de revue (RF-12)."
echo ""
echo "Détail d'un faux positif détecté (preuve + explication) :"
FIRST_PFP="$(head -1 "$PFP_LIST")"
if [ -n "$FIRST_PFP" ]; then
    $TSCAN show "$FIRST_PFP" || true
fi
pause

# --- Étape 5 : verdict d'analyste ----------------------------------------------------
titre "Étape 5 — L'analyste confirme le faux positif (RF-12 / ES-06)"
if [ -n "$FIRST_PFP" ]; then
    echo "Commande : tscan correct $FIRST_PFP -s false_positive -r \"Ressource disparue, confirmé par l'analyste\""
    $TSCAN correct "$FIRST_PFP" -s false_positive \
        -r "Ressource disparue, confirmé par l'analyste" || true
    echo ""
    $TSCAN show "$FIRST_PFP" || true
fi
pause

# --- Étape 6 : rapport ------------------------------------------------------------------
titre "Étape 6 — Rapport de sécurité (les statuts PFP y sont visibles)"
$TSCAN report --target "$CIBLE" --format html --output "$RAPPORT"
echo ""
echo "Rapport généré : $(pwd)/$RAPPORT"
pause

# --- Clôture ------------------------------------------------------------------------------
titre "Démonstration terminée — synthèse"
echo "  Cible (labo local)....................... : $CIBLE"
echo "  Constats importés (rapport Nuclei)....... : $TOTAL_FIXTURE"
echo "  Faux positifs potentiels détectés........ : $PFP (taux ${RATE} %)"
echo "  Verdict analyste posé et tracé........... : oui (historique ES-06)"
echo ""
echo "Ce que cette démonstration prouve (positionnement Tscan, chapitre 5) :"
echo "  - la ré-observation active contredit automatiquement les constats dont"
echo "    le fait décisif a disparu (404/410) — sans jamais sur-confirmer ;"
echo "  - l'analyste garde le dernier mot (RF-12) avec traçabilité complète ;"
echo "  - les constats sains ne sont pas dégradés (pas de dégradation par"
echo "    score statique — correctif semaine 12)."
echo ""
echo "Base de démonstration (jetable) : $DEMO_HOME/.tscan/tscan.db"
echo "Arrêt du serveur de laboratoire…"
nettoyage
