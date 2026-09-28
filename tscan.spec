# -*- mode: python ; coding: utf-8 -*-
"""Configuration PyInstaller pour Tscan (exécutables Windows CLI et GUI).

Construire les deux exécutables :

    .venv/Scripts/python.exe -m PyInstaller tscan.spec --noconfirm

Produits (dossier `dist/tscan/`) :
- `tscan.exe`      : interface en ligne de commande (console)
- `tscan-gui.exe`  : application desktop PySide6 (fenêtre, pas de console)

Les règles YAML (`rules/`) et les fichiers de connaissances (`knowledge/`)
sont embarqués dans le bundle et retrouvés à l'exécution via
`tscan_core.app_paths.data_root()` (sys._MEIPASS en one-file).
"""

a = Analysis(
    ["src/tscan_cli/__entry__.py"],
    pathex=[],
    binaries=[],
    # Règles de détection et base de connaissances embarquées (RF-13, BNF-10).
    datas=[
        ("rules", "rules"),
        ("knowledge", "knowledge"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)

# --- Exécutable CLI (console) -------------------------------------------------
pyz = PYZ(a.pure)

cli = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="tscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon="assets/tscan.ico",
    version="version_info.txt",
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# --- Exécutable desktop (fenêtre) --------------------------------------------
# Deuxième Analysis : la GUI et la CLI n'embarquent pas les mêmes dépendances
# (PySide6 seulement côté GUI), ce qui évite de gonfler le bundle CLI.
a_gui = Analysis(
    ["src/tscan_gui/__entry__.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("rules", "rules"),
        ("knowledge", "knowledge"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)

pyz_gui = PYZ(a_gui.pure)

gui = EXE(
    pyz_gui,
    a_gui.scripts,
    a_gui.binaries,
    a_gui.datas,
    [],
    name="tscan-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon="assets/tscan.ico",
    version="version_info.txt",
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
