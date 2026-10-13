"""Tests du thème visuel de l'application desktop (clair / sombre).

`tscan_gui.theme` centralise les jetons de couleur, la feuille de style QSS,
la palette Fusion et la mémorisation du thème. Les fonctions « pures » sont
testées ici **sans instancier la moindre fenêtre Qt** (aucun écran requis, la
suite reste lancable en SSH/headless) :

- jetons et repli sur le thème par défaut ;
- génération de la QSS (uniquement des jetons résolus, widgets couverts) ;
- couverture des pastilles de gravité / statut par le vocabulaire métier ;
- rangs de tri et libellés français ;
- persistance du thème, isolée dans un dossier temporaire via
  `TSCAN_SETTINGS_DIR` (aucune préférence réelle de la machine n'est touchée).
"""

from __future__ import annotations

from tscan_gui import theme
from tscan_gui.viewmodel import (
    SEVERITY_ORDER,
    VALID_STATUSES,
    severity_label,
    severity_rank,
    status_rank,
)


def test_default_theme_is_dark_and_listed() -> None:
    assert theme.DEFAULT_THEME == "dark"
    assert theme.THEMES == ("dark", "light")
    assert theme.DEFAULT_THEME in theme.THEMES


def test_tokens_returns_independent_copies_with_same_keys() -> None:
    dark = theme.tokens("dark")
    light = theme.tokens("light")
    assert set(dark) == set(light)
    assert dark["window"] != light["window"]
    dark["window"] = "#000000"  # la copie ne corrompt pas le jeton d'origine
    assert theme.tokens("dark")["window"] != "#000000"


def test_tokens_falls_back_on_default_theme() -> None:
    assert theme.tokens() == theme.tokens(theme.DEFAULT_THEME)
    assert theme.tokens("inconnu") == theme.tokens(theme.DEFAULT_THEME)


def test_next_theme_and_label_announce_the_target() -> None:
    assert theme.next_theme("dark") == "light"
    assert theme.next_theme("light") == "dark"
    assert theme.next_theme("inconnu") == "light"  # repli sur dark
    # Le bouton annonce le thème dans lequel on bascule.
    assert theme.theme_label("dark") == "Thème clair"
    assert theme.theme_label("light") == "Thème sombre"


def test_stylesheet_has_no_unresolved_placeholder() -> None:
    for name in theme.THEMES:
        css = theme.build_stylesheet(name)
        assert css.strip()
        assert "$" not in css
    assert theme.build_stylesheet("inconnu") == theme.build_stylesheet("dark")


def test_stylesheet_differs_between_themes() -> None:
    assert theme.build_stylesheet("dark") != theme.build_stylesheet("light")


def test_stylesheet_covers_the_widgets_of_the_main_window() -> None:
    css = theme.build_stylesheet("dark")
    for selector in (
        "QMainWindow",
        "QToolBar",
        "QToolButton",
        "QGroupBox",
        "QSplitter::handle",
        "QTabBar::tab",
        "QLineEdit",
        "QComboBox",
        "QCheckBox",
        "QPushButton#primaryButton",
        "QTableWidget",
        "QHeaderView::section",
        "QProgressBar",
        "QScrollBar",
        "QLabel#countLabel",
        "QLabel#emptyStateLabel",
        "QToolTip",
    ):
        assert selector in css, f"selecteur absent de la QSS : {selector}"


def test_badge_colors_cover_the_whole_vocabulary() -> None:
    """Pastilles par thème : chaque valeur du vocabulaire a ses couleurs dans
    les deux thèmes, et le texte sombre est réservé au thème clair (sur fond
    de table sombre, un texte noir devenait illisible)."""
    for theme_name in theme.THEMES:
        for value in SEVERITY_ORDER:
            background, foreground = theme.severity_badge(value, theme_name)
            assert background.startswith("#") and len(background) == 7
            assert foreground.startswith("#") and len(foreground) == 7
        for value in VALID_STATUSES:
            background, foreground = theme.status_badge(value, theme_name)
            assert background.startswith("#") and len(background) == 7
            assert foreground.startswith("#") and len(foreground) == 7
    assert len(theme.DEFAULT_BADGE_COLOR) == 2
    # Valeur hors vocabulaire : repli identique quel que soit le thème.
    assert theme.severity_badge("inconnue") == theme.severity_badge("inconnue", "light")
    assert theme.status_badge("inconnu", "dark") == theme.DEFAULT_BADGE_COLOR


def test_dark_theme_badges_have_white_text() -> None:
    """Retour utilisateur 09/10/2026 : en thème sombre, le texte des pastilles
    de gravité et de statut restait noir (illisible). Toutes les pastilles du
    thème sombre doivent porter un texte blanc."""
    for value in SEVERITY_ORDER:
        assert theme.severity_badge(value, "dark")[1] == "#ffffff"
    for value in VALID_STATUSES:
        assert theme.status_badge(value, "dark")[1] == "#ffffff"


def test_severity_and_status_labels_and_ranks() -> None:
    assert severity_label("high") == "Élevée"
    assert severity_label("critical") == "Critique"
    assert severity_label("valeur_inconnue") == "valeur_inconnue"

    assert severity_rank("critical") == 0
    assert severity_rank("HIGH") == SEVERITY_ORDER.index("high")
    assert severity_rank("inconnue") == len(SEVERITY_ORDER)

    assert status_rank(VALID_STATUSES[0]) == 0
    assert status_rank("statut_inconnu") == len(VALID_STATUSES)


def test_palette_builds_without_a_qapplication() -> None:
    # QPalette/QColor s'utilisent sans écran : `apply_theme` (elle, qui
    # modifie le QApplication) n'est pas testée ici.
    for name in theme.THEMES:
        palette = theme.build_palette(name)
        assert palette.color(palette.ColorRole.Window).name() == theme.tokens(name)[
            "window"
        ]


def test_theme_persists_in_isolated_settings(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("TSCAN_SETTINGS_DIR", str(tmp_path))

    # Aucune préférence : le défaut s'applique.
    assert theme.stored_theme() == theme.DEFAULT_THEME

    theme.store_theme("light")
    assert theme.stored_theme() == "light"

    # Une valeur inconnue n'est jamais enregistrée ni relue.
    theme.store_theme("bogus")
    assert theme.stored_theme() == "light"

    # Une valeur corrompue en base retombe sur le défaut.
    from PySide6.QtCore import QSettings

    settings = QSettings(str(tmp_path / "tscan.ini"), QSettings.Format.IniFormat)
    settings.setValue("theme", "rainbow")
    settings.sync()
    assert theme.stored_theme() == theme.DEFAULT_THEME
