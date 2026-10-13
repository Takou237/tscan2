"""Thème visuel de l'application desktop Tscan (clair / sombre).

Jusqu'ici l'interface était « Qt natif » : aucune feuille de style, aucune
palette, rendu variable selon la machine et impossible à personnaliser. Ce
module centralise la charte graphique de Tscan :

- deux thèmes, **sombre par défaut** et clair, commutables depuis la barre
  d'outils et mémorisés entre les lancements (`QSettings`) ;
- une feuille de style QSS unique construite à partir de jetons de couleur :
  aucune valeur de couleur n'est écrite en dur dans `widgets.py` ;
- une palette Fusion cohérente pour les widgets non couverts par la QSS.

Le thème est appliqué dans `main()` **avant** la construction de la fenêtre ;
les dialogues, créés ensuite, héritent de la feuille de style de
`QApplication`. Les couleurs de pastille (gravité, statut) dépendent du
thème : sur fond sombre, le texte des pastilles est blanc (fond de pastille
assombri en conséquence) ; sur fond clair, il reste sombre. La table est
donc repeinte lors d'une commutation (`FindingsTable.set_theme`).
"""

from __future__ import annotations

from string import Template

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

# Thème appliqué à la première exécution (aucune préférence enregistrée).
DEFAULT_THEME = "dark"

THEMES: tuple[str, ...] = ("dark", "light")

_TOKENS: dict[str, dict[str, str]] = {
    "dark": {
        "window": "#1e2024",
        "base": "#262a30",
        "raised": "#2c313a",
        "alternate": "#2a2e35",
        "header": "#22252b",
        "text": "#e8eaed",
        "muted": "#9aa3af",
        "border": "#3a3f49",
        "accent": "#3f7ff0",
        "accent_hover": "#5a94f4",
        "on_accent": "#ffffff",
        "hover": "#333842",
        "selection": "#2c4a7c",
        "selection_text": "#ffffff",
        "handle": "#4a5160",
    },
    "light": {
        "window": "#f2f4f7",
        "base": "#ffffff",
        "raised": "#ffffff",
        "alternate": "#f7f8fa",
        "header": "#eceef2",
        "text": "#1f2328",
        "muted": "#667085",
        "border": "#d5d9e0",
        "accent": "#2f6fed",
        "accent_hover": "#255ed1",
        "on_accent": "#ffffff",
        "hover": "#e8ecf3",
        "selection": "#cfe0ff",
        "selection_text": "#10233f",
        "handle": "#c6ccd6",
    },
}

# Pastilles des colonnes « Gravité » et « Statut » : (fond, texte) PAR THÈME.
#
# Clair : fonds vifs (Bootstrap-like) et texte sombre choisi pour le
# contraste. Sombre : mêmes teintes mais fonds assombris et texte BLANC —
# un texte noir sur la table sombre devenait illisible (retour utilisateur
# 09/10/2026). Les fonds assombris conservent la teinte sémantique (rouge =
# critique, vert = faible…) tout en garantissant un contraste suffisant
# avec le texte blanc.
SEVERITY_COLORS: dict[str, dict[str, tuple[str, str]]] = {
    "dark": {
        "critical": ("#b02a37", "#ffffff"),
        "high": ("#b45309", "#ffffff"),
        "medium": ("#8f6600", "#ffffff"),
        "low": ("#2f7d32", "#ffffff"),
        "info": ("#1f7a99", "#ffffff"),
    },
    "light": {
        "critical": ("#d9534f", "#ffffff"),
        "high": ("#f0ad4e", "#1f2328"),
        "medium": ("#f7e200", "#1f2328"),
        "low": ("#5cb85c", "#1f2328"),
        "info": ("#5bc0de", "#1f2328"),
    },
}

STATUS_COLORS: dict[str, dict[str, tuple[str, str]]] = {
    "dark": {
        "unvalidated": ("#1f7a99", "#ffffff"),
        "confirmed": ("#2f7d32", "#ffffff"),
        "probable": ("#b45309", "#ffffff"),
        "potential_false_positive": ("#8f6600", "#ffffff"),
        "false_positive": ("#5f656c", "#ffffff"),
    },
    "light": {
        "unvalidated": ("#5bc0de", "#1f2328"),
        "confirmed": ("#5cb85c", "#1f2328"),
        "probable": ("#f0ad4e", "#1f2328"),
        "potential_false_positive": ("#f7e200", "#1f2328"),
        "false_positive": ("#6c757d", "#ffffff"),
    },
}

# Pastille de repli (valeur hors vocabulaire) : fond de table neutre.
DEFAULT_BADGE_COLOR: tuple[str, str] = ("#ffffff", "#1f2328")


def severity_badge(value: str, theme: str | None = None) -> tuple[str, str]:
    """Couleurs (fond, texte) de la pastille de gravité pour le thème."""
    name = theme if theme in _TOKENS else DEFAULT_THEME
    return SEVERITY_COLORS[name].get(value.lower(), DEFAULT_BADGE_COLOR)


def status_badge(value: str, theme: str | None = None) -> tuple[str, str]:
    """Couleurs (fond, texte) de la pastille de statut pour le thème."""
    name = theme if theme in _TOKENS else DEFAULT_THEME
    return STATUS_COLORS[name].get(value.lower(), DEFAULT_BADGE_COLOR)


def tokens(theme: str | None = None) -> dict[str, str]:
    """Jetons de couleur d'un thème (repli sur le thème par défaut)."""
    name = theme if theme in _TOKENS else DEFAULT_THEME
    return dict(_TOKENS[name])


def next_theme(theme: str | None = None) -> str:
    """Thème suivant pour la bascule : dark <-> light."""
    return "light" if (theme if theme in _TOKENS else DEFAULT_THEME) == "dark" else "dark"


def theme_label(theme: str) -> str:
    """Libellé FR du bouton de bascule (le bouton annonce la cible)."""
    return "Thème clair" if (theme if theme in _TOKENS else DEFAULT_THEME) == "dark" else "Thème sombre"


_STYLESHEET = Template(
    """
/* --- Fond général ------------------------------------------------------- */
QWidget {
    color: $text;
}
QMainWindow, QDialog {
    background-color: $window;
}
QScrollArea {
    background-color: $window;
    border: none;
}
QLabel#mutedLabel {
    color: $muted;
}
QLabel#countLabel {
    color: $muted;
    font-weight: 600;
}
QLabel#emptyStateLabel {
    color: $muted;
    font-size: 13px;
}

/* --- Barre d'outils ------------------------------------------------------ */
QToolBar {
    background-color: $base;
    border: none;
    border-bottom: 1px solid $border;
    spacing: 4px;
    padding: 3px 4px;
}
QToolButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 5px 9px;
}
QToolButton:hover {
    background-color: $hover;
    border-color: $border;
}
QToolButton:pressed {
    background-color: $selection;
}
QToolButton:disabled {
    color: $muted;
}

/* --- Conteneurs ---------------------------------------------------------- */
QGroupBox {
    background-color: $base;
    border: 1px solid $border;
    border-radius: 6px;
    margin-top: 11px;
    padding: 8px 6px 6px 6px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: $muted;
    font-weight: 600;
}
QSplitter::handle {
    background-color: $border;
}
QSplitter::handle:horizontal {
    width: 2px;
}
QTabWidget::pane {
    background-color: $base;
    border: 1px solid $border;
    border-radius: 4px;
    top: -1px;
}
/* Onglets accolés, séparés par un simple trait vertical (plus d'espace
   entre eux). `border-left: none` évite la double bordure entre deux
   onglets voisins ; le premier onglet retrouve son trait gauche. */
QTabBar::tab {
    background-color: $window;
    color: $muted;
    border: 1px solid $border;
    border-left: none;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 5px 14px;
    margin: 0;
}
QTabBar::tab:first {
    border-left: 1px solid $border;
}
QTabBar::tab:selected {
    background-color: $base;
    color: $text;
    font-weight: 600;
}
QTabBar::tab:hover:!selected {
    color: $text;
}

/* --- Champs de saisie ---------------------------------------------------- */
QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit {
    background-color: $raised;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 3px 6px;
    selection-background-color: $accent;
    selection-color: $on_accent;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QTextEdit:focus, QPlainTextEdit:focus {
    border-color: $accent;
}
QLineEdit:read-only {
    color: $muted;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid $muted;
    margin-right: 7px;
}
QComboBox QAbstractItemView {
    background-color: $raised;
    border: 1px solid $border;
    selection-background-color: $accent;
    selection-color: $on_accent;
    outline: none;
}
QCheckBox {
    spacing: 7px;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border: 1px solid $border;
    border-radius: 3px;
    background-color: $raised;
}
QCheckBox::indicator:hover {
    border-color: $accent;
}
QCheckBox::indicator:checked {
    background-color: $accent;
    border-color: $accent;
}

/* --- Boutons ------------------------------------------------------------- */
QPushButton {
    background-color: $raised;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 5px 14px;
}
QPushButton:hover {
    border-color: $accent;
}
QPushButton:pressed {
    background-color: $hover;
}
QPushButton:disabled {
    color: $muted;
    border-color: $border;
}
QPushButton#primaryButton {
    background-color: $accent;
    border: 1px solid $accent;
    color: $on_accent;
    font-weight: 600;
    padding: 5px 18px;
}
QPushButton#primaryButton:hover {
    background-color: $accent_hover;
    border-color: $accent_hover;
}
QPushButton#primaryButton:pressed {
    background-color: $accent;
}

/* --- Listes et tableaux -------------------------------------------------- */
QTableView, QTableWidget {
    background-color: $base;
    alternate-background-color: $alternate;
    border: 1px solid $border;
    gridline-color: $border;
    selection-background-color: $selection;
    selection-color: $selection_text;
}
QTableView::item, QTableWidget::item {
    padding: 3px 5px;
    border: none;
}
QHeaderView::section {
    background-color: $header;
    color: $muted;
    border: none;
    border-right: 1px solid $border;
    border-bottom: 1px solid $border;
    padding: 5px 6px;
    font-weight: 600;
}
QHeaderView::section:hover {
    color: $text;
}
QTableCornerButton::section {
    background-color: $header;
    border: none;
}

/* --- Barre de progression ------------------------------------------------ */
QProgressBar {
    background-color: $raised;
    border: 1px solid $border;
    border-radius: 4px;
    text-align: center;
    color: $text;
    min-height: 17px;
}
QProgressBar::chunk {
    background-color: $accent;
    border-radius: 3px;
}

/* --- Barres de défilement ------------------------------------------------ */
QScrollBar:vertical {
    background: $window;
    width: 11px;
    margin: 0;
    border: none;
}
QScrollBar::handle:vertical {
    background: $handle;
    border-radius: 4px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: $muted;
}
QScrollBar:horizontal {
    background: $window;
    height: 11px;
    margin: 0;
    border: none;
}
QScrollBar::handle:horizontal {
    background: $handle;
    border-radius: 4px;
    min-width: 28px;
}
QScrollBar::handle:horizontal:hover {
    background: $muted;
}
QScrollBar::add-line, QScrollBar::sub-line {
    width: 0;
    height: 0;
}
QScrollBar::add-page, QScrollBar::sub-page {
    background: transparent;
}
QScrollBar:vertical QScrollBar::add-line:disabled,
QScrollBar:vertical QScrollBar::sub-line:disabled,
QScrollBar:horizontal QScrollBar::add-line:disabled,
QScrollBar:horizontal QScrollBar::sub-line:disabled {
    background: transparent;
    width: 0;
    height: 0;
}

/* --- Infobulles ---------------------------------------------------------- */
QToolTip {
    background-color: $raised;
    color: $text;
    border: 1px solid $border;
    padding: 4px 6px;
}
"""
)


def build_stylesheet(theme: str | None = None) -> str:
    """Feuille de style complète du thème demandé."""
    return _STYLESHEET.substitute(tokens(theme))


def build_palette(theme: str | None = None) -> QPalette:
    """Palette Fusion du thème : couvre les widgets non ciblés par la QSS."""
    t = tokens(theme)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(t["window"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(t["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(t["base"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(t["alternate"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(t["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(t["raised"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(t["text"]))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link, QColor(t["accent"]))
    palette.setColor(QPalette.ColorRole.LinkVisited, QColor(t["accent"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(t["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(t["on_accent"]))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(t["raised"]))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(t["text"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(t["muted"]))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(t["muted"]))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(t["muted"]))
    return palette


def apply_theme(app: QApplication, theme: str | None = None) -> str:
    """Applique un thème (style Fusion + palette + QSS) à l'application.

    Retourne le thème réellement appliqué (le défaut si l'entrée est inconnue).
    """
    name = theme if theme in _TOKENS else DEFAULT_THEME
    app.setStyle("Fusion")
    app.setPalette(build_palette(name))
    app.setStyleSheet(build_stylesheet(name))
    return name


def _settings():
    # `Tscan` (application) / `Tscan` (organisation) : registry Windows,
    # plist macOS, fichier INI ailleurs — géré par Qt. `TSCAN_SETTINGS_DIR`
    # force un fichier INI dans un dossier donné : sert à isoler une recette
    # (guide de test manuel) et les tests, sans toucher aux préférences réelles.
    import os

    from PySide6.QtCore import QSettings

    directory = os.environ.get("TSCAN_SETTINGS_DIR")
    if directory:
        return QSettings(
            os.path.join(directory, "tscan.ini"), QSettings.Format.IniFormat
        )
    return QSettings("Tscan", "Tscan")


def stored_theme() -> str:
    """Thème mémorisé entre les lancements (défaut : sombre)."""
    settings = _settings()
    value = settings.value("theme", DEFAULT_THEME)
    return value if value in _TOKENS else DEFAULT_THEME


def store_theme(theme: str) -> None:
    """Mémorise le thème choisi pour les prochains lancements."""
    if theme in _TOKENS:
        settings = _settings()
        settings.setValue("theme", theme)
        settings.sync()


def load_window_setting(key: str, default=None):
    """Préférence de fenêtre mémorisée (géométrie, position du séparateur)."""
    return _settings().value(key, default)


def save_window_setting(key: str, value) -> None:
    """Enregistre une préférence de fenêtre."""
    _settings().setValue(key, value)
