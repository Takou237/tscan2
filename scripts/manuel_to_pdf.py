"""Convertit un manuel Markdown de Tscan en PDF — sans dépendance externe.

Utilise uniquement PySide6 (déjà une dépendance du projet) : le Markdown est
interprété par ``QTextDocument.setMarkdown`` puis imprimé en PDF via
``QPrinter``. Aucun pandoc / LaTeX / wkhtmltopdf n'est requis, et rien n'est
envoyé sur le réseau.

Usage (depuis la racine du dépôt, environnement virtuel activé) :

    .venv\\Scripts\\python.exe scripts\\manuel_to_pdf.py
    .venv\\Scripts\\python.exe scripts\\manuel_to_pdf.py docs\\manuel_utilisation.md -o docs\\manuel_utilisation.pdf

Par défaut : source ``docs/manuel_utilisation.md`` → sortie du même nom en ``.pdf``.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QPageSize, QTextDocument
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import QApplication

# Feuille de style appliquée au document PDF. Qt rich-text ne gère qu'un
# sous-ensemble de CSS, mais titres, tableaux, listes, citations et blocs de
# code sont couverts.
_STYLESHEET = """
body { font-family: 'Segoe UI', 'Calibri', sans-serif; font-size: 10.5pt; color: #1c1c1c; }
h1 { color: #0b3d5c; font-size: 19pt; margin-top: 18px; margin-bottom: 8px; }
h2 { color: #0b3d5c; font-size: 14.5pt; margin-top: 16px; margin-bottom: 6px; }
h3 { color: #17527a; font-size: 12pt; margin-top: 12px; margin-bottom: 4px; }
h4 { color: #17527a; font-size: 11pt; }
p { margin-top: 2px; margin-bottom: 6px; }
table { border-collapse: collapse; margin-top: 6px; margin-bottom: 10px; }
th { background-color: #e8eef3; border: 1px solid #9bb0bf; padding: 4px 7px; }
td { border: 1px solid #9bb0bf; padding: 4px 7px; }
pre { font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt;
      background-color: #f4f4f4; border: 1px solid #dcdcdc; padding: 6px; }
code { font-family: 'Consolas', 'Courier New', monospace; font-size: 9.5pt;
       background-color: #f0f0f0; }
blockquote { color: #444; background-color: #fbf6e6; border-left: 4px solid #e0b84c;
             padding-left: 10px; margin-left: 0px; }
hr { border: none; border-top: 1px solid #cccccc; }
a { color: #17527a; }
"""


def _markdown_to_body(markdown_text: str) -> str:
    """Convertit du Markdown en HTML (corps interne) via QTextDocument."""
    tmp = QTextDocument()
    tmp.setMarkdown(markdown_text)
    html = tmp.toHtml()
    match = re.search(r"<body[^>]*>(.*)</body>", html, flags=re.DOTALL)
    return match.group(1) if match else html


def render_pdf(markdown_text: str, output_path: Path) -> None:
    """Rend ``markdown_text`` en PDF à l'emplacement ``output_path``."""
    body = _markdown_to_body(markdown_text)
    document = QTextDocument()
    document.setHtml(f"<html><head><style>{_STYLESHEET}</style></head><body>{body}</body></html>")

    printer = QPrinter(QPrinter.PrinterMode.HighResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(str(output_path))
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(18, 16, 18, 16))

    document.print_(printer)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convertit un manuel Tscan (Markdown) en PDF.")
    parser.add_argument(
        "source",
        nargs="?",
        default="docs/manuel_utilisation.md",
        help="Fichier Markdown source (défaut : docs/manuel_utilisation.md).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Fichier PDF de sortie (défaut : même nom que la source, extension .pdf).",
    )
    args = parser.parse_args(argv)

    source = Path(args.source)
    if not source.is_file():
        print(f"Erreur : le fichier source {source} est introuvable.", file=sys.stderr)
        return 1

    output = Path(args.output) if args.output else source.with_suffix(".pdf")
    output.parent.mkdir(parents=True, exist_ok=True)

    # QTextDocument / QPrinter exigent une instance de QApplication ; la
    # référence est conservée le temps du rendu (sinon elle serait collectée).
    _app = QApplication.instance() or QApplication(sys.argv[:1])

    markdown_text = source.read_text(encoding="utf-8")
    render_pdf(markdown_text, output)
    print(f"PDF généré : {output} ({output.stat().st_size} octets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
