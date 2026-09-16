"""Serveur HTTP de laboratoire pour les tests d'intégration de Tscan.

C'est la « cible de test contrôlée et autorisée » prévue au planning de la
semaine 7 (environnement de laboratoire local) : un petit serveur HTTP
stdlib, lancé localement dans les tests, qui expose des routes fixées
servant aux scénarios de reconnaissance et, à partir de la semaine 7b, de
détection. Aucune ressource externe n'est touchée.
"""

from __future__ import annotations

import html as html_module
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self
from urllib.parse import parse_qs, urlparse

HOMEPAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="generator" content="WordPress 6.4.2">
<title>Site de laboratoire Tscan</title>
</head>
<body>
<h1>Bienvenue</h1>
<p>Page de test du laboratoire Tscan.</p>
<script src="/wp-content/themes/site/js/jquery-3.6.0.min.js"></script>
</body>
</html>
"""

ROUTES: dict[str, tuple[int, dict[str, str], bytes]] = {
    "/": (
        200,
        {
            "Server": "Apache/2.4.53",
            "X-Powered-By": "PHP/7.4.33",
            "Content-Type": "text/html; charset=utf-8",
        },
        HOMEPAGE.encode("utf-8"),
    ),
    "/bare": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"Reponse sans signature de technologie.",
    ),
    "/robots.txt": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"User-agent: *\nDisallow: /wp-admin/\n",
    ),
    "/wp-admin/": (
        403,
        {"Server": "Apache/2.4.53", "Content-Type": "text/html; charset=utf-8"},
        b"<html><body><h1>403 Forbidden</h1></body></html>",
    ),
    "/admin/": (
        200,
        {"Content-Type": "text/html; charset=utf-8"},
        b"<html><body><h1>Panneau d'administration</h1></body></html>",
    ),
    "/status-404": (
        404,
        {"Content-Type": "text/html; charset=utf-8"},
        b"<html><body><h1>404 Not Found</h1></body></html>",
    ),
    # Semaine 8 : cibles des détections actives bénignes et passives.
    "/contact": (
        200,
        {"Content-Type": "text/html; charset=utf-8"},
        (
            b"<html><body><h1>Contact</h1>"
            b'<form method="post" action="/contact">'
            b'<input type="text" name="message">'
            b'<input type="submit">'
            b"</form></body></html>"
        ),
    ),
    "/secure-form": (
        200,
        {"Content-Type": "text/html; charset=utf-8"},
        (
            b"<html><body><h1>Formulaire securise</h1>"
            b'<form method="post" action="/secure-form">'
            b'<input type="hidden" name="csrf_token" value="abc123">'
            b'<input type="text" name="message">'
            b'<input type="submit">'
            b"</form></body></html>"
        ),
    ),
    "/files/": (
        200,
        {"Content-Type": "text/html; charset=utf-8"},
        b"<html><body><h1>Index of /files/</h1><ul><li>docs/</li><li>notes.txt</li></ul></body></html>",
    ),
    "/.git/config": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/example/lab.git\n",
    ),
    "/.env": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"APP_KEY=labo-secret-cle-importante\nDB_PASSWORD=supersecret\n",
    ),
    "/backup.zip": (
        200,
        {"Content-Type": "application/zip"},
        b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00backup.txt",
    ),
    "/dump.sql": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"CREATE TABLE users (id INTEGER PRIMARY KEY, login TEXT);\nINSERT INTO users (login) VALUES ('admin');\n",
    ),
    # Fichier .htpasswd exposé : hachage MD5 legacy (parité ZAP weak-hash).
    "/.htpasswd": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"admin:$apr1$X6d3k8L2$QmY0wT0Vqvok0hLK9A2tP0\napp:$1$salt$abcdefg\n",
    ),
    # Contre-exemple : hachage Argon2 moderne (aucun constat weak-hash).
    "/.htpasswd-strong": (
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
        b"admin:$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$hashvalue0123456789\n",
    ),
    "/cors-open": (
        200,
        {"Access-Control-Allow-Origin": "*", "Content-Type": "text/plain; charset=utf-8"},
        b"Ressource ouverte a toutes les origines.",
    ),
    # Cookie de session SANS drapeaux de sécurité (analyse passive cookies).
    "/login": (
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": "session=abc123; Path=/",
        },
        b"<html><body><h1>Connexion</h1></body></html>",
    ),
    # Contre-exemple : cookie correctement protégé (aucun constat attendu).
    "/secure-login": (
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
        },
        b"<html><body><h1>Connexion securisee</h1></body></html>",
    ),
    # CSP restrictive : aucun constat CSP/SRI (tout auto-hébergé). Contre-exemple.
    "/secure-page": (
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self'; connect-src 'self'; frame-src 'self'; font-src 'self'; "
                "media-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'self'; form-action 'self'; "
                "plugin-types application/pdf; upgrade-insecure-requests"
            ),
        },
        (
            b"<html><body><h1>Page securisee</h1>"
            b'<script src="/js/app.js"></script></body></html>'
        ),
    ),
    # CSP permissive : déclenche tous les constats CSP + SRI + cross-domain JS.
    "/weak-page": (
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline' *; "
            "style-src 'self' 'unsafe-inline' *; img-src *",
        },
        (
            b"<html><body><h1>Page faible</h1>"
            b'<script src="https://cdn.example.com/lib.js" defer></script>'
            b'<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">'
            b"<!-- generer en 1700000000 -->"
            b"</body></html>"
        ),
    ),
}

SLOW_ROUTE = "/slow"
REDIRECT_ROUTE = "/redirect"
SLOW_DELAY_SECONDS = 1.5

# Routes dynamiques de la semaine 8 (dépendent des paramètres de la requête).
ECHO_ROUTE = "/echo"  # reflète le paramètre q sans échappement (XSS)

# Redirection « géante » : Location > 100 caractères avec chaîne de requête
# (parité ZAP 10043, big redirect). L'URL encode un jeton de session simulé.
BIG_REDIRECT_ROUTE = "/big-redirect"
_BIG_REDIRECT_LOCATION = "/landing?" + "sid=0123456789ab&key=cdef0123456789ab&next=%2Fprofile&" * 4 + "done=1"
ESCAPE_ROUTE = "/escape"  # reflète le paramètre q en l'échappant (négatif XSS)
SEARCH_ROUTE = "/search"  # simule une requête SQL vulnérable (SQLi error-based)
SAFE_SEARCH_ROUTE = "/safe-search"  # requête préparée, jamais d'erreur (négatif SQLi)
CORS_ECHO_ROUTE = "/cors-echo"  # reflète l'en-tête Origin (CORS permissif)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        q = (params.get("q") or [""])[0]

        if path == SLOW_ROUTE:
            time.sleep(SLOW_DELAY_SECONDS)

        if path == REDIRECT_ROUTE:
            self.send_response_only(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == BIG_REDIRECT_ROUTE:
            self.send_response_only(302)
            self.send_header("Location", _BIG_REDIRECT_LOCATION)
            self.end_headers()
            return

        if path == ECHO_ROUTE:
            self._send_text(
                200,
                f"<html><body><p>Vous avez dit : {q}</p></body></html>",
            )
            return
        if path == ESCAPE_ROUTE:
            self._send_text(
                200,
                f"<html><body><p>Vous avez dit : {html_module.escape(q)}</p></body></html>",
            )
            return
        if path == SEARCH_ROUTE and "'" in q:
            self._send_text(
                500,
                f"<html><body><h1>Erreur serveur</h1>"
                f"<p>SQL syntax error near '{q}' at line 1</p></body></html>",
            )
            return
        if path == SEARCH_ROUTE or path == SAFE_SEARCH_ROUTE:
            self._send_text(
                200,
                "<html><body><p>Aucun resultat pour cette recherche.</p></body></html>",
            )
            return
        if path == CORS_ECHO_ROUTE:
            origin = self.headers.get("Origin", "")
            self.send_response_only(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Ressource CORS reflechie.")
            return

        # ── Familles de parité ZAP (semaine augmentée) ────────────────────
        # Traversée de répertoire : un paramètre `file` avec `../` qui aboutit
        # à `/etc/passwd` renvoie un contenu de démonstration portant la
        # signature d'un fichier système.
        if path in ("/download", "/file") and "../../../../../../etc/passwd" in params.get("file", [""])[0]:
            self._send_text(
                200,
                "root:x:0:0:root:/root:/bin/bash\nd aemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            )
            return
        if path in ("/download", "/file"):
            self._send_text(404, "<html><body><h1>Fichier introuvable</h1></body></html>")
            return

        # Redirection ouverte : un paramètre `redirect` vers un hôte externe
        # est reflété dans Location (302) sans validation.
        if path in ("/go", "/open", "/redirect") and params.get("redirect"):
            target = params["redirect"][0]
            self.send_response_only(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Injection de commande : un paramètre `cmd` qui produit le marqueur
        # TSCAN-OK est exécuté (simulation) et le marqueur reflété.
        if path in ("/exec", "/cmd") and any("TSCAN-OK" in v for v in params.get("cmd", [])):
            self._send_text(200, "TSCAN-OK: commande executee")
            return

        # SSTI : un paramètre de template contenant `{{7*7}}` est évalué (49).
        if path in ("/template", "/render", "/view"):
            template = ""
            for v in params.values():
                template = v[0] if v else ""
                break
            if "{{7*7}}" in template or "${7*7}" in template or "<%= 7*7 %>" in template:
                self._send_text(200, "<html><body><h1>Bonjour</h1><p>resultat: 49</p></body></html>")
                return
            self._send_text(200, "<html><body><h1>Template</h1><p>aucun calcul</p></body></html>")
            return

        # SSRF : un paramètre `url` vers la boucle locale déclenche un
        # chargement simulé (le serveur affiche un marqueur interne).
        if path in ("/api", "/fetch", "/proxy", "/load"):
            bl = params.get("url", [""])[0]
            if "127.0.0.1" in bl or "localhost" in bl:
                self._send_text(
                    200,
                    "<html><body><p>fetch de http://127.0.0.1 : contenu interne</p></body></html>",
                )
                return
            self._send_text(404, "<html><body><h1>404</h1></body></html>")
            return

        # Injection de headers : un paramètre reflété dans un en-tête
        # personnalisé X-Reflected (simulation d'une non-filtrage CRLF).
        if path in ("/header-reflect", "/reflect-header"):
            value = ""
            for v in params.values():
                value = v[0] if v else ""
                break
            self.send_response_only(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Reflected", value)
            body = b"<html><body><h1>Reflexion</h1></body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Simulation de WAF : la racine rejette les charges de forme « agressive »
        # (rapport : les réponses 412/403 déclenchées par les injections doivent
        # être classées « bloquées par WAF » et non « neutres »).
        if path in ("/", "") and _looks_aggressive(q):
            self.send_response_only(412)
            self.send_header("X-WAF-Sim", "blocked")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = b"<html><body>Request blocked by security policy</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        status, headers, body = ROUTES.get(path, ROUTES["/status-404"])
        # `send_response_only` n'ajoute pas l'en-tête `Server` de http.server
        # (Python 3.12 le préfixerait à notre valeur, cassant la signature
        # `^Apache/` du fingerprinting) : on contrôle les en-têtes tels quels.
        self.send_response_only(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return  # silencieux : le serveur de test ne doit pas polluer les logs


def _looks_aggressive(q: str) -> bool:
    """Vrai si la valeur ressemble à une charge d'attaque (pour la simulation WAF)."""
    lowered = q.lower()
    return "<script>" in lowered or "or 1=1" in lowered


class LabServer:
    """Serveur de laboratoire : démarre sur un port libre de la boucle locale."""

    def __init__(self) -> None:
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="tscan-lab-server"
        )
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


if __name__ == "__main__":
    # Lancement autonome pour les tests manuels de l'interface (guide
    # `documentation/guide_test_manuel_gui.md`, UC4) : sert des routes
    # vulnérables sur 127.0.0.1. Arrêt : Ctrl+C.
    import signal

    server = LabServer()
    server.start()
    print(f"Laboratoire Tscan démarre : {server.base_url}/  (Ctrl+C pour arrêter)", flush=True)
    done = threading.Event()

    def _stop(*_args: object) -> None:
        server.stop()
        done.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    done.wait()
