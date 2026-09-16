"""Client HTTP de la phase de reconnaissance (RF-15).

Fournit un client `httpx` configuré pour Tscan (User-Agent identifiable,
timeout borné, redirections limitées) et la sonde de base de la
reconnaissance : la requête GET sur la racine de la cible, avec collecte du
statut, des en-têtes et d'un extrait du corps.

Ce module est le seul, avec `tscan_core.recon.tls`, à toucher la cible lors
de la phase de reconnaissance. Il ne fait aucun traitement métier : le
fingerprinting est une responsabilité distincte (`fingerprint.py`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from tscan_core.scan.request_log import RequestRecord, format_wat

# User-Agent réaliste pour éviter la détection par WAF
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 3
MAX_BODY_CHARS = 200_000
DEFAULT_REQUEST_DELAY = 0.05  # 50ms entre les requêtes (pacing léger)
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # 1 seconde


class ReconError(Exception):
    """Levée lorsqu'une sonde de reconnaissance ne peut pas joindre la cible
    (réseau, TLS, réponse illisible)."""


@dataclass(frozen=True)
class RootResponse:
    """Résultat de la requête sur la racine de la cible.

    `headers` est normalisé en clés minuscules (les en-têtes HTTP sont
    insensibles à la casse), ce qui évite aux consommateurs -- fingerprinting,
    contrôles de configuration -- de gérer eux-mêmes cette variabilité.
    """

    status_code: int
    headers: dict[str, str]
    body: str
    final_url: str
    body_truncated: bool
    reason: str = ""
    request_url: str = ""
    method: str = "GET"
    rtt_ms: float | None = None


def create_http_client(
    verify_tls: bool = True,
    request_delay: float = DEFAULT_REQUEST_DELAY,
    user_agent: str | None = None,
) -> httpx.Client:
    """Crée un client HTTP borné et identifiable pour les sondes Tscan."""
    if user_agent is None:
        user_agent = USER_AGENTS[0]

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    client = httpx.Client(
        timeout=DEFAULT_TIMEOUT_SECONDS,
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        verify=verify_tls,
        headers=headers,
        limits=httpx.Limits(max_connections=5),
    )

    # Stocker le délai et le timestamp de la dernière requête sur le client
    client._tscan_request_delay = request_delay  # type: ignore[attr-defined]
    client._tscan_last_request_time = 0.0  # type: ignore[attr-defined]
    client._tscan_user_agent_index = 0  # type: ignore[attr-defined]
    client._tscan_user_agents = USER_AGENTS  # type: ignore[attr-defined]

    # Journal structuré des requêtes (format « History » ZAP), collecté par
    # `fetch_url`. Vide par défaut : seuls les clients qui en ont besoin
    # (scan actif) y branchent un `RequestHistory`.
    client._tscan_request_log = None  # type: ignore[attr-defined]

    return client


def probe_fetch(
    http_client: httpx.Client,
    url: str,
    max_retries: int = 1,
    backoff: float = 0.2,
    timeout: float = 5.0,
) -> RootResponse:
    """Requête de sonde à coût réduit (cadence courte, pas de retry lourd).

    Les sondes de détection (XSS, SQLi, SSRF...) ne rejouent ni la politique
    robuste de reconnaissance (3 tentatives, backoff exponentiel) ni le
    timeout complet de 10 s : sur une cible bloquante (WAF, anti-bot) chaque
    sonde coûterait ~35 s, et un scan en envoie des centaines. Ici : 1 seule
    tentative, timeout 5 s — une sonde qui échoue n'est pas un constat, elle
    est simplement tracée par l'appelant.
    """
    return fetch_url(
        http_client, url, max_retries=max_retries, backoff=backoff, timeout=timeout
    )


def fetch_root(http_client: httpx.Client, target: str) -> RootResponse:
    """Requête GET sur la racine de la cible (reconnaissance de base).

    Même comportement que `fetch_url`, avec un nom qui reflète l'usage :
    c'est la sonde utilisée par la phase de reconnaissance (7a).
    """
    return fetch_url(http_client, target)


def fetch_url(
    http_client: httpx.Client,
    url: str,
    headers: dict[str, str] | None = None,
    max_retries: int = MAX_RETRIES,
    backoff: float = INITIAL_BACKOFF,
    timeout: float | None = None,
) -> RootResponse:
    """Requête GET sur une URL de la cible (sonde de scan).

    Une réponse HTTP 4xx/5xx n'est pas une erreur : le statut fait partie de
    l'information de reconnaissance. Seules les défaillances réseau, TLS ou
    de lecture de la réponse lèvent `ReconError`. Les sondes `path_status`
    (BAC basique, 7b) et les sondes de détection actives bénignes (8) passent
    par cette fonction, bornée par le même timeout et les mêmes redirections
    limitées que la sonde racine. `headers` permet d'ajouter des en-têtes
    spécifiques à une sonde (ex : `Origin` pour le contrôle CORS).

    `max_retries` et `backoff` bornent la politique de nouvelle tentative sur
    défaillance réseau. Les sondes racine/crawl gardent les valeurs robustes
    (3 tentatives, backoff exponentiel) ; les sondes de détection passent par
    `tscan_core.scan.detections.probe.probe_fetch`, qui réduit ce coût
    (1-2 tentatives, backoff court) pour que l'énorme volume de sondes d'un
    grand site ne s'appuie pas sur de longues attentes (ES-02 : durée
    prévisible). `timeout` écrase le timeout du client pour cette requête
    uniquement (sondes de détection = 5s pour éviter d'attendre 10s sur
    chaque requête d'un WAF lent).
    """
    import random

    # Rate limiting : délai entre les requêtes (0 pour un client brut, sans
    # pacing ni rainure temporelle, comme ceux construits par les tests).
    request_delay = getattr(http_client, "_tscan_request_delay", 0.0)
    last_request_time = getattr(http_client, "_tscan_last_request_time", 0.0)
    elapsed = time.time() - last_request_time
    if elapsed < request_delay:
        time.sleep(request_delay - elapsed)

    # Rotation du User-Agent pour éviter la détection
    user_agents = getattr(http_client, "_tscan_user_agents", USER_AGENTS)
    ua_index = getattr(http_client, "_tscan_user_agent_index", 0)
    if user_agents:
        current_ua = user_agents[ua_index % len(user_agents)]
        http_client._tscan_user_agent_index = ua_index + 1  # type: ignore[attr-defined]
        merged_headers = {"User-Agent": current_ua}
        if headers:
            merged_headers.update(headers)
        headers = merged_headers

    # Retry avec backoff exponentiel (base réglable pour les sondes de détection)
    last_exception = None
    request_log = getattr(http_client, "_tscan_request_log", None)
    for attempt in range(max(1, max_retries)):
        try:
            request_id = request_log.next_id() if request_log is not None else None
            sent_at = datetime.now(UTC)
            http_client._tscan_last_request_time = time.time()  # type: ignore[attr-defined]
            kwargs = {}
            if timeout is not None:
                kwargs["timeout"] = timeout
            response = http_client.get(url, headers=headers, **kwargs)
            received_at = datetime.now(UTC)
            rtt_ms = (received_at - sent_at).total_seconds() * 1000.0

            if request_log is not None:
                try:
                    reason = response.reason_phrase or ""
                except AttributeError:  # pragma: no cover - champ indisponible
                    reason = ""
                request_log.add(
                    RequestRecord(
                        id=request_id or 0,
                        sent_at=format_wat(sent_at),
                        received_at=format_wat(received_at),
                        method="GET",
                        url=url,
                        status_code=response.status_code,
                        reason=reason,
                    )
                )

            truncated = len(response.content) > MAX_BODY_CHARS
            body = response.text[:MAX_BODY_CHARS]
            resp_headers = {key.lower(): value for key, value in response.headers.items()}

            return RootResponse(
                status_code=response.status_code,
                headers=resp_headers,
                body=body,
                final_url=str(response.url),
                body_truncated=truncated,
                reason=reason if request_log is not None else "",
                request_url=url,
                method="GET",
                rtt_ms=rtt_ms,
            )
        except httpx.HTTPError as exc:
            last_exception = exc
            if request_log is not None:
                request_log.add(
                    RequestRecord(
                        id=request_id or 0,
                        sent_at=format_wat(sent_at),
                        received_at=format_wat(datetime.now(UTC)),
                        method="GET",
                        url=url,
                        status_code=None,
                        reason="",
                    )
                )
            if attempt < max(1, max_retries) - 1:
                wait = backoff * (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait)

    message = (
        f"Impossible de joindre la cible {url} après {max(1, max_retries)} tentatives : {last_exception}"
    )
    # Une cible qui droppe les connexions en silence (sans RST ni réponse
    # HTTP) est le signe typique d'un filtrage anti-bot / WAF : certaines
    # requêtes passent, d'autres pendent jusqu'au timeout, par fenêtres.
    # On l'indique explicitement pour distinguer ce cas d'une panne réseau.
    if isinstance(last_exception, httpx.ConnectTimeout | httpx.ReadTimeout):
        message += (
            " — la cible semble filtrer les connexions (anti-bot/WAF) : "
            "réessayez plus tard ou changez d'adresse IP."
        )
    raise ReconError(message)
