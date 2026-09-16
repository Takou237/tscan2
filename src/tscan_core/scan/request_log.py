"""Journal des requêtes HTTP d'un scan (format « History » de ZAP).

Chaque requête envoyée par le moteur de scan est enregistrée avec les champs
affichables dans un tableau (comme l'onglet History d'OWASP ZAP) :

- `id` : compteur croissant (l'identifiant visible du fil, ex. 17507) ;
- `sent_at` / `received_at` : horodatages côté client (fuseau WAT, ex.
  « Wed Sep 02 14:10:44 WAT 2026 ») ;
- `method`, `url` : requête envoyée ;
- `status_code`, `reason` : réponse reçue.

Le journal est collecté à partir du point central d'émission des requêtes
(`tscan_core.recon.client.fetch_url`) grâce à un `RequestHistory` attaché au
client HTTP. Les interfaces (GUI) peuvent brancher un écouteur
(`on_record`) pour afficher chaque entrée en temps réel.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo

_WAT_OFFSET = timedelta(hours=1)


class _WatTz(tzinfo):
    """Fuseau fixe UTC+1 (heure d'Afrique de l'Ouest), sans heure d'été."""

    def utcoffset(self, dt):
        return _WAT_OFFSET

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "WAT"


_WAT = _WatTz()


def format_wat(moment: datetime) -> str:
    """Formate un instant (aware) au fuseau WAT : « Wed Sep 02 14:10:44 WAT 2026 »."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    local = moment.astimezone(_WAT)
    return local.strftime("%a %b %d %H:%M:%S WAT %Y")


@dataclass
class RequestRecord:
    """Une requête HTTP journalisée (une ligne du tableau History)."""

    id: int
    sent_at: str
    received_at: str
    method: str
    url: str
    status_code: int | None
    reason: str = ""


@dataclass
class RequestHistory:
    """Collecteur thread-safe du journal de requêtes d'un scan.

    `on_record` est un écouteur optionnel appelé à chaque ajout (depuis le fil
    qui exécute le scan) pour remonter l'entrée vers l'interface en temps réel.
    """

    on_record: Callable[[RequestRecord], None] | None = None
    _counter: int = field(default=0, init=False)
    _items: list[RequestRecord] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def add(self, record: RequestRecord) -> None:
        with self._lock:
            self._items.append(record)
        if self.on_record is not None:
            try:
                self.on_record(record)
            except Exception:  # noqa: S110, BLE001 - jamais casser le scan pour un affichage
                pass

    def __iter__(self):
        with self._lock:
            return iter(list(self._items))

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
