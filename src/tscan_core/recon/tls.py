"""Sonde TLS de la phase de reconnaissance (RF-15).

Ouvre une connexion TLS passive vers la cible et lit les informations du
certificat présenté (émetteur, sujet, périodes de validité, version TLS) sans
valider la chaîne de confiance : la phase de reconnaissance n'émet aucun test
et ne fait que constater -- la validation de la configuration TLS fera l'objet
d'un contrôle de détection dédié (famille Security Misconfiguration).

La lecture d'un certificat sans validation de confiance est une opération
purement locale (aucune donnée transmise à un tiers), conforme à ES-09.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


class TlsProbeError(Exception):
    """Levée lorsqu'aucune connexion TLS ne peut être établie (hôte injoignable,
    pas de TLS sur le port, protocole refusé)."""


@dataclass(frozen=True)
class TlsInfo:
    """Informations TLS collectées sur la cible ; champs `None` lorsque la
    donnée n'est pas disponible."""

    issuer: str | None
    subject: str | None
    not_before: str | None
    not_after: str | None
    tls_version: str | None
    self_signed: bool | None

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "tls_version": self.tls_version,
            "self_signed": self.self_signed,
        }


def probe_tls(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Établit une connexion TLS passive et lit le certificat de la cible.

    `host` peut être un nom de domaine ou une adresse IP. Une erreur de
    connexion (port fermé, hôte injoignable, pas de TLS) lève `TlsProbeError`
    : l'orchestrateur la transforme en absence d'information TLS pour la
    cible concernée, sans interrompre le scan.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            cert = tls_sock.getpeercert()
            return _extract_tls_info(cert, tls_sock.version())
    except (OSError, ssl.SSLError) as exc:
        raise TlsProbeError(f"Sonde TLS impossible vers {host}:{port} : {exc}") from exc


def _extract_tls_info(cert: dict, tls_version: str | None) -> TlsInfo:
    """Convertit le certificat (format `getpeercert()`) en `TlsInfo`.

    Séparée de `probe_tls` pour pouvoir être testée unitairement sans réseau
    (la structure du certificat est complexe et fragile).
    """
    issuer = _format_x509_name(cert.get("issuer")) if cert else None
    subject = _format_x509_name(cert.get("subject")) if cert else None

    self_signed = None
    if issuer is not None and subject is not None:
        self_signed = issuer == subject

    return TlsInfo(
        issuer=issuer,
        subject=subject,
        not_before=cert.get("notBefore") if cert else None,
        not_after=cert.get("notAfter") if cert else None,
        tls_version=tls_version,
        self_signed=self_signed,
    )


def _format_x509_name(name: list) -> str | None:
    """Formate un nom X.509 (liste de tuples du format `getpeercert()`) en
    chaîne lisible (ex : 'CN=example.test, O=Example Corp')."""
    if not name:
        return None
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
