"""Tests de la sonde TLS de reconnaissance (RF-15).

Le probe réseau lui-même (connexion TLS réelle) est vérifié manuellement sur
le laboratoire lors de l'intégration ; ici sont testés le parsing du
certificat (structure `getpeercert()`, fragile) et le comportement sur un
port sans service TLS.
"""

from __future__ import annotations

import pytest

from tscan_core.recon.tls import (
    TlsProbeError,
    _extract_tls_info,
    _format_x509_name,
    probe_tls,
)

_X509_ISSUER = [[("countryName", "CM"), ("organizationName", "ANTIC Lab")]]
_X509_SUBJECT = [[("commonName", "lab.local")]]


def test_format_x509_name() -> None:
    assert _format_x509_name(_X509_ISSUER) == "countryName=CM, organizationName=ANTIC Lab"
    assert _format_x509_name([]) is None
    assert _format_x509_name(None) is None


def test_extract_tls_info_full_certificate() -> None:
    cert = {
        "issuer": _X509_ISSUER,
        "subject": _X509_SUBJECT,
        "notBefore": "Jan 1 00:00:00 2026 GMT",
        "notAfter": "Jan 1 00:00:00 2027 GMT",
    }
    info = _extract_tls_info(cert, "TLSv1.3")

    assert info.issuer == "countryName=CM, organizationName=ANTIC Lab"
    assert info.subject == "commonName=lab.local"
    assert info.not_before == "Jan 1 00:00:00 2026 GMT"
    assert info.not_after == "Jan 1 00:00:00 2027 GMT"
    assert info.tls_version == "TLSv1.3"
    assert info.self_signed is False


def test_extract_tls_info_detects_self_signed() -> None:
    same = [[("commonName", "lab.local")]]
    info = _extract_tls_info({"issuer": same, "subject": same}, "TLSv1.2")
    assert info.self_signed is True


def test_extract_tls_info_without_certificate() -> None:
    info = _extract_tls_info({}, None)
    assert info.issuer is None
    assert info.subject is None
    assert info.self_signed is None
    assert info.tls_version is None


def test_probe_tls_on_closed_port_raises() -> None:
    """Un port sans service TLS doit lever TlsProbeError (et non pas bloquer
    ou corrompre la suite du scan) : l'orchestrateur la transforme en
    absence d'information TLS."""
    with pytest.raises(TlsProbeError):
        probe_tls("127.0.0.1", port=1, timeout=2.0)