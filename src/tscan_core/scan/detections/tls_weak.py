"""Détection de configuration TLS faible (family Security Misconfiguration).

Aucune sonde : les informations TLS sont déjà collectées lors de la
reconnaissance (`observations["tls"]`, `probe_tls`) et relues ici pour
déclarer des constats sur la confiance du certificat et le niveau du
protocole. Le contrôle est entièrement local (ES-09 : aucune donnée
transmise à un tiers) et purement passif : il juge des faits déjà constatés.

Le jugement porte sur : un certificat auto-signé, un certificat expiré ou pas
encore valide, un protocole TLS désuet (TLS 1.0/1.1). La vérification de la
chaîne de confiance (HSTS, validité du chemin) dépasse ce contrôle, qui
produit donc des constats `Probable`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult

# Protocoles TLS désuets et vulnérables (RFC 8996, PCI-DSS 3.2) : leur
# présence seule n'est pas toujours exploitable, le constat est Low.
# Comparaison exacte : "TLSv1.1" ne doit pas matcher "TLSv1.2" (préfixe).
WEAK_TLS_VERSIONS = frozenset({"TLSv1", "TLSv1.1", "SSLv3"})

RULE_ID = "RULE-TLS-WEAK-001"
CATEGORY = "security_misconfiguration"


def run(config: ScanConfig, observations: dict) -> list[DetectionResult]:
    """Émet des constats TLS à partir de l'observation de reconnaissance.

    Aucune erreur n'interrompt le scan : si la sonde TLS de reconnaissance a
    échoué (`{"error": ...}`) ou n'existe pas (cible http), il n'y a tout
    simplement pas de constat à produire.
    """
    tls = observations.get("tls")
    if not isinstance(tls, dict) or "error" in tls or not tls:
        return []

    results: list[DetectionResult] = []
    now = datetime.now(UTC)

    if tls.get("self_signed"):
        results.append(_constat(
            severity="medium",
            title="Certificat TLS auto-signé",
            description=(
                "Le certificat présenté par la cible est auto-signé : aucun émetteur "
                "reconnu ne garantit son identité. Les visiteurs ne peuvent pas vérifier "
                "qu'ils parlent bien à la cible (risque d'attaque de l'homme du milieu)."
            ),
            matched_at=config.target,
            evidence="Certificat auto-signé (issuer == subject) sur " + config.target,
        ))

    not_before = _parse_tls_time(tls.get("not_before"))
    not_after = _parse_tls_time(tls.get("not_after"))

    if not_after is not None and not_after < now:
        results.append(_constat(
            severity="high",
            title="Certificat TLS expiré",
            description=(
                "Le certificat de la cible a expiré : les clients conformes le refusent "
                "et ceux qui l'acceptent le font au prix d'une vérification affaiblie."
            ),
            matched_at=config.target,
            evidence=f"Certificat expiré le {not_after.isoformat()} sur " + config.target,
        ))
    elif not_after is not None and not_after < now + timedelta(days=30):
        results.append(_constat(
            severity="low",
            title="Certificat TLS proche de l'expiration",
            description=(
                "Le certificat expire sous moins de 30 jours : un oubli de renouvellement "
                "couperait le service de ses visiteurs."
            ),
            matched_at=config.target,
            evidence=f"Certificat expirant le {not_after.isoformat()} sur " + config.target,
        ))

    if not_before is not None and not_before > now:
        results.append(_constat(
            severity="medium",
            title="Certificat TLS pas encore valide",
            description=(
                "Le certificat présente une date de début de validité future : l'horloge "
                "de la cible est en avance ou le certificat est mal sélectionné, et les "
                "clients le refusent pour l'instant."
            ),
            matched_at=config.target,
            evidence=f"Certificat valide à partir du {not_before.isoformat()} sur " + config.target,
        ))

    version = (tls.get("tls_version") or "").strip()
    if version in WEAK_TLS_VERSIONS:
        results.append(_constat(
            severity="low",
            title="Protocole TLS désuet",
            description=(
                f"La cible négocie {version}, un protocole historiquement vulnérable "
                "qui ne devrait plus être proposé."
            ),
            matched_at=config.target,
            evidence=f"Version TLS négociée : {version} sur " + config.target,
        ))

    return results


def _constat(severity: str, title: str, description: str, matched_at: str, evidence: str) -> DetectionResult:
    return DetectionResult(
        rule_id=RULE_ID,
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        matched_at=matched_at,
        evidence_text=evidence,
    )


def _parse_tls_time(value: str | None) -> datetime | None:
    """Parse une date TLS au format ASN.1 (`YYYYMMDDHHMMSSZ`) en datetime UTC.

    Retourne None quand la valeur absente ou illisible : un constat ne peut
    pas reposer sur une date qu'on ne sait pas lire.
    """
    if not value:
        return None
    text = value.strip().lstrip("'").rstrip("'").removesuffix("Z")
    padded = text.ljust(14, "0")  # "YYYYMMDDHHMM" -> "YYYYMMDDHHMM00"
    if not padded.isdigit() or len(padded) != 14:
        return None
    try:
        zulu = f"{padded}+0000"
        return datetime.strptime(zulu, "%Y%m%d%H%M%S%z")
    except ValueError:
        return None