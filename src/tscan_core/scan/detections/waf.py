"""Détection de la présence d'un Pare-feu d'Application Web (WAF) (RF, roadmap).

Un WAF bloque ou normalise en amont les sondes du scanner : une réponse
`412 Precondition Failed`, `403` après une charge « agressive », ou un paquet
d'en-têtes/signatures caractéristiques indiquent qu'un filtre applique une
règle de sécurité. Dans ce cas, les résultats des autres détections doivent
être lus avec précaution : ce qui ressemble à « rien trouvé » peut être « la
sonde a été jetée par le WAF ».

Ce module envoie des charges de test *inoffensives* (ES-03) ayant la *forme*
de ce qu'un WAF pourrait rejeter (balise `<script>`, début d'injection SQL),
puis classe la réponse. Il alimente `observations` (bilan réseau/waf) et, si
la signature est nette, produit un constat `Maybe`/`medium` pour signaler à
l'analyste qu'une partie de la surface a pu être filtrée.
"""

from __future__ import annotations

from tscan_core.recon.client import RootResponse
from tscan_core.scan.config import ScanConfig
from tscan_core.scan.detections import DetectionResult
from tscan_core.scan.detections.encoding import ENCODED_ONLY_LABELS, payload_variants
from tscan_core.scan.detections.probe import probe_fetch

BLOCKED_STATUSES = frozenset({412, 429, 503})
# 403 n'est un blocage WAF que lorsqu'une charge de test est présente : on le
# considère comme un candidat, confirmé par une signature d'en-tête/corps.
SUSPICIOUS_STATUSES = frozenset({403})

# Champs d'en-tête HTTP associés à des WAF / CDN de protection courants.
WAF_HEADER_SIGNATURES = {
    "x-waf": "WAF générique (en-tête x-waf)",
    "x-tsc-waf": "WAF générique (en-tête x-tsc-waf)",
    "x-waf-sim": "WAF (en-tête x-waf-sim)",
    "cf-ray": "Cloudflare (en-tête cf-ray)",
    "x-sucuri-id": "Sucuri / CloudProxy",
    "x-vercel-waf": "Vercel WAF",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cdn": "CDN / WAF (en-tête x-cdn)",
    "server": "WAF/CDN (serveur)",
}

# Sous-chaînes caractéristiques d'un blocage par WAF dans le corps de réponse.
WAF_BODY_SIGNATURES = (
    "request blocked",
    "access denied",
    "your ip has been banned",
    "cf-error-code",
    "attention required",
    "sec-request-id",
    "mod_security",
    "challenge denied",
    "west780304",
)

RULE_ID = "RULE-WAF-001"
SEVERITY = "medium"
CATEGORY = "waf"

# Charges de test bénignes, à la forme de ce qu'un WAF rejette. Aucune
# exécution possible : `data-` est un attribut, la chaîne SQL est tronquée.
_WAF_CHARGES = (
    "<script>alert(document.domain)</script>",
    "' OR 1=1 --",
)


def run(
    config: ScanConfig,
    client,
    root: RootResponse,
    observations: dict,
    started_at: object = None,
    pages: dict | None = None,
    on_event=None,
) -> list[DetectionResult]:
    """Sonde la cible avec des charges de forme « agressive » et classe la
    réponse (blocage WAF) sans jamais lancer d'exploitation (ES-03).

    La sonde porte sur la racine et, si disponible, la première page crawlée.
    Chaque charge est aussi envoyée sous plusieurs encodages (rotation) : si
    une forme « brute » est bloquée mais que des variantes encodées passent,
    le filtre est signalé comme *contournable* — c'est le parallèle du
    Fuzzer de ZAP. Le résultat est porté dans `observations["waf"]`
    (détection + nb de sondes bloquées + contournable) ; un constat n'est
    émis que si la signature est claire.
    """
    del started_at
    base = config.target.rstrip("/")
    blocked: list[str] = []
    passed_variants: list[str] = []
    detected_via: list[str] = []

    # Signatures passives sur toute réponse déjà collectée (root + pages).
    checked = [root]
    if pages:
        checked.extend(pages.values())
    for page in checked:
        for signature in _header_waf_signature(page.headers):
            if signature not in detected_via:
                detected_via.append(signature)
        for signature in _body_waf_signature(page.body):
            if signature not in detected_via:
                detected_via.append(signature)

    # Sonde active : envoie chaque charge, brute puis dans ses variantes
    # d'encodage, sur la racine.
    for charge in _WAF_CHARGES:
        for variant in payload_variants(charge):
            probe_url = _with_query(base + "/", {"q": variant["value"]}, pre_encoded=True)
            page = probe_fetch(client, probe_url, observations, on_event)
            if page is None:
                continue

            if page.status_code in BLOCKED_STATUSES or (
                page.status_code in SUSPICIOUS_STATUSES and _looks_waf(page)
            ):
                from urllib.parse import urlparse

                blocked.append(
                    f"{variant['label']} {page.status_code}@{urlparse(probe_url).netloc}"
                )
                for signature in _header_waf_signature(page.headers):
                    if signature not in detected_via:
                        detected_via.append(signature)
                for signature in _body_waf_signature(page.body):
                    if signature not in detected_via:
                        detected_via.append(signature)
            else:
                passed_variants.append(variant["label"])

    # Variantes « encodées » qui atteignent l'application malgré un blocage en
    # forme brute : le filtre est là mais contournable par re-lecture.
    encoded_passed = [lbl for lbl in dict.fromkeys(passed_variants) if lbl in ENCODED_ONLY_LABELS]
    bypassable = bool(blocked or detected_via) and bool(encoded_passed)

    observations["waf"] = {
        "detected": bool(detected_via or blocked),
        "blocked_probes": len(blocked),
        "encoded_passed": encoded_passed,
        "bypassable": bypassable,
        "evidence": detected_via or blocked,
    }

    if not (detected_via or blocked):
        return []

    # Un WAF détecté n'est pas une faille : c'est un signal de contexte qui
    # relativise les autres constats (les négatifs peuvent être des blocages).
    base_desc = (
        "Un pare-feu applicatif (WAF) semble filtrer les requêtes vers la cible "
        "(statuts 412/403/429 avec charges de test, ou signatures d'en-têtes/corps). "
        "Les résultats « rien trouvé » des autres détections doivent être lus avec "
        "précaution : la sonde a pu être rejetée avant d'atteindre l'application."
    )
    evidence_parts = []
    if blocked:
        evidence_parts.append(f"statut {', '.join(blocked)} sur {len(blocked)} sonde(s)")
    if detected_via:
        evidence_parts.extend(detected_via)
    if bypassable:
        evidence_parts.append(
            f"filtre contournable par encodage ({', '.join(encoded_passed)})"
        )
    evidence = " ; ".join(evidence_parts) or "Sonde bloquée sans signature nominale."

    return [
        DetectionResult(
            rule_id=RULE_ID,
            category=CATEGORY,
            severity=SEVERITY,
            title="Pare-feu applicatif (WAF) détecté sur la cible",
            description=base_desc,
            matched_at=root.final_url if root else base,
            evidence_text=f"Bloqué : {evidence}",
        )
    ]


def _header_waf_signature(headers: dict[str, str]) -> list[str]:
    """Retourne la liste des signatures de WAF présentes dans les en-têtes."""
    found: list[str] = []
    for header, label in WAF_HEADER_SIGNATURES.items():
        value = headers.get(header)
        if value is None:
            continue
        if header == "server":
            lowered = value.lower()
            for marker in ("cloudflare", "sucuri", "akamai", "incapsula", "imperva"):
                if marker in lowered:
                    found.append(f"{label} ({value})")
                    break
        else:
            found.append(f"{label} ({value})")
    return found


def _body_waf_signature(body: str) -> list[str]:
    """Retourne la liste des signatures de blocage WAF présentes dans le corps."""
    lowered = body.lower()
    return [sig for sig in WAF_BODY_SIGNATURES if sig in lowered]


def _looks_waf(page: RootResponse) -> bool:
    """Vrai si une réponse 403 porte une signature d'en-tête ou de corps de WAF."""
    return bool(_header_waf_signature(page.headers) or _body_waf_signature(page.body))


def _with_query(url: str, params: dict[str, str], pre_encoded: bool = False) -> str:
    """Ajoute des paramètres de requête à une URL.

    Avec `pre_encoded=True`, les valeurs sont déjà encodées (rotation des
    charges) : elles sont ajoutées telles quelles, sans re-encodage.
    """
    from urllib.parse import urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    query = parsed.query
    separator = "&" if query else ""
    if pre_encoded:
        extra = "&".join(f"{key}={value}" for key, value in params.items())
    else:
        extra = urlencode(params)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query + separator + extra,
            parsed.fragment,
        )
    )
