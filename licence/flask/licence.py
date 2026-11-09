"""
licence.py — HANA

Vérification de la licence côté Flask.
L'app Swift envoie à chaque requête :
    X-Hana-Licence : "<payload_base64>.<signature_base64>"   (licence signée par n8n)
    X-Hana-Machine : identifiant du Mac (SHA-256)

Utilisation :

    from flask import Flask, g
    from licence import init_licence, licence_requise

    app = Flask(__name__)
    init_licence(app)

    @app.get("/api/donnees")
    @licence_requise
    def donnees():
        return {"plan": g.licence["plan"]}

    @app.get("/api/export")
    @licence_requise(plans={"pro"})        # réservé à certains plans
    def export():
        ...

Dépendance : pip install cryptography
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import platform
import re
import subprocess
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import g, jsonify, request

# Clé PUBLIQUE produite par generer-cles.js (la même que dans LicenceManager.swift)
PUBLIC_KEY_B64 = "REMPLACER_PAR_LA_CLE_PUBLIQUE"

# True  : Flask tourne EN LOCAL sur le Mac du client (embarqué dans l'app)
#         -> on vérifie que la licence correspond bien à CE Mac.
# False : Flask tourne sur VOTRE serveur -> on vérifie l'en-tête X-Hana-Machine.
FLASK_LOCAL = True


class LicenceInvalide(Exception):
    def __init__(self, message: str, code: int = 403):
        super().__init__(message)
        self.message = message
        self.code = code


def _cle_publique() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))


@functools.lru_cache(maxsize=1)
def machine_id() -> str:
    """Même calcul que LicenceManager.machineId() en Swift (uniquement sur macOS)."""
    if platform.system() != "Darwin":
        raise RuntimeError("machine_id() n'est disponible que sur macOS")
    sortie = subprocess.run(
        ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
        capture_output=True, text=True, check=True,
    ).stdout
    m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', sortie)
    uuid = m.group(1) if m else "inconnu"
    return hashlib.sha256(f"hana:{uuid}".encode()).hexdigest()


def verifier_jeton(jeton: str, machine_attendue: str | None = None,
                   maintenant: float | None = None) -> dict:
    """Vérifie signature, machine et dates. Renvoie le contenu de la licence."""
    if not jeton or jeton.count(".") != 1:
        raise LicenceInvalide("Licence manquante", 401)

    payload_b64, signature_b64 = jeton.split(".")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
        _cle_publique().verify(signature, payload)
        lic = json.loads(payload)
    except (InvalidSignature, ValueError):
        raise LicenceInvalide("Licence falsifiée ou corrompue", 401)

    t = time.time() if maintenant is None else maintenant
    if lic.get("expiresAt") and lic["expiresAt"] < t:
        raise LicenceInvalide("Licence expirée")
    if t > lic["validUntil"]:
        raise LicenceInvalide("Licence à revalider (connexion Internet requise)")
    if machine_attendue and lic.get("machineId") != machine_attendue:
        raise LicenceInvalide("Licence activée sur un autre Mac")

    return lic


def _verifier_requete() -> dict:
    jeton = request.headers.get("X-Hana-Licence", "")
    machine = machine_id() if FLASK_LOCAL else request.headers.get("X-Hana-Machine", "")
    if not machine:
        raise LicenceInvalide("Identifiant de machine manquant", 401)
    return verifier_jeton(jeton, machine)


def licence_requise(fonction=None, *, plans: set[str] | None = None):
    """Décorateur : refuse la requête si la licence n'est pas valide."""
    def decorateur(f):
        @functools.wraps(f)
        def enveloppe(*args, **kwargs):
            try:
                lic = _verifier_requete()
            except LicenceInvalide as e:
                return jsonify(error=e.message), e.code
            if plans and lic.get("plan") not in plans:
                return jsonify(error="Fonction non incluse dans votre licence"), 403
            g.licence = lic
            return f(*args, **kwargs)
        return enveloppe

    return decorateur(fonction) if fonction else decorateur


def init_licence(app, proteger_tout: bool = False, routes_libres: set[str] | None = None):
    """
    proteger_tout=True : TOUTES les routes exigent une licence, sauf routes_libres
    (ex. {"static", "sante"} — noms d'endpoints Flask).
    """
    libres = {"static"} | (routes_libres or set())

    if proteger_tout:
        @app.before_request
        def _controle_global():
            if request.endpoint in libres:
                return None
            try:
                g.licence = _verifier_requete()
            except LicenceInvalide as e:
                return jsonify(error=e.message), e.code
            return None
