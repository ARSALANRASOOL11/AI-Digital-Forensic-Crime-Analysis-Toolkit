# =============================================================================
#  modules/evidence_signing.py  — Digital Evidence Signing System
#
#  RSA-2048 based evidence signing and verification.
#  Each evidence file gets a cryptographic signature stored in the database.
#  Reports can be signed by the examiner for court admissibility.
# =============================================================================

import os, hashlib, base64, time, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

KEY_DIR       = "keys"
PRIV_KEY_PATH = os.path.join(KEY_DIR, "evidence_signing.key")
PUB_KEY_PATH  = os.path.join(KEY_DIR, "evidence_signing.pub")
KEY_BITS      = 2048


def _ensure_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(PRIV_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_BITS,
            backend=default_backend()
        )
        with open(PRIV_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        os.chmod(PRIV_KEY_PATH, 0o600)
        with open(PUB_KEY_PATH, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))


def _load_private_key():
    _ensure_keys()
    with open(PRIV_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_public_key():
    _ensure_keys()
    with open(PUB_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_evidence(filepath: str, examiner: str, case_id: str) -> dict:
    """Sign an evidence file. Returns signature bundle."""
    if not os.path.exists(filepath):
        return {"success": False, "error": "File not found"}
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        file_hash = h.hexdigest()

        payload = json.dumps({
            "filepath": os.path.basename(filepath),
            "sha256":   file_hash,
            "examiner": examiner,
            "case_id":  case_id,
            "signed_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, sort_keys=True).encode()

        private_key = _load_private_key()
        signature   = private_key.sign(payload, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

        sig_b64 = base64.b64encode(signature).decode()
        bundle  = {
            "success":    True,
            "sha256":     file_hash,
            "signature":  sig_b64,
            "payload":    payload.decode(),
            "examiner":   examiner,
            "case_id":    case_id,
            "signed_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "key_bits":   KEY_BITS,
            "algorithm":  "RSA-PSS / SHA-256",
        }
        return bundle
    except Exception as e:
        return {"success": False, "error": str(e)}


def verify_evidence(filepath: str, signature_b64: str, payload_json: str) -> dict:
    """Verify an evidence file signature."""
    if not os.path.exists(filepath):
        return {"valid": False, "error": "File not found"}
    try:
        # Recompute hash
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        current_hash = h.hexdigest()

        payload = json.loads(payload_json)
        stored_hash = payload.get("sha256", "")

        # Hash integrity check
        if current_hash != stored_hash:
            return {
                "valid":        False,
                "error":        "File hash mismatch — evidence may have been tampered",
                "current_hash": current_hash,
                "stored_hash":  stored_hash,
            }

        # Signature verification
        signature = base64.b64decode(signature_b64)
        pub_key   = _load_public_key()
        pub_key.verify(
            signature,
            payload_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "valid":        True,
            "sha256":       current_hash,
            "examiner":     payload.get("examiner",""),
            "case_id":      payload.get("case_id",""),
            "signed_at":    payload.get("signed_at",""),
            "algorithm":    "RSA-PSS / SHA-256",
        }
    except InvalidSignature:
        return {"valid": False, "error": "Invalid RSA signature — signature does not match"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def get_public_key_pem() -> str:
    _ensure_keys()
    with open(PUB_KEY_PATH, "r") as f:
        return f.read()
