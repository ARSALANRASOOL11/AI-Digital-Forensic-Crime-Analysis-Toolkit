# =============================================================================
#  modules/encryption.py  — Evidence File Encryption
#
#  Uses:
#    Fernet (AES-128-CBC + HMAC-SHA256) from cryptography library
#    PBKDF2-HMAC-SHA256 for key derivation from password
#    Encrypted files stored with .enc extension + metadata header
#
#  Encrypted file format:
#    [4 bytes magic "CFIS"] [4 bytes version] [16 bytes salt]
#    [4 bytes original_filename_len] [N bytes filename]
#    [8 bytes original_size] [Fernet ciphertext...]
# =============================================================================

import os, struct, secrets, base64, hashlib, json, time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC      = b"CFIS"
VERSION    = b"\x00\x01\x00\x00"
ITERATIONS = 480_000   # OWASP 2023 minimum for PBKDF2-SHA256
KEY_LEN    = 32


# =============================================================================
#  Key derivation
# =============================================================================

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a password + salt using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _master_key() -> str:
    """
    Get or generate the master encryption key stored in the environment.
    Falls back to a file-based key in the app directory.
    """
    env_key = os.environ.get("EVIDENCE_MASTER_KEY", "")
    if env_key:
        return env_key

    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".master.key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()

    # Generate and save
    new_key = Fernet.generate_key().decode()
    with open(key_file, "w") as f:
        f.write(new_key)
    os.chmod(key_file, 0o600)
    return new_key


# =============================================================================
#  Encrypt / Decrypt
# =============================================================================

def encrypt_file(source_path: str, dest_path: str = None,
                 password: str = None) -> dict:
    """
    Encrypt a file.
    - If password is given: PBKDF2 key derivation from password
    - If no password: uses the master key (per-installation Fernet key)

    Returns {"success": bool, "path": str, "size_original": int,
             "size_encrypted": int, "algorithm": str}
    """
    if not os.path.exists(source_path):
        return {"success": False, "error": "Source file not found"}

    original_name = os.path.basename(source_path).encode("utf-8")
    original_size = os.path.getsize(source_path)

    try:
        with open(source_path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Key setup
    salt = secrets.token_bytes(16)
    if password:
        key  = _derive_key(password, salt)
        algo = f"Fernet(AES-128-CBC+HMAC-SHA256) / PBKDF2-SHA256 {ITERATIONS} iter"
    else:
        raw  = _master_key()
        key  = raw.encode() if isinstance(raw, str) else raw
        salt = b"\x00" * 16   # sentinel for "no PBKDF2"
        algo = "Fernet(AES-128-CBC+HMAC-SHA256) / master key"

    f_obj     = Fernet(key)
    ciphertext = f_obj.encrypt(plaintext)

    dest_path = dest_path or source_path + ".enc"

    # Build header
    header = (
        MAGIC +
        VERSION +
        salt +
        struct.pack(">I", len(original_name)) +
        original_name +
        struct.pack(">Q", original_size)
    )

    with open(dest_path, "wb") as out:
        out.write(header + ciphertext)

    os.chmod(dest_path, 0o640)

    return {
        "success":        True,
        "path":           dest_path,
        "size_original":  original_size,
        "size_encrypted": os.path.getsize(dest_path),
        "algorithm":      algo,
        "salt_hex":       salt.hex(),
    }


def decrypt_file(enc_path: str, dest_path: str = None,
                 password: str = None) -> dict:
    """
    Decrypt a CFIS-encrypted file.
    Returns {"success": bool, "path": str, "original_name": str}
    """
    if not os.path.exists(enc_path):
        return {"success": False, "error": "Encrypted file not found"}

    try:
        with open(enc_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Parse header
    if not data.startswith(MAGIC):
        return {"success": False, "error": "Not a CFIS-encrypted file"}

    offset = 4 + 4   # magic + version
    salt   = data[offset: offset+16]; offset += 16
    fn_len = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
    orig_name = data[offset:offset+fn_len].decode("utf-8", "ignore"); offset += fn_len
    _orig_sz  = struct.unpack(">Q", data[offset:offset+8])[0]; offset += 8
    ciphertext = data[offset:]

    # Key setup
    if password:
        key = _derive_key(password, salt)
    else:
        raw = _master_key()
        key = raw.encode() if isinstance(raw, str) else raw

    try:
        f_obj     = Fernet(key)
        plaintext = f_obj.decrypt(ciphertext)
    except Exception as e:
        return {"success": False, "error": "Decryption failed — wrong password or corrupted file"}

    dest_path = dest_path or enc_path.replace(".enc", "_decrypted")
    with open(dest_path, "wb") as out:
        out.write(plaintext)

    return {
        "success":       True,
        "path":          dest_path,
        "original_name": orig_name,
        "size":          len(plaintext),
    }


def is_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except Exception:
        return False


def encryption_info(enc_path: str) -> dict:
    """Return metadata from an encrypted file header."""
    try:
        with open(enc_path, "rb") as f:
            data = f.read(200)
        if not data.startswith(MAGIC):
            return {"encrypted": False}
        offset   = 8
        salt     = data[offset:offset+16]; offset += 16
        fn_len   = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        fname    = data[offset:offset+fn_len].decode("utf-8","ignore"); offset += fn_len
        orig_sz  = struct.unpack(">Q", data[offset:offset+8])[0]
        password_protected = (salt != b"\x00"*16)
        return {
            "encrypted":           True,
            "original_filename":   fname,
            "original_size":       orig_sz,
            "password_protected":  password_protected,
            "algorithm":           "Fernet / AES-128-CBC + HMAC-SHA256",
        }
    except Exception as e:
        return {"encrypted": False, "error": str(e)}


def get_file_hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        pass
    return h.hexdigest()
