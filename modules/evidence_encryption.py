# =============================================================================
#  modules/evidence_encryption.py
#  Enhanced Evidence Encryption System
#
#  Extends the existing modules/encryption.py with:
#    - Auto-encrypt on upload
#    - Integrity verification before decrypt
#    - Tamper detection
#    - Encryption metadata in DB
#    - Audit logging for every decrypt
#    - Batch encrypt existing evidence
# =============================================================================

import os, hashlib, base64, time, json, secrets, struct
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC      = b"CFIS"
VERSION    = b"\x00\x02\x00\x00"
ITERATIONS = 480_000
KEY_LEN    = 32
CHUNK_SIZE = 64 * 1024   # 64 KB chunks for large files


# =============================================================================
#  Key management
# =============================================================================

KEY_DIR       = "keys"
MASTER_KEY_PATH = os.path.join(KEY_DIR, ".evidence_master.key")


def _get_master_key() -> str:
    """Get or generate the master Fernet key."""
    env_key = os.environ.get("EVIDENCE_MASTER_KEY","")
    if env_key:
        return env_key
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(MASTER_KEY_PATH):
        with open(MASTER_KEY_PATH,"r") as f:
            return f.read().strip()
    key = Fernet.generate_key().decode()
    with open(MASTER_KEY_PATH,"w") as f:
        f.write(key)
    os.chmod(MASTER_KEY_PATH, 0o600)
    return key


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_LEN,
        salt=salt, iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# =============================================================================
#  Core encrypt / decrypt
# =============================================================================

def encrypt_file(source_path: str, dest_path: str = None,
                 password: str = None) -> dict:
    """
    Encrypt a file using Fernet (AES-128-CBC + HMAC-SHA256).
    Stores: magic, version, salt, original filename, original size, SHA-256 hash.

    Args:
        source_path : path to plaintext file
        dest_path   : destination path (default: source_path + ".enc")
        password    : optional password (uses master key if None)

    Returns result dict with success, path, algorithm, hash.
    """
    if not os.path.exists(source_path):
        return {"success":False,"error":"Source file not found"}

    original_name = os.path.basename(source_path).encode()
    original_size = os.path.getsize(source_path)

    # Compute SHA-256 of plaintext before encrypting
    sha256 = _sha256_file(source_path)

    try:
        with open(source_path,"rb") as f:
            plaintext = f.read()
    except Exception as e:
        return {"success":False,"error":str(e)}

    # Key setup
    salt = secrets.token_bytes(16)
    if password:
        key  = _derive_key(password, salt)
        algo = f"Fernet/AES-128-CBC+HMAC-SHA256/PBKDF2-SHA256({ITERATIONS}iter)"
    else:
        key  = _get_master_key().encode()
        salt = b"\x00"*16   # sentinel
        algo = "Fernet/AES-128-CBC+HMAC-SHA256/master-key"

    fernet     = Fernet(key)
    ciphertext = fernet.encrypt(plaintext)

    dest_path  = dest_path or (source_path + ".enc")

    # Header: magic(4) + version(4) + salt(16) + fn_len(4) + filename + sha256(32) + orig_size(8)
    header = (
        MAGIC + VERSION + salt +
        struct.pack(">I", len(original_name)) + original_name +
        bytes.fromhex(sha256) +
        struct.pack(">Q", original_size)
    )

    with open(dest_path,"wb") as f:
        f.write(header + ciphertext)
    os.chmod(dest_path, 0o640)

    return {
        "success":         True,
        "path":            dest_path,
        "original_path":   source_path,
        "size_original":   original_size,
        "size_encrypted":  os.path.getsize(dest_path),
        "sha256_original": sha256,
        "algorithm":       algo,
        "password_protected": bool(password),
    }


def decrypt_file(enc_path: str, dest_path: str = None,
                 password: str = None) -> dict:
    """
    Decrypt a CFIS-encrypted file with tamper detection.

    Returns result dict. Raises no exceptions — errors returned in dict.
    """
    if not os.path.exists(enc_path):
        return {"success":False,"error":"Encrypted file not found"}

    try:
        with open(enc_path,"rb") as f:
            data = f.read()
    except Exception as e:
        return {"success":False,"error":str(e)}

    if not data.startswith(MAGIC):
        return {"success":False,"error":"Not a CFIS-encrypted file"}

    # Parse header
    try:
        offset    = 8   # skip magic + version
        salt      = data[offset:offset+16]; offset += 16
        fn_len    = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        orig_name = data[offset:offset+fn_len].decode("utf-8","ignore"); offset += fn_len
        stored_hash = data[offset:offset+32].hex(); offset += 32
        orig_size   = struct.unpack(">Q", data[offset:offset+8])[0]; offset += 8
        ciphertext  = data[offset:]
    except Exception as e:
        return {"success":False,"error":f"Header parse error: {e}"}

    # Key setup
    pw_protected = (salt != b"\x00"*16)
    if pw_protected:
        if not password:
            return {"success":False,"error":"Password required to decrypt this file"}
        key = _derive_key(password, salt)
    else:
        key = _get_master_key().encode()

    # Decrypt
    try:
        fernet    = Fernet(key)
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        return {"success":False,"error":"Decryption failed — wrong password or corrupted file"}
    except Exception as e:
        return {"success":False,"error":f"Decryption error: {e}"}

    # Integrity check — verify SHA-256 of decrypted content
    current_hash = hashlib.sha256(plaintext).hexdigest()
    if current_hash != stored_hash:
        return {
            "success":       False,
            "error":         "Integrity check FAILED — file has been tampered with",
            "tampered":      True,
            "stored_hash":   stored_hash,
            "current_hash":  current_hash,
        }

    # Write decrypted file
    dest_path = dest_path or enc_path.replace(".enc","_decrypted")
    with open(dest_path,"wb") as f:
        f.write(plaintext)

    return {
        "success":      True,
        "path":         dest_path,
        "original_name":orig_name,
        "size":         len(plaintext),
        "sha256":       current_hash,
        "tampered":     False,
        "integrity":    "VERIFIED",
    }


def verify_integrity(enc_path: str, password: str = None) -> dict:
    """Verify integrity of encrypted file without writing output."""
    result = decrypt_file(enc_path, dest_path="/dev/null", password=password)
    if os.path.exists("/dev/null"):
        pass   # Unix no-op
    return {
        "valid":    result.get("success",False),
        "tampered": result.get("tampered",False),
        "error":    result.get("error",""),
        "sha256":   result.get("sha256",""),
        "integrity":result.get("integrity","UNKNOWN"),
    }


def is_encrypted(path: str) -> bool:
    """Return True if file has CFIS encryption header."""
    try:
        with open(path,"rb") as f:
            return f.read(4) == MAGIC
    except Exception:
        return False


def encryption_info(path: str) -> dict:
    """Return metadata from encrypted file header."""
    try:
        with open(path,"rb") as f:
            data = f.read(200)
        if not data.startswith(MAGIC):
            return {"encrypted":False}
        offset    = 8
        salt      = data[offset:offset+16]; offset += 16
        fn_len    = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        fname     = data[offset:offset+fn_len].decode("utf-8","ignore"); offset += fn_len
        sha256    = data[offset:offset+32].hex(); offset += 32
        orig_size = struct.unpack(">Q", data[offset:offset+8])[0]
        return {
            "encrypted":          True,
            "original_filename":  fname,
            "original_size":      orig_size,
            "stored_sha256":      sha256,
            "password_protected": salt != b"\x00"*16,
            "algorithm":          "Fernet/AES-128-CBC+HMAC-SHA256",
        }
    except Exception as e:
        return {"encrypted":False,"error":str(e)}


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
#  Database helpers
# =============================================================================

def init_encryption_tables(conn):
    """Add encryption metadata table (idempotent)."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS encryption_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id     INTEGER,
        action          TEXT,
        actor           TEXT,
        timestamp       REAL,
        sha256_before   TEXT DEFAULT '',
        sha256_after    TEXT DEFAULT '',
        algorithm       TEXT DEFAULT '',
        success         INTEGER DEFAULT 1,
        ip              TEXT DEFAULT ''
    );
    """)
    # Add encryption columns to evidence table
    for col, dflt in [
        ("is_encrypted",   "0"),
        ("enc_path",       "''"),
        ("enc_sha256",     "''"),
        ("enc_algorithm",  "''"),
    ]:
        try:
            conn.execute(f"ALTER TABLE evidence ADD COLUMN {col} TEXT DEFAULT {dflt}")
        except Exception:
            pass
    conn.commit()


def log_encryption_action(conn, evidence_id: int, action: str,
                           actor: str, ip: str = "", **kwargs):
    """Log an encryption or decryption action."""
    conn.execute("""
        INSERT INTO encryption_log
        (evidence_id,action,actor,timestamp,sha256_before,sha256_after,algorithm,success,ip)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (
        evidence_id, action, actor, time.time(),
        kwargs.get("sha256_before",""),
        kwargs.get("sha256_after",""),
        kwargs.get("algorithm",""),
        int(kwargs.get("success",True)),
        ip,
    ))
    conn.commit()


def get_encryption_stats(conn) -> dict:
    total     = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    encrypted = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE is_encrypted='1'"
    ).fetchone()[0]
    logs      = conn.execute("SELECT COUNT(*) FROM encryption_log").fetchone()[0]
    decrypts  = conn.execute(
        "SELECT COUNT(*) FROM encryption_log WHERE action='DECRYPT'"
    ).fetchone()[0]
    return {
        "total_evidence":  total,
        "encrypted":       encrypted,
        "unencrypted":     total - encrypted,
        "pct_encrypted":   round(encrypted/max(total,1)*100,1),
        "total_actions":   logs,
        "decrypt_count":   decrypts,
    }


def batch_encrypt_existing(conn, upload_folder: str, actor: str = "system") -> dict:
    """Encrypt all existing plaintext evidence files."""
    rows = conn.execute(
        "SELECT id, path, hash FROM evidence WHERE is_encrypted IS NULL OR is_encrypted='0'"
    ).fetchall()
    success_count = 0
    errors        = []
    for row in rows:
        ev_id, path, original_hash = row[0], row[1], row[2]
        if not os.path.exists(path) or is_encrypted(path):
            continue
        result = encrypt_file(path, path + ".enc")
        if result["success"]:
            # Replace original with encrypted
            try:
                os.remove(path)
                os.rename(path + ".enc", path)
                conn.execute("""
                    UPDATE evidence
                    SET is_encrypted='1', enc_path=?, enc_sha256=?, enc_algorithm=?
                    WHERE id=?
                """, (path, result["sha256_original"], result["algorithm"], ev_id))
                log_encryption_action(conn, ev_id, "AUTO_ENCRYPT", actor,
                                      sha256_before=original_hash,
                                      sha256_after=result["sha256_original"],
                                      algorithm=result["algorithm"])
                success_count += 1
            except Exception as e:
                errors.append(f"EV-{ev_id}: {e}")
        else:
            errors.append(f"EV-{ev_id}: {result.get('error','')}")
    conn.commit()
    return {"encrypted": success_count, "errors": errors}
