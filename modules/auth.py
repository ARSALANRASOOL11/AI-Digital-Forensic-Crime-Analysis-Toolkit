# =============================================================================
#  modules/auth.py  — Authentication, CSRF, Session Timeout, RBAC
#  Uses hashlib.scrypt (PBKDF-equivalent, built-in) for secure password hashing
# =============================================================================

import hashlib, secrets, time, os, sqlite3, functools
from flask import session, redirect, request, abort, g

DB = "evidence.db"
SESSION_TIMEOUT = 30 * 60   # 30 minutes idle timeout

# ---------------------------------------------------------------------------
# Password hashing  (scrypt  — memory-hard, no extra lib needed)
# ---------------------------------------------------------------------------
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
HASH_LEN = 32

def hash_password(plain: str) -> str:
    """Return  'scrypt$<hex_salt>$<hex_hash>'  — never store plain text."""
    salt = secrets.token_bytes(16)
    key  = hashlib.scrypt(plain.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=HASH_LEN)
    return f"scrypt${salt.hex()}${key.hex()}"

def verify_password(plain: str, stored: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    try:
        scheme, salt_hex, key_hex = stored.split("$")
        if scheme != "scrypt":
            # Legacy SHA-256 support (migration path)
            return secrets.compare_digest(
                hashlib.sha256(plain.encode()).hexdigest(), stored
            )
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
        actual   = hashlib.scrypt(plain.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=HASH_LEN)
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# CSRF  (synchronizer token pattern)
# ---------------------------------------------------------------------------
def generate_csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def validate_csrf(token: str) -> bool:
    stored = session.get("_csrf", "")
    return stored and secrets.compare_digest(stored, token)

def csrf_protect():
    """Call at top of POST handlers — aborts 403 on bad token."""
    if request.method == "POST":
        token = request.form.get("_csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not validate_csrf(token):
            abort(403)

# ---------------------------------------------------------------------------
# Session timeout check
# ---------------------------------------------------------------------------
def check_session_timeout():
    if "user" not in session:
        return False
    last = session.get("_last_active", 0)
    if time.time() - last > SESSION_TIMEOUT:
        session.clear()
        return False
    session["_last_active"] = time.time()
    return True

# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------
ROLE_PERMISSIONS = {
    "administrator":    {"*"},              # all pages
    "forensic_analyst": {"dashboard", "upload", "verify", "metadata",
                         "autopsy", "chat", "carve", "notes", "custody",
                         "audit", "report", "export", "ml_analysis"},
    "soc_analyst":      {"dashboard", "verify", "metadata", "autopsy",
                         "chat", "carve", "audit", "ml_analysis"},
    "red_team_operator":{"dashboard", "metadata", "carve", "ml_analysis"},
}

def has_permission(role: str, page: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    return "*" in perms or page in perms

def login_required(page: str = "dashboard"):
    """Decorator factory: @login_required('upload')"""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if not check_session_timeout():
                return redirect("/login?timeout=1")
            role = session.get("role", "")
            if not has_permission(role, page):
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not check_session_timeout():
            return redirect("/login?timeout=1")
        if session.get("role") != "administrator":
            abort(403)
        return f(*args, **kwargs)
    return wrapper
