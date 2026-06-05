# =============================================================================
#  modules/mfa.py  — Multi-Factor Authentication (TOTP / Google Authenticator)
#
#  Pure stdlib TOTP (RFC 6238) — no pyotp needed.
#  QR code generated with PIL (already installed).
#  Compatible with Google Authenticator, Authy, Microsoft Authenticator.
# =============================================================================

import hmac, hashlib, base64, struct, time, secrets, os, io, json
from PIL import Image

# ---------------------------------------------------------------------------
TOTP_DIGITS  = 6
TOTP_PERIOD  = 30   # seconds per code
TOTP_ALGO    = hashlib.sha1
ISSUER       = "ForensicToolkit"
BACKUP_CODES = 8    # number of one-time backup codes


# =============================================================================
#  Core TOTP (RFC 6238)
# =============================================================================

def generate_secret() -> str:
    """Generate a random 20-byte base32 TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(key_bytes: bytes, counter: int) -> int:
    msg = struct.pack(">Q", counter)
    h   = hmac.new(key_bytes, msg, TOTP_ALGO).digest()
    offset = h[-1] & 0x0F
    code   = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return code % (10 ** TOTP_DIGITS)


def get_totp(secret: str, ts: float = None) -> str:
    """Return the current 6-digit TOTP code for a given secret."""
    pad    = secret + "=" * ((8 - len(secret) % 8) % 8)
    key    = base64.b32decode(pad.upper())
    ts     = ts or time.time()
    counter = int(ts) // TOTP_PERIOD
    return str(_hotp(key, counter)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code with ±window period tolerance.
    window=1 allows one period (30s) before/after for clock drift.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    pad     = secret + "=" * ((8 - len(secret) % 8) % 8)
    key     = base64.b32decode(pad.upper())
    now     = int(time.time()) // TOTP_PERIOD
    for offset in range(-window, window + 1):
        expected = str(_hotp(key, now + offset)).zfill(TOTP_DIGITS)
        if hmac.compare_digest(expected, code):
            return True
    return False


def get_totp_uri(secret: str, username: str) -> str:
    """Return the otpauth:// URI for QR code scanning."""
    import urllib.parse
    return (f"otpauth://totp/{urllib.parse.quote(ISSUER)}:"
            f"{urllib.parse.quote(username)}"
            f"?secret={secret}&issuer={urllib.parse.quote(ISSUER)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


# =============================================================================
#  QR Code generator — pure PIL, no external qrcode lib
# =============================================================================

def _qr_matrix(data: str) -> list[list[int]]:
    """
    Minimal QR code matrix using a pre-encoded lookup for short otpauth URIs.
    For production: replaces with full QR encoder below using PIL pixel drawing.
    We encode via a compact Reed-Solomon-free approach for display purposes,
    wrapping the URI in a high-contrast pixel grid renderable by authenticator apps.

    Since qrcode lib isn't available, we generate a data-URL PNG that contains
    the URI text encoded as a simple barcode-style image with the URI overlaid,
    PLUS instructions to manually enter the secret — which is the fallback
    Google Authenticator supports ("Enter a setup key").
    """
    # Build a simple visual representation: black/white cells
    # encoding the URI as a 1D barcode + text for manual entry fallback
    bits = []
    for char in data.encode("utf-8"):
        for bit in range(7, -1, -1):
            bits.append((char >> bit) & 1)
    return bits


def generate_qr_png_b64(secret: str, username: str) -> str:
    """
    Returns a base64-encoded PNG showing:
    - The TOTP secret prominently (for manual entry into authenticator apps)
    - A simple visual pattern
    - Setup instructions
    This works even without the qrcode library.
    """
    uri = get_totp_uri(secret, username)

    # Try to generate proper QR if segno or qrcode is available
    try:
        import qrcode
        buf = io.BytesIO()
        img = qrcode.make(uri)
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        pass

    try:
        import segno
        buf = io.BytesIO()
        qr  = segno.make(uri, error="M")
        qr.save(buf, kind="png", scale=6, dark="#00ffe7", light="#020b18")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        pass

    # Fallback: generate a branded PNG with the secret displayed clearly
    W, H = 300, 300
    img  = Image.new("RGB", (W, H), color=(2, 11, 24))

    # Draw a simple grid pattern as visual placeholder
    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(img)

    # Border
    draw.rectangle([2, 2, W-3, H-3], outline=(0, 255, 231), width=2)

    # Title
    draw.rectangle([10, 10, W-10, 45], fill=(4, 21, 37))
    draw.text((15, 18), "FORENSIC TOOLKIT MFA", fill=(0, 255, 231))

    # Secret display (chunked for readability)
    chunks  = [secret[i:i+4] for i in range(0, len(secret), 4)]
    display = "  ".join(chunks)
    draw.text((15, 60), "Setup Key:", fill=(196, 223, 240))
    draw.text((15, 80), display[:20], fill=(255, 255, 255))
    if len(display) > 20:
        draw.text((15, 100), display[20:40], fill=(255, 255, 255))

    draw.text((15, 130), "Steps:", fill=(196, 223, 240))
    steps = [
        "1. Open Google Authenticator",
        "2. Tap + → Enter setup key",
        "3. Account: " + username,
        "4. Key: (above)",
        "5. Type: Time-based",
    ]
    for i, step in enumerate(steps):
        draw.text((15, 150 + i*22), step, fill=(196, 223, 240))

    draw.text((15, 270), f"Issuer: {ISSUER}", fill=(74, 112, 144))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# =============================================================================
#  Backup codes
# =============================================================================

def generate_backup_codes(n: int = BACKUP_CODES) -> list[str]:
    """Generate n one-time backup codes."""
    return [secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper()
            for _ in range(n)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def verify_backup_code(code: str, hashed_codes: list[str]) -> tuple[bool, list[str]]:
    """
    Verify a backup code (one-time use).
    Returns (valid, remaining_hashed_codes).
    """
    h = hash_backup_code(code)
    if h in hashed_codes:
        remaining = [c for c in hashed_codes if c != h]
        return True, remaining
    return False, hashed_codes


# =============================================================================
#  DB helpers  (stores MFA state per user)
# =============================================================================

def setup_mfa_tables(conn):
    """Add MFA columns to users table."""
    for col_def in [
        "mfa_secret TEXT DEFAULT ''",
        "mfa_enabled INTEGER DEFAULT 0",
        "mfa_backup_codes TEXT DEFAULT '[]'",
        "mfa_verified INTEGER DEFAULT 0",
    ]:
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col_def}")
        except Exception:
            pass
    conn.commit()


def get_user_mfa(conn, username: str) -> dict:
    row = conn.execute(
        "SELECT mfa_secret, mfa_enabled, mfa_backup_codes, mfa_verified "
        "FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row:
        return {"secret": "", "enabled": False, "backup_codes": [], "verified": False}
    return {
        "secret":       row[0] or "",
        "enabled":      bool(row[1]),
        "backup_codes": json.loads(row[2] or "[]"),
        "verified":     bool(row[3]),
    }


def save_user_mfa(conn, username: str, secret: str, enabled: bool,
                  backup_codes: list, verified: bool):
    conn.execute(
        "UPDATE users SET mfa_secret=?,mfa_enabled=?,mfa_backup_codes=?,mfa_verified=? "
        "WHERE username=?",
        (secret, int(enabled), json.dumps(backup_codes), int(verified), username)
    )
    conn.commit()
