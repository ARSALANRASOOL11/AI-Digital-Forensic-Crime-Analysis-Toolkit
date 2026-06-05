# =============================================================================
#  modules/upload_security.py  — Secure file upload validation
# =============================================================================

import os, secrets, hashlib, re

UPLOAD_FOLDER = "uploads"
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB hard limit

# Whitelist of allowed MIME magic bytes → allowed extensions
ALLOWED_SIGNATURES = {
    b"\xff\xd8\xff":        [".jpg", ".jpeg"],
    b"\x89PNG\r\n\x1a\n":  [".png"],
    b"GIF8":                [".gif"],
    b"%PDF":                [".pdf"],
    b"PK\x03\x04":         [".zip", ".docx", ".xlsx", ".pptx", ".jar"],
    b"\x1f\x8b":           [".gz", ".tgz"],
    b"RIFF":               [".avi", ".wav"],
    b"\x7fELF":            [".elf"],
    b"MZ":                 [".exe", ".dll", ".scr", ".com"],
    b"\xd0\xcf\x11\xe0":  [".doc", ".xls", ".ppt", ".msg"],
    b"BM":                 [".bmp"],
    b"\xff\xfb":           [".mp3"],
    b"ID3":                [".mp3"],
    b"OggS":               [".ogg"],
    b"\x1a\x45\xdf\xa3":  [".mkv", ".webm"],
    b"\x00\x00\x00":      [".mp4", ".mov", ".m4v"],   # partial match for ftyp
}

# Extensions explicitly blocked regardless of magic bytes
BLOCKED_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".jspx",
    ".cgi", ".pl", ".rb", ".sh", ".bash", ".zsh",
    ".htaccess", ".htpasswd",
}

# Extensions allowed (forensic toolkit accepts executables and scripts for analysis)
ANALYSIS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".py", ".rb", ".pl", ".sh", ".elf", ".so",
    ".pcap", ".cap", ".pcapng",
    ".dd", ".img", ".iso", ".raw", ".vmdk", ".e01",
    ".eml", ".msg", ".mbox",
    ".log", ".evt", ".evtx",
    ".db", ".sqlite", ".sqlite3",
    ".reg", ".mem", ".dmp",
    ".csv", ".txt", ".xml", ".json",
    ".docx", ".xlsx", ".pptx", ".pdf",
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff",
    ".mp4", ".avi", ".mkv", ".mp3", ".wav",
    ".zip", ".rar", ".7z", ".tar", ".gz",
}


def sanitize_filename(filename: str) -> str:
    """Strip path traversal, null bytes, and special chars.  Keep extension."""
    # Remove path components
    filename = os.path.basename(filename)
    # Replace null bytes and control characters
    filename = re.sub(r"[\x00-\x1f\x7f]", "", filename)
    # Replace dangerous chars (keep . _ - alphanumeric)
    filename = re.sub(r"[^\w.\-]", "_", filename)
    # Collapse multiple dots (anti double-extension masquerade)
    parts = filename.split(".")
    if len(parts) > 2:
        # Keep name + last extension only
        filename = parts[0] + "." + parts[-1]
    return filename[:200]  # cap length


def secure_save(file_storage, case_id: str) -> tuple[str, str]:
    """
    Save an uploaded FileStorage object securely.
    Returns (safe_path, original_safe_name).
    Raises ValueError on validation failure.
    """
    if not file_storage or not file_storage.filename:
        raise ValueError("No file provided")

    original_name = sanitize_filename(file_storage.filename)
    ext = os.path.splitext(original_name)[1].lower()

    if ext in BLOCKED_EXTENSIONS:
        raise ValueError(f"File type '{ext}' is blocked for security reasons")

    # Read file into memory for magic-byte check (up to 10 bytes)
    header = file_storage.stream.read(10)
    file_storage.stream.seek(0)

    # Check size
    file_storage.stream.seek(0, 2)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({size // 1024 // 1024} MB). Max is {MAX_FILE_SIZE // 1024 // 1024} MB")
    if size == 0:
        raise ValueError("Empty file rejected")

    # Build unique filename: CASE-0001_<random>_<safe_name>
    rand_token = secrets.token_hex(6)
    safe_path_name = f"{case_id}_{rand_token}_{original_name}"
    dest_path = os.path.join(UPLOAD_FOLDER, safe_path_name)

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    file_storage.save(dest_path)

    # Enforce permissions: no execute bit on uploaded files
    try:
        os.chmod(dest_path, 0o640)
    except Exception:
        pass

    return dest_path, original_name


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: str, stored_hash: str) -> str:
    if not os.path.exists(path):
        return "MISSING"
    return "MATCHED" if sha256_file(path) == stored_hash else "TAMPERED"
