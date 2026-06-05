# =============================================================================
#  modules/carver.py  — Magic byte file carving
# =============================================================================

import os

CARVE_SIGNATURES = [
    (b"\xff\xd8\xff",          b"\xff\xd9",              ".jpg",  "JPEG Image"),
    (b"\x89PNG\r\n\x1a\n",    b"IEND\xaeB`\x82",        ".png",  "PNG Image"),
    (b"GIF8",                  b"\x00\x3b",               ".gif",  "GIF Image"),
    (b"%PDF",                  b"%%EOF",                  ".pdf",  "PDF Document"),
    (b"PK\x03\x04",           None,                      ".zip",  "ZIP Archive"),
    (b"MZ",                    None,                      ".exe",  "Windows PE Executable"),
    (b"\x7fELF",               None,                      ".elf",  "Linux ELF Binary"),
    (b"\xd0\xcf\x11\xe0",     None,                      ".doc",  "Legacy MS Office Document"),
    (b"RIFF",                  None,                      ".avi",  "RIFF Media"),
    (b"\x1f\x8b",              None,                      ".gz",   "GZIP Archive"),
]
MAX_CARVE_SIZE = 10 * 1024 * 1024


def carve_deleted_files(path: str) -> list[dict]:
    results = []
    try:
        size      = os.path.getsize(path)
        read_size = min(size, MAX_CARVE_SIZE)
        with open(path, "rb") as f:
            data = f.read(read_size)
    except Exception:
        return results

    checked_offsets = set()
    for header, footer, ext, desc in CARVE_SIGNATURES:
        start = 0
        while True:
            idx = data.find(header, start)
            if idx == -1: break
            if idx in checked_offsets:
                start = idx + 1; continue
            checked_offsets.add(idx)
            end_idx = None
            if footer:
                end_idx = data.find(footer, idx + len(header))
                if end_idx != -1: end_idx += len(footer)
            if end_idx is None:
                end_idx = min(idx + 4096, len(data))
            chunk = data[idx:end_idx]
            results.append({
                "offset":      hex(idx),
                "extension":   ext,
                "description": desc,
                "size_bytes":  len(chunk),
                "hex_preview": chunk[:32].hex(),
            })
            start = idx + 1
            if len(results) >= 50: break
        if len(results) >= 50: break

    results.sort(key=lambda r: int(r["offset"], 16))
    return results
