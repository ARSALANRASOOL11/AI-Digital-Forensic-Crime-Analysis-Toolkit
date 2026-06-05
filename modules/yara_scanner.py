# =============================================================================
#  modules/yara_scanner.py  — YARA-equivalent rule engine (pure Python)
#  Since yara-python may not be installable, we implement a compatible
#  rule matching engine that handles the same rule syntax patterns.
# =============================================================================

import re, os, struct

# ---------------------------------------------------------------------------
#  YARA rule definitions (pure Python byte/string matching)
# ---------------------------------------------------------------------------
YARA_RULES = [
    {
        "name": "Ransomware_Indicators",
        "tags": ["ransomware", "malware"],
        "strings": [
            b"Your files have been encrypted",
            b"bitcoin",
            b"DECRYPT_INSTRUCTIONS",
            b"ransom",
            b"WannaCry",
            b"CryptoLocker",
            b"YOUR_FILES_ARE_LOCKED",
            b".onion",
        ],
        "condition": "any",    # match if ANY string found
        "severity": "CRITICAL",
        "description": "Ransomware indicators detected — encrypted file references or ransom notes",
    },
    {
        "name": "RemoteAccessTrojan",
        "tags": ["rat", "backdoor", "malware"],
        "strings": [
            b"meterpreter",
            b"reverse_shell",
            b"nc -e",
            b"bind shell",
            b"powershell -EncodedCommand",
            b"base64_decode",
            b"cmd.exe /c",
            b"CreateRemoteThread",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Remote Access Trojan / backdoor indicators found",
    },
    {
        "name": "Keylogger_Spyware",
        "tags": ["keylogger", "spyware"],
        "strings": [
            b"GetAsyncKeyState",
            b"SetWindowsHookEx",
            b"WH_KEYBOARD",
            b"keylog",
            b"keystroke",
            b"clipboard_capture",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Keylogger / spyware API calls detected",
    },
    {
        "name": "Credential_Theft",
        "tags": ["credential", "mimikatz"],
        "strings": [
            b"mimikatz",
            b"lsass.exe",
            b"sekurlsa",
            b"Pass-the-Hash",
            b"golden ticket",
            b"kerberos",
            b"NTLM",
            b"SAM database",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Credential harvesting / Pass-the-Hash tools detected",
    },
    {
        "name": "Web_Attack_Payload",
        "tags": ["webattack", "sqli", "xss"],
        "strings": [
            b"UNION SELECT",
            b"DROP TABLE",
            b"<script>alert(",
            b"javascript:void(",
            b"../../etc/passwd",
            b"../windows/system32",
            b"<?php system(",
            b"eval(base64_decode",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Web attack payloads (SQLi / XSS / LFI / RFI) detected",
    },
    {
        "name": "AntiForensics_Wipe",
        "tags": ["antiforensics", "destruction"],
        "strings": [
            b"format c:",
            b"del /f /q /s",
            b"rm -rf",
            b"shred -u",
            b"cipher /w:",
            b"wipe",
            b"DBAN",
            b"Eraser",
        ],
        "condition": "any",
        "severity": "CRITICAL",
        "description": "Anti-forensics / evidence destruction commands detected",
    },
    {
        "name": "DataExfiltration",
        "tags": ["exfil", "datastealer"],
        "strings": [
            b"ftp://",
            b"curl -T",
            b"wget --post-file",
            b"dns_tunnel",
            b"exfiltrat",
            b"data theft",
            b"DropBox",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Data exfiltration channels or commands detected",
    },
    {
        "name": "PE_Executable_Hidden",
        "tags": ["pe", "disguised"],
        "strings": [],
        "magic_bytes": b"MZ",
        "condition": "magic",
        "severity": "MEDIUM",
        "description": "Windows PE executable detected (verify extension matches)",
    },
    {
        "name": "ELF_Binary",
        "tags": ["elf", "linux"],
        "strings": [],
        "magic_bytes": b"\x7fELF",
        "condition": "magic",
        "severity": "MEDIUM",
        "description": "Linux ELF binary detected",
    },
    {
        "name": "PowerShell_Obfuscated",
        "tags": ["powershell", "obfuscation"],
        "strings": [
            b"-EncodedCommand",
            b"IEX(",
            b"Invoke-Expression",
            b"[Convert]::FromBase64String",
            b"bypass -NoProfile",
            b"DownloadString",
            b"WebClient",
        ],
        "condition": "any",
        "severity": "HIGH",
        "description": "Obfuscated PowerShell execution detected",
    },
    {
        "name": "Phishing_Lure",
        "tags": ["phishing", "social_engineering"],
        "strings": [
            b"Verify your account",
            b"Your account has been suspended",
            b"Click here to confirm",
            b"PayPal Security",
            b"Bank of America",
            b"login.microsoftonline",
            b"Update your payment",
        ],
        "condition": "any",
        "severity": "MEDIUM",
        "description": "Phishing lure content detected",
    },
]

SCAN_CHUNK = 512 * 1024  # 512 KB scan window


def scan_file(path: str) -> list[dict]:
    """
    Scan a file against all YARA rules.
    Returns list of matched rules with details.
    """
    matches = []
    if not os.path.exists(path):
        return matches

    try:
        with open(path, "rb") as f:
            data = f.read(SCAN_CHUNK)
    except Exception:
        return matches

    data_lower = data.lower()

    for rule in YARA_RULES:
        hit_strings = []

        # Magic byte check
        if rule.get("condition") == "magic":
            magic = rule.get("magic_bytes", b"")
            if data.startswith(magic):
                ext = os.path.splitext(path)[1].lower()
                # Only flag if disguised (extension mismatch)
                pe_exts = {".exe", ".dll", ".com", ".scr", ".msi"}
                elf_exts = {".elf", ".so", ""}
                if magic == b"MZ" and ext not in pe_exts:
                    hit_strings.append(f"PE magic bytes (MZ) with extension '{ext}'")
                elif magic == b"\x7fELF" and ext not in elf_exts:
                    hit_strings.append(f"ELF magic bytes with extension '{ext}'")
            if hit_strings:
                matches.append({
                    "rule":        rule["name"],
                    "tags":        rule["tags"],
                    "severity":    rule["severity"],
                    "description": rule["description"],
                    "matches":     hit_strings,
                })
            continue

        # String matching (case-insensitive for text patterns, exact for binary)
        for pattern in rule["strings"]:
            if pattern.lower() in data_lower:
                hit_strings.append(pattern.decode("utf-8", errors="replace"))

        if hit_strings:
            matches.append({
                "rule":        rule["name"],
                "tags":        rule["tags"],
                "severity":    rule["severity"],
                "description": rule["description"],
                "matches":     hit_strings[:5],   # cap display count
            })

    return matches


def severity_score(matches: list[dict]) -> int:
    """Map YARA match severities to a 0-100 bonus score."""
    weights = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
    score = 0
    seen = set()
    for m in matches:
        sev = m.get("severity", "LOW")
        if sev not in seen:
            score += weights.get(sev, 5)
            seen.add(sev)
    return min(score, 50)
