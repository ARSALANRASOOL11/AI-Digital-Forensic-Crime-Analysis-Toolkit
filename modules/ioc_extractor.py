# =============================================================================
#  modules/ioc_extractor.py
#  Indicator of Compromise (IOC) Extraction Engine
#
#  Extracts from any file (binary, text, PDF, Office, log, email, PCAP):
#    - IPv4 / IPv6 addresses
#    - Domain names / FQDNs
#    - URLs (HTTP/HTTPS/FTP/etc.)
#    - Email addresses
#    - File hashes (MD5 / SHA1 / SHA256 / SHA512)
#    - Windows registry keys
#    - File paths (Windows & Unix)
#    - CVE identifiers
#    - MITRE ATT&CK technique IDs
#    - Bitcoin / Monero addresses
#    - Mutex names
#    - User-Agent strings
#    - Base64-encoded blobs
#    - Encoded PowerShell commands
#
#  For each IOC, adds:
#    - Context snippet (surrounding text)
#    - Defang (safe display) version
#    - Confidence score
#    - Threat classification
# =============================================================================

import re, os, struct, base64, hashlib

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# IP addresses
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)

# Domains  (eTLD check via common TLD list)
_COMMON_TLDS = (
    r"(?:com|net|org|io|gov|mil|edu|int|info|biz|co|uk|de|ru|cn|"
    r"onion|su|cc|pw|xyz|top|club|site|live|online|shop|app|dev)"
)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9\-]{1,63}\.)+?" + _COMMON_TLDS + r"\b",
    re.IGNORECASE
)

# URLs
_URL = re.compile(
    r"(?:https?|ftp|ftps|sftp|smb|ldap|ldaps|irc|ircs|xmpp)://"
    r"[\w\-\.@:/?=&%#+~!$\'()*,;]+",
    re.IGNORECASE
)

# Email
_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Hashes
_MD5    = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_SHA1   = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
_SHA512 = re.compile(r"\b[A-Fa-f0-9]{128}\b")

# Registry keys
_REGKEY = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
    r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKU|HKCR)"
    r"(?:\\[\w\- .{}()]+)+",
    re.IGNORECASE
)

# File paths
_WIN_PATH  = re.compile(r"[A-Za-z]:\\(?:[\w\- .{}()+,;@#$]+\\)*[\w\- .{}()+,;@#$]*")
_UNIX_PATH = re.compile(r"(?:^|[\s\"'])(/(?:[\w\-\.]+/)*[\w\-\.]+)(?=[\s\"']|$)", re.MULTILINE)

# CVE
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# MITRE ATT&CK
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Crypto addresses
_BTC     = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BC1 = re.compile(r"\bbc1[a-z0-9]{39,59}\b")
_XMR     = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Mutex (common patterns from malware)
_MUTEX = re.compile(
    r"(?:CreateMutex|OpenMutex|mutex_name|mutant)[\s\(\"\']+([A-Za-z0-9_\-]{4,40})",
    re.IGNORECASE
)

# User-Agent
_UA = re.compile(
    r"User-Agent:\s*([^\r\n]{10,200})",
    re.IGNORECASE
)

# Base64 blobs (long, high-density)
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2})")

# PowerShell encoded command
_PS_ENC = re.compile(
    r"-[Ee](?:nc(?:odedCommand)?)?[\s]+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE
)

# Suspicious IPs (private ranges excluded from general results)
_PRIVATE_NETS = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|255\.)"
)
_EVIL_PORTS = {4444,4445,5555,31337,1337,8888,9999,6666,7777,2222,
               3333,65535,12345,54321,4321,1234}

# Suspicious TLDs often abused for C2
_EVIL_TLDS = {"onion","su","cc","pw","top","xyz","ru","tk","ml","ga","cf","gq"}

# Common file types embedded in strings
_EMBEDDED_EXT = re.compile(
    r"[\w\-\.]{2,40}\.(?:exe|dll|bat|vbs|ps1|scr|com|pif|hta|lnk|msi|cmd|reg)",
    re.IGNORECASE
)


# =============================================================================
#  Public API
# =============================================================================

def extract_iocs(filepath: str, max_read_mb: int = 20) -> dict:
    """
    Main extraction function. Reads up to max_read_mb of the file
    and returns categorised IOCs with metadata.
    """
    if not os.path.exists(filepath):
        return _empty()

    # Read raw bytes and decode as text (best-effort)
    max_bytes = max_read_mb * 1024 * 1024
    try:
        with open(filepath, "rb") as f:
            raw = f.read(max_bytes)
    except Exception:
        return _empty()

    # Decode: try UTF-8, then latin-1
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    iocs = {
        "ipv4":         _extract_ipv4(text),
        "ipv6":         _extract_ipv6(text),
        "domains":      _extract_domains(text),
        "urls":         _extract_urls(text),
        "emails":       _extract_emails(text),
        "md5":          _extract_hashes(text, _MD5,    "MD5"),
        "sha1":         _extract_hashes(text, _SHA1,   "SHA-1"),
        "sha256":       _extract_hashes(text, _SHA256, "SHA-256"),
        "sha512":       _extract_hashes(text, _SHA512, "SHA-512"),
        "registry_keys":_extract_regex(text, _REGKEY,  "Registry Key"),
        "win_paths":    _extract_regex(text, _WIN_PATH,  "Win Path"),
        "unix_paths":   _extract_regex(text, _UNIX_PATH, "Unix Path"),
        "cves":         _extract_regex(text, _CVE,       "CVE"),
        "attack_ttps":  _extract_attack(text),
        "bitcoin":      _extract_regex(text, _BTC,     "Bitcoin"),
        "monero":       _extract_regex(text, _XMR,     "Monero"),
        "mutexes":      _extract_mutex(text),
        "user_agents":  _extract_ua(text),
        "base64_blobs": _extract_b64(text),
        "ps_encoded":   _extract_ps_enc(text),
        "embedded_exes":_extract_regex(text, _EMBEDDED_EXT, "Embedded EXE ref"),
    }

    # Compute stats
    total = sum(len(v) for v in iocs.values())
    high_confidence = sum(
        1 for lst in iocs.values() for item in lst
        if item.get("confidence","") in ("HIGH","CRITICAL")
    )
    threat_score = min(
        len(iocs["urls"]) * 5 +
        len(iocs["ipv4"]) * 3 +
        len(iocs["sha256"]) * 8 +
        len(iocs["cves"]) * 10 +
        len(iocs["attack_ttps"]) * 12 +
        len(iocs["ps_encoded"]) * 15 +
        len(iocs["embedded_exes"]) * 8,
        100
    )

    alerts = _generate_alerts(iocs)

    return {
        "total_iocs":       total,
        "high_confidence":  high_confidence,
        "threat_score":     threat_score,
        "alerts":           alerts,
        "iocs":             iocs,
        "file":             os.path.basename(filepath),
        "bytes_read":       len(raw),
    }


# =============================================================================
#  Extractors
# =============================================================================

def _defang_ip(ip: str)  -> str: return ip.replace(".", "[.]")
def _defang_url(url: str)-> str: return url.replace(".", "[.]").replace("://", "[://]")
def _defang_dom(d: str)  -> str: return d.replace(".", "[.]")

def _ctx(text: str, start: int, end: int, w: int = 30) -> str:
    """Return surrounding context snippet."""
    s = max(0, start - w)
    e = min(len(text), end + w)
    return text[s:e].replace("\n"," ").replace("\r","")[:80]


def _extract_ipv4(text: str) -> list:
    seen, result = set(), []
    for m in _IPV4.finditer(text):
        ip = m.group()
        if ip in seen: continue
        seen.add(ip)
        private = bool(_PRIVATE_NETS.match(ip))
        conf    = "LOW" if private else "HIGH"
        evil    = False
        for port in _EVIL_PORTS:
            if f":{port}" in text[max(0,m.start()-5):m.end()+10]:
                evil = True; conf = "CRITICAL"
        result.append({
            "value":    ip,
            "defanged": _defang_ip(ip),
            "private":  private,
            "evil_port":evil,
            "confidence": conf,
            "context":  _ctx(text, m.start(), m.end()),
        })
    return result[:60]


def _extract_ipv6(text: str) -> list:
    seen, result = set(), []
    for m in _IPV6.finditer(text):
        v = m.group()
        if v in seen or len(v) < 7: continue
        seen.add(v)
        result.append({"value":v, "confidence":"MEDIUM",
                       "context":_ctx(text,m.start(),m.end())})
    return result[:20]


def _extract_domains(text: str) -> list:
    seen, result = set(), []
    for m in _DOMAIN.finditer(text):
        d = m.group().lower()
        if d in seen or len(d) < 4: continue
        seen.add(d)
        tld  = d.rsplit(".",1)[-1]
        evil = tld in _EVIL_TLDS
        conf = "CRITICAL" if ".onion" in d else "HIGH" if evil else "MEDIUM"
        result.append({
            "value":    d,
            "defanged": _defang_dom(d),
            "tld":      tld,
            "evil_tld": evil,
            "confidence": conf,
            "context":  _ctx(text, m.start(), m.end()),
        })
    return result[:60]


def _extract_urls(text: str) -> list:
    seen, result = set(), []
    for m in _URL.finditer(text):
        u = m.group()
        if u in seen: continue
        seen.add(u)
        evil  = any(b in u for b in ["pastebin","ngrok","dyndns","no-ip","bit.ly",
                                      "tinyurl",".onion","filebin","transfer.sh"])
        conf  = "CRITICAL" if ".onion" in u else "HIGH" if evil else "MEDIUM"
        result.append({
            "value":    u[:200],
            "defanged": _defang_url(u[:200]),
            "suspicious":evil,
            "confidence": conf,
            "context":  _ctx(text,m.start(),m.end()),
        })
    return result[:40]


def _extract_emails(text: str) -> list:
    seen, result = set(), []
    for m in _EMAIL.finditer(text):
        e = m.group().lower()
        if e in seen: continue
        seen.add(e)
        conf = "HIGH" if any(b in e for b in ["protonmail","tutanota","guerrilla","temp-mail"]) else "MEDIUM"
        result.append({"value":e,"confidence":conf,
                       "context":_ctx(text,m.start(),m.end())})
    return result[:30]


def _extract_hashes(text: str, pattern: re.Pattern, hash_type: str) -> list:
    seen, result = set(), []
    for m in pattern.finditer(text):
        h = m.group().lower()
        if h in seen: continue
        seen.add(h)
        # Sanity check: skip all-zero, all-f, sequential
        if len(set(h)) < 4: continue
        result.append({
            "value":    h,
            "type":     hash_type,
            "confidence":"HIGH",
            "context":  _ctx(text,m.start(),m.end()),
        })
    return result[:30]


def _extract_regex(text: str, pattern: re.Pattern, label: str) -> list:
    seen, result = set(), []
    for m in pattern.finditer(text):
        g = m.group(1) if m.lastindex else m.group()
        if not g or g in seen or len(g) < 3: continue
        seen.add(g)
        result.append({
            "value":    g[:200],
            "type":     label,
            "confidence":"MEDIUM",
            "context":  _ctx(text,m.start(),m.end()),
        })
    return result[:30]


def _extract_attack(text: str) -> list:
    """Extract MITRE ATT&CK TTP IDs with tactic lookup."""
    TACTIC_MAP = {
        "T1059":"Execution / Command Scripting",
        "T1053":"Scheduled Task/Job",
        "T1547":"Boot/Logon Autostart",
        "T1003":"OS Credential Dumping",
        "T1021":"Remote Services",
        "T1071":"Application Layer Protocol (C2)",
        "T1566":"Phishing",
        "T1190":"Exploit Public-Facing Application",
        "T1027":"Obfuscated Files or Information",
        "T1078":"Valid Accounts",
        "T1083":"File and Directory Discovery",
        "T1082":"System Information Discovery",
        "T1055":"Process Injection",
        "T1574":"Hijack Execution Flow",
        "T1486":"Data Encrypted for Impact (Ransomware)",
        "T1490":"Inhibit System Recovery",
        "T1048":"Exfiltration Over Alternative Protocol",
        "T1041":"Exfiltration Over C2 Channel",
    }
    seen, result = set(), []
    for m in _ATTACK.finditer(text):
        ttp = m.group().upper()
        if ttp in seen: continue
        seen.add(ttp)
        base = ttp.split(".")[0]
        result.append({
            "value":    ttp,
            "tactic":   TACTIC_MAP.get(base, "Unknown Technique"),
            "confidence":"HIGH",
            "url":      f"https://attack.mitre.org/techniques/{ttp.replace('.','/')}",
            "context":  _ctx(text,m.start(),m.end()),
        })
    return result[:20]


def _extract_mutex(text: str) -> list:
    seen, result = set(), []
    for m in _MUTEX.finditer(text):
        name = m.group(1)
        if name in seen: continue
        seen.add(name)
        result.append({"value":name,"type":"Mutex","confidence":"HIGH",
                       "context":_ctx(text,m.start(),m.end())})
    return result[:20]


def _extract_ua(text: str) -> list:
    result = []
    for m in _UA.finditer(text):
        ua = m.group(1).strip()
        if len(ua) < 10: continue
        evil = any(b in ua for b in ["python-requests","curl","wget","nikto","sqlmap",
                                      "masscan","nmap","metasploit","go-http"])
        result.append({
            "value":    ua[:200],
            "suspicious":evil,
            "confidence":"HIGH" if evil else "LOW",
            "context":  _ctx(text,m.start(),m.end()),
        })
    return result[:15]


def _extract_b64(text: str) -> list:
    result = []
    seen   = set()
    for m in _B64.finditer(text):
        blob = m.group()
        if blob in seen or len(blob) < 60: continue
        seen.add(blob)
        # Try to decode and check if meaningful
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8","ignore")
            preview = decoded[:80]
            sus = any(kw in decoded.lower() for kw in
                      ["powershell","cmd","exec","shell","eval","system","invoke",
                       "download","http","iex","mimikatz"])
            result.append({
                "value":    blob[:80] + ("…" if len(blob)>80 else ""),
                "decoded_preview": preview,
                "suspicious": sus,
                "confidence": "CRITICAL" if sus else "MEDIUM",
                "context":  _ctx(text,m.start(),m.end()),
            })
        except Exception:
            pass
        if len(result) >= 10:
            break
    return result


def _extract_ps_enc(text: str) -> list:
    result = []
    for m in _PS_ENC.finditer(text):
        blob = m.group(1)
        try:
            decoded_bytes = base64.b64decode(blob + "==")
            # PowerShell uses UTF-16LE
            try:
                decoded = decoded_bytes.decode("utf-16-le","ignore")
            except Exception:
                decoded = decoded_bytes.decode("utf-8","ignore")
            result.append({
                "value":      blob[:60] + "…",
                "decoded":    decoded[:200],
                "confidence": "CRITICAL",
                "context":    _ctx(text, m.start(), m.end()),
            })
        except Exception:
            result.append({
                "value":      blob[:60],
                "decoded":    "[decode failed]",
                "confidence": "HIGH",
                "context":    _ctx(text,m.start(),m.end()),
            })
        if len(result) >= 5:
            break
    return result


# =============================================================================
#  Alert generation
# =============================================================================

def _generate_alerts(iocs: dict) -> list:
    alerts = []

    if iocs["ps_encoded"]:
        alerts.append(f"CRITICAL: {len(iocs['ps_encoded'])} encoded PowerShell command(s) found")

    if iocs["attack_ttps"]:
        ttps = [i["value"] for i in iocs["attack_ttps"]]
        alerts.append(f"HIGH: MITRE ATT&CK TTPs: {', '.join(ttps[:5])}")

    evil_domains = [i["value"] for i in iocs["domains"] if i.get("evil_tld")]
    if evil_domains:
        alerts.append(f"HIGH: Suspicious TLD domains: {', '.join(evil_domains[:3])}")

    onion = [i["value"] for i in iocs["urls"] if ".onion" in i["value"]]
    if onion:
        alerts.append(f"CRITICAL: Tor .onion URLs found: {onion[0][:50]}")

    evil_ips = [i["value"] for i in iocs["ipv4"] if i.get("evil_port")]
    if evil_ips:
        alerts.append(f"HIGH: IPs on C2/RAT ports: {', '.join(evil_ips[:3])}")

    if iocs["cves"]:
        cves = [i["value"] for i in iocs["cves"]]
        alerts.append(f"MEDIUM: CVE references: {', '.join(cves[:4])}")

    crypto = iocs["bitcoin"] + iocs["monero"]
    if crypto:
        alerts.append(f"HIGH: Cryptocurrency addresses ({len(crypto)}) — possible ransomware/miner")

    sus_b64 = [i for i in iocs["base64_blobs"] if i.get("suspicious")]
    if sus_b64:
        alerts.append(f"HIGH: {len(sus_b64)} suspicious Base64 payload(s) decoded")

    if iocs["sha256"]:
        alerts.append(f"INFO: {len(iocs['sha256'])} SHA-256 hashes extracted — recommend VT lookup")

    return alerts[:20]


def _empty() -> dict:
    empty_iocs = {k: [] for k in [
        "ipv4","ipv6","domains","urls","emails","md5","sha1","sha256","sha512",
        "registry_keys","win_paths","unix_paths","cves","attack_ttps","bitcoin",
        "monero","mutexes","user_agents","base64_blobs","ps_encoded","embedded_exes",
    ]}
    return {"total_iocs":0,"high_confidence":0,"threat_score":0,
            "alerts":[],"iocs":empty_iocs,"file":"","bytes_read":0}


def ioc_summary(result: dict) -> str:
    """One-liner for dashboard display."""
    t = result.get("total_iocs", 0)
    s = result.get("threat_score", 0)
    a = len(result.get("alerts", []))
    return f"{t} IOCs extracted | Score: {s}/100 | {a} alert(s)"
