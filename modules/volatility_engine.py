# =============================================================================
#  modules/volatility_engine.py
#  Volatility-compatible Memory Forensics Engine
#
#  Architecture:
#   - If volatility3 is installed (pip install volatility3), uses it directly
#     via subprocess for full plugin support (pslist, netscan, malfind, etc.)
#   - If not installed, falls back to a pure-Python memory parser that reads
#     raw .mem/.vmem/.dmp/.raw files and extracts artefacts via structural
#     pattern matching — no external dependency required.
#
#  Supported plugins (both modes):
#    pslist      - running process list
#    netscan     - network connections + sockets
#    malfind     - injected code / suspicious VAD regions
#    cmdline     - process command line arguments
#    dlllist     - loaded DLLs per process
#    hashdump    - NTLM password hashes (SAM/SYSTEM hive)
#    strings     - printable strings + IOC extraction
#    filescan    - open file handles
#    svcscan     - Windows services
# =============================================================================

import os, re, struct, subprocess, json, time, shutil, tempfile

# ---------------------------------------------------------------------------
# Detect volatility3 installation
# ---------------------------------------------------------------------------
_VOL3_PATH = shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3")

def _has_vol3() -> bool:
    if _VOL3_PATH:
        return True
    try:
        r = subprocess.run(
            ["python3", "-m", "volatility3", "--help"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False

VOLATILITY3_AVAILABLE = _has_vol3()

# ---------------------------------------------------------------------------
# Suspicious patterns for pure-Python fallback parser
# ---------------------------------------------------------------------------
_PROC_NAMES_EVIL = {
    "mimikatz","meterpreter","nc.exe","ncat","netcat","pwdump",
    "wce.exe","fgdump","procdump","lsass","gsecdump","wceaux",
    "htran","lcx","socks4","socks5","rat","keylog","spyware",
    "cryptominer","xmrig","monero","claymore",
}
_SUSPICIOUS_CMD_PATTERNS = [
    r"powershell.*-[Ee]nc",
    r"cmd.*\/c.*del",
    r"net\s+user.*\/add",
    r"reg\s+add.*run",
    r"schtasks.*\/create",
    r"wscript.*\.vbs",
    r"mshta.*http",
    r"bitsadmin.*transfer",
    r"certutil.*-decode",
    r"rundll32.*javascript",
    r"regsvr32.*\/s.*\/n.*\/u.*\/i:http",
]
_COMPILED_CMD = [re.compile(p, re.IGNORECASE) for p in _SUSPICIOUS_CMD_PATTERNS]

_PE_MAGIC         = b"MZ"
_NT_MAGIC         = b"PE\x00\x00"
_SHELLCODE_NOPS   = b"\x90" * 16   # NOP sled
_SHELLCODE_COMMON = [b"\xfc\xe8\x82",b"\x31\xc0\x50",b"\x55\x8b\xec",
                     b"\x64\xa1\x30",b"\xeb\xfe",b"\xcc\xcc\xcc"]
_HASH_REGEX = re.compile(rb"[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}")
_IPV4_REGEX = re.compile(
    rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
_STRING_REGEX = re.compile(rb"[\x20-\x7e]{6,}")

# Known malicious port numbers
_EVIL_PORTS = {4444,4445,5555,31337,1337,8888,9999,6666,7777,
               2222,3333,65535,12345,54321,4321,1234,8080,8443}


# =============================================================================
#  PUBLIC API
# =============================================================================

def run_plugin(mem_path: str, plugin: str, profile: str = "") -> dict:
    """
    Run a Volatility plugin against a memory image.
    Returns {"plugin": str, "rows": [...], "summary": str, "alerts": [...]}
    """
    if not os.path.exists(mem_path):
        return _err(plugin, f"Memory file not found: {mem_path}")

    size_mb = os.path.getsize(mem_path) / 1024 / 1024
    if size_mb < 0.001:
        return _err(plugin, "Memory file is empty")

    if VOLATILITY3_AVAILABLE:
        return _vol3_plugin(mem_path, plugin, profile)
    else:
        return _fallback_plugin(mem_path, plugin)


def analyse_memory(mem_path: str, profile: str = "") -> dict:
    """
    Run all plugins and return aggregated result dict.
    """
    plugins = ["pslist","netscan","malfind","cmdline","hashdump",
               "strings","filescan","svcscan"]
    results  = {}
    all_alerts = []
    for pl in plugins:
        r = run_plugin(mem_path, pl, profile)
        results[pl]  = r
        all_alerts  += r.get("alerts", [])

    threat_score = min(len(all_alerts) * 8, 100)
    return {
        "plugins":      results,
        "alerts":       all_alerts,
        "threat_score": threat_score,
        "profile":      profile or "auto-detect",
        "file":         os.path.basename(mem_path),
        "size_mb":      round(os.path.getsize(mem_path) / 1024 / 1024, 2),
        "engine":       "volatility3" if VOLATILITY3_AVAILABLE else "built-in parser",
    }


# =============================================================================
#  Volatility3 subprocess backend
# =============================================================================

def _vol3_plugin(mem_path: str, plugin: str, profile: str) -> dict:
    plugin_map = {
        "pslist":   "windows.pslist.PsList",
        "netscan":  "windows.netstat.NetStat",
        "malfind":  "windows.malfind.Malfind",
        "cmdline":  "windows.cmdline.CmdLine",
        "dlllist":  "windows.dlllist.DllList",
        "hashdump": "windows.hashdump.Hashdump",
        "strings":  "windows.strings.Strings",
        "filescan": "windows.filescan.FileScan",
        "svcscan":  "windows.svcscan.SvcScan",
    }
    vol_plugin = plugin_map.get(plugin, f"windows.{plugin}.{plugin.capitalize()}")
    cmd = [
        "python3", "-m", "volatility3",
        "-f", mem_path,
        "--renderer", "json",
        vol_plugin,
    ]
    if profile:
        cmd += ["--profile", profile]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return _err(plugin, proc.stderr[:400])
        data   = json.loads(proc.stdout)
        rows   = data.get("rows", data) if isinstance(data, dict) else data
        alerts = _alert_check(plugin, rows)
        return {
            "plugin":  plugin,
            "rows":    rows[:200],
            "summary": f"{len(rows)} records from volatility3",
            "alerts":  alerts,
            "source":  "volatility3",
        }
    except subprocess.TimeoutExpired:
        return _err(plugin, "Volatility3 timed out (>120s)")
    except json.JSONDecodeError:
        return _err(plugin, "Failed to parse volatility3 JSON output")
    except Exception as e:
        return _err(plugin, str(e))


# =============================================================================
#  Pure-Python fallback memory parser
# =============================================================================

def _fallback_plugin(mem_path: str, plugin: str) -> dict:
    dispatch = {
        "pslist":   _parse_pslist,
        "netscan":  _parse_netscan,
        "malfind":  _parse_malfind,
        "cmdline":  _parse_cmdline,
        "dlllist":  _parse_dlllist,
        "hashdump": _parse_hashdump,
        "strings":  _parse_strings,
        "filescan": _parse_filescan,
        "svcscan":  _parse_svcscan,
    }
    fn = dispatch.get(plugin)
    if fn is None:
        return _err(plugin, f"Unknown plugin: {plugin}")
    try:
        return fn(mem_path)
    except Exception as e:
        return _err(plugin, f"Parser error: {e}")


def _read_chunk(path: str, offset: int = 0, size: int = 4 * 1024 * 1024) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def _read_strings(path: str, min_len: int = 6, max_mb: int = 8) -> list[str]:
    with open(path, "rb") as f:
        data = f.read(max_mb * 1024 * 1024)
    return [m.decode("ascii", "ignore")
            for m in _STRING_REGEX.findall(data)]


# --- pslist ---
def _parse_pslist(path: str) -> dict:
    data   = _read_chunk(path, size=8 * 1024 * 1024)
    strs   = _STRING_REGEX.findall(data)
    procs  = {}
    alerts = []

    exe_re = re.compile(rb"[\w\-]{1,32}\.exe", re.IGNORECASE)
    for m in exe_re.finditer(data):
        name = m.group().decode("ascii", "ignore").lower()
        procs[name] = procs.get(name, 0) + 1

    rows = [{"Process": n, "Count": c,
             "Suspicious": name.rstrip(".exe") in _PROC_NAMES_EVIL}
            for n, c in sorted(procs.items(), key=lambda x: -x[1])[:40]]

    for row in rows:
        if row["Suspicious"]:
            alerts.append(f"Suspicious process: {row['Process']}")

    return {"plugin": "pslist", "rows": rows,
            "summary": f"{len(rows)} process names extracted",
            "alerts": alerts, "source": "built-in parser"}


# --- netscan ---
def _parse_netscan(path: str) -> dict:
    data   = _read_chunk(path, size=8 * 1024 * 1024)
    ips    = list(set(_IPV4_REGEX.findall(data)))
    alerts = []

    # Filter RFC1918 / loopback
    public_ips = []
    for raw in ips:
        ip = raw.decode()
        if ip.startswith(("192.168.","10.","172.","127.","0.")): continue
        if all(c == "0" or c == "." for c in ip): continue
        public_ips.append(ip)

    # Port pattern scan
    port_re = re.compile(rb":(\d{1,5})\b")
    ports   = [int(m.group(1)) for m in port_re.finditer(data)
               if m.group(1).isdigit() and int(m.group(1)) < 65536]
    evil_p  = [p for p in set(ports) if p in _EVIL_PORTS]

    rows = [{"IP": ip, "Note": "Public IP found in memory"} for ip in public_ips[:30]]
    for p in evil_p[:10]:
        rows.append({"Port": p, "Note": "Known C2 / RAT port"})
        alerts.append(f"Evil port detected in memory: {p}")
    for ip in public_ips[:5]:
        alerts.append(f"External IP in memory: {ip}")

    return {"plugin": "netscan", "rows": rows,
            "summary": f"{len(public_ips)} public IPs, {len(evil_p)} suspicious ports",
            "alerts": alerts, "source": "built-in parser"}


# --- malfind ---
def _parse_malfind(path: str) -> dict:
    data   = _read_chunk(path, size=16 * 1024 * 1024)
    alerts = []
    rows   = []
    CHUNK  = 4096

    for offset in range(0, len(data) - CHUNK, CHUNK):
        block = data[offset: offset + CHUNK]

        # Hidden PE
        if block.startswith(_PE_MAGIC):
            pe_ok = _NT_MAGIC in block[:256]
            rows.append({
                "Offset":  hex(offset),
                "Type":    "Hidden PE Executable",
                "Detail":  "MZ header found in non-mapped region",
                "PE_Valid": pe_ok,
            })
            alerts.append(f"Hidden PE at offset {hex(offset)}")

        # NOP sled (shellcode)
        if _SHELLCODE_NOPS in block:
            rows.append({
                "Offset": hex(offset),
                "Type":   "Shellcode NOP Sled",
                "Detail": "16+ consecutive 0x90 NOP instructions",
            })
            alerts.append(f"NOP sled shellcode at {hex(offset)}")

        # Common shellcode stubs
        for sc in _SHELLCODE_COMMON:
            if sc in block:
                rows.append({
                    "Offset": hex(offset),
                    "Type":   "Shellcode Stub",
                    "Detail": f"Pattern: {sc.hex()}",
                })
                alerts.append(f"Shellcode pattern {sc.hex()} at {hex(offset)}")
                break

    rows = rows[:50]
    return {"plugin": "malfind", "rows": rows,
            "summary": f"{len(rows)} suspicious memory regions",
            "alerts": alerts[:20], "source": "built-in parser"}


# --- cmdline ---
def _parse_cmdline(path: str) -> dict:
    strs   = _read_strings(path)
    alerts = []
    rows   = []
    seen   = set()

    for s in strs:
        if len(s) < 10 or s in seen: continue
        for pat in _COMPILED_CMD:
            if pat.search(s):
                seen.add(s)
                rows.append({"CommandLine": s[:200], "Suspicious": True})
                alerts.append(f"Suspicious command: {s[:100]}")
                break

    return {"plugin": "cmdline", "rows": rows[:30],
            "summary": f"{len(rows)} suspicious command lines",
            "alerts": alerts[:20], "source": "built-in parser"}


# --- dlllist ---
def _parse_dlllist(path: str) -> dict:
    data   = _read_chunk(path, size=8 * 1024 * 1024)
    dll_re = re.compile(rb"[\w\\\-\.]{4,60}\.dll", re.IGNORECASE)
    dlls   = list(set(m.group().decode("ascii","ignore")
                      for m in dll_re.finditer(data)))
    alerts = []

    suspicious_dlls = ["injected","unknown","temp","appdata",
                       "\\users\\","hollowed","hook","syringe"]
    rows = []
    for d in dlls[:60]:
        susp = any(s in d.lower() for s in suspicious_dlls)
        rows.append({"DLL": d, "Suspicious": susp})
        if susp:
            alerts.append(f"Suspicious DLL path: {d}")

    return {"plugin": "dlllist", "rows": rows,
            "summary": f"{len(rows)} DLL references extracted",
            "alerts": alerts, "source": "built-in parser"}


# --- hashdump ---
def _parse_hashdump(path: str) -> dict:
    data   = _read_chunk(path, size=8 * 1024 * 1024)
    hashes = _HASH_REGEX.findall(data)
    rows   = [{"Hash": h.decode("ascii","ignore"), "Type": "NTLM"} for h in hashes[:30]]
    alerts = [f"NTLM hash found: {h.decode('ascii','ignore')[:32]}…" for h in hashes[:5]]

    return {"plugin": "hashdump", "rows": rows,
            "summary": f"{len(rows)} NTLM hashes found",
            "alerts": alerts, "source": "built-in parser"}


# --- strings ---
def _parse_strings(path: str) -> dict:
    strs    = _read_strings(path)
    ioc_re  = re.compile(
        r"https?://[\w\-\.]+(?:/[\w\-\./?=&%#]*)?|"
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|"
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
    )
    iocs   = []
    alerts = []
    seen   = set()
    for s in strs:
        for m in ioc_re.finditer(s):
            v = m.group()
            if v not in seen and len(v) > 8:
                seen.add(v)
                kind = ("URL" if v.startswith("http") else
                        "Email" if "@" in v else "IP")
                iocs.append({"Value": v, "Type": kind})
                if kind == "URL" and any(b in v for b in ["pastebin","ngrok","dyndns","no-ip"]):
                    alerts.append(f"Suspicious {kind}: {v}")

    return {"plugin": "strings", "rows": iocs[:60],
            "summary": f"{len(iocs)} IOCs extracted from strings",
            "alerts": alerts[:20], "source": "built-in parser"}


# --- filescan ---
def _parse_filescan(path: str) -> dict:
    strs    = _read_strings(path)
    file_re = re.compile(r"[A-Za-z]:\\[\w\\ \-\.]{4,120}")
    files   = list(set(m.group() for s in strs for m in file_re.finditer(s)))
    alerts  = []

    suspicious_paths = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp",
                        "\\users\\public\\","\\windows\\temp\\"]
    rows = []
    for f in files[:60]:
        susp = any(s in f.lower() for s in suspicious_paths)
        rows.append({"Path": f, "Suspicious": susp})
        if susp:
            alerts.append(f"Suspicious file path: {f}")

    return {"plugin": "filescan", "rows": rows,
            "summary": f"{len(rows)} file paths found",
            "alerts": alerts, "source": "built-in parser"}


# --- svcscan ---
def _parse_svcscan(path: str) -> dict:
    strs     = _read_strings(path)
    svc_re   = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{3,30}(?:svc|service|daemon|agent)", re.IGNORECASE)
    services = list(set(m.group() for s in strs for m in svc_re.finditer(s)))
    alerts   = []

    evil_svc = ["meterpreter","nc","netcat","ratservice","backdoor","malware",
                "cryptominer","keylogger","spyware","injector"]
    rows = []
    for svc in services[:40]:
        susp = any(e in svc.lower() for e in evil_svc)
        rows.append({"Service": svc, "Suspicious": susp})
        if susp:
            alerts.append(f"Suspicious service: {svc}")

    return {"plugin": "svcscan", "rows": rows,
            "summary": f"{len(rows)} service names found",
            "alerts": alerts, "source": "built-in parser"}


# =============================================================================
#  Helpers
# =============================================================================

def _err(plugin: str, msg: str) -> dict:
    return {"plugin": plugin, "rows": [], "summary": msg,
            "alerts": [], "source": "error", "error": msg}


def _alert_check(plugin: str, rows: list) -> list:
    alerts = []
    for row in rows:
        row_str = str(row).lower()
        if plugin == "malfind" or "injected" in row_str:
            alerts.append(f"[malfind] Suspicious region: {str(row)[:80]}")
        if plugin == "netscan":
            for raw_port in re.findall(r"\b(\d{4,5})\b", row_str):
                if int(raw_port) in _EVIL_PORTS:
                    alerts.append(f"Evil port in netscan: {raw_port}")
    return alerts[:20]


def supported_formats() -> list[str]:
    return [".mem", ".vmem", ".dmp", ".raw", ".bin", ".img", ".lime"]


def is_memory_image(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in supported_formats():
        return True
    # Check first 4 bytes for LiME or raw memory markers
    try:
        with open(path, "rb") as f:
            hdr = f.read(4)
        return hdr == b"EMiL" or (hdr[:2] != b"\x4d\x5a" and len(hdr) == 4)
    except Exception:
        return False
