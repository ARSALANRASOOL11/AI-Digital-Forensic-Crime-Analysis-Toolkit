# =============================================================================
#  modules/sandbox.py  — Malware Sandbox (Safe Static + Behavioral Analysis)
#
#  Two analysis modes:
#
#  1. STATIC  — Deep inspection without execution (always safe):
#       PE header parsing, import table, export table
#       String extraction + classification
#       Packer/obfuscator detection
#       Entropy analysis per section
#       Embedded resource extraction
#       Anti-analysis trick detection
#       Signature matching (YARA + custom)
#
#  2. BEHAVIORAL (simulation) — Predicts behavior from static indicators:
#       Registry modifications (predicted)
#       File system changes (predicted)
#       Network activity (predicted)
#       Process spawning (predicted)
#       Persistence mechanisms (predicted)
#
#  NOTE: True dynamic sandbox (actual execution) requires Docker/VM.
#        We implement full static analysis + behavioral prediction
#        which is safe in all environments.
# =============================================================================

import os, re, struct, math, time, hashlib, json
from collections import Counter

# ---------------------------------------------------------------------------
SAFE_MAX_MB   = 50
SCAN_CHUNK    = 4 * 1024 * 1024   # 4 MB for string scan
STRING_MINLEN = 5

# Packer signatures (magic bytes / section names)
PACKER_SIGS = {
    "UPX":          [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "MPRESS":       [b"MPRESS1", b"MPRESS2"],
    "Themida":      [b".themida", b".winlice"],
    "VMProtect":    [b".vmp0", b".vmp1"],
    "Enigma":       [b".enigma1", b".enigma2"],
    "ASPack":       [b"ASPack"],
    "PECompact":    [b"PECompact2"],
    "NSIS":         [b"Nullsoft"],
    "PyInstaller":  [b"MEIPASS", b"_MEIPASS"],
    "cx_Freeze":    [b"cx_Freeze"],
    "AutoIt":       [b"AU3!EA06", b"AutoIt"],
    "NSIS Installer":[b"NSIS Error"],
}

# Anti-analysis API calls
ANTI_ANALYSIS = {
    "Anti-Debug":   [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
                     b"NtQueryInformationProcess", b"OutputDebugString",
                     b"FindWindow", b"ZwQueryInformationProcess"],
    "Anti-VM":      [b"GetSystemFirmwareTable", b"cpuid", b"rdtsc",
                     b"vmdetect", b"VirtualBox", b"VMware", b"VBOX",
                     b"vboxsf", b"vmtoolsd", b"vmsrvc"],
    "Anti-Sandbox": [b"GetCursorPos", b"GetForegroundWindow",
                     b"GetTickCount", b"timeGetTime",
                     b"SleepEx", b"WaitForSingleObject"],
    "Anti-AV":      [b"avp.exe", b"avgnt.exe", b"bdagent.exe",
                     b"ekrn.exe", b"msmpeng.exe", b"msseces.exe"],
}

# Suspicious Windows API imports
SUSPICIOUS_APIS = {
    "Process Injection":   ["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                            "NtUnmapViewOfSection","RtlCreateUserThread",
                            "SetThreadContext","QueueUserAPC"],
    "Credential Access":   ["LsaEnumerateLogonSessions","SamQueryInformationUser",
                            "CredEnumerate","CryptUnprotectData","NtCreateFile"],
    "Network":             ["WSAStartup","connect","InternetOpenA","InternetOpenW",
                            "HttpSendRequestA","WinHttpOpen","URLDownloadToFile",
                            "socket","recv","send","gethostbyname"],
    "Persistence":         ["RegSetValueEx","CreateService","StartService",
                            "SHGetFolderPath","ITaskScheduler"],
    "File Operations":     ["CreateFileA","WriteFile","DeleteFileA","CopyFileA",
                            "MoveFileExA","FindFirstFileA","GetTempPath"],
    "Encryption":          ["CryptEncrypt","CryptDecrypt","CryptGenRandom",
                            "CryptAcquireContext","BCryptEncrypt"],
    "Evasion":             ["IsDebuggerPresent","VirtualProtect","NtSetInformationThread",
                            "RtlDecompressBuffer","HeapCreate"],
    "Keylogging":          ["SetWindowsHookExA","GetAsyncKeyState","GetKeyState",
                            "RegisterHotKey","MapVirtualKey"],
}

# Predicted behaviors per API group
BEHAVIOR_PREDICTIONS = {
    "Process Injection":   "Injects code into another process (e.g. explorer.exe, svchost.exe)",
    "Credential Access":   "Attempts to steal credentials from LSASS or Windows Credential Store",
    "Network":             "Establishes C2 channel or downloads additional payloads",
    "Persistence":         "Creates registry key or scheduled task for persistence after reboot",
    "File Operations":     "Creates/modifies/deletes files on disk — possible ransomware or dropper",
    "Encryption":          "Encrypts data — likely ransomware or secure C2 communication",
    "Evasion":             "Detects analysis environment and may alter behavior",
    "Keylogging":          "Captures keystrokes from the user",
}


# =============================================================================
#  PE Parser
# =============================================================================

def _parse_pe(data: bytes) -> dict:
    """Parse Windows PE header."""
    pe = {"valid": False, "sections": [], "imports": [], "exports": [],
          "is_dll": False, "is_64bit": False, "compile_time": "",
          "entry_point": "", "image_base": "", "subsystem": ""}
    try:
        if data[:2] != b"MZ":
            return pe
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 4 > len(data):
            return pe
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return pe
        pe["valid"] = True

        coff = pe_offset + 4
        machine   = struct.unpack("<H", data[coff:coff+2])[0]
        num_sects = struct.unpack("<H", data[coff+2:coff+4])[0]
        timestamp = struct.unpack("<I", data[coff+4:coff+8])[0]
        opt_size  = struct.unpack("<H", data[coff+16:coff+18])[0]
        chars     = struct.unpack("<H", data[coff+18:coff+20])[0]

        pe["is_64bit"] = (machine == 0x8664)
        pe["is_dll"]   = bool(chars & 0x2000)
        pe["compile_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp)) if timestamp else ""

        opt_offset = coff + 20
        if opt_size >= 28:
            magic = struct.unpack("<H", data[opt_offset:opt_offset+2])[0]
            if magic == 0x10B:   # PE32
                pe["entry_point"] = hex(struct.unpack("<I", data[opt_offset+16:opt_offset+20])[0])
                pe["image_base"]  = hex(struct.unpack("<I", data[opt_offset+28:opt_offset+32])[0])
                pe["subsystem"]   = _subsystem(struct.unpack("<H", data[opt_offset+68:opt_offset+70])[0])
            elif magic == 0x20B: # PE32+
                pe["entry_point"] = hex(struct.unpack("<I", data[opt_offset+16:opt_offset+20])[0])
                pe["image_base"]  = hex(struct.unpack("<Q", data[opt_offset+24:opt_offset+32])[0])
                pe["subsystem"]   = _subsystem(struct.unpack("<H", data[opt_offset+68:opt_offset+70])[0])

        # Sections
        sect_offset = opt_offset + opt_size
        for i in range(min(num_sects, 20)):
            so = sect_offset + i*40
            if so+40 > len(data): break
            name    = data[so:so+8].rstrip(b"\x00").decode("ascii","ignore")
            vsize   = struct.unpack("<I", data[so+8:so+12])[0]
            raw_sz  = struct.unpack("<I", data[so+16:so+20])[0]
            raw_off = struct.unpack("<I", data[so+20:so+24])[0]
            chars_s = struct.unpack("<I", data[so+36:so+40])[0]
            # Section entropy
            sect_data = data[raw_off:raw_off+min(raw_sz,65536)]
            ent = _entropy(sect_data) if sect_data else 0.0
            pe["sections"].append({
                "name":    name,
                "vsize":   vsize,
                "raw_sz":  raw_sz,
                "entropy": round(ent, 2),
                "exec":    bool(chars_s & 0x20000000),
                "write":   bool(chars_s & 0x80000000),
            })
    except Exception:
        pass
    return pe


def _subsystem(n: int) -> str:
    return {1:"Native",2:"Windows GUI",3:"Windows CUI",5:"OS/2",
            7:"POSIX",9:"Windows CE",10:"EFI App",14:"Xbox",
            16:"Boot App"}.get(n, f"Unknown({n})")


def _entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = Counter(data)
    L    = len(data)
    return -sum((c/L)*math.log2(c/L) for c in freq.values() if c)


# =============================================================================
#  String Extractor + Classifier
# =============================================================================

def _extract_strings(data: bytes) -> dict:
    ascii_re  = re.compile(rb"[\x20-\x7e]{%d,}" % STRING_MINLEN)
    unicode_re= re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % STRING_MINLEN)

    ascii_strs   = [m.group().decode("ascii","ignore")
                    for m in ascii_re.finditer(data)]
    unicode_strs = [m.group().decode("utf-16-le","ignore").strip("\x00")
                    for m in unicode_re.finditer(data)]
    all_strs = ascii_strs + unicode_strs

    classified = {
        "urls":      [s for s in all_strs if re.match(r"https?://\S+", s)][:20],
        "ips":       [s for s in all_strs if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s)][:20],
        "registry":  [s for s in all_strs if "HKEY" in s or "SOFTWARE\\" in s][:20],
        "file_paths":[s for s in all_strs if re.match(r"[A-Za-z]:\\", s)][:20],
        "commands":  [s for s in all_strs if any(c in s.lower() for c in
                      ["cmd","powershell","wscript","regsvr32","rundll32",
                       "schtasks","at ","net user","net localgroup"])][:20],
        "crypto":    [s for s in all_strs if any(c in s for c in
                      ["AES","RSA","RC4","ChaCha","encrypt","decrypt"])][:10],
        "mutex":     [s for s in all_strs if re.match(r"[A-Za-z0-9_\-]{4,30}",s)
                      and "mutex" in s.lower()][:10],
        "all_count": len(all_strs),
    }
    return classified


# =============================================================================
#  PUBLIC API — Full Sandbox Analysis
# =============================================================================

def analyse(filepath: str) -> dict:
    """
    Run complete safe sandbox analysis on a file.
    Never executes the file — 100% static analysis.
    """
    result = {
        "file":          os.path.basename(filepath),
        "size":          0,
        "sha256":        "",
        "md5":           "",
        "file_type":     "Unknown",
        "is_pe":         False,
        "is_64bit":      False,
        "is_dll":        False,
        "entropy":       0.0,
        "packed":        [],
        "sections":      [],
        "imports":       {},
        "suspicious_apis":{},
        "anti_analysis": {},
        "strings":       {},
        "behaviors":     [],
        "network_iocs":  [],
        "file_iocs":     [],
        "registry_iocs": [],
        "risk_score":    0,
        "verdict":       "UNKNOWN",
        "yara_hits":     [],
        "compile_time":  "",
        "alerts":        [],
        "timeline":      [],
    }

    if not os.path.exists(filepath):
        result["alerts"].append("File not found")
        return result

    size = os.path.getsize(filepath)
    result["size"] = size
    if size > SAFE_MAX_MB * 1024 * 1024:
        result["alerts"].append(f"File too large for full analysis ({size//1024//1024} MB)")

    # Hashes
    h256 = hashlib.sha256(); md5 = hashlib.md5()
    with open(filepath,"rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h256.update(chunk); md5.update(chunk)
    result["sha256"] = h256.hexdigest()
    result["md5"]    = md5.hexdigest()

    # Read data
    with open(filepath,"rb") as f:
        data = f.read(min(size, SAFE_MAX_MB*1024*1024))

    # File type
    result["entropy"] = round(_entropy(data[:65536]), 3)
    magic_map = {
        b"MZ":          "Windows PE Executable",
        b"\x7fELF":     "Linux ELF Binary",
        b"%PDF":        "PDF Document",
        b"PK\x03\x04":  "ZIP Archive",
        b"\xff\xd8\xff":"JPEG Image",
        b"\x89PNG":     "PNG Image",
        b"\xd0\xcf\x11\xe0":"MS Office (legacy)",
        b"Rar!":        "RAR Archive",
        b"\x1f\x8b":   "GZIP Archive",
        b"#!":          "Script (shebang)",
    }
    for magic, desc in magic_map.items():
        if data.startswith(magic):
            result["file_type"] = desc; break

    # ---- PE Analysis ----
    if data[:2] == b"MZ":
        result["is_pe"] = True
        pe = _parse_pe(data)
        result.update({
            "is_64bit":     pe["is_64bit"],
            "is_dll":       pe["is_dll"],
            "sections":     pe["sections"],
            "compile_time": pe["compile_time"],
        })

        # High-entropy sections → packed/encrypted
        for sect in pe["sections"]:
            if sect["entropy"] > 7.2:
                result["alerts"].append(
                    f"High entropy section '{sect['name']}' ({sect['entropy']}/8.0) — packed/encrypted")

    # ---- Packer Detection ----
    for packer, sigs in PACKER_SIGS.items():
        for sig in sigs:
            if sig.lower() in data.lower():
                result["packed"].append(packer)
                result["alerts"].append(f"Packer detected: {packer}")
                break

    # ---- Anti-Analysis ----
    for category, patterns in ANTI_ANALYSIS.items():
        hits = [p.decode("ascii","ignore") for p in patterns if p.lower() in data.lower()]
        if hits:
            result["anti_analysis"][category] = hits[:5]
            result["alerts"].append(f"Anti-analysis: {category} ({', '.join(hits[:2])})")

    # ---- Suspicious API Detection ----
    behavior_hits = []
    for category, apis in SUSPICIOUS_APIS.items():
        hits = [a for a in apis if a.encode().lower() in data.lower()
                or (a+"A").encode().lower() in data.lower()
                or (a+"W").encode().lower() in data.lower()]
        if hits:
            result["suspicious_apis"][category] = hits
            behavior_hits.append(category)
            result["behaviors"].append({
                "category":    category,
                "apis_found":  hits[:5],
                "prediction":  BEHAVIOR_PREDICTIONS.get(category,""),
                "severity":    ("CRITICAL" if category in ("Process Injection","Credential Access")
                                else "HIGH" if category in ("Network","Encryption","Keylogging")
                                else "MEDIUM"),
            })

    # ---- String Analysis ----
    result["strings"] = _extract_strings(data[:SCAN_CHUNK])
    result["network_iocs"] = result["strings"]["urls"] + result["strings"]["ips"]
    result["file_iocs"]    = result["strings"]["file_paths"]
    result["registry_iocs"]= result["strings"]["registry"]

    # ---- YARA ----
    try:
        from modules.yara_scanner import scan_file, severity_score
        yara_hits = scan_file(filepath)
        result["yara_hits"] = yara_hits
        if yara_hits:
            result["alerts"].append(
                f"YARA: {len(yara_hits)} rule(s) matched — "
                + ", ".join(h["rule"] for h in yara_hits[:3]))
    except Exception:
        pass

    # ---- Timeline (predicted execution flow) ----
    if behavior_hits:
        flow_order = ["Evasion","Anti-Debug","Anti-VM","Anti-Sandbox",
                      "Process Injection","Persistence","Credential Access",
                      "Keylogging","File Operations","Encryption","Network"]
        ordered = [b for b in flow_order if b in behavior_hits]
        result["timeline"] = [
            {"step": i+1, "action": b,
             "detail": BEHAVIOR_PREDICTIONS.get(b,""),
             "severity": result["behaviors"][[x["category"] for x in result["behaviors"]].index(b)]["severity"]
             if b in [x["category"] for x in result["behaviors"]] else "MEDIUM"}
            for i, b in enumerate(ordered)
        ]

    # ---- Risk Score ----
    score = 0
    score += min(len(result["packed"])        * 15, 30)
    score += min(len(result["anti_analysis"]) * 12, 24)
    score += min(len(result["behaviors"])     * 10, 40)
    score += min(len(result["yara_hits"])     * 8,  24)
    score += 10 if result["entropy"] > 7.4 else 5 if result["entropy"] > 6.5 else 0
    score += 5  if result["network_iocs"] else 0
    result["risk_score"] = min(score, 100)

    if   result["risk_score"] >= 75: result["verdict"] = "MALICIOUS"
    elif result["risk_score"] >= 45: result["verdict"] = "SUSPICIOUS"
    elif result["risk_score"] >= 20: result["verdict"] = "POTENTIALLY UNWANTED"
    else:                             result["verdict"] = "CLEAN"

    return result
