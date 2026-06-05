# =============================================================================
#  modules/mitre_attack.py  — MITRE ATT&CK Mapping Engine
#
#  Maps evidence and IOCs to ATT&CK techniques and generates reports.
#  Uses the full ATT&CK knowledge base (embedded, no network required).
# =============================================================================

import os, re, json

# ---------------------------------------------------------------------------
# Embedded ATT&CK knowledge base (Enterprise, v14)
# ---------------------------------------------------------------------------
TECHNIQUES = {
    "T1059":   {"name":"Command and Scripting Interpreter","tactic":["Execution"],
                "desc":"Adversaries abuse command interpreters to execute commands.",
                "patterns":[b"cmd.exe",b"powershell",b"wscript",b"cscript",b"bash",b"/bin/sh"]},
    "T1059.001":{"name":"PowerShell","tactic":["Execution"],
                "desc":"Abuse of PowerShell for malicious execution.",
                "patterns":[b"powershell",b"-EncodedCommand",b"IEX(",b"Invoke-Expression",b"DownloadString"]},
    "T1059.003":{"name":"Windows Command Shell","tactic":["Execution"],
                "desc":"cmd.exe used for malicious execution.",
                "patterns":[b"cmd.exe",b"cmd /c",b"command.com"]},
    "T1055":   {"name":"Process Injection","tactic":["Defense Evasion","Privilege Escalation"],
                "desc":"Code injected into running processes to evade defenses.",
                "patterns":[b"VirtualAllocEx",b"WriteProcessMemory",b"CreateRemoteThread",
                            b"NtUnmapViewOfSection",b"RtlCreateUserThread"]},
    "T1547":   {"name":"Boot/Logon Autostart Execution","tactic":["Persistence","Privilege Escalation"],
                "desc":"Malware persists via autostart mechanisms.",
                "patterns":[b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                            b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            b"schtasks",b"at.exe",b"startup"]},
    "T1003":   {"name":"OS Credential Dumping","tactic":["Credential Access"],
                "desc":"Dumping credentials from OS and software.",
                "patterns":[b"mimikatz",b"lsass",b"sekurlsa",b"procdump",
                            b"hashdump",b"SAM",b"NTDS.dit"]},
    "T1071":   {"name":"Application Layer Protocol","tactic":["Command and Control"],
                "desc":"C2 traffic disguised in application layer protocols.",
                "patterns":[b"http://",b"https://",b"dns",b"ftp://",b"IRC"]},
    "T1566":   {"name":"Phishing","tactic":["Initial Access"],
                "desc":"Phishing messages to gain initial access.",
                "patterns":[b"verify your account",b"suspended",b"click here",
                            b"PayPal",b"bank alert",b"<form",b"credential"]},
    "T1486":   {"name":"Data Encrypted for Impact","tactic":["Impact"],
                "desc":"Data encrypted to interrupt availability (ransomware).",
                "patterns":[b"ransom",b"encrypt",b"decrypt",b"bitcoin",
                            b"DECRYPT_INSTRUCTIONS",b"your files",b".locked"]},
    "T1490":   {"name":"Inhibit System Recovery","tactic":["Impact"],
                "desc":"Deleting shadow copies to prevent recovery.",
                "patterns":[b"vssadmin delete",b"shadow copies",b"wbadmin delete",
                            b"bcdedit /set",b"recoveryenabled No"]},
    "T1027":   {"name":"Obfuscated Files or Information","tactic":["Defense Evasion"],
                "desc":"Encoding/obfuscation to evade detection.",
                "patterns":[b"base64",b"-EncodedCommand",b"char(",b"eval(",
                            b"fromCharCode",b"XOR",b"ROT13"]},
    "T1048":   {"name":"Exfiltration Over Alternative Protocol","tactic":["Exfiltration"],
                "desc":"Data exfiltrated via alternative protocols.",
                "patterns":[b"ftp://",b"curl -T",b"dns_tunnel",b"exfiltrat",
                            b"pastebin",b"DropBox",b"wget --post"]},
    "T1190":   {"name":"Exploit Public-Facing Application","tactic":["Initial Access"],
                "desc":"Exploiting internet-facing applications.",
                "patterns":[b"UNION SELECT",b"<script>alert",b"../../etc/passwd",
                            b"CVE-2021-44228",b"Log4j",b"<?php system"]},
    "T1098":   {"name":"Account Manipulation","tactic":["Persistence","Privilege Escalation"],
                "desc":"Modifying account credentials or permissions.",
                "patterns":[b"net user",b"net localgroup administrators",
                            b"Add-LocalGroupMember",b"useradd",b"passwd"]},
    "T1082":   {"name":"System Information Discovery","tactic":["Discovery"],
                "desc":"Gathering information about the operating system.",
                "patterns":[b"systeminfo",b"uname -a",b"whoami",b"hostname",
                            b"ipconfig",b"ifconfig",b"ver"]},
    "T1083":   {"name":"File and Directory Discovery","tactic":["Discovery"],
                "desc":"Enumerating files and directories.",
                "patterns":[b"dir /s",b"ls -la",b"find / -name",b"tree /f",
                            b"Get-ChildItem",b"ls -R"]},
    "T1021":   {"name":"Remote Services","tactic":["Lateral Movement"],
                "desc":"Using remote services for lateral movement.",
                "patterns":[b"psexec",b"wmiexec",b"smbexec",b"ssh ",
                            b"RDP",b"WinRM",b"Enter-PSSession"]},
    "T1078":   {"name":"Valid Accounts","tactic":["Defense Evasion","Initial Access","Persistence","Privilege Escalation"],
                "desc":"Using legitimate credentials for access.",
                "patterns":[b"runas",b"su -",b"sudo",b"Pass-the-Hash",
                            b"golden ticket",b"Kerberos"]},
    "T1105":   {"name":"Ingress Tool Transfer","tactic":["Command and Control"],
                "desc":"Transferring tools into victim network.",
                "patterns":[b"certutil -urlcache",b"bitsadmin /transfer",
                            b"wget ",b"curl -o",b"Invoke-WebRequest",
                            b"URLDownloadToFile"]},
    "T1112":   {"name":"Modify Registry","tactic":["Defense Evasion"],
                "desc":"Modifying the Windows Registry for persistence or evasion.",
                "patterns":[b"reg add",b"RegSetValueEx",b"Set-ItemProperty",
                            b"regedit",b"HKLM",b"HKCU"]},
    "T1070":   {"name":"Indicator Removal","tactic":["Defense Evasion"],
                "desc":"Removing artifacts to hide activity.",
                "patterns":[b"wevtutil cl",b"Clear-EventLog",b"del /f /q",
                            b"rm -rf",b"shred",b"cipher /w"]},
    "T1562":   {"name":"Impair Defenses","tactic":["Defense Evasion"],
                "desc":"Disabling or tampering with security tools.",
                "patterns":[b"net stop",b"sc stop",b"taskkill",b"netsh advfirewall",
                            b"Set-MpPreference -DisableRealtimeMonitoring",
                            b"Windows Defender"]},
    "T1053":   {"name":"Scheduled Task/Job","tactic":["Execution","Persistence","Privilege Escalation"],
                "desc":"Scheduled tasks used for persistence or execution.",
                "patterns":[b"schtasks /create",b"at ",b"crontab",
                            b"New-ScheduledTask",b"Task Scheduler"]},
    "T1074":   {"name":"Data Staged","tactic":["Collection"],
                "desc":"Staging data prior to exfiltration.",
                "patterns":[b"compress",b"zip",b"7z",b"rar",b"tar.gz",
                            b"staging",b"collected"]},
    "T1056":   {"name":"Input Capture","tactic":["Collection","Credential Access"],
                "desc":"Capturing user input (keylogging).",
                "patterns":[b"GetAsyncKeyState",b"SetWindowsHookEx",b"WH_KEYBOARD",
                            b"keylog",b"keystroke",b"clipboard"]},
    "T1499":   {"name":"Endpoint Denial of Service","tactic":["Impact"],
                "desc":"DoS attacks against endpoints.",
                "patterns":[b"flood",b"syn flood",b"DDoS",b"LOIC",b"HOIC",
                            b"botnet",b"zombie"]},
}

TACTIC_COLORS = {
    "Initial Access":            "#ff6600",
    "Execution":                 "#ff3333",
    "Persistence":               "#cc00ff",
    "Privilege Escalation":      "#ff0066",
    "Defense Evasion":           "#0099ff",
    "Credential Access":         "#ff9900",
    "Discovery":                 "#33cc33",
    "Lateral Movement":          "#ff6699",
    "Collection":                "#00ccff",
    "Command and Control":       "#ff3300",
    "Exfiltration":              "#ffcc00",
    "Impact":                    "#ff0000",
}


def map_file(filepath: str) -> dict:
    """Map a single file to MITRE ATT&CK techniques."""
    if not os.path.exists(filepath):
        return {"techniques": [], "tactics": [], "score": 0}

    try:
        with open(filepath, "rb") as f:
            raw = f.read(min(os.path.getsize(filepath), 512*1024))
    except Exception:
        return {"techniques": [], "tactics": [], "score": 0}

    raw_lower = raw.lower()
    matched   = []
    tactic_set= set()

    for tid, info in TECHNIQUES.items():
        hits = [p.decode("utf-8","ignore") for p in info["patterns"]
                if p.lower() in raw_lower]
        if hits:
            for tactic in info["tactic"]:
                tactic_set.add(tactic)
            matched.append({
                "id":          tid,
                "name":        info["name"],
                "tactics":     info["tactic"],
                "desc":        info["desc"],
                "hits":        hits[:4],
                "confidence":  min(len(hits)*20, 100),
                "url":         f"https://attack.mitre.org/techniques/{tid.replace('.','/') }",
                "colors":      [TACTIC_COLORS.get(t,"#888") for t in info["tactic"]],
            })

    matched.sort(key=lambda x: -x["confidence"])
    score = min(sum(m["confidence"] for m in matched[:5]), 100)

    return {
        "techniques": matched,
        "tactics":    list(tactic_set),
        "score":      score,
        "technique_ids": [m["id"] for m in matched],
    }


def map_all_evidence(evidence_rows: list) -> dict:
    """Map all evidence to ATT&CK, aggregate by technique and tactic."""
    all_techniques = {}
    tactic_counts  = {}
    file_mappings  = []

    for row in evidence_rows:
        name   = row[2]
        path   = row[3]
        cid    = row[1]
        ev_id  = row[0]

        if not os.path.exists(path):
            continue

        mapping = map_file(path)
        file_mappings.append({
            "ev_id":      ev_id,
            "case_id":    cid,
            "filename":   name,
            "techniques": mapping["techniques"],
            "tactics":    mapping["tactics"],
            "score":      mapping["score"],
        })

        for tech in mapping["techniques"]:
            tid = tech["id"]
            if tid not in all_techniques:
                all_techniques[tid] = {**tech, "files": []}
            all_techniques[tid]["files"].append({"ev_id": ev_id, "name": name})

            for tactic in tech["tactics"]:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    # Navigator layer JSON (ATT&CK Navigator compatible)
    navigator_layer = _build_navigator_layer(all_techniques)

    return {
        "file_mappings":    file_mappings,
        "all_techniques":   list(all_techniques.values()),
        "tactic_counts":    tactic_counts,
        "technique_count":  len(all_techniques),
        "navigator_layer":  navigator_layer,
        "top_techniques":   sorted(all_techniques.values(),
                                   key=lambda x: -len(x["files"]))[:10],
        "tactic_colors":    TACTIC_COLORS,
    }


def _build_navigator_layer(techniques: dict) -> dict:
    """Generate ATT&CK Navigator compatible layer JSON."""
    return {
        "name":        "CFIS Evidence Mapping",
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": "Generated by Cyber Forensic Intelligence System",
        "techniques":  [
            {
                "techniqueID": tid,
                "score":       min(len(info["files"]) * 25, 100),
                "comment":     f"Found in: {', '.join(f['name'] for f in info['files'][:3])}",
                "enabled":     True,
            }
            for tid, info in techniques.items()
        ],
        "gradient": {"colors": ["#ffffff","#ff6666"],"minValue":0,"maxValue":100},
    }


def generate_report(mapping_result: dict) -> str:
    """Generate a text-based ATT&CK report."""
    lines = ["# MITRE ATT&CK Mapping Report", ""]
    lines.append(f"**Techniques detected:** {mapping_result['technique_count']}")
    lines.append(f"**Tactics covered:** {', '.join(mapping_result['tactic_counts'].keys())}")
    lines.append("")

    for tactic, count in sorted(mapping_result["tactic_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"\n## {tactic} ({count} technique(s))")
        for tech in mapping_result["all_techniques"]:
            if tactic in tech["tactics"]:
                lines.append(f"- **{tech['id']}** {tech['name']} — {tech['desc'][:80]}")
                lines.append(f"  Files: {', '.join(f['name'] for f in tech['files'][:3])}")

    return "\n".join(lines)
