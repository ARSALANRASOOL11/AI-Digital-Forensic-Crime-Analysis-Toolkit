# =============================================================================
#  modules/siem_integration.py  — SIEM Integration
#
#  Wazuh, Elastic Security, Security Onion, Sigma Rules
#  Sends alerts and evidence findings to connected SIEM platforms.
#  Generates Sigma rules from detected patterns.
# =============================================================================

import os, json, time, re, urllib.request, urllib.error, hashlib, base64

# ---------------------------------------------------------------------------
# Configuration from environment variables
# ---------------------------------------------------------------------------
WAZUH_HOST    = os.environ.get("WAZUH_HOST",    "https://localhost:55000")
WAZUH_USER    = os.environ.get("WAZUH_USER",    "wazuh")
WAZUH_PASS    = os.environ.get("WAZUH_PASS",    "")
ELASTIC_HOST  = os.environ.get("ELASTIC_HOST",  "http://localhost:9200")
ELASTIC_USER  = os.environ.get("ELASTIC_USER",  "")
ELASTIC_PASS  = os.environ.get("ELASTIC_PASS",  "")
ELASTIC_INDEX = os.environ.get("ELASTIC_INDEX", "cfis-forensics")
SIEM_TIMEOUT  = 8

# ---------------------------------------------------------------------------
# Sigma rule templates per crime type
# ---------------------------------------------------------------------------
SIGMA_TEMPLATES = {
    "Ransomware": {
        "title":       "Ransomware Activity Detected",
        "description": "Ransomware indicators found in forensic evidence",
        "status":      "experimental",
        "level":       "critical",
        "tags":        ["attack.impact","attack.t1486"],
        "detection": {
            "keywords": ["ransom","decrypt","bitcoin","YOUR_FILES","DECRYPT_INSTRUCTIONS"],
            "condition": "keywords"
        }
    },
    "Remote Access Trojan": {
        "title":       "Remote Access Trojan (RAT) Detected",
        "status":      "experimental",
        "level":       "high",
        "tags":        ["attack.command_and_control","attack.t1071"],
        "detection": {
            "keywords": ["meterpreter","reverse_shell","CreateRemoteThread","VirtualAllocEx"],
            "condition": "keywords"
        }
    },
    "Phishing": {
        "title":       "Phishing Content Detected",
        "status":      "experimental",
        "level":       "high",
        "tags":        ["attack.initial_access","attack.t1566"],
        "detection": {
            "keywords": ["verify your account","suspended","Click here","PayPal Security"],
            "condition": "keywords"
        }
    },
    "Credential Theft": {
        "title":       "Credential Theft Tool Detected",
        "status":      "experimental",
        "level":       "critical",
        "tags":        ["attack.credential_access","attack.t1003"],
        "detection": {
            "keywords": ["mimikatz","sekurlsa","lsass","Pass-the-Hash","NTLM"],
            "condition": "keywords"
        }
    },
    "Web Attack / Exploit": {
        "title":       "Web Attack Payload Detected",
        "status":      "experimental",
        "level":       "high",
        "tags":        ["attack.initial_access","attack.t1190"],
        "detection": {
            "keywords": ["UNION SELECT","DROP TABLE","<script>alert","../../etc/passwd","Log4Shell"],
            "condition": "keywords"
        }
    },
    "Anti-Forensics": {
        "title":       "Anti-Forensics Activity Detected",
        "status":      "experimental",
        "level":       "high",
        "tags":        ["attack.defense_evasion","attack.t1070"],
        "detection": {
            "keywords": ["wevtutil cl","cipher /w","vssadmin delete","shred -u","DBAN"],
            "condition": "keywords"
        }
    },
}


def _http_post(url: str, data: dict, headers: dict, timeout: int = SIEM_TIMEOUT) -> dict:
    try:
        payload = json.dumps(data).encode()
        req     = urllib.request.Request(url, data=payload,
                                          headers={"Content-Type":"application/json", **headers},
                                          method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"success": True, "status": r.status,
                    "response": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _http_get(url: str, headers: dict, timeout: int = SIEM_TIMEOUT) -> dict:
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"success": True, "data": json.loads(r.read().decode())}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
#  Wazuh Integration
# =============================================================================

def wazuh_status() -> dict:
    if not WAZUH_PASS:
        return {"connected": False, "message": "Set WAZUH_HOST, WAZUH_USER, WAZUH_PASS env vars"}
    creds   = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}
    result  = _http_get(f"{WAZUH_HOST}/", headers)
    if result["success"]:
        return {"connected": True, "host": WAZUH_HOST,
                "data": result.get("data", {})}
    return {"connected": False, "error": result.get("error")}


def wazuh_send_alert(event: dict) -> dict:
    """Send a custom alert to Wazuh manager via API."""
    if not WAZUH_PASS:
        return {"success": False, "error": "Wazuh not configured"}
    creds   = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}
    payload = {
        "level":    event.get("severity_level", 10),
        "description": event.get("description", ""),
        "rule": {
            "id":       event.get("rule_id", "100001"),
            "level":    event.get("severity_level", 10),
            "description": event.get("description", ""),
            "groups":   ["forensic_toolkit"],
        },
        "agent": {"id": "000", "name": "CFIS-Forensic"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime()),
    }
    return _http_post(f"{WAZUH_HOST}/events", payload, headers)


# =============================================================================
#  Elastic Security Integration
# =============================================================================

def elastic_status() -> dict:
    if not ELASTIC_HOST:
        return {"connected": False, "message": "Set ELASTIC_HOST env var"}
    headers = {}
    if ELASTIC_USER and ELASTIC_PASS:
        creds   = base64.b64encode(f"{ELASTIC_USER}:{ELASTIC_PASS}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}"}
    result = _http_get(f"{ELASTIC_HOST}/_cluster/health", headers)
    if result["success"]:
        data = result.get("data", {})
        return {"connected": True, "host": ELASTIC_HOST,
                "cluster": data.get("cluster_name",""),
                "status":  data.get("status","")}
    return {"connected": False, "error": result.get("error")}


def elastic_index_evidence(evidence: dict) -> dict:
    """Index a forensic evidence record into Elasticsearch."""
    headers = {"Content-Type": "application/json"}
    if ELASTIC_USER and ELASTIC_PASS:
        creds   = base64.b64encode(f"{ELASTIC_USER}:{ELASTIC_PASS}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    doc_id  = hashlib.md5(f"{evidence.get('case_id','')}{evidence.get('filename','')}".encode()).hexdigest()
    payload = {
        "@timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": {
            "kind":     "event",
            "category": "file",
            "type":     "info",
            "module":   "cfis_forensics",
        },
        "file": {
            "name":   evidence.get("filename",""),
            "hash":   {"sha256": evidence.get("hash","")},
            "size":   evidence.get("size", 0),
        },
        "cfis": {
            "case_id":    evidence.get("case_id",""),
            "crime_type": evidence.get("crime_type",""),
            "risk_level": evidence.get("risk_level",""),
            "risk_score": evidence.get("risk_score", 0),
            "yara_hits":  evidence.get("yara_hits", 0),
            "integrity":  evidence.get("integrity",""),
        },
        "threat": {
            "indicator": {
                "type":        "file",
                "description": evidence.get("crime_type",""),
            }
        },
        "tags": ["cfis", "forensics", evidence.get("crime_type","").lower().replace(" ","_")],
    }

    url = f"{ELASTIC_HOST}/{ELASTIC_INDEX}/_doc/{doc_id}"
    try:
        data    = json.dumps(payload).encode()
        req     = urllib.request.Request(url, data=data, headers=headers, method="PUT")
        with urllib.request.urlopen(req, timeout=SIEM_TIMEOUT) as r:
            return {"success": True, "doc_id": doc_id, "index": ELASTIC_INDEX}
    except Exception as e:
        return {"success": False, "error": str(e)}


def elastic_index_all(evidence_rows: list) -> dict:
    """Bulk-index all evidence into Elasticsearch."""
    success_count = 0
    errors        = []
    for row in evidence_rows:
        ev = {
            "case_id":    row[1],
            "filename":   row[2],
            "hash":       row[4] if len(row) > 4 else "",
            "crime_type": row[6] if len(row) > 6 else "Unknown",
        }
        r = elastic_index_evidence(ev)
        if r.get("success"):
            success_count += 1
        else:
            errors.append(r.get("error",""))
    return {"success": success_count, "errors": errors[:5],
            "total": len(evidence_rows)}


# =============================================================================
#  Sigma Rule Generator
# =============================================================================

def generate_sigma_rule(crime_type: str, evidence: dict) -> str:
    """Generate a Sigma rule YAML from detected crime type and evidence."""
    template = SIGMA_TEMPLATES.get(crime_type, {
        "title":       f"Malicious Activity: {crime_type}",
        "description": f"Indicators of {crime_type} detected in forensic evidence",
        "status":      "experimental",
        "level":       "high",
        "tags":        ["attack.unknown"],
        "detection":   {
            "keywords": [crime_type.lower()],
            "condition": "keywords"
        }
    })

    iocs = evidence.get("iocs", {})
    kws  = template["detection"].get("keywords", [])

    # Enrich with actual IOC values
    for url in iocs.get("urls", [])[:3]:
        kws.append(url.get("value","")[:60])
    for ip in iocs.get("ipv4", [])[:3]:
        if not ip.get("private"):
            kws.append(ip.get("value",""))

    kws = [k for k in kws if k][:15]

    filename = evidence.get("filename", "unknown")
    case_id  = evidence.get("case_id", "CASE-0000")
    ts       = time.strftime("%Y/%m/%d")

    rule = f"""title: {template['title']}
id: {hashlib.md5(crime_type.encode()).hexdigest()[:8]}-{case_id}
status: {template['status']}
description: |
    {template.get('description', '')}
    Generated from: {filename} (Case: {case_id})
author: CFIS Forensic Toolkit
date: {ts}
references:
    - https://attack.mitre.org
tags:
"""
    for tag in template.get("tags", []):
        rule += f"    - {tag}\n"

    rule += f"""logsource:
    category: file_event
    product: windows
detection:
    keywords:
"""
    for kw in kws:
        rule += f"        - '{kw}'\n"

    rule += f"""    condition: keywords
level: {template['level']}
falsepositives:
    - Legitimate security research
    - Penetration testing
fields:
    - FileName
    - CommandLine
    - ParentCommandLine
"""
    return rule


def generate_all_sigma_rules(evidence_rows: list) -> list:
    """Generate Sigma rules for all evidence with detected crime types."""
    from modules.crime_classifier import classify
    rules = []
    for row in evidence_rows:
        name  = row[2]
        path  = row[3]
        cid   = row[1]
        crime = row[6] if len(row) > 6 else ""

        if not crime or crime in ("Unknown","Unclassified"):
            if os.path.exists(path):
                try:
                    result = classify(path)
                    crime  = result.get("predicted_crime","Unknown Malware")
                except Exception:
                    continue

        if crime and crime in SIGMA_TEMPLATES:
            rule = generate_sigma_rule(crime, {"filename": name, "case_id": cid, "iocs": {}})
            rules.append({
                "filename": name,
                "case_id":  cid,
                "crime":    crime,
                "rule":     rule,
            })
    return rules


def siem_status_all() -> dict:
    """Check connection status of all SIEM integrations."""
    return {
        "wazuh":   wazuh_status(),
        "elastic": elastic_status(),
        "configured": {
            "wazuh":   bool(WAZUH_PASS),
            "elastic": bool(ELASTIC_HOST),
        }
    }
