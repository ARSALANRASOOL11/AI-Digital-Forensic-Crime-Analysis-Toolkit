# =============================================================================
#  modules/virustotal.py  — VirusTotal v3 API integration
#  Set VIRUSTOTAL_API_KEY in environment or app config to enable live lookups.
# =============================================================================

import os, json, hashlib, urllib.request, urllib.error, time

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE    = "https://www.virustotal.com/api/v3"
TIMEOUT    = 10


def _vt_request(endpoint: str) -> dict:
    """Make an authenticated GET request to the VT API."""
    if not VT_API_KEY:
        return {"error": "No API key configured. Set VIRUSTOTAL_API_KEY environment variable."}
    url = VT_BASE + endpoint
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def lookup_hash(file_hash: str) -> dict:
    """
    Look up a SHA-256 hash on VirusTotal.
    Returns normalised result dict.
    """
    raw = _vt_request(f"/files/{file_hash}")
    if "error" in raw:
        return raw

    try:
        attr  = raw["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        names = attr.get("meaningful_name", "Unknown")
        sig   = attr.get("signature_info", {}).get("description", "")
        vdict = attr.get("last_analysis_results", {})

        # Collect detecting engines
        detections = [
            {"engine": eng, "result": info.get("result",""), "category": info.get("category","")}
            for eng, info in vdict.items()
            if info.get("category") in ("malicious","suspicious")
        ]

        return {
            "found":          True,
            "name":           names,
            "signature":      sig,
            "malicious":      stats.get("malicious", 0),
            "suspicious":     stats.get("suspicious", 0),
            "undetected":     stats.get("undetected", 0),
            "harmless":       stats.get("harmless", 0),
            "total_engines":  sum(stats.values()),
            "detections":     detections[:10],
            "reputation":     attr.get("reputation", 0),
            "threat_label":   attr.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", ""),
            "tags":           attr.get("tags", []),
            "permalink":      f"https://www.virustotal.com/gui/file/{file_hash}",
            "scan_date":      attr.get("last_analysis_date", ""),
        }
    except (KeyError, TypeError) as e:
        return {"error": f"Unexpected API response: {e}", "raw": str(raw)[:200]}


def lookup_url(url_str: str) -> dict:
    """URL reputation lookup via VirusTotal."""
    import base64
    url_id = base64.urlsafe_b64encode(url_str.encode()).decode().rstrip("=")
    raw = _vt_request(f"/urls/{url_id}")
    if "error" in raw:
        return raw
    try:
        attr  = raw["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        return {
            "found":       True,
            "url":         url_str,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "undetected":  stats.get("undetected", 0),
            "harmless":    stats.get("harmless", 0),
            "reputation":  attr.get("reputation", 0),
            "permalink":   f"https://www.virustotal.com/gui/url/{url_id}",
        }
    except Exception as e:
        return {"error": str(e)}


def format_vt_summary(result: dict) -> str:
    """Return a human-readable one-liner for dashboard/report use."""
    if "error" in result:
        return f"VT: {result['error']}"
    if not result.get("found"):
        return "VT: Not found in database"
    mal = result.get("malicious", 0)
    sus = result.get("suspicious", 0)
    tot = result.get("total_engines", 0)
    lbl = result.get("threat_label", "")
    if mal > 0:
        return f"VT: {mal}/{tot} engines flagged malicious" + (f" [{lbl}]" if lbl else "")
    if sus > 0:
        return f"VT: {sus}/{tot} engines flagged suspicious"
    return f"VT: Clean ({tot} engines)"
