# =============================================================================
#  modules/threat_intel.py
#  Multi-Source Threat Intelligence Aggregator
#
#  Supported APIs (all free-tier friendly):
#    1. VirusTotal v3      — file hash, URL, IP, domain reputation
#    2. AbuseIPDB          — IP abuse confidence + reports
#    3. Shodan             — internet-exposed host info (banners, vulns, ports)
#    4. OTX AlienVault     — threat indicators, pulses, CVE cross-refs
#    5. MalwareBazaar      — malware hash lookup (SHA256/MD5/SHA1)
#    6. URLhaus            — malicious URL/host database
#    7. ThreatFox          — IOC lookup (IPs, domains, URLs, hashes)
#    8. GreyNoise          — internet scanner / noise classification
#
#  Configuration:
#    Set env vars before starting the app:
#      VIRUSTOTAL_API_KEY
#      ABUSEIPDB_API_KEY
#      SHODAN_API_KEY
#      OTX_API_KEY
#      (MalwareBazaar, URLhaus, ThreatFox are free, no key required)
#      GREYNOISE_API_KEY   (community key works)
# =============================================================================

import os, json, urllib.request, urllib.parse, urllib.error, time, hashlib

# ---------------------------------------------------------------------------
# API keys from environment
# ---------------------------------------------------------------------------
_KEYS = {
    "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", ""),
    "abuseipdb":  os.environ.get("ABUSEIPDB_API_KEY",  ""),
    "shodan":     os.environ.get("SHODAN_API_KEY",      ""),
    "otx":        os.environ.get("OTX_API_KEY",         ""),
    "greynoise":  os.environ.get("GREYNOISE_API_KEY",   ""),
}
TIMEOUT = 8

# Severity thresholds
ABUSE_HIGH_THRESHOLD   = 25   # AbuseIPDB confidence %
VT_MALICIOUS_THRESHOLD = 3    # minimum detection count
OTX_PULSE_THRESHOLD    = 1


# =============================================================================
#  Generic HTTP helpers
# =============================================================================

def _get(url: str, headers: dict = None, timeout: int = TIMEOUT) -> dict | None:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_reason": e.reason}
    except Exception as e:
        return {"_error": str(e)}


def _post_json(url: str, payload: dict, headers: dict = None) -> dict | None:
    try:
        data = json.dumps(payload).encode()
        h    = {"Content-Type":"application/json", **(headers or {})}
        req  = urllib.request.Request(url, data=data, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        return {"_error": str(e)}


def _b64url(s: str) -> str:
    import base64
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


# =============================================================================
#  1. VirusTotal
# =============================================================================

def virustotal_hash(file_hash: str) -> dict:
    key = _KEYS["virustotal"]
    if not key:
        return _no_key("virustotal")
    raw = _get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
               {"x-apikey": key})
    if not raw or "_error" in raw or "_http_error" in raw:
        return _err("virustotal", raw)
    try:
        attr  = raw["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        tot   = sum(stats.values())
        dets  = [
            {"engine": k, "result": v.get("result",""), "category": v.get("category","")}
            for k, v in attr.get("last_analysis_results",{}).items()
            if v.get("category") in ("malicious","suspicious")
        ]
        return {
            "source":       "virustotal",
            "found":        True,
            "malicious":    mal,
            "suspicious":   sus,
            "harmless":     stats.get("harmless",0),
            "total_engines":tot,
            "detections":   dets[:10],
            "threat_label": attr.get("popular_threat_classification",{})
                                .get("suggested_threat_label",""),
            "reputation":   attr.get("reputation",0),
            "tags":         attr.get("tags",[]),
            "permalink":    f"https://www.virustotal.com/gui/file/{file_hash}",
            "severity":     "CRITICAL" if mal >= 10 else "HIGH" if mal >= VT_MALICIOUS_THRESHOLD else "LOW",
        }
    except (KeyError, TypeError):
        return _err("virustotal", raw)


def virustotal_ip(ip: str) -> dict:
    key = _KEYS["virustotal"]
    if not key:
        return _no_key("virustotal")
    raw = _get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
               {"x-apikey": key})
    if not raw or "_http_error" in raw:
        return _err("virustotal", raw)
    try:
        attr  = raw["data"]["attributes"]
        stats = attr.get("last_analysis_stats",{})
        return {
            "source":    "virustotal",
            "type":      "ip",
            "ip":        ip,
            "malicious": stats.get("malicious",0),
            "harmless":  stats.get("harmless",0),
            "country":   attr.get("country",""),
            "asn":       attr.get("asn",""),
            "owner":     attr.get("as_owner",""),
            "reputation":attr.get("reputation",0),
            "severity":  "HIGH" if stats.get("malicious",0) >= VT_MALICIOUS_THRESHOLD else "LOW",
        }
    except (KeyError, TypeError):
        return _err("virustotal", raw)


def virustotal_url(url_str: str) -> dict:
    key = _KEYS["virustotal"]
    if not key:
        return _no_key("virustotal")
    url_id = _b64url(url_str)
    raw = _get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
               {"x-apikey": key})
    if not raw or "_http_error" in raw:
        return _err("virustotal", raw)
    try:
        attr  = raw["data"]["attributes"]
        stats = attr.get("last_analysis_stats",{})
        return {
            "source":    "virustotal",
            "type":      "url",
            "url":       url_str,
            "malicious": stats.get("malicious",0),
            "harmless":  stats.get("harmless",0),
            "reputation":attr.get("reputation",0),
            "severity":  "HIGH" if stats.get("malicious",0) >= VT_MALICIOUS_THRESHOLD else "LOW",
        }
    except (KeyError,TypeError):
        return _err("virustotal", raw)


# =============================================================================
#  2. AbuseIPDB
# =============================================================================

def abuseipdb_check(ip: str, days: int = 30) -> dict:
    key = _KEYS["abuseipdb"]
    if not key:
        return _no_key("abuseipdb")
    url = (f"https://api.abuseipdb.com/api/v2/check"
           f"?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays={days}&verbose")
    raw = _get(url, {"Key": key, "Accept": "application/json"})
    if not raw or "_error" in raw:
        return _err("abuseipdb", raw)
    try:
        d = raw["data"]
        conf = d.get("abuseConfidenceScore", 0)
        return {
            "source":           "abuseipdb",
            "ip":               ip,
            "abuse_confidence": conf,
            "total_reports":    d.get("totalReports", 0),
            "country":          d.get("countryCode",""),
            "usage_type":       d.get("usageType",""),
            "isp":              d.get("isp",""),
            "domain":           d.get("domain",""),
            "is_whitelisted":   d.get("isWhitelisted", False),
            "is_tor":           d.get("isTor", False),
            "last_reported":    d.get("lastReportedAt",""),
            "severity":         ("CRITICAL" if conf >= 75
                                 else "HIGH" if conf >= ABUSE_HIGH_THRESHOLD
                                 else "LOW"),
        }
    except (KeyError, TypeError):
        return _err("abuseipdb", raw)


# =============================================================================
#  3. Shodan
# =============================================================================

def shodan_host(ip: str) -> dict:
    key = _KEYS["shodan"]
    if not key:
        return _no_key("shodan")
    raw = _get(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    if not raw or "_error" in raw or "_http_error" in raw:
        return _err("shodan", raw)
    try:
        ports  = raw.get("ports", [])
        vulns  = list(raw.get("vulns", {}).keys())
        banners = [
            {"port": s.get("port"), "transport": s.get("transport",""),
             "product": s.get("product",""), "version": s.get("version","")}
            for s in raw.get("data", [])[:10]
        ]
        return {
            "source":   "shodan",
            "ip":       ip,
            "country":  raw.get("country_name",""),
            "org":      raw.get("org",""),
            "isp":      raw.get("isp",""),
            "os":       raw.get("os",""),
            "ports":    ports[:20],
            "vulns":    vulns[:10],
            "banners":  banners,
            "hostnames":raw.get("hostnames",[])[:5],
            "tags":     raw.get("tags",[]),
            "severity": ("CRITICAL" if vulns else "HIGH" if 4444 in ports or 31337 in ports else "LOW"),
        }
    except (KeyError, TypeError):
        return _err("shodan", raw)


# =============================================================================
#  4. OTX AlienVault
# =============================================================================

def otx_ip(ip: str) -> dict:
    key = _KEYS["otx"]
    if not key:
        return _no_key("otx")
    raw = _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
               {"X-OTX-API-KEY": key})
    if not raw or "_error" in raw:
        return _err("otx", raw)
    try:
        pulses = raw.get("pulse_info",{}).get("count",0)
        tags   = [t for p in raw.get("pulse_info",{}).get("pulses",[])[:5]
                  for t in p.get("tags",[])]
        return {
            "source":      "otx",
            "ip":          ip,
            "pulse_count": pulses,
            "country":     raw.get("country_name",""),
            "reputation":  raw.get("reputation",0),
            "tags":        list(set(tags))[:10],
            "severity":    "HIGH" if pulses >= OTX_PULSE_THRESHOLD else "LOW",
        }
    except (KeyError, TypeError):
        return _err("otx", raw)


def otx_hash(file_hash: str) -> dict:
    key = _KEYS["otx"]
    if not key:
        return _no_key("otx")
    raw = _get(f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general",
               {"X-OTX-API-KEY": key})
    if not raw or "_error" in raw:
        return _err("otx", raw)
    try:
        pulses = raw.get("pulse_info",{}).get("count",0)
        return {
            "source":      "otx",
            "hash":        file_hash,
            "pulse_count": pulses,
            "malware_family": raw.get("malware_families",[""])[0] if raw.get("malware_families") else "",
            "severity":    "HIGH" if pulses >= OTX_PULSE_THRESHOLD else "LOW",
        }
    except (KeyError, TypeError):
        return _err("otx", raw)


def otx_domain(domain: str) -> dict:
    key = _KEYS["otx"]
    if not key:
        return _no_key("otx")
    raw = _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
               {"X-OTX-API-KEY": key})
    if not raw or "_error" in raw:
        return _err("otx", raw)
    try:
        pulses = raw.get("pulse_info",{}).get("count",0)
        return {
            "source":      "otx",
            "domain":      domain,
            "pulse_count": pulses,
            "alexa_rank":  raw.get("alexa",{}).get("rank",""),
            "severity":    "HIGH" if pulses >= OTX_PULSE_THRESHOLD else "LOW",
        }
    except (KeyError,TypeError):
        return _err("otx", raw)


# =============================================================================
#  5. MalwareBazaar  (no key required)
# =============================================================================

def malwarebazaar_hash(file_hash: str) -> dict:
    raw = _post_json(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_info", "hash": file_hash}
    )
    if not raw or "_error" in raw:
        return _err("malwarebazaar", raw)
    try:
        if raw.get("query_status") != "hash_found":
            return {"source":"malwarebazaar","found":False,"hash":file_hash,
                    "severity":"LOW","message": raw.get("query_status","")}
        data = raw["data"][0]
        return {
            "source":        "malwarebazaar",
            "found":         True,
            "hash":          file_hash,
            "file_name":     data.get("file_name",""),
            "file_type":     data.get("file_type",""),
            "file_size":     data.get("file_size",0),
            "malware_family":data.get("tags",[""])[0] if data.get("tags") else "",
            "signature":     data.get("signature",""),
            "first_seen":    data.get("first_seen",""),
            "reporter":      data.get("reporter",""),
            "tags":          data.get("tags",[])[:8],
            "delivery_method":data.get("delivery_method",""),
            "intelligence":  data.get("intelligence",{}),
            "severity":      "CRITICAL",
        }
    except (KeyError, IndexError, TypeError):
        return _err("malwarebazaar", raw)


# =============================================================================
#  6. URLhaus  (no key required)
# =============================================================================

def urlhaus_url(url_str: str) -> dict:
    raw = _post_json(
        "https://urlhaus-api.abuse.ch/v1/url/",
        {"url": url_str}
    )
    if not raw or "_error" in raw:
        return _err("urlhaus", raw)
    try:
        status = raw.get("query_status","")
        if status == "no_results":
            return {"source":"urlhaus","found":False,"url":url_str,"severity":"LOW"}
        return {
            "source":    "urlhaus",
            "found":     True,
            "url":       url_str,
            "url_status":raw.get("url_status",""),
            "threat":    raw.get("threat",""),
            "tags":      raw.get("tags",[])[:8],
            "host":      raw.get("host",""),
            "date_added":raw.get("date_added",""),
            "severity":  "CRITICAL" if raw.get("url_status") == "online" else "HIGH",
        }
    except (KeyError, TypeError):
        return _err("urlhaus", raw)


def urlhaus_host(host: str) -> dict:
    raw = _post_json(
        "https://urlhaus-api.abuse.ch/v1/host/",
        {"host": host}
    )
    if not raw or "_error" in raw:
        return _err("urlhaus", raw)
    try:
        status = raw.get("query_status","")
        if status == "no_results":
            return {"source":"urlhaus","found":False,"host":host,"severity":"LOW"}
        urls   = raw.get("urls",[])
        return {
            "source":    "urlhaus",
            "found":     True,
            "host":      host,
            "blacklists":raw.get("blacklists",{}),
            "url_count": len(urls),
            "urls":      urls[:5],
            "severity":  "CRITICAL" if len(urls) > 5 else "HIGH",
        }
    except (KeyError, TypeError):
        return _err("urlhaus", raw)


# =============================================================================
#  7. ThreatFox  (no key required)
# =============================================================================

def threatfox_ioc(value: str) -> dict:
    raw = _post_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "search_ioc", "search_term": value}
    )
    if not raw or "_error" in raw:
        return _err("threatfox", raw)
    try:
        status = raw.get("query_status","")
        if status != "ok":
            return {"source":"threatfox","found":False,"value":value,"severity":"LOW",
                    "message":status}
        data = raw.get("data",[])
        rows = [
            {
                "ioc_type":      d.get("ioc_type",""),
                "malware":       d.get("malware",""),
                "malware_alias": d.get("malware_alias",""),
                "confidence":    d.get("confidence_level",0),
                "first_seen":    d.get("first_seen",""),
                "last_seen":     d.get("last_seen",""),
                "tags":          d.get("tags",[])[:5],
            }
            for d in data[:10]
        ]
        conf_max = max((r["confidence"] for r in rows), default=0)
        return {
            "source":     "threatfox",
            "found":      True,
            "value":      value,
            "matches":    len(rows),
            "results":    rows,
            "severity":   ("CRITICAL" if conf_max >= 90
                           else "HIGH" if conf_max >= 50 else "MEDIUM"),
        }
    except (KeyError, TypeError):
        return _err("threatfox", raw)


# =============================================================================
#  8. GreyNoise
# =============================================================================

def greynoise_ip(ip: str) -> dict:
    key = _KEYS["greynoise"]
    headers = {"key": key} if key else {}
    # Community endpoint (free, no key needed for basic info)
    raw = _get(f"https://api.greynoise.io/v3/community/{ip}", headers)
    if not raw or "_error" in raw:
        # Try v2 endpoint
        raw = _get(f"https://api.greynoise.io/v2/noise/quick/{ip}", headers)
    if not raw or "_error" in raw:
        return _err("greynoise", raw)
    try:
        noise = raw.get("noise", False)
        riot  = raw.get("riot",  False)
        name  = raw.get("name",  raw.get("classification",""))
        return {
            "source":         "greynoise",
            "ip":             ip,
            "is_noise":       noise,
            "is_riot":        riot,
            "classification": raw.get("classification",""),
            "name":           name,
            "link":           raw.get("link",""),
            "message":        raw.get("message",""),
            "severity":       ("LOW" if riot
                               else "MEDIUM" if noise
                               else "HIGH"),
        }
    except (KeyError, TypeError):
        return _err("greynoise", raw)


# =============================================================================
#  Aggregated lookups
# =============================================================================

def lookup_hash_all(file_hash: str) -> dict:
    """Run hash against all relevant sources and aggregate."""
    results = {
        "virustotal":    virustotal_hash(file_hash),
        "malwarebazaar": malwarebazaar_hash(file_hash),
        "otx":           otx_hash(file_hash),
        "threatfox":     threatfox_ioc(file_hash),
    }
    return _aggregate(file_hash, "hash", results)


def lookup_ip_all(ip: str) -> dict:
    """Run IP against all relevant sources."""
    results = {
        "virustotal": virustotal_ip(ip),
        "abuseipdb":  abuseipdb_check(ip),
        "shodan":     shodan_host(ip),
        "otx":        otx_ip(ip),
        "urlhaus":    urlhaus_host(ip),
        "threatfox":  threatfox_ioc(ip),
        "greynoise":  greynoise_ip(ip),
    }
    return _aggregate(ip, "ip", results)


def lookup_url_all(url_str: str) -> dict:
    """Run URL against all relevant sources."""
    results = {
        "virustotal": virustotal_url(url_str),
        "urlhaus":    urlhaus_url(url_str),
        "threatfox":  threatfox_ioc(url_str),
    }
    return _aggregate(url_str, "url", results)


def lookup_domain_all(domain: str) -> dict:
    """Run domain against all sources."""
    results = {
        "otx":       otx_domain(domain),
        "urlhaus":   urlhaus_host(domain),
        "threatfox": threatfox_ioc(domain),
        "greynoise": greynoise_ip(domain),
    }
    return _aggregate(domain, "domain", results)


def _aggregate(value: str, ioc_type: str, results: dict) -> dict:
    SEVERITY_W = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    max_sev    = "LOW"
    all_alerts = []
    sources_hit = 0

    for src, r in results.items():
        if r.get("_error") or r.get("_no_key"):
            continue
        sev = r.get("severity","LOW")
        if SEVERITY_W.get(sev,1) > SEVERITY_W.get(max_sev,1):
            max_sev = sev
        if r.get("found") or r.get("malicious",0) > 0 or r.get("pulse_count",0) > 0:
            sources_hit += 1
            all_alerts.append(f"[{src.upper()}] {sev}: {value[:50]}")

    return {
        "value":          value,
        "ioc_type":       ioc_type,
        "severity":       max_sev,
        "sources_checked":len(results),
        "sources_hit":    sources_hit,
        "alerts":         all_alerts,
        "results":        results,
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


# =============================================================================
#  Helpers
# =============================================================================

def _no_key(source: str) -> dict:
    return {"source": source, "found": False, "_no_key": True, "severity": "LOW",
            "message": f"No API key configured for {source}. Set {source.upper()}_API_KEY env var."}

def _err(source: str, raw) -> dict:
    msg = str(raw)[:120] if raw else "No response"
    return {"source": source, "found": False, "_error": True,
            "severity": "LOW", "message": msg}

def available_sources() -> dict:
    """Return which sources have API keys configured."""
    return {k: bool(v) for k, v in _KEYS.items()} | {
        "malwarebazaar": True,
        "urlhaus":       True,
        "threatfox":     True,
    }
