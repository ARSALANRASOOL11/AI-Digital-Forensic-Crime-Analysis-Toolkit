# =============================================================================
#  modules/ti_correlation.py  — Threat Intelligence Correlation Center
#
#  Aggregates VT, AbuseIPDB, OTX, URLHaus, ThreatFox into unified dashboard.
#  Correlates IOCs across all evidence files automatically.
# =============================================================================

import os, json, time, hashlib
from collections import defaultdict

SOURCE_PRIORITY = ["virustotal","malwarebazaar","otx","abuseipdb","urlhaus","threatfox","shodan","greynoise"]

SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _safe_lookup(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        return {"error": str(e), "severity": "LOW"}


def correlate_evidence(evidence_rows: list) -> dict:
    """
    Run TI lookups on all IOCs extracted from every evidence file.
    Returns unified correlation dashboard data.
    """
    from modules.threat_intel import (
        lookup_hash_all, lookup_ip_all, lookup_url_all,
        malwarebazaar_hash, threatfox_ioc, urlhaus_host,
        available_sources
    )
    from modules.ioc_extractor import extract_iocs

    sources_status = available_sources()
    results        = []
    global_ioc_map = defaultdict(list)   # ioc_value → [evidence refs]
    threat_actors  = defaultdict(set)    # actor/family → {ev_ids}
    timeline       = []

    for row in evidence_rows:
        ev_id  = row[0]
        cid    = row[1]
        name   = row[2]
        path   = row[3]
        fhash  = row[4] if len(row) > 4 else ""

        if not os.path.exists(path):
            continue

        ev_result = {
            "ev_id":    ev_id,
            "case_id":  cid,
            "filename": name,
            "hash":     fhash,
            "lookups":  {},
            "severity": "LOW",
            "alerts":   [],
            "families": [],
        }

        # Hash lookup
        if fhash:
            r = _safe_lookup(lookup_hash_all, fhash)
            ev_result["lookups"]["hash"] = r
            global_ioc_map[fhash].append({"ev_id": ev_id, "name": name, "type": "hash"})

            # Extract malware family
            for src in SOURCE_PRIORITY:
                src_data = r.get("results", {}).get(src, {})
                family   = (src_data.get("malware_family") or
                            src_data.get("threat_label") or
                            src_data.get("signature") or "")
                if family:
                    ev_result["families"].append(family)
                    threat_actors[family].add(ev_id)
                    break

            # Severity from TI
            sev = r.get("severity", "LOW")
            if SEVERITY_WEIGHT.get(sev, 1) > SEVERITY_WEIGHT.get(ev_result["severity"], 1):
                ev_result["severity"] = sev

            if r.get("sources_hit", 0) > 0:
                ev_result["alerts"].append(
                    f"Hash flagged by {r['sources_hit']} TI source(s): {fhash[:16]}…"
                )
                timeline.append({
                    "time":   time.strftime("%Y-%m-%d %H:%M:%S"),
                    "event":  f"TI Hit: {name}",
                    "detail": f"{r['sources_hit']} source(s) matched hash",
                    "sev":    sev,
                })

        # IOC-level lookups (top IPs and domains from file)
        ioc_result = extract_iocs(path)
        for ip in ioc_result.get("iocs", {}).get("ipv4", [])[:2]:
            ip_val = ip.get("value", "")
            if ip_val and not ip_val.startswith(("192.168.","10.","127.")):
                r = _safe_lookup(lookup_ip_all, ip_val)
                ev_result["lookups"][f"ip:{ip_val}"] = r
                global_ioc_map[ip_val].append({"ev_id": ev_id, "name": name, "type": "ip"})
                sev = r.get("severity", "LOW")
                if SEVERITY_WEIGHT.get(sev,1) > SEVERITY_WEIGHT.get(ev_result["severity"],1):
                    ev_result["severity"] = sev
                if r.get("sources_hit", 0) > 0:
                    ev_result["alerts"].append(f"IP {ip_val} flagged by TI")

        results.append(ev_result)

    # Shared IOCs across files
    shared = {
        ioc: refs for ioc, refs in global_ioc_map.items()
        if len(refs) > 1
    }

    # Aggregate severity counts
    sev_counts = defaultdict(int)
    for r in results:
        sev_counts[r["severity"]] += 1

    # Top threat families
    top_families = sorted(
        [(family, len(ev_ids)) for family, ev_ids in threat_actors.items()],
        key=lambda x: -x[1]
    )[:10]

    return {
        "evidence_results":  results,
        "shared_iocs":       shared,
        "threat_families":   top_families,
        "severity_counts":   dict(sev_counts),
        "sources_status":    sources_status,
        "timeline":          timeline[-20:],
        "total_lookups":     sum(len(r["lookups"]) for r in results),
        "flagged_count":     sum(1 for r in results if r["severity"] in ("HIGH","CRITICAL")),
        "summary": {
            "total_evidence": len(results),
            "flagged":        sum(1 for r in results if r["severity"] in ("HIGH","CRITICAL")),
            "families_found": len(threat_actors),
            "shared_iocs":    len(shared),
        },
    }
