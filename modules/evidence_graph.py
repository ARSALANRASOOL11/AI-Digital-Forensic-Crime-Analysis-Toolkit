# =============================================================================
#  modules/evidence_graph.py  — Evidence Relationship Graph Engine
#
#  Builds a directed graph of relationships between:
#    - Evidence files  (nodes)
#    - Cases           (nodes)
#    - IOCs            (nodes: IPs, domains, hashes, emails)
#    - Crime types     (nodes)
#    - Threat actors   (inferred nodes)
#
#  Edges represent:
#    - file → case         (belongs_to)
#    - file → IOC          (contains)
#    - file → crime_type   (classified_as)
#    - IOC  → IOC          (shared infrastructure)
#    - case → case         (linked via shared IOC)
#
#  Output: D3.js-compatible JSON for force-directed graph rendering
# =============================================================================

import os, json, re, hashlib, time
from collections import defaultdict


# ---------------------------------------------------------------------------
# Node types and colours (matching CSS variables)
# ---------------------------------------------------------------------------
NODE_TYPES = {
    "case":        {"color": "#00ffe7", "size": 18, "shape": "diamond"},
    "file":        {"color": "#0088ff", "size": 12, "shape": "circle"},
    "ip":          {"color": "#ff3c3c", "size": 10, "shape": "circle"},
    "domain":      {"color": "#ffb800", "size": 10, "shape": "circle"},
    "hash":        {"color": "#cc44ff", "size": 9,  "shape": "circle"},
    "email":       {"color": "#ff6699", "size": 9,  "shape": "circle"},
    "url":         {"color": "#ff8800", "size": 9,  "shape": "circle"},
    "crime_type":  {"color": "#ff3c3c", "size": 14, "shape": "rect"},
    "risk":        {"color": "#ffb800", "size": 11, "shape": "rect"},
    "yara_rule":   {"color": "#00ff88", "size": 9,  "shape": "triangle"},
}

RISK_COLORS = {
    "CLEAN":       "#00ff88",
    "LOW_RISK":    "#0088ff",
    "MEDIUM_RISK": "#ffb800",
    "HIGH_RISK":   "#ff3c3c",
    "CRITICAL":    "#ff0055",
}


# =============================================================================
#  Graph Builder
# =============================================================================

def build_evidence_graph(evidence_rows: list,
                          custody_rows: list = None,
                          ioc_results:  dict = None) -> dict:
    """
    Build a complete relationship graph from database evidence.

    Args:
        evidence_rows: rows from evidence table
        custody_rows:  rows from custody_log (optional)
        ioc_results:   {ev_id: ioc_extractor_result} (optional)

    Returns D3.js force-graph JSON: {"nodes": [...], "links": [...], "stats": {...}}
    """
    nodes   = {}   # id → node dict
    links   = []   # list of link dicts
    seen_links = set()

    def add_node(nid: str, label: str, ntype: str,
                 extra: dict = None) -> str:
        if nid not in nodes:
            style = NODE_TYPES.get(ntype, {"color":"#888","size":8,"shape":"circle"})
            nodes[nid] = {
                "id":    nid,
                "label": label[:40],
                "type":  ntype,
                "color": style["color"],
                "size":  style["size"],
                "shape": style["shape"],
                **(extra or {}),
            }
        return nid

    def add_link(src: str, tgt: str, rel: str,
                 weight: float = 1.0, color: str = "") -> None:
        key = f"{src}→{tgt}→{rel}"
        if key in seen_links:
            return
        seen_links.add(key)
        links.append({
            "source": src,
            "target": tgt,
            "label":  rel,
            "weight": weight,
            "color":  color or "#4a7090",
        })

    # ----------------------------------------------------------------
    # 1. Case nodes
    # ----------------------------------------------------------------
    cases_seen = set()
    for row in evidence_rows:
        cid = row[1] if not hasattr(row, "keys") else row["case_id"]
        if cid not in cases_seen:
            cases_seen.add(cid)
            add_node(f"case:{cid}", cid, "case",
                     {"case_id": cid, "tooltip": f"Case {cid}"})

    # ----------------------------------------------------------------
    # 2. Evidence file nodes + case links
    # ----------------------------------------------------------------
    for row in evidence_rows:
        ev_id   = row[0]  if not hasattr(row,"keys") else row.get("id",0)
        cid     = row[1]  if not hasattr(row,"keys") else row["case_id"]
        name    = row[2]  if not hasattr(row,"keys") else row["filename"]
        path    = row[3]  if not hasattr(row,"keys") else row["path"]
        fhash   = row[4]  if not hasattr(row,"keys") else row.get("hash","")
        crime   = row[6]  if (not hasattr(row,"keys") and len(row)>6) else row.get("crime_type","Unknown")
        ev_cat  = row[7]  if (not hasattr(row,"keys") and len(row)>7) else row.get("evidence_category","Unknown")

        # Risk score
        risk_level, risk_color = "UNKNOWN", "#888"
        try:
            from modules.analysis import ai_risk_score
            r = ai_risk_score(name, path)
            risk_level = r["level"]
            risk_color = RISK_COLORS.get(risk_level, "#888")
        except Exception:
            pass

        fnode = f"file:{ev_id}"
        add_node(fnode, name, "file", {
            "ev_id":      ev_id,
            "case_id":    cid,
            "hash":       fhash[:16] if fhash else "",
            "crime_type": crime,
            "ev_category":ev_cat,
            "risk":       risk_level,
            "color":      risk_color,
            "tooltip":    f"{name}\nRisk: {risk_level}\nCrime: {crime}",
        })

        # file → case
        add_link(fnode, f"case:{cid}", "belongs_to",
                 weight=2.0, color="#00ffe7")

        # file → crime type
        if crime and crime not in ("Unknown","Unclassified"):
            crime_nid = f"crime:{crime}"
            add_node(crime_nid, crime, "crime_type",
                     {"tooltip": f"Crime Type: {crime}"})
            add_link(fnode, crime_nid, "classified_as",
                     weight=1.5, color="#ff3c3c")

        # file → risk level
        if risk_level and risk_level != "UNKNOWN":
            risk_nid = f"risk:{risk_level}"
            add_node(risk_nid, risk_level.replace("_"," "), "risk",
                     {"color": risk_color, "tooltip": f"Risk: {risk_level}"})
            add_link(fnode, risk_nid, "risk_level",
                     weight=0.8, color=risk_color)

        # hash node (shared hash = same file in multiple cases)
        if fhash:
            hn = f"hash:{fhash[:16]}"
            add_node(hn, fhash[:12]+"…", "hash",
                     {"full_hash": fhash, "tooltip": fhash[:32]})
            add_link(fnode, hn, "has_hash", weight=1.0, color="#cc44ff")

    # ----------------------------------------------------------------
    # 3. IOC nodes from extractor results
    # ----------------------------------------------------------------
    if ioc_results:
        for ev_id_key, ioc_data in ioc_results.items():
            fnode = f"file:{ev_id_key}"
            if fnode not in nodes:
                continue
            iocs = ioc_data.get("iocs", {})

            for ip_item in iocs.get("ipv4", [])[:8]:
                ip  = ip_item.get("value","")
                nid = f"ip:{ip}"
                add_node(nid, ip, "ip",
                         {"private": ip_item.get("private",False),
                          "tooltip": f"IP: {ip}"})
                add_link(fnode, nid, "connects_to",
                         weight=1.2, color="#ff3c3c")

            for dom in iocs.get("domains", [])[:8]:
                d   = dom.get("value","")
                nid = f"domain:{d}"
                add_node(nid, d, "domain",
                         {"evil_tld": dom.get("evil_tld",False),
                          "tooltip": f"Domain: {d}"})
                add_link(fnode, nid, "contacts", weight=1.2, color="#ffb800")

            for url in iocs.get("urls", [])[:5]:
                u   = url.get("value","")[:50]
                nid = f"url:{hashlib.md5(u.encode()).hexdigest()[:8]}"
                add_node(nid, u[:35]+"…" if len(u)>35 else u, "url",
                         {"tooltip": u})
                add_link(fnode, nid, "references", weight=1.0, color="#ff8800")

            for em in iocs.get("emails", [])[:5]:
                e   = em.get("value","")
                nid = f"email:{e}"
                add_node(nid, e, "email", {"tooltip": f"Email: {e}"})
                add_link(fnode, nid, "email_found", weight=1.0, color="#ff6699")

            for h256 in iocs.get("sha256", [])[:3]:
                hv  = h256.get("value","")
                nid = f"hash:{hv[:16]}"
                add_node(nid, hv[:12]+"…", "hash", {"full_hash": hv})
                add_link(fnode, nid, "contains_hash", weight=1.0, color="#cc44ff")

    # ----------------------------------------------------------------
    # 4. YARA rule nodes
    # ----------------------------------------------------------------
    for row in evidence_rows:
        ev_id = row[0] if not hasattr(row,"keys") else row.get("id",0)
        name  = row[2] if not hasattr(row,"keys") else row["filename"]
        path  = row[3] if not hasattr(row,"keys") else row["path"]
        fnode = f"file:{ev_id}"
        if fnode not in nodes:
            continue
        try:
            from modules.yara_scanner import scan_file
            hits = scan_file(path)
            for hit in hits[:4]:
                rule_nid = f"yara:{hit['rule']}"
                add_node(rule_nid, hit["rule"], "yara_rule",
                         {"severity": hit["severity"],
                          "tooltip":  hit["description"][:60]})
                add_link(fnode, rule_nid, "yara_match",
                         weight=1.5, color="#00ff88")
        except Exception:
            pass

    # ----------------------------------------------------------------
    # 5. Cross-case links via shared IOCs
    # ----------------------------------------------------------------
    # Find files sharing same crime type across cases
    crime_to_files = defaultdict(list)
    for nid, nd in nodes.items():
        if nd["type"] == "file" and nd.get("crime_type","") not in ("Unknown","Unclassified",""):
            crime_to_files[nd["crime_type"]].append((nid, nd.get("case_id","")))

    for crime, file_list in crime_to_files.items():
        cases_involved = list(set(cid for _, cid in file_list))
        if len(cases_involved) > 1:
            # Link cases together via shared crime type
            for i in range(len(cases_involved)-1):
                add_link(
                    f"case:{cases_involved[i]}",
                    f"case:{cases_involved[i+1]}",
                    f"shared:{crime[:20]}",
                    weight=3.0, color="#ff3c3c"
                )

    # ----------------------------------------------------------------
    # 6. Stats
    # ----------------------------------------------------------------
    type_counts = defaultdict(int)
    for nd in nodes.values():
        type_counts[nd["type"]] += 1

    stats = {
        "total_nodes":  len(nodes),
        "total_links":  len(links),
        "node_types":   dict(type_counts),
        "cases":        len(cases_seen),
        "files":        type_counts.get("file", 0),
        "ioc_nodes":    type_counts.get("ip",0) + type_counts.get("domain",0) +
                        type_counts.get("url",0) + type_counts.get("email",0),
    }

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "stats": stats,
    }


def graph_summary(graph: dict) -> str:
    s = graph["stats"]
    return (f"{s['total_nodes']} nodes · {s['total_links']} relationships · "
            f"{s['cases']} cases · {s['ioc_nodes']} IOC nodes")
