# =============================================================================
#  modules/autopsy_export.py
#  Autopsy Case Export Parser
#
#  Parses the four main export formats Autopsy 4.x generates:
#    1. TSV body-file   (mactime / fls format)  — timestamps, inodes, filenames
#    2. CSV artifact    (Keyword Hits, EXIF, etc.)
#    3. XML report      (standard Autopsy XML schema)
#    4. JSON report     (newer Autopsy JSON schema)
#
#  Also understands Autopsy's directory structure:
#    Export/
#      *.body     ← mactime body file
#      Reports/
#        *.csv    ← artifact exports
#        *.xml    ← full report
#        *.json   ← full report
#      ModuleOutput/
#        keyword_hits.txt
#        *.html   ← HTML summaries
# =============================================================================

import os, csv, json, re, time
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# Artifact type classification
# ---------------------------------------------------------------------------
ARTIFACT_RISK = {
    "TSK_WEB_DOWNLOAD":     ("Web Download",        "MEDIUM"),
    "TSK_WEB_HISTORY":      ("Browser History",     "LOW"),
    "TSK_WEB_COOKIE":       ("Browser Cookie",      "LOW"),
    "TSK_WEB_SEARCH_QUERY": ("Search Query",        "LOW"),
    "TSK_WEB_BOOKMARK":     ("Browser Bookmark",    "LOW"),
    "TSK_EMAIL_MSG":        ("Email Message",        "LOW"),
    "TSK_INSTALLED_PROG":   ("Installed Program",   "MEDIUM"),
    "TSK_RECENT_OBJECT":    ("Recent File",         "LOW"),
    "TSK_DEVICE_ATTACHED":  ("USB Device",          "HIGH"),
    "TSK_KEYWORD_HIT":      ("Keyword Hit",         "HIGH"),
    "TSK_HASHSET_HIT":      ("Hash Set Hit",        "CRITICAL"),
    "TSK_METADATA":         ("File Metadata",       "LOW"),
    "TSK_ENCRYPTION_DETECTED":("Encrypted File",   "HIGH"),
    "TSK_MALWARE":          ("Malware Artefact",    "CRITICAL"),
    "TSK_INTERESTING_FILE": ("Interesting File",    "MEDIUM"),
    "TSK_CONTACT":          ("Contact",             "LOW"),
    "TSK_MESSAGE":          ("Message",             "LOW"),
    "TSK_CALLLOG":          ("Call Log",            "MEDIUM"),
    "TSK_GPS_TRACKPOINT":   ("GPS Location",        "MEDIUM"),
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Keyword patterns that flag evidence as suspicious
SUSPICIOUS_KW = [
    r"password", r"passwd", r"credential", r"secret",
    r"exploit", r"payload", r"malware", r"ransomware",
    r"bitcoin", r"\.onion", r"base64", r"mimikatz",
    r"delete.*evidence", r"wipe", r"shred",
]
_SUSP_RE = re.compile("|".join(SUSPICIOUS_KW), re.IGNORECASE)


# =============================================================================
#  PUBLIC API
# =============================================================================

def parse_export(path: str) -> dict:
    """
    Auto-detect and parse an Autopsy export.
    `path` can be:
      - A single file (.body / .csv / .xml / .json / .txt)
      - A directory (full Autopsy case export folder)
    Returns unified result dict.
    """
    if os.path.isdir(path):
        return _parse_directory(path)

    ext = os.path.splitext(path)[1].lower()
    if ext == ".body":
        return _parse_body_file(path)
    elif ext == ".csv":
        return _parse_csv(path)
    elif ext == ".xml":
        return _parse_xml(path)
    elif ext in (".json", ".js"):
        return _parse_json(path)
    elif ext in (".txt", ".log"):
        return _parse_keyword_hits(path)
    else:
        # Try CSV first, then XML, then JSON
        for fn in (_parse_csv, _parse_xml, _parse_json):
            try:
                r = fn(path)
                if r.get("total_artifacts", 0) > 0:
                    return r
            except Exception:
                pass
        return _empty_result("Could not detect Autopsy export format")


def get_timeline(path: str) -> list[dict]:
    """Return parsed events sorted chronologically."""
    result = parse_export(path)
    events = result.get("events", [])
    return sorted(events, key=lambda e: e.get("epoch", 0))


def get_iocs(path: str) -> list[dict]:
    """Extract all IOCs found in the Autopsy export."""
    result = parse_export(path)
    return result.get("iocs", [])


# =============================================================================
#  Directory parser
# =============================================================================

def _parse_directory(dirpath: str) -> dict:
    all_results = []

    for root, dirs, files in os.walk(dirpath):
        for fname in files:
            fpath = os.path.join(root, fname)
            ext   = os.path.splitext(fname)[1].lower()
            try:
                if ext == ".body":
                    all_results.append(_parse_body_file(fpath))
                elif ext == ".csv":
                    all_results.append(_parse_csv(fpath))
                elif ext == ".xml":
                    all_results.append(_parse_xml(fpath))
                elif ext in (".json", ".js"):
                    all_results.append(_parse_json(fpath))
                elif fname.endswith("keyword_hits.txt"):
                    all_results.append(_parse_keyword_hits(fpath))
            except Exception:
                pass

    if not all_results:
        return _empty_result(f"No parseable Autopsy files found in {dirpath}")

    # Merge
    merged = _merge_results(all_results)
    merged["source"] = f"Directory: {os.path.basename(dirpath)}"
    return merged


# =============================================================================
#  Body file parser  (mactime / fls format)
# =============================================================================
# Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

def _parse_body_file(path: str) -> dict:
    events   = []
    alerts   = []
    seen_del = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 11:
                continue
            md5, name, inode, mode, uid, gid, size = parts[:7]
            atime, mtime, ctime, crtime = parts[7:11]

            deleted  = name.startswith("$OrphanFiles") or "($OrphanFiles)" in name
            susp_kw  = bool(_SUSP_RE.search(name))

            for ts_str, ts_label in [
                (mtime, "Modified"),
                (atime, "Accessed"),
                (ctime, "Changed"),
                (crtime, "Created"),
            ]:
                try:
                    ts = int(ts_str)
                    if ts <= 0:
                        continue
                    ev = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                        "epoch":     ts,
                        "filename":  name[:120],
                        "event":     ts_label,
                        "size":      size,
                        "md5":       md5 if md5 and md5 != "0" else "",
                        "deleted":   deleted,
                        "suspicious":susp_kw,
                        "source":    "body_file",
                    }
                    events.append(ev)
                    if susp_kw and ts_label == "Created":
                        alerts.append(f"Suspicious file created: {name[:80]}")
                    if deleted and ts_label == "Modified":
                        seen_del += 1
                except (ValueError, OSError):
                    pass

    if seen_del:
        alerts.append(f"{seen_del} deleted/orphaned file modification events")

    events.sort(key=lambda e: e["epoch"])
    return _make_result("body_file", events, alerts, path)


# =============================================================================
#  CSV artifact parser
# =============================================================================

def _parse_csv(path: str) -> dict:
    events = []
    alerts = []

    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return _empty_result(f"Empty CSV: {path}")

        headers_lower = [h.lower() for h in reader.fieldnames]

        for row in reader:
            # Normalise key lookup
            rlow = {k.lower(): v for k, v in row.items()}

            # Detect artifact type
            artifact_type = (rlow.get("artifact type","") or
                             rlow.get("artifact_type","") or
                             rlow.get("type","") or "UNKNOWN")
            desc, severity = ARTIFACT_RISK.get(artifact_type, ("Artifact", "LOW"))

            # Timestamp
            ts_raw = (rlow.get("date/time","") or rlow.get("datetime","") or
                      rlow.get("date","") or rlow.get("timestamp","") or "")
            epoch  = _parse_ts(ts_raw)

            # Value / detail
            value  = (rlow.get("value","") or rlow.get("detail","") or
                      rlow.get("name","") or rlow.get("filename","") or
                      rlow.get("keyword","") or "")

            susp = bool(_SUSP_RE.search(value + " " + artifact_type))

            ev = {
                "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else ts_raw,
                "epoch":         epoch,
                "artifact_type": artifact_type,
                "description":   desc,
                "severity":      severity,
                "value":         value[:200],
                "suspicious":    susp,
                "source":        "csv_artifact",
                "raw":           dict(list(row.items())[:8]),
            }
            events.append(ev)
            if severity in ("HIGH","CRITICAL") or susp:
                alerts.append(f"[{severity}] {desc}: {value[:80]}")

    events.sort(key=lambda e: e["epoch"])
    return _make_result("csv", events, alerts, path)


# =============================================================================
#  XML report parser
# =============================================================================

def _parse_xml(path: str) -> dict:
    events = []
    alerts = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        return _empty_result(f"XML parse error: {e}")

    # Handle both namespaced and plain XML
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def find_all(node, tag):
        return node.findall(f"{ns}{tag}") + node.findall(tag)

    def text(node, tag):
        el = node.find(f"{ns}{tag}") or node.find(tag)
        return el.text.strip() if el is not None and el.text else ""

    # Autopsy XML schema: <artifact> elements
    for art in root.iter(f"{ns}artifact") or root.iter("artifact"):
        atype = text(art, "artifactTypeName") or art.get("type","")
        desc, severity = ARTIFACT_RISK.get(atype, ("Artifact","LOW"))
        ts_raw = (text(art,"dateTime") or text(art,"date") or
                  text(art,"timestamp") or "")
        epoch  = _parse_ts(ts_raw)
        value  = (text(art,"value") or text(art,"detail") or
                  text(art,"description") or "")
        susp   = bool(_SUSP_RE.search(value + " " + atype))

        ev = {
            "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else ts_raw,
            "epoch":         epoch,
            "artifact_type": atype,
            "description":   desc,
            "severity":      severity,
            "value":         value[:200],
            "suspicious":    susp,
            "source":        "xml_report",
        }
        events.append(ev)
        if severity in ("HIGH","CRITICAL") or susp:
            alerts.append(f"[{severity}] {desc}: {value[:80]}")

    # Fallback: generic element scan for file references
    if not events:
        for el in root.iter():
            txt = (el.text or "").strip()
            if len(txt) > 10 and "\\" in txt:
                susp = bool(_SUSP_RE.search(txt))
                events.append({
                    "timestamp":"", "epoch":0,
                    "artifact_type":"TSK_METADATA", "description":"File Reference",
                    "severity":"LOW", "value":txt[:200],
                    "suspicious":susp, "source":"xml_generic",
                })

    events.sort(key=lambda e: e["epoch"])
    return _make_result("xml", events, alerts, path)


# =============================================================================
#  JSON report parser
# =============================================================================

def _parse_json(path: str) -> dict:
    events = []
    alerts = []

    with open(path, "r", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            return _empty_result(f"JSON parse error: {e}")

    # Autopsy JSON can be list or dict with "artifacts" key
    if isinstance(data, dict):
        artifact_list = (data.get("artifacts") or data.get("results") or
                         data.get("events") or [data])
    elif isinstance(data, list):
        artifact_list = data
    else:
        return _empty_result("Unrecognised JSON structure")

    for item in artifact_list:
        if not isinstance(item, dict):
            continue
        atype    = (item.get("artifactTypeName") or item.get("type") or
                    item.get("artifact_type") or "UNKNOWN")
        desc, severity = ARTIFACT_RISK.get(atype, ("Artifact","LOW"))
        ts_raw   = (item.get("dateTime") or item.get("date") or
                    item.get("timestamp") or item.get("time") or "")
        epoch    = _parse_ts(str(ts_raw))
        value    = str(item.get("value") or item.get("detail") or
                       item.get("name") or item.get("description") or "")
        susp     = bool(_SUSP_RE.search(value + " " + atype))

        ev = {
            "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else ts_raw,
            "epoch":         epoch,
            "artifact_type": atype,
            "description":   desc,
            "severity":      severity,
            "value":         value[:200],
            "suspicious":    susp,
            "source":        "json_report",
        }
        events.append(ev)
        if severity in ("HIGH","CRITICAL") or susp:
            alerts.append(f"[{severity}] {desc}: {value[:80]}")

    events.sort(key=lambda e: e["epoch"])
    return _make_result("json", events, alerts, path)


# =============================================================================
#  Keyword hits txt parser
# =============================================================================

def _parse_keyword_hits(path: str) -> dict:
    events = []
    alerts = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            susp = bool(_SUSP_RE.search(line))
            events.append({
                "timestamp":"", "epoch":0,
                "artifact_type":"TSK_KEYWORD_HIT",
                "description":"Keyword Hit",
                "severity":"HIGH",
                "value":line[:200],
                "suspicious":susp,
                "source":"keyword_txt",
            })
            if susp:
                alerts.append(f"Suspicious keyword hit: {line[:80]}")

    return _make_result("keyword_hits", events, alerts, path)


# =============================================================================
#  Helpers
# =============================================================================

def _parse_ts(ts_str: str) -> int:
    """Try multiple timestamp formats; return epoch int or 0."""
    if not ts_str:
        return 0
    # Already epoch
    try:
        v = int(float(ts_str))
        if 0 < v < 9_999_999_999:
            return v
    except (ValueError, TypeError):
        pass
    # Common formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d", "%m/%d/%Y",
    ):
        try:
            return int(time.mktime(time.strptime(ts_str[:19], fmt)))
        except (ValueError, OverflowError):
            pass
    return 0


def _extract_iocs(events: list) -> list:
    ioc_re = re.compile(
        r"https?://[\w\-\./?=&%#:@]{6,200}|"
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|"
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b|"
        r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b"
    )
    iocs = []
    seen = set()
    for ev in events:
        for m in ioc_re.finditer(ev.get("value","") + " " + ev.get("artifact_type","")):
            v = m.group()
            if v in seen or len(v) < 7:
                continue
            seen.add(v)
            if v.startswith("http"):    kind = "URL"
            elif "@" in v:             kind = "Email"
            elif re.match(r"\d+\.\d+\.\d+\.\d+", v): kind = "IPv4"
            elif len(v) == 64:         kind = "SHA-256"
            elif len(v) == 40:         kind = "SHA-1"
            elif len(v) == 32:         kind = "MD5"
            else:                      kind = "Unknown"
            iocs.append({"value": v, "type": kind,
                         "context": ev.get("description","")[:40]})
    return iocs


def _make_result(fmt: str, events: list, alerts: list, path: str) -> dict:
    # Stats
    by_severity = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    suspicious_count = 0
    for ev in events:
        sev = ev.get("severity","LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if ev.get("suspicious"):
            suspicious_count += 1

    iocs = _extract_iocs(events)
    return {
        "format":           fmt,
        "source":           os.path.basename(path),
        "total_artifacts":  len(events),
        "suspicious_count": suspicious_count,
        "by_severity":      by_severity,
        "events":           events,
        "alerts":           alerts[:50],
        "iocs":             iocs,
        "threat_score":     min(
            by_severity["CRITICAL"]*25 + by_severity["HIGH"]*10 +
            by_severity["MEDIUM"]*4  + len(iocs)*2, 100
        ),
    }


def _merge_results(results: list) -> dict:
    all_ev = []
    all_al = []
    all_iocs = []
    by_sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    susp   = 0
    fmts   = []
    for r in results:
        all_ev   += r.get("events",[])
        all_al   += r.get("alerts",[])
        all_iocs += r.get("iocs",[])
        fmts.append(r.get("format","?"))
        for k in by_sev:
            by_sev[k] += r.get("by_severity",{}).get(k,0)
        susp += r.get("suspicious_count",0)

    all_ev.sort(key=lambda e: e.get("epoch",0))
    return {
        "format":           "+".join(set(fmts)),
        "source":           "merged",
        "total_artifacts":  len(all_ev),
        "suspicious_count": susp,
        "by_severity":      by_sev,
        "events":           all_ev,
        "alerts":           all_al[:50],
        "iocs":             all_iocs,
        "threat_score":     min(
            by_sev["CRITICAL"]*25 + by_sev["HIGH"]*10 +
            by_sev["MEDIUM"]*4 + len(all_iocs)*2, 100
        ),
    }


def _empty_result(msg: str = "") -> dict:
    return {
        "format":"none","source":"","total_artifacts":0,"suspicious_count":0,
        "by_severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0},
        "events":[],"alerts":[msg] if msg else [],"iocs":[],"threat_score":0,
    }
