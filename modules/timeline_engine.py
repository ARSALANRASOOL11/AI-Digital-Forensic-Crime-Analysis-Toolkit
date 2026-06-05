# =============================================================================
#  modules/timeline_engine.py  — Attack Timeline Reconstruction Engine
#
#  Automatically reconstructs attack chains from evidence:
#    - Parses timestamps from files, logs, metadata, EXIF, PE headers
#    - Maps events to MITRE ATT&CK kill chain phases
#    - Detects temporal gaps and event sequences
#    - Generates chronological attack narrative
# =============================================================================

import os, re, struct, time, json
from datetime import datetime

# Kill chain phases (Lockheed Martin + MITRE hybrid)
KILL_CHAIN_PHASES = [
    'Reconnaissance',
    'Weaponization',
    'Delivery',
    'Exploitation',
    'Installation',
    'Command & Control',
    'Actions on Objectives',
    'Exfiltration',
    'Impact',
]

# Event type → kill chain phase mapping
EVENT_PHASE_MAP = {
    # Reconnaissance
    'nmap_scan':        'Reconnaissance',
    'port_scan':        'Reconnaissance',
    'web_crawl':        'Reconnaissance',
    'dns_lookup':       'Reconnaissance',
    'whois_query':      'Reconnaissance',
    # Weaponization
    'malware_compiled': 'Weaponization',
    'exploit_packed':   'Weaponization',
    'payload_created':  'Weaponization',
    # Delivery
    'email_sent':       'Delivery',
    'file_download':    'Delivery',
    'usb_inserted':     'Delivery',
    'phishing_click':   'Delivery',
    'exploit_triggered':'Delivery',
    # Exploitation
    'cve_exploit':      'Exploitation',
    'buffer_overflow':  'Exploitation',
    'sql_injection':    'Exploitation',
    'privilege_esc':    'Exploitation',
    # Installation
    'malware_dropped':  'Installation',
    'persistence_set':  'Installation',
    'service_created':  'Installation',
    'registry_modified':'Installation',
    # C2
    'c2_connect':       'Command & Control',
    'beacon':           'Command & Control',
    'tunnel_created':   'Command & Control',
    'reverse_shell':    'Command & Control',
    # Actions
    'lateral_movement': 'Actions on Objectives',
    'credential_dump':  'Actions on Objectives',
    'data_accessed':    'Actions on Objectives',
    'file_encrypted':   'Impact',
    # Exfiltration
    'data_exfil':       'Exfiltration',
    'upload':           'Exfiltration',
    # Impact
    'ransom_note':      'Impact',
    'logs_cleared':     'Impact',
    'system_wiped':     'Impact',
    'service_stopped':  'Impact',
}

# Pattern → event type detection
PATTERN_EVENT_MAP = [
    (re.compile(r'nmap|masscan|port.?scan|network.?scan', re.I), 'port_scan'),
    (re.compile(r'phish|click.*link|verify.*account|suspended', re.I), 'phishing_click'),
    (re.compile(r'CVE-\d{4}-\d+|exploit|buffer.?overflow|heap.?spray', re.I), 'cve_exploit'),
    (re.compile(r'mimikatz|lsass|credential.?dump|sekurlsa|hashdump', re.I), 'credential_dump'),
    (re.compile(r'HKEY.*\\Run|schtasks.*create|service.*install|persist', re.I), 'persistence_set'),
    (re.compile(r'reverse.?shell|meterpreter|bind.?shell|nc -e|netcat', re.I), 'reverse_shell'),
    (re.compile(r'c2|command.?control|beacon|call.?home|C&C', re.I), 'c2_connect'),
    (re.compile(r'exfil|ftp.*upload|curl.*-T|dns.*tunnel|data.*theft', re.I), 'data_exfil'),
    (re.compile(r'ransom|your files.*encrypted|decrypt.*key|pay.*bitcoin', re.I), 'ransom_note'),
    (re.compile(r'wevtutil|clear.*log|delete.*event|cipher.*\/w|shred', re.I), 'logs_cleared'),
    (re.compile(r'lateral|pass.?the.?hash|psexec|wmiexec|remote.*exec', re.I), 'lateral_movement'),
    (re.compile(r'encrypt.*file|\.locked|\.encrypted|ransomware', re.I), 'file_encrypted'),
    (re.compile(r'usb|removable.*media|external.*drive|thumb.*drive', re.I), 'usb_inserted'),
    (re.compile(r'dropper|loader|payload.*drop|malware.*install', re.I), 'malware_dropped'),
    (re.compile(r'VirtualAlloc|CreateRemoteThread|WriteProcessMemory|inject', re.I), 'exploit_triggered'),
]


def _detect_event_type(text: str) -> str:
    for pattern, event_type in PATTERN_EVENT_MAP:
        if pattern.search(text):
            return event_type
    return 'data_accessed'


def _extract_timestamps_from_file(filepath: str) -> list[dict]:
    """Extract all timestamps from a file using multiple methods."""
    timestamps = []
    if not os.path.exists(filepath):
        return timestamps

    # 1. File system timestamps
    try:
        st = os.stat(filepath)
        timestamps += [
            {'epoch': st.st_mtime, 'source': 'fs_modified',  'confidence': 0.9},
            {'epoch': st.st_ctime, 'source': 'fs_changed',   'confidence': 0.8},
            {'epoch': st.st_atime, 'source': 'fs_accessed',  'confidence': 0.7},
        ]
    except Exception:
        pass

    # 2. PE compile timestamp
    try:
        with open(filepath, 'rb') as f:
            hdr = f.read(1024)
        if hdr[:2] == b'MZ':
            pe_off = struct.unpack('<I', hdr[0x3C:0x40])[0]
            if pe_off + 8 < len(hdr):
                ts = struct.unpack('<I', hdr[pe_off+8:pe_off+12])[0]
                if 0 < ts < 2_000_000_000:
                    timestamps.append({'epoch': ts, 'source': 'pe_compile', 'confidence': 0.95})
    except Exception:
        pass

    # 3. Embedded timestamp strings in content
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(min(os.path.getsize(filepath), 256*1024))
        text = raw.decode('utf-8', errors='replace')

        ts_patterns = [
            (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'), '%Y-%m-%dT%H:%M:%S'),
            (re.compile(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'),    '%Y/%m/%d %H:%M:%S'),
            (re.compile(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}'),    '%m/%d/%Y %H:%M:%S'),
            (re.compile(r'\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}'),    '%d-%b-%Y %H:%M:%S'),
        ]
        for pat, fmt in ts_patterns:
            for m in pat.findall(text)[:5]:
                try:
                    ts_str = m.replace('T',' ')[:19]
                    epoch  = int(datetime.strptime(ts_str, fmt.replace('T',' ')).timestamp())
                    if 0 < epoch < 2_000_000_000:
                        timestamps.append({'epoch': epoch, 'source': 'embedded_ts', 'confidence': 0.75})
                except Exception:
                    pass

        # Log-style timestamps: [Mon Jan  1 00:00:00 2024]
        log_pat = re.compile(r'(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})')
        for m in log_pat.findall(text)[:5]:
            try:
                ts_str = f"{m[0]} {m[1].zfill(2)} {m[2]} {m[3]}"
                epoch  = int(datetime.strptime(ts_str, '%b %d %H:%M:%S %Y').timestamp())
                timestamps.append({'epoch': epoch, 'source': 'log_ts', 'confidence': 0.8})
            except Exception:
                pass

    except Exception:
        pass

    return timestamps


def reconstruct_timeline(evidence_rows: list, custody_rows: list = None) -> dict:
    """
    Full attack timeline reconstruction from evidence database.
    Returns structured timeline with phases, events, and narrative.
    """
    events = []

    # 1. Evidence file events
    for row in evidence_rows:
        ev_id  = row[0]
        cid    = row[1]
        name   = row[2]
        path   = row[3]
        fhash  = row[4] if len(row) > 4 else ''
        crime  = row[6] if len(row) > 6 else 'Unknown'

        # Get timestamps
        ts_list = _extract_timestamps_from_file(path)

        # Detect event type from filename + content preview
        try:
            with open(path,'rb') as f:
                preview = f.read(4096).decode('utf-8','replace')
        except Exception:
            preview = name

        event_type = _detect_event_type(name + ' ' + preview)
        phase      = EVENT_PHASE_MAP.get(event_type, 'Actions on Objectives')

        # Use most confident timestamp
        best_ts = sorted(ts_list, key=lambda x: -x['confidence'])
        epoch   = best_ts[0]['epoch'] if best_ts else 0
        ts_src  = best_ts[0]['source'] if best_ts else 'unknown'

        events.append({
            'ev_id':       ev_id,
            'case_id':     cid,
            'filename':    name,
            'epoch':       epoch,
            'timestamp':   _fmt(epoch),
            'event_type':  event_type,
            'phase':       phase,
            'crime_type':  crime,
            'ts_source':   ts_src,
            'confidence':  best_ts[0]['confidence'] if best_ts else 0.5,
            'detail':      f"{name} — {crime}",
            'severity':    _phase_severity(phase),
        })

    # 2. Chain of custody events
    if custody_rows:
        for row in custody_rows:
            try:
                cid, fname, action, actor, ts, detail = row[0],row[1],row[2],row[3],row[4],row[5]
                epoch = float(ts) if ts else 0
                events.append({
                    'ev_id':     None,
                    'case_id':   cid,
                    'filename':  fname,
                    'epoch':     epoch,
                    'timestamp': _fmt(epoch),
                    'event_type':'custody_event',
                    'phase':     'Actions on Objectives',
                    'crime_type':'',
                    'ts_source': 'custody_log',
                    'confidence':1.0,
                    'detail':    f"[{action}] by {actor}: {detail[:80]}",
                    'severity':  'LOW',
                    'actor':     actor,
                    'action':    action,
                })
            except Exception:
                pass

    # Sort by epoch
    events.sort(key=lambda e: e['epoch'])

    # Detect temporal gaps (suspicious time gaps between events)
    gaps = []
    for i in range(1, len(events)):
        gap_sec = events[i]['epoch'] - events[i-1]['epoch']
        if 0 < gap_sec < 300:  # Events within 5 minutes — suspicious burst
            gaps.append({
                'between': [events[i-1]['filename'], events[i]['filename']],
                'gap_sec': round(gap_sec, 1),
                'note':    f"Rapid succession: {round(gap_sec,1)}s apart",
            })

    # Build phase summary
    phase_counts = {}
    for ev in events:
        ph = ev['phase']
        phase_counts[ph] = phase_counts.get(ph, 0) + 1

    phases_present = [p for p in KILL_CHAIN_PHASES if p in phase_counts]

    # Generate narrative
    narrative = _generate_narrative(events, phases_present)

    # Attack chain — ordered phases
    attack_chain = []
    seen_phases  = set()
    for ev in events:
        if ev['phase'] not in seen_phases:
            seen_phases.add(ev['phase'])
            attack_chain.append({
                'phase':      ev['phase'],
                'first_seen': ev['timestamp'],
                'event':      ev['detail'],
                'severity':   ev['severity'],
            })

    # Threat actors — unique actors from custody
    actors = list(set(e.get('actor','') for e in events if e.get('actor')))

    return {
        'events':         events,
        'attack_chain':   attack_chain,
        'phases_present': phases_present,
        'phase_counts':   phase_counts,
        'temporal_gaps':  gaps[:10],
        'narrative':      narrative,
        'total_events':   len(events),
        'time_span':      _time_span(events),
        'actors':         actors,
        'start_time':     events[0]['timestamp']  if events else '',
        'end_time':       events[-1]['timestamp'] if events else '',
    }


def _phase_severity(phase: str) -> str:
    return {
        'Reconnaissance':         'LOW',
        'Weaponization':          'MEDIUM',
        'Delivery':               'MEDIUM',
        'Exploitation':           'HIGH',
        'Installation':           'HIGH',
        'Command & Control':      'CRITICAL',
        'Actions on Objectives':  'CRITICAL',
        'Exfiltration':           'CRITICAL',
        'Impact':                 'CRITICAL',
    }.get(phase, 'MEDIUM')


def _fmt(epoch: float) -> str:
    if not epoch or epoch <= 0:
        return 'Unknown'
    try:
        return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(epoch)


def _time_span(events: list) -> str:
    valid = [e['epoch'] for e in events if e['epoch'] > 0]
    if not valid:
        return 'Unknown'
    span  = max(valid) - min(valid)
    if span < 60:       return f"{int(span)} seconds"
    if span < 3600:     return f"{int(span/60)} minutes"
    if span < 86400:    return f"{int(span/3600)} hours"
    return f"{int(span/86400)} days"


def _generate_narrative(events: list, phases: list) -> str:
    if not events:
        return "No timeline events reconstructed yet. Upload evidence to generate the attack narrative."

    lines = ["## Attack Timeline Narrative\n"]
    lines.append(f"**{len(events)} events** reconstructed across **{len(phases)} attack phase(s)**.\n")

    phase_events = {}
    for ev in events:
        phase_events.setdefault(ev['phase'], []).append(ev)

    for phase in KILL_CHAIN_PHASES:
        if phase not in phase_events:
            continue
        pevs = phase_events[phase]
        lines.append(f"\n### Phase: {phase}")
        lines.append(f"*{len(pevs)} event(s) — first seen: {pevs[0]['timestamp']}*")
        for ev in pevs[:3]:
            lines.append(f"- {ev['detail']}")
        if len(pevs) > 3:
            lines.append(f"- ...and {len(pevs)-3} more events")

    return '\n'.join(lines)
