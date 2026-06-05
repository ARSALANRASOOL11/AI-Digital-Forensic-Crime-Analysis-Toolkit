# =============================================================================
#  modules/correlation_engine.py  — Evidence Correlation Engine
#
#  Links evidence through shared IOCs:
#    IP addresses, Domains, Emails, Hashes, Usernames, Wallet addresses
#  Generates investigation clusters and correlation scores
# =============================================================================

import os, re, json, time, hashlib
from collections import defaultdict

_IPV4    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_EMAIL   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.I)
_DOMAIN  = re.compile(r'\b(?:[a-zA-Z0-9\-]{1,63}\.)+(?:com|net|org|io|ru|cn|onion|xyz|cc|pw)\b', re.I)
_BTC     = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_ETH     = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_SHA256  = re.compile(r'\b[a-fA-F0-9]{64}\b')
_MD5     = re.compile(r'\b[a-fA-F0-9]{32}\b')
_USER    = re.compile(r'(?:username|user|login|account)[:\s]+([a-zA-Z0-9_\.\-]{3,30})', re.I)

IOC_WEIGHTS = {
    'ip':       10,
    'domain':   8,
    'email':    9,
    'hash':     15,
    'wallet':   12,
    'username': 7,
}


def extract_iocs_from_file(filepath: str) -> dict:
    iocs = defaultdict(set)
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(min(os.path.getsize(filepath), 512*1024))
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return {}

    for ip in _IPV4.findall(text):
        if not ip.startswith(('127.','0.','255.','192.168.','10.','172.')):
            iocs['ip'].add(ip)
    for em in _EMAIL.findall(text):     iocs['email'].add(em.lower())
    for dm in _DOMAIN.findall(text):    iocs['domain'].add(dm.lower())
    for bt in _BTC.findall(text):       iocs['wallet'].add(bt)
    for et in _ETH.findall(text):       iocs['wallet'].add(et.lower())
    for h in _SHA256.findall(text):
        if len(set(h)) > 4:             iocs['hash'].add(h.lower())
    for md in _MD5.findall(text):
        if len(set(md)) > 4:            iocs['hash'].add(md.lower())
    for u in _USER.findall(text):       iocs['username'].add(u.lower())

    return {k: list(v)[:30] for k, v in iocs.items()}


def correlate(evidence_rows: list) -> dict:
    """
    Build correlation map across all evidence files.
    Returns clusters, correlation matrix, and shared IOC graph.
    """
    # Extract IOCs per evidence file
    file_iocs = {}
    for row in evidence_rows:
        ev_id = row[0]
        name  = row[2]
        path  = row[3]
        cid   = row[1]
        iocs  = extract_iocs_from_file(path)
        # Also include the file hash itself
        fhash = row[4] if len(row) > 4 else ''
        if fhash:
            iocs.setdefault('hash', [])
            if fhash not in iocs['hash']:
                iocs['hash'].append(fhash)
        file_iocs[ev_id] = {
            'name': name, 'case_id': cid,
            'path': path, 'iocs': iocs,
        }

    # Build IOC → [file_ids] reverse index
    ioc_index = defaultdict(list)   # (ioc_type, ioc_value) → [ev_ids]
    for ev_id, info in file_iocs.items():
        for ioc_type, values in info['iocs'].items():
            for val in values:
                ioc_index[(ioc_type, val)].append(ev_id)

    # Find shared IOCs (appear in 2+ files)
    shared_iocs = {k: v for k, v in ioc_index.items() if len(v) > 1}

    # Correlation matrix: score between each pair of files
    ev_ids   = list(file_iocs.keys())
    corr_mat = defaultdict(float)
    links    = []

    for (ioc_type, ioc_val), ev_id_list in shared_iocs.items():
        weight = IOC_WEIGHTS.get(ioc_type, 5)
        for i in range(len(ev_id_list)):
            for j in range(i+1, len(ev_id_list)):
                a, b = ev_id_list[i], ev_id_list[j]
                key  = tuple(sorted([a, b]))
                corr_mat[key] += weight
                links.append({
                    'source':   a,
                    'target':   b,
                    'ioc_type': ioc_type,
                    'ioc_val':  ioc_val[:50],
                    'weight':   weight,
                })

    # De-duplicate links (keep highest weight per pair)
    seen_pairs = {}
    for lnk in links:
        key = (lnk['source'], lnk['target'])
        if key not in seen_pairs or lnk['weight'] > seen_pairs[key]['weight']:
            seen_pairs[key] = lnk
    dedup_links = list(seen_pairs.values())

    # Cluster files by connected components
    clusters = _connected_components(ev_ids, dedup_links)

    # Build nodes for graph
    nodes = []
    for ev_id, info in file_iocs.items():
        score = sum(corr_mat.get(tuple(sorted([ev_id,o])),0)
                    for o in ev_ids if o != ev_id)
        nodes.append({
            'id':       ev_id,
            'name':     info['name'],
            'case_id':  info['case_id'],
            'ioc_count':sum(len(v) for v in info['iocs'].values()),
            'corr_score':round(score,1),
            'cluster':  next((i for i,cl in enumerate(clusters) if ev_id in cl), 0),
        })

    # IOC summary
    ioc_summary = defaultdict(list)
    for (ioc_type, ioc_val), ev_id_list in shared_iocs.items():
        ioc_summary[ioc_type].append({
            'value':     ioc_val[:60],
            'files':     len(ev_id_list),
            'ev_ids':    ev_id_list,
            'weight':    IOC_WEIGHTS.get(ioc_type, 5),
        })

    alerts = []
    for ioc_type, items in ioc_summary.items():
        for item in items:
            if item['files'] >= 3:
                alerts.append(
                    f"CRITICAL: {ioc_type} '{item['value'][:40]}' "
                    f"found in {item['files']} evidence files — likely same threat actor"
                )
            elif item['files'] == 2:
                alerts.append(
                    f"HIGH: {ioc_type} '{item['value'][:40]}' "
                    f"shared between 2 files"
                )

    return {
        'nodes':         nodes,
        'links':         dedup_links,
        'clusters':      [list(c) for c in clusters],
        'shared_iocs':   {k: v for k, v in ioc_summary.items()},
        'alerts':        alerts[:20],
        'total_files':   len(file_iocs),
        'total_links':   len(dedup_links),
        'total_clusters':len(clusters),
        'corr_matrix':   {str(k): v for k, v in corr_mat.items()},
    }


def _connected_components(nodes: list, links: list) -> list:
    """Union-Find for clustering correlated files."""
    parent = {n: n for n in nodes}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        parent[find(a)] = find(b)

    for lnk in links:
        if lnk['source'] in parent and lnk['target'] in parent:
            union(lnk['source'], lnk['target'])

    groups = defaultdict(set)
    for n in nodes:
        groups[find(n)].add(n)
    return [s for s in groups.values() if s]
