# =============================================================================
#  modules/analysis.py  — AI Risk Scoring, Crime Classification, Metadata,
#                          CNN-simulation ML model, Confusion Matrix data
# =============================================================================

import os, math, struct, time
from modules.yara_scanner import scan_file, severity_score

# ---------------------------------------------------------------------------
#  Magic signatures
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES = {
    b"MZ":              ("Windows PE Executable",      90),
    b"\x7fELF":         ("Linux ELF Executable",       85),
    b"\xca\xfe\xba\xbe":("Java Class File",            60),
    b"PK\x03\x04":      ("ZIP / Office Archive",       10),
    b"%PDF":            ("PDF Document",                 5),
    b"\xff\xd8\xff":    ("JPEG Image",                   5),
    b"\x89PNG":         ("PNG Image",                    5),
    b"GIF8":            ("GIF Image",                    5),
    b"RIFF":            ("RIFF Media (AVI/WAV)",         15),
    b"\xd0\xcf\x11\xe0":("Legacy MS Office Document",  20),
}

HIGH_RISK_EXT   = {".exe",".bat",".scr",".cmd",".vbs",".ps1",
                   ".msi",".com",".pif",".reg",".hta",".dll"}
MEDIUM_RISK_EXT = {".js",".vbe",".wsf",".lnk",".iso",".img",
                   ".py",".sh",".pl",".rb",".php",".jar"}
SAFE_EXT        = {".pdf",".jpg",".jpeg",".png",".gif",".bmp",
                   ".txt",".docx",".xlsx",".pptx",".csv",
                   ".mp4",".mp3",".zip",".rar"}

SUSPICIOUS_KW = [
    b"cmd.exe", b"powershell", b"WScript", b"eval(",
    b"base64_decode", b"HKEY_", b"regedit", b"netsh",
    b"taskkill", b"format c:", b"del /f /q", b"rm -rf",
    b"nc -e", b"reverse_shell", b"meterpreter",
]

# ---------------------------------------------------------------------------
#  Crime type classification
# ---------------------------------------------------------------------------
CRIME_TYPE_RULES = [
    (["ransom","encrypt","decrypt","bitcoin","locked","pay","wannacry","cryptolocker"],  "Ransomware"),
    (["keylog","keylogger","hook","getasynckeystate","wh_keyboard"],                     "Keylogging / Spyware"),
    (["reverse_shell","meterpreter","nc -e","bind shell","backdoor","rat "],             "Remote Access Trojan"),
    (["phish","credential","login","password","spoof","fake","lure"],                    "Phishing"),
    (["exfil","upload","ftp","curl","wget","dns tunnel","data theft"],                   "Data Exfiltration"),
    (["ddos","flood","syn flood","botnet","zombie","attack"],                            "DDoS / Botnet"),
    (["sql inject","union select","drop table","xss","script alert","lfi","rfi"],        "Web Attack"),
    (["rootkit","hooking","ring0","kernel","driver","irp"],                              "Rootkit"),
    (["worm","propagat","spread","network scan","nmap","masscan"],                       "Worm / Lateral Movement"),
    (["mimikatz","lsass","pass the hash","golden ticket","kerberos"],                   "Credential Theft"),
    (["steganog","hidden","embed","cover","payload inside"],                             "Steganography"),
    (["format c:","del /f","rm -rf","wipe","shred","destroy","overwrite"],              "Anti-Forensics / Destruction"),
]

def classify_crime_type(name: str, path: str) -> str:
    """
    Unified crime classifier:
    - Images → crime_detection.py (OpenCV vision + YOLO if available)
    - All files → keyword + content pattern matching
    Returns a specific crime category, never "Unclassified".
    """
    ext = os.path.splitext(name)[1].lower()
    IMAGE_EXTS = {".jpg",".jpeg",".png",".bmp",".tiff",".tif",".gif",".webp"}

    # --- IMAGE: use vision-based crime detection ---
    if ext in IMAGE_EXTS and os.path.exists(path):
        try:
            from modules.crime_detection import detect
            result = detect(path)
            crime  = result.get("crime_type","Unknown Crime Type")
            if result.get("success") and crime not in ("Unknown Crime Type","Needs Manual Review"):
                return crime
            elif crime == "Needs Manual Review":
                return crime   # Return threshold flag as-is
        except Exception:
            pass

    # --- ALL FILES: keyword + content matching ---
    text = name.lower()
    try:
        with open(path, "rb") as f:
            raw = f.read(16384)
        text += " " + raw.decode("utf-8", errors="replace").lower()
    except Exception:
        pass
    for keywords, crime in CRIME_TYPE_RULES:
        if any(kw in text for kw in keywords):
            return crime

    # --- Extension fallback ---
    ext_map = {
        frozenset({".exe",".dll",".scr",".com",".pif",".cpl"}): "Malware / Executable",
        frozenset({".pcap",".cap",".pcapng"}):                   "Network Forensics",
        frozenset({".eml",".msg",".mbox"}):                      "Email / Communication",
        frozenset({".jpg",".jpeg",".png",".bmp",".gif",
                   ".tiff",".webp"}):                            "Image Evidence",
        frozenset({".pdf",".docx",".xlsx",".txt",".csv"}):       "Document Evidence",
        frozenset({".log",".evt",".evtx"}):                      "System Log",
        frozenset({".mem",".dmp",".vmem"}):                      "Memory Forensics",
        frozenset({".db",".sqlite",".sqlite3"}):                  "Database Evidence",
    }
    for ext_set, crime in ext_map.items():
        if ext in ext_set:
            return crime
    return "Unknown Crime Type"


CATEGORY_MAP = {
    frozenset({".pcap",".cap",".pcapng",".netflow",".flow"}):       "Network Log",
    frozenset({".dd",".img",".iso",".raw",".vmdk",".e01",".aff"}):  "Disk Image",
    frozenset({".pdf",".docx",".doc",".xlsx",".xls",".pptx",
               ".odt",".txt",".csv",".rtf"}):                       "Document",
    frozenset({".exe",".dll",".bat",".scr",".com",".vbs",
               ".ps1",".sh",".py",".rb",".pl"}):                    "Executable / Script",
    frozenset({".jpg",".jpeg",".png",".bmp",".gif",".tiff",
               ".svg"}):                                             "Image",
    frozenset({".mp4",".avi",".mkv",".mov",".wmv",".flv",
               ".mp3",".wav",".aac"}):                              "Media",
    frozenset({".log",".evt",".evtx",".syslog"}):                   "Log File",
    frozenset({".zip",".rar",".7z",".tar",".gz",".bz2"}):          "Archive",
    frozenset({".eml",".msg",".mbox",".pst",".ost"}):               "Email",
    frozenset({".db",".sqlite",".sqlite3",".mdb",".accdb"}):        "Database",
    frozenset({".reg"}):                                             "Registry",
    frozenset({".mem",".dmp",".vmem"}):                             "Memory Dump",
}

def tag_evidence_category(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    for ext_set, cat in CATEGORY_MAP.items():
        if ext in ext_set:
            return cat
    return "Unknown"


# ---------------------------------------------------------------------------
#  AI Risk Score  (rule-based + YARA bonus)
# ---------------------------------------------------------------------------
def ai_risk_score(name: str, path: str) -> dict:
    score   = 0
    reasons = []
    ext     = os.path.splitext(name)[1].lower()

    # 1. Extension
    if ext in HIGH_RISK_EXT:
        score += 40; reasons.append("High-risk extension: " + ext)
    elif ext in MEDIUM_RISK_EXT:
        score += 20; reasons.append("Medium-risk extension: " + ext)
    elif ext not in SAFE_EXT and ext:
        score += 8;  reasons.append("Uncommon/unknown extension: " + ext)

    # 2. Double extension
    parts = name.split(".")
    if len(parts) > 2:
        score += 25; reasons.append("Double extension — possible file masquerading")

    # 3. Magic bytes vs extension mismatch
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        for magic, (desc, _) in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                if magic == b"MZ" and ext not in {".exe",".dll",".com",".scr",".msi"}:
                    score += 35; reasons.append("PE/EXE header disguised as " + (ext or "no-ext"))
                elif magic == b"\x7fELF" and ext not in {".elf","",".so"}:
                    score += 30; reasons.append("Linux ELF binary disguised as " + (ext or "unknown"))
                elif magic == b"\xca\xfe\xba\xbe" and ext != ".class":
                    score += 20; reasons.append("Java class file with wrong extension")
                break
    except Exception:
        pass

    # 4. Suspicious keyword scan (first 8 KB)
    try:
        with open(path, "rb") as f:
            sample = f.read(8192)
        hits = [kw.decode("utf-8", errors="replace") for kw in SUSPICIOUS_KW if kw in sample]
        if hits:
            score += min(30, len(hits) * 7)
            reasons.append("Suspicious strings: " + ", ".join(hits[:5]))
    except Exception:
        pass

    # 5. File size anomaly
    try:
        size_mb = os.path.getsize(path) / 1024 / 1024
        if size_mb > 100:
            score += 15; reasons.append(f"Very large file ({round(size_mb,1)} MB)")
        elif size_mb < 0.001 and ext in HIGH_RISK_EXT:
            score += 12; reasons.append("Tiny executable — possible dropper stub")
    except Exception:
        pass

    # 6. Byte entropy
    try:
        with open(path, "rb") as f:
            data = f.read(16384)
        if len(data) > 512:
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            entropy = 0.0
            L = len(data)
            for count in freq:
                if count:
                    p = count / L
                    entropy -= p * math.log2(p)
            if entropy > 7.6:
                score += 20; reasons.append(f"High entropy ({round(entropy,2)}/8.0) — encrypted/packed")
            elif entropy > 7.2:
                score += 10; reasons.append(f"Elevated entropy ({round(entropy,2)}/8.0)")
    except Exception:
        pass

    # 7. YARA rules bonus
    yara_matches = scan_file(path)
    if yara_matches:
        yara_bonus = severity_score(yara_matches)
        score += yara_bonus
        for m in yara_matches[:2]:
            reasons.append(f"YARA [{m['rule']}]: {m['description'][:60]}")

    score = min(score, 100)
    if   score >= 70: level = "HIGH_RISK"
    elif score >= 40: level = "MEDIUM_RISK"
    elif score >= 15: level = "LOW_RISK"
    else:             level = "CLEAN"

    if not reasons:
        reasons.append("No suspicious indicators detected")

    return {
        "score":        score,
        "level":        level,
        "reasons":      reasons,
        "yara_matches": yara_matches,
    }


# ---------------------------------------------------------------------------
#  Metadata extraction
# ---------------------------------------------------------------------------
def extract_metadata(name: str, path: str) -> dict:
    meta = {}
    ext  = os.path.splitext(name)[1].lower()
    try:
        st = os.stat(path)
        meta["File Size"]     = f"{round(st.st_size / 1024, 2)} KB"
        meta["Created"]       = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime))
        meta["Last Modified"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
        meta["Last Accessed"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime))
    except Exception:
        pass
    try:
        with open(path, "rb") as f:
            hdr = f.read(8)
        for magic, (desc, _) in MAGIC_SIGNATURES.items():
            if hdr.startswith(magic):
                meta["Detected File Type"] = desc
                break
        else:
            meta["Detected File Type"] = "Unknown / Binary"
    except Exception:
        pass

    if ext in {".jpg", ".jpeg"}:
        try:
            with open(path, "rb") as f:
                raw = f.read()
            for brand in [b"Apple",b"Canon",b"Nikon",b"Sony",b"Samsung",
                          b"Huawei",b"Google",b"Xiaomi",b"OLYMPUS",b"Fujifilm"]:
                if brand in raw:
                    meta["Camera Brand"] = brand.decode(); break
            if b"GPS" in raw:
                meta["GPS Data"] = "GPS coordinates present in EXIF block"
            idx = raw.find(b"Exif")
            if idx != -1:
                block = raw[idx: idx+2000]
                tokens, cur = [], b""
                for byte in block:
                    if 32 <= byte < 127:
                        cur += bytes([byte])
                    else:
                        if len(cur) >= 4: tokens.append(cur.decode("ascii", errors="ignore"))
                        cur = b""
                useful = [t for t in tokens if 4 <= len(t) <= 60 and not t.startswith("Exif")]
                if useful: meta["EXIF Strings"] = " | ".join(useful[:5])
        except Exception:
            pass

    if ext == ".png":
        try:
            with open(path, "rb") as f:
                f.read(8)
                while True:
                    lb = f.read(4)
                    if len(lb) < 4: break
                    length = struct.unpack(">I", lb)[0]
                    ctype  = f.read(4).decode("ascii", errors="ignore")
                    cdata  = f.read(length)
                    f.read(4)
                    if ctype == "IHDR":
                        W = struct.unpack(">I", cdata[0:4])[0]
                        H = struct.unpack(">I", cdata[4:8])[0]
                        meta["Image Dimensions"] = f"{W} x {H} px"
                    elif ctype == "tEXt":
                        parts = cdata.split(b"\x00", 1)
                        if len(parts) == 2:
                            meta["PNG " + parts[0].decode("ascii","ignore")] = parts[1].decode("ascii","ignore")[:100]
                    elif ctype == "IEND":
                        break
        except Exception:
            pass

    if ext == ".pdf":
        try:
            with open(path, "rb") as f:
                raw = f.read(10000).decode("latin-1", errors="ignore")
            if raw.startswith("%PDF-"):
                meta["PDF Version"] = raw[5:8]
            for field in ["Author","Title","Subject","Creator","Producer","CreationDate","ModDate","Keywords"]:
                marker = "/" + field + " ("
                i = raw.find(marker)
                if i != -1:
                    s = i + len(marker)
                    e = raw.find(")", s)
                    if e != -1: meta["PDF " + field] = raw[s:e][:100]
        except Exception:
            pass

    if ext == ".txt":
        try:
            with open(path, "r", errors="ignore") as f:
                text = f.read()
            meta["Lines"] = str(len(text.splitlines()))
            meta["Words"] = str(len(text.split()))
            meta["Chars"] = str(len(text))
            hits = [kw for kw in ["password","secret","delete","hack","exploit","payload","keylog"]
                    if kw in text.lower()]
            if hits: meta["Suspicious Keywords"] = ", ".join(hits)
        except Exception:
            pass

    if ext in {".exe",".dll",".scr"}:
        try:
            with open(path, "rb") as f:
                dos = f.read(64)
            if dos[:2] == b"MZ":
                pe_off = struct.unpack("<I", dos[60:64])[0]
                meta["PE Header Offset"] = hex(pe_off)
                with open(path, "rb") as f:
                    f.seek(pe_off); sig = f.read(4)
                meta["PE Signature Valid"] = "Yes" if sig == b"PE\x00\x00" else "No"
        except Exception:
            pass

    return meta


# ---------------------------------------------------------------------------
#  CNN + ML analysis simulation
#  Produces: feature vector, CNN decision, precision/recall per class,
#            confusion-matrix-style aggregated stats from DB evidence.
# ---------------------------------------------------------------------------
CNN_CLASSES = [
    "Clean",
    "Low Risk",
    "Medium Risk",
    "High Risk",
    "CRITICAL",
]

def extract_cnn_features(name: str, path: str) -> dict:
    """
    Extract numerical features for CNN-style classification.
    Returns a feature vector with interpretable names.
    """
    features = {}
    ext = os.path.splitext(name)[1].lower()

    # Feature 1: Extension risk score (0-1)
    if ext in HIGH_RISK_EXT:         features["ext_risk"]   = 1.0
    elif ext in MEDIUM_RISK_EXT:     features["ext_risk"]   = 0.6
    elif ext in SAFE_EXT:            features["ext_risk"]   = 0.05
    else:                            features["ext_risk"]   = 0.3

    # Feature 2: Double extension flag
    features["double_ext"] = 1.0 if len(name.split(".")) > 2 else 0.0

    # Feature 3: File entropy (normalized 0-1)
    entropy = 0.0
    try:
        with open(path, "rb") as f:
            data = f.read(16384)
        if len(data) > 512:
            freq = [0]*256
            for b in data: freq[b] += 1
            L = len(data)
            for count in freq:
                if count:
                    p = count / L
                    entropy -= p * math.log2(p)
        features["entropy"] = round(entropy / 8.0, 4)
    except Exception:
        features["entropy"] = 0.0

    # Feature 4: Magic byte mismatch (0 or 1)
    features["magic_mismatch"] = 0.0
    try:
        with open(path, "rb") as f:
            hdr = f.read(4)
        if hdr[:2] == b"MZ" and ext not in {".exe",".dll",".com",".scr",".msi"}:
            features["magic_mismatch"] = 1.0
        elif hdr[:4] == b"\x7fELF" and ext not in {".elf","",".so"}:
            features["magic_mismatch"] = 0.9
    except Exception:
        pass

    # Feature 5: Suspicious keyword density
    try:
        with open(path, "rb") as f:
            sample = f.read(8192)
        hits = sum(1 for kw in SUSPICIOUS_KW if kw in sample)
        features["kw_density"] = round(min(hits / 15.0, 1.0), 4)
    except Exception:
        features["kw_density"] = 0.0

    # Feature 6: YARA score (normalized)
    yara_matches = scan_file(path)
    features["yara_score"] = round(min(severity_score(yara_matches) / 50.0, 1.0), 4)

    # Feature 7: File size category
    try:
        size_kb = os.path.getsize(path) / 1024
        if size_kb < 1:          features["size_cat"] = 0.9   # suspiciously tiny
        elif size_kb < 100:      features["size_cat"] = 0.2
        elif size_kb < 10000:    features["size_cat"] = 0.1
        else:                    features["size_cat"] = 0.5   # very large
    except Exception:
        features["size_cat"] = 0.3

    return features


def cnn_predict(features: dict) -> dict:
    """
    Simulated CNN forward pass using weighted feature combination.
    Returns class probabilities and prediction.
    """
    # Weighted combination (simulating learned weights)
    weights = {
        "ext_risk":      0.30,
        "double_ext":    0.20,
        "entropy":       0.15,
        "magic_mismatch":0.20,
        "kw_density":    0.08,
        "yara_score":    0.05,
        "size_cat":      0.02,
    }
    score = sum(features.get(k, 0) * w for k, w in weights.items())

    # Map to class probabilities (softmax-like)
    if   score >= 0.75: probs = [0.01, 0.03, 0.06, 0.25, 0.65]
    elif score >= 0.55: probs = [0.02, 0.05, 0.10, 0.65, 0.18]
    elif score >= 0.35: probs = [0.05, 0.10, 0.60, 0.20, 0.05]
    elif score >= 0.15: probs = [0.10, 0.65, 0.18, 0.05, 0.02]
    else:               probs = [0.75, 0.17, 0.05, 0.02, 0.01]

    predicted_idx   = probs.index(max(probs))
    predicted_class = CNN_CLASSES[predicted_idx]
    confidence      = round(max(probs) * 100, 1)

    return {
        "predicted_class": predicted_class,
        "confidence":      confidence,
        "score":           round(score, 4),
        "class_probs":     dict(zip(CNN_CLASSES, [round(p*100,1) for p in probs])),
    }


def compute_confusion_matrix_data(evidence_rows: list) -> dict:
    """
    Build confusion matrix and precision/recall from all evidence in DB.
    Uses AI risk scoring as ground-truth proxy and CNN as predictor.
    """
    label_map = {
        "CLEAN":       "Clean",
        "LOW_RISK":    "Low Risk",
        "MEDIUM_RISK": "Medium Risk",
        "HIGH_RISK":   "High Risk",
    }
    classes = ["Clean", "Low Risk", "Medium Risk", "High Risk"]
    n = len(classes)

    # Initialize confusion matrix
    matrix = [[0]*n for _ in range(n)]
    idx_map = {c: i for i, c in enumerate(classes)}

    acc_history = []
    all_predictions = []

    for row in evidence_rows:
        name = row[2] if isinstance(row, (list, tuple)) else row["filename"]
        path = row[3] if isinstance(row, (list, tuple)) else row["path"]

        if not os.path.exists(path):
            continue

        risk    = ai_risk_score(name, path)
        true_lbl = label_map.get(risk["level"], "Clean")
        if true_lbl not in idx_map:
            continue

        features  = extract_cnn_features(name, path)
        cnn_pred  = cnn_predict(features)
        pred_lbl  = cnn_pred["predicted_class"]
        if pred_lbl not in idx_map:
            pred_lbl = "Clean"

        ti = idx_map[true_lbl]
        pi = idx_map[pred_lbl]
        matrix[ti][pi] += 1

        correct = (true_lbl == pred_lbl)
        all_predictions.append(correct)
        acc_history.append(sum(all_predictions) / len(all_predictions) * 100)

    # Compute per-class precision, recall, F1
    metrics = {}
    for i, cls in enumerate(classes):
        tp = matrix[i][i]
        fp = sum(matrix[j][i] for j in range(n)) - tp
        fn = sum(matrix[i][j] for j in range(n)) - tp
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        metrics[cls] = {
            "precision": round(precision * 100, 1),
            "recall":    round(recall    * 100, 1),
            "f1":        round(f1        * 100, 1),
            "support":   sum(matrix[i]),
        }

    overall_acc = (round(acc_history[-1], 1) if acc_history else 0.0)

    return {
        "classes":      classes,
        "matrix":       matrix,
        "metrics":      metrics,
        "accuracy":     overall_acc,
        "acc_history":  acc_history,
        "total_samples":len(all_predictions),
    }
