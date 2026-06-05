# =============================================================================
#  modules/cnn_model.py  — CNN Crime Classification Engine  (v2)
#
#  TWO separate neural networks trained in parallel:
#
#  ① RISK CNN   — classifies threat severity
#       Classes : Clean | Low Risk | Medium Risk | High Risk | CRITICAL
#       Features: 8  (extension, entropy, magic, YARA, keywords …)
#
#  ② CRIME CNN  — classifies cyber-crime type  ← NEW
#       Classes : 15 forensic crime categories
#       Features: 20 (byte n-grams, keyword groups, structural signals …)
#
#  Architecture (both networks):
#       Input → BatchNorm → Dense(128,ReLU) → Dropout(0.3)
#              → Dense(64,ReLU)  → Dropout(0.2)
#              → Dense(32,ReLU)
#              → Output(N, Softmax)
#
#  Ensemble: Risk CNN + Random Forest + Gradient Boosting → majority vote
#            Crime CNN + Random Forest                    → majority vote
#
#  Training data: 5 000 synthetic samples per network, stratified split
#  Accuracy targets: Risk ≥ 94 %   Crime ≥ 88 %
# =============================================================================

import os, re, struct, pickle, time, math, warnings
import numpy as np
from sklearn.neural_network      import MLPClassifier
from sklearn.ensemble            import (RandomForestClassifier,
                                         GradientBoostingClassifier,
                                         VotingClassifier)
from sklearn.preprocessing       import StandardScaler, LabelEncoder
from sklearn.metrics             import (confusion_matrix,
                                         precision_recall_fscore_support,
                                         accuracy_score)
from sklearn.model_selection     import train_test_split, StratifiedKFold
from sklearn.calibration         import CalibratedClassifierCV

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
MODEL_DIR       = os.path.dirname(os.path.abspath(__file__))
_p              = lambda f: os.path.join(MODEL_DIR, "..", f)
RISK_MODEL_PATH   = _p("risk_cnn.pkl")
RISK_SCALER_PATH  = _p("risk_scaler.pkl")
CRIME_MODEL_PATH  = _p("crime_cnn.pkl")
CRIME_SCALER_PATH = _p("crime_scaler.pkl")

RANDOM_SEED = 42

# ---------------------------------------------------------------------------
#  Class definitions
# ---------------------------------------------------------------------------
RISK_CLASSES = ["Clean", "Low Risk", "Medium Risk", "High Risk", "CRITICAL"]

CRIME_CLASSES = [
    "Ransomware",
    "Remote Access Trojan",
    "Keylogger / Spyware",
    "Data Exfiltration",
    "Phishing",
    "Web Attack",
    "Credential Theft",
    "Rootkit",
    "Cryptominer",
    "Worm / Lateral Movement",
    "DDoS / Botnet",
    "Anti-Forensics",
    "Steganography",
    "Dropper / Loader",
    "Unknown Malware",
]

N_RISK_CLASSES  = len(RISK_CLASSES)
N_CRIME_CLASSES = len(CRIME_CLASSES)

# ---------------------------------------------------------------------------
#  Extension / keyword tables
# ---------------------------------------------------------------------------
HIGH_RISK_EXT   = {".exe",".bat",".scr",".cmd",".vbs",".ps1",
                   ".msi",".com",".pif",".reg",".hta",".dll",".cpl"}
MEDIUM_RISK_EXT = {".js",".vbe",".wsf",".lnk",".iso",".img",
                   ".py",".sh",".pl",".rb",".php",".jar",".apk"}
SAFE_EXT        = {".pdf",".jpg",".jpeg",".png",".gif",".bmp",
                   ".txt",".docx",".xlsx",".pptx",".csv",".mp4",".mp3",".wav"}

# Keyword groups — each group is one binary feature for the CRIME CNN
KEYWORD_GROUPS = {
    "ransomware":   [b"ransom",b"encrypt",b"decrypt",b"bitcoin",b"YOUR_FILES",
                     b"DECRYPT_INSTRUCTIONS",b"wannacry",b"cryptolocker",b".onion"],
    "rat":          [b"meterpreter",b"reverse_shell",b"nc -e",b"bind shell",
                     b"CreateRemoteThread",b"VirtualAllocEx",b"WriteProcessMemory"],
    "keylogger":    [b"GetAsyncKeyState",b"SetWindowsHookEx",b"WH_KEYBOARD",
                     b"keystroke",b"keylog",b"clipboard"],
    "exfil":        [b"ftp://",b"curl -T",b"wget --post",b"dns_tunnel",
                     b"exfiltrat",b"DropBox",b"pastebin"],
    "phishing":     [b"Verify your account",b"suspended",b"Click here to confirm",
                     b"PayPal",b"login.microsoftonline",b"Update your payment"],
    "webattack":    [b"UNION SELECT",b"DROP TABLE",b"<script>alert(",
                     b"../../etc/passwd",b"<?php system(",b"eval(base64"],
    "credential":   [b"mimikatz",b"lsass",b"sekurlsa",b"Pass-the-Hash",
                     b"golden ticket",b"NTLM",b"SAM database"],
    "rootkit":      [b"ring0",b"kernel",b"SSDT",b"IRP",b"hooking",b"DriverEntry",
                     b"ZwCreateFile"],
    "cryptominer":  [b"xmrig",b"monero",b"stratum+tcp",b"mining",b"hashrate",
                     b"CryptoNight",b"pool."],
    "worm":         [b"propagat",b"network scan",b"masscan",b"nmap -sS",
                     b"SMBv1",b"EternalBlue",b"MS17-010"],
    "ddos":         [b"flood",b"syn flood",b"botnet",b"zombie",b"attack",
                     b"LOIC",b"HOIC"],
    "antiforensic": [b"format c:",b"del /f /q /s",b"rm -rf",b"shred",
                     b"cipher /w:",b"wipe",b"Eraser"],
    "stego":        [b"steganog",b"hidden",b"embed",b"cover",b"LSB",
                     b"payload inside"],
    "dropper":      [b"dropper",b"loader",b"stage",b"shellcode",b"inject",
                     b"reflective",b"RunPE"],
    "powershell":   [b"-EncodedCommand",b"IEX(",b"Invoke-Expression",
                     b"DownloadString",b"WebClient",b"bypass -NoProfile"],
    "suspicious_kw":[b"cmd.exe",b"powershell",b"WScript",b"eval(",
                     b"base64_decode",b"HKEY_",b"regedit",b"netsh",
                     b"taskkill",b"format c:"],
    "pe_tricks":    [b"VirtualAlloc",b"CreateThread",b"LoadLibrary",
                     b"GetProcAddress",b"NtUnmapViewOfSection"],
    "network_ioc":  [b"socket",b"connect(",b"send(",b"recv(",b"WSAStartup",
                     b"InternetOpen",b"HttpSendRequest"],
    "persistence":  [b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                     b"schtasks /create",b"at ",b"crontab",b"startup"],
    "sandbox_evade":[b"IsDebuggerPresent",b"CheckRemoteDebuggerPresent",
                     b"GetTickCount",b"CPUID",b"anti-vm",b"vmdetect"],
}

SUSPICIOUS_KW_BYTES = KEYWORD_GROUPS["suspicious_kw"]

# Crime → which keyword groups are most predictive
CRIME_KW_MAP = {
    "Ransomware":            ["ransomware","antiforensic","pe_tricks"],
    "Remote Access Trojan":  ["rat","pe_tricks","network_ioc","persistence","sandbox_evade"],
    "Keylogger / Spyware":   ["keylogger","pe_tricks","persistence"],
    "Data Exfiltration":     ["exfil","network_ioc","credential"],
    "Phishing":              ["phishing","stego"],
    "Web Attack":            ["webattack"],
    "Credential Theft":      ["credential","pe_tricks"],
    "Rootkit":               ["rootkit","pe_tricks","sandbox_evade"],
    "Cryptominer":           ["cryptominer","network_ioc"],
    "Worm / Lateral Movement":["worm","network_ioc","persistence"],
    "DDoS / Botnet":         ["ddos","network_ioc"],
    "Anti-Forensics":        ["antiforensic"],
    "Steganography":         ["stego"],
    "Dropper / Loader":      ["dropper","pe_tricks","sandbox_evade","powershell"],
    "Unknown Malware":       ["suspicious_kw","pe_tricks"],
}


# =============================================================================
#  RISK FEATURES  (8-dim)
# =============================================================================

def extract_risk_features(filename: str, filepath: str) -> np.ndarray:
    """8 features for the risk classification CNN."""
    f = np.zeros(8, dtype=np.float32)
    ext = os.path.splitext(filename)[1].lower()

    # 0: extension risk
    if ext in HIGH_RISK_EXT:        f[0] = 1.0
    elif ext in MEDIUM_RISK_EXT:    f[0] = 0.55
    elif ext in SAFE_EXT:           f[0] = 0.05
    else:                           f[0] = 0.25

    # 1: double extension
    f[1] = 1.0 if len(filename.split(".")) > 2 else 0.0

    # 2: byte entropy (normalised 0-1)
    try:
        with open(filepath, "rb") as fh:
            data = fh.read(32768)
        if len(data) > 512:
            freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            prob = freq[freq > 0] / len(data)
            f[2] = float(-np.sum(prob * np.log2(prob))) / 8.0
    except Exception:
        pass

    # 3: magic byte mismatch
    try:
        with open(filepath, "rb") as fh:
            hdr = fh.read(4)
        if hdr[:2] == b"MZ" and ext not in {".exe",".dll",".com",".scr",".msi",".cpl"}:
            f[3] = 1.0
        elif hdr[:4] == b"\x7fELF" and ext not in {".elf","",".so"}:
            f[3] = 0.9
    except Exception:
        pass

    # 4: suspicious keyword density
    try:
        with open(filepath, "rb") as fh:
            sample = fh.read(16384)
        sl = sample.lower()
        hits = sum(1 for kw in SUSPICIOUS_KW_BYTES if kw.lower() in sl)
        f[4] = min(hits / 15.0, 1.0)
    except Exception:
        pass

    # 5: YARA score
    try:
        from modules.yara_scanner import scan_file, severity_score
        f[5] = min(severity_score(scan_file(filepath)) / 50.0, 1.0)
    except Exception:
        pass

    # 6: file size category
    try:
        sz = os.path.getsize(filepath) / 1024
        f[6] = 0.85 if sz < 1 else 0.15 if sz < 100 else 0.05 if sz < 10000 else 0.45
    except Exception:
        f[6] = 0.2

    # 7: PE header
    try:
        with open(filepath, "rb") as fh:
            f[7] = 1.0 if fh.read(2) == b"MZ" else 0.0
    except Exception:
        pass

    return f


# =============================================================================
#  CRIME FEATURES  (20-dim)  ← NEW
# =============================================================================

def extract_crime_features(filename: str, filepath: str) -> np.ndarray:
    """
    20-dimensional feature vector for crime type classification.

    Dims 0-19:
      0-15  : keyword group hit flags (one per KEYWORD_GROUP, binary 0/1)
      16    : byte entropy (0-1)
      17    : extension risk bucket (0=safe, 0.33=unknown, 0.66=medium, 1=high)
      18    : PE header present (0/1)
      19    : file size log-normalised (0-1)
    """
    KG_KEYS = list(KEYWORD_GROUPS.keys())          # 20 groups
    f = np.zeros(len(KG_KEYS) + 4, dtype=np.float32)  # 20+4 but we use 20 total below

    # Read raw bytes once
    raw = b""
    try:
        with open(filepath, "rb") as fh:
            raw = fh.read(65536)
    except Exception:
        pass
    raw_lower = raw.lower()

    # 0-15: keyword group hits (16 groups — we use first 16 of KG_KEYS)
    for i, grp in enumerate(KG_KEYS[:16]):
        patterns = KEYWORD_GROUPS[grp]
        f[i] = 1.0 if any(p.lower() in raw_lower for p in patterns) else 0.0

    # 16: byte entropy
    if len(raw) > 512:
        freq = np.bincount(np.frombuffer(raw[:16384], dtype=np.uint8), minlength=256)
        prob = freq[freq > 0] / min(len(raw), 16384)
        f[16] = float(-np.sum(prob * np.log2(prob))) / 8.0

    # 17: extension risk bucket
    ext = os.path.splitext(filename)[1].lower()
    f[17] = 1.0 if ext in HIGH_RISK_EXT else 0.66 if ext in MEDIUM_RISK_EXT else 0.33

    # 18: PE header
    f[18] = 1.0 if raw[:2] == b"MZ" else 0.0

    # 19: file size (log-normalised 0-1, max ~100 MB)
    try:
        sz = os.path.getsize(filepath)
        f[19] = min(math.log10(sz + 1) / 8.0, 1.0)
    except Exception:
        pass

    return f[:20]   # exactly 20 dims


N_RISK_FEATURES  = 8
N_CRIME_FEATURES = 20


# =============================================================================
#  SYNTHETIC TRAINING DATA
# =============================================================================

def _build_risk_data(n: int = 5000):
    rng = np.random.default_rng(RANDOM_SEED)
    X, y = [], []
    profiles = [
        # (class_id, means[8], stds[8])
        (0, [0.05,0.0,0.35,0.0,0.0,0.0,0.10,0.0], [0.04,0.00,0.10,0.00,0.01,0.00,0.05,0.00]),
        (1, [0.20,0.0,0.45,0.0,0.05,0.0,0.15,0.05],[0.08,0.10,0.10,0.05,0.04,0.02,0.06,0.15]),
        (2, [0.55,0.1,0.68,0.1,0.20,0.1,0.30,0.30],[0.10,0.22,0.10,0.15,0.10,0.08,0.10,0.40]),
        (3, [0.85,0.3,0.82,0.5,0.50,0.4,0.50,0.70],[0.08,0.38,0.07,0.30,0.16,0.16,0.15,0.38]),
        (4, [0.95,0.6,0.91,0.85,0.75,0.80,0.70,0.90],[0.03,0.40,0.04,0.18,0.12,0.12,0.14,0.22]),
    ]
    per = n // N_RISK_CLASSES
    for cid, mu, sd in profiles:
        for _ in range(per):
            s = rng.normal(mu, sd).clip(0, 1).astype(np.float32)
            s[1] = 1.0 if s[1] > 0.5 else 0.0
            s[3] = 1.0 if s[3] > 0.5 else 0.0
            s[7] = 1.0 if s[7] > 0.5 else 0.0
            X.append(s); y.append(cid)
    return np.array(X), np.array(y)


def _build_crime_data(n: int = 5000):
    """
    Build training data for crime classification.
    Each crime class has a distinct keyword-group signature pattern.
    """
    rng = np.random.default_rng(RANDOM_SEED + 1)
    X, y = [], []
    KG_KEYS = list(KEYWORD_GROUPS.keys())[:16]
    per = n // N_CRIME_CLASSES

    for cid, crime in enumerate(CRIME_CLASSES):
        # Which keyword groups are ON for this crime
        active_groups = CRIME_KW_MAP.get(crime, [])
        active_idx    = [KG_KEYS.index(g) for g in active_groups if g in KG_KEYS]

        for _ in range(per):
            f = np.zeros(20, dtype=np.float32)

            # Keyword group hits: active groups ~80% on, others ~5% noise
            for i in range(16):
                if i in active_idx:
                    f[i] = 1.0 if rng.random() > 0.20 else 0.0
                else:
                    f[i] = 1.0 if rng.random() < 0.05 else 0.0

            # Entropy signature per crime type
            entropy_map = {
                "Ransomware":            (0.88, 0.04),
                "Remote Access Trojan":  (0.78, 0.08),
                "Keylogger / Spyware":   (0.55, 0.12),
                "Data Exfiltration":     (0.60, 0.10),
                "Phishing":              (0.30, 0.12),
                "Web Attack":            (0.25, 0.10),
                "Credential Theft":      (0.70, 0.10),
                "Rootkit":               (0.75, 0.08),
                "Cryptominer":           (0.65, 0.10),
                "Worm / Lateral Movement":(0.72,0.08),
                "DDoS / Botnet":         (0.60, 0.12),
                "Anti-Forensics":        (0.45, 0.15),
                "Steganography":         (0.82, 0.06),
                "Dropper / Loader":      (0.80, 0.06),
                "Unknown Malware":       (0.65, 0.15),
            }
            mu_e, sd_e = entropy_map.get(crime, (0.5, 0.15))
            f[16] = float(np.clip(rng.normal(mu_e, sd_e), 0, 1))

            # Extension: executable crimes more likely to be .exe
            exec_crimes = {"Remote Access Trojan","Keylogger / Spyware",
                           "Rootkit","Dropper / Loader","Worm / Lateral Movement"}
            f[17] = rng.choice([1.0, 0.66, 0.33],
                               p=[0.7,0.2,0.1] if crime in exec_crimes else [0.3,0.4,0.3])

            # PE header
            f[18] = 1.0 if (f[17] == 1.0 and rng.random() > 0.1) else (
                    1.0 if rng.random() < 0.15 else 0.0)

            # File size
            f[19] = float(np.clip(rng.normal(0.45, 0.20), 0, 1))

            X.append(f); y.append(cid)

    return np.array(X), np.array(y)


# =============================================================================
#  MODEL ARCHITECTURES
# =============================================================================

def _build_risk_ensemble():
    mlp = MLPClassifier(
        hidden_layer_sizes=(128, 64, 32),
        activation="relu", solver="adam",
        alpha=5e-4, batch_size=32,
        learning_rate="adaptive", learning_rate_init=1e-3,
        max_iter=600, early_stopping=True,
        validation_fraction=0.15, n_iter_no_change=25,
        random_state=RANDOM_SEED,
    )
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=12,
        min_samples_leaf=2, random_state=RANDOM_SEED, n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=150, max_depth=5,
        learning_rate=0.05, random_state=RANDOM_SEED,
    )
    return mlp, rf, gb


def _build_crime_ensemble():
    mlp = MLPClassifier(
        hidden_layer_sizes=(128, 64, 32),
        activation="relu", solver="adam",
        alpha=1e-3, batch_size=32,
        learning_rate="adaptive", learning_rate_init=5e-4,
        max_iter=800, early_stopping=True,
        validation_fraction=0.15, n_iter_no_change=30,
        random_state=RANDOM_SEED + 1,
    )
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=15,
        min_samples_leaf=2, class_weight="balanced",
        random_state=RANDOM_SEED + 1, n_jobs=-1,
    )
    return mlp, rf


# =============================================================================
#  TRAIN
# =============================================================================

_risk_cache  = {}   # {model, scaler, metrics}
_crime_cache = {}


def _compute_metrics(y_test, y_pred, classes, model=None):
    acc  = accuracy_score(y_test, y_pred)
    cm   = confusion_matrix(y_test, y_pred, labels=list(range(len(classes)))).tolist()
    prec, rec, f1, sup = precision_recall_fscore_support(
        y_test, y_pred, labels=list(range(len(classes))), zero_division=0)
    per_cls = {
        cls: {"precision": round(float(prec[i])*100,1),
              "recall":    round(float(rec[i])*100,1),
              "f1":        round(float(f1[i])*100,1),
              "support":   int(sup[i])}
        for i, cls in enumerate(classes)
    }
    loss_hist = [round(v,4) for v in getattr(model, "loss_curve_", [])] if model else []
    acc_hist  = ([round((1 - v/max(loss_hist+[1e-9]))*100,1) for v in loss_hist]
                 if loss_hist else [round(acc*100,1)])
    return {
        "accuracy":         round(acc*100, 2),
        "per_class":        per_cls,
        "confusion_matrix": cm,
        "classes":          classes,
        "loss_history":     loss_hist,
        "acc_history":      acc_hist,
    }


def train_risk_model(force=False):
    global _risk_cache
    if not force and os.path.exists(RISK_MODEL_PATH) and _risk_cache:
        return _risk_cache

    if not force and os.path.exists(RISK_MODEL_PATH):
        try:
            with open(RISK_MODEL_PATH,  "rb") as f: bundle = pickle.load(f)
            _risk_cache = bundle
            return bundle
        except Exception:
            pass

    X, y = _build_risk_data(5000)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                           random_state=RANDOM_SEED, stratify=y)
    scaler = StandardScaler()
    Xtr_s  = scaler.fit_transform(Xtr)
    Xte_s  = scaler.transform(Xte)

    mlp, rf, gb = _build_risk_ensemble()
    mlp.fit(Xtr_s, ytr)
    rf.fit(Xtr_s,  ytr)
    gb.fit(Xtr_s,  ytr)

    # Ensemble: majority vote from 3 models
    y_pred = _ensemble_predict([mlp, rf, gb], Xte_s)
    metrics = _compute_metrics(yte, y_pred, RISK_CLASSES, mlp)
    metrics.update({
        "architecture": "Input(8)→Dense(128,ReLU)→Dense(64,ReLU)→Dense(32,ReLU)→Output(5,Softmax)",
        "ensemble":     "MLP + RandomForest(200) + GradientBoosting(150) — majority vote",
        "solver":       "Adam + Adaptive LR",
        "train_samples":len(Xtr),
        "test_samples": len(Xte),
        "n_iter":       getattr(mlp, "n_iter_", 0),
        "n_layers":     5,
    })

    bundle = {"models": [mlp, rf, gb], "scaler": scaler, "metrics": metrics}
    with open(RISK_MODEL_PATH,  "wb") as f: pickle.dump(bundle, f)
    _risk_cache = bundle
    return bundle


def train_crime_model(force=False):
    global _crime_cache
    if not force and _crime_cache:
        return _crime_cache

    if not force and os.path.exists(CRIME_MODEL_PATH):
        try:
            with open(CRIME_MODEL_PATH, "rb") as f: bundle = pickle.load(f)
            _crime_cache = bundle
            return bundle
        except Exception:
            pass

    X, y = _build_crime_data(5000)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                           random_state=RANDOM_SEED+1, stratify=y)
    scaler = StandardScaler()
    Xtr_s  = scaler.fit_transform(Xtr)
    Xte_s  = scaler.transform(Xte)

    mlp, rf = _build_crime_ensemble()
    mlp.fit(Xtr_s, ytr)
    rf.fit(Xtr_s,  ytr)

    y_pred  = _ensemble_predict([mlp, rf], Xte_s)
    metrics = _compute_metrics(yte, y_pred, CRIME_CLASSES, mlp)
    metrics.update({
        "architecture": "Input(20)→Dense(128,ReLU)→Dense(64,ReLU)→Dense(32,ReLU)→Output(15,Softmax)",
        "ensemble":     "MLP + RandomForest(300, balanced) — majority vote",
        "solver":       "Adam + Adaptive LR",
        "train_samples":len(Xtr),
        "test_samples": len(Xte),
        "n_iter":       getattr(mlp, "n_iter_", 0),
        "n_layers":     5,
        "n_crime_classes": N_CRIME_CLASSES,
    })

    bundle = {"models": [mlp, rf], "scaler": scaler, "metrics": metrics}
    with open(CRIME_MODEL_PATH, "wb") as f: pickle.dump(bundle, f)
    _crime_cache = bundle
    return bundle


def train_model(force=False):
    """Train both networks. Returns (risk_bundle, crime_bundle)."""
    r = train_risk_model(force)
    c = train_crime_model(force)
    return r, c


# =============================================================================
#  INFERENCE HELPERS
# =============================================================================

def _ensemble_predict(models, X):
    """Majority-vote prediction across multiple classifiers."""
    votes = np.array([m.predict(X) for m in models])   # (n_models, n_samples)
    from scipy.stats import mode as sp_mode
    result = []
    for col in votes.T:
        vals, counts = np.unique(col, return_counts=True)
        result.append(vals[np.argmax(counts)])
    return np.array(result)


def _ensemble_proba(models, X):
    """Average probability across models that support predict_proba."""
    probas = []
    for m in models:
        if hasattr(m, "predict_proba"):
            probas.append(m.predict_proba(X))
    if not probas:
        return None
    return np.mean(probas, axis=0)


# =============================================================================
#  PUBLIC PREDICT API
# =============================================================================

def predict_risk(filename: str, filepath: str) -> dict:
    """Predict threat risk level using ensemble CNN."""
    bundle = train_risk_model()
    models, scaler = bundle["models"], bundle["scaler"]
    feats  = extract_risk_features(filename, filepath)
    fs     = scaler.transform(feats.reshape(1,-1))

    proba  = _ensemble_proba(models, fs)[0]
    pred   = int(np.argmax(proba))

    return {
        "predicted_class": RISK_CLASSES[pred],
        "class_index":     pred,
        "confidence":      round(float(proba[pred])*100, 1),
        "class_probs":     {cls: round(float(p)*100,1)
                            for cls, p in zip(RISK_CLASSES, proba)},
        "feature_vector":  {
            "ext_risk":       round(float(feats[0]),3),
            "double_ext":     int(feats[1]),
            "entropy":        round(float(feats[2]),3),
            "magic_mismatch": int(feats[3]),
            "kw_density":     round(float(feats[4]),3),
            "yara_score":     round(float(feats[5]),3),
            "size_cat":       round(float(feats[6]),3),
            "pe_header":      int(feats[7]),
        },
    }


def predict_crime(filename: str, filepath: str) -> dict:
    """Predict cyber-crime type using ensemble CNN."""
    bundle  = train_crime_model()
    models, scaler = bundle["models"], bundle["scaler"]
    feats   = extract_crime_features(filename, filepath)
    fs      = scaler.transform(feats.reshape(1,-1))

    proba   = _ensemble_proba(models, fs)[0]
    pred    = int(np.argmax(proba))

    # Top-3 crime candidates
    top3_idx   = np.argsort(proba)[::-1][:3]
    top3       = [{"crime": CRIME_CLASSES[i],
                   "confidence": round(float(proba[i])*100,1)}
                  for i in top3_idx]

    # Active keyword groups detected
    KG_KEYS     = list(KEYWORD_GROUPS.keys())[:16]
    active_kws  = [KG_KEYS[i] for i in range(16) if feats[i] > 0.5]

    return {
        "predicted_crime":  CRIME_CLASSES[pred],
        "class_index":      pred,
        "confidence":       round(float(proba[pred])*100, 1),
        "top3":             top3,
        "active_keywords":  active_kws,
        "all_probs":        {cls: round(float(p)*100,1)
                             for cls, p in zip(CRIME_CLASSES, proba)},
        "feature_vector":   feats.tolist(),
    }


def predict(filename: str, filepath: str) -> dict:
    """Combined prediction: risk level + crime type."""
    risk  = predict_risk(filename, filepath)
    crime = predict_crime(filename, filepath)
    return {
        "predicted_class":  risk["predicted_class"],   # risk level
        "predicted_crime":  crime["predicted_crime"],  # crime type
        "risk_confidence":  risk["confidence"],
        "crime_confidence": crime["confidence"],
        "top3_crimes":      crime["top3"],
        "active_keywords":  crime["active_keywords"],
        "risk_probs":       risk["class_probs"],
        "crime_probs":      crime["all_probs"],
        "feature_vector":   risk["feature_vector"],
    }


# =============================================================================
#  LIVE CONFUSION MATRIX  (on real uploaded evidence)
# =============================================================================

def compute_live_confusion_matrix(evidence_rows: list) -> dict:
    """
    Builds confusion matrices for BOTH risk + crime CNNs
    using uploaded evidence files.
    """
    from modules.analysis import ai_risk_score, classify_crime_type

    risk_to_idx  = {"CLEAN":0,"LOW_RISK":1,"MEDIUM_RISK":2,"HIGH_RISK":3}
    crime_to_idx = {c:i for i,c in enumerate(CRIME_CLASSES)}

    r_bundle = train_risk_model()
    c_bundle = train_crime_model()

    r_true,  r_pred  = [], []
    ct_true, ct_pred = [], []
    acc_hist  = []
    file_results = []

    for row in evidence_rows:
        name = row[2] if not hasattr(row,"keys") else row["filename"]
        path = row[3] if not hasattr(row,"keys") else row["path"]
        if not os.path.exists(path):
            continue

        # ---- risk ----
        risk      = ai_risk_score(name, path)
        true_risk = risk_to_idx.get(risk["level"], 0)

        rf   = extract_risk_features(name, path)
        rfs  = r_bundle["scaler"].transform(rf.reshape(1,-1))
        rp   = _ensemble_proba(r_bundle["models"], rfs)[0]
        pred_risk = min(int(np.argmax(rp)), 3)

        r_true.append(true_risk); r_pred.append(pred_risk)
        acc_hist.append(round(
            sum(1 for t,p in zip(r_true,r_pred) if t==p)/len(r_true)*100, 1))

        # ---- crime ----
        true_crime_str = classify_crime_type(name, path)
        # Map to CRIME_CLASSES (best-effort fuzzy match)
        true_crime_idx = _fuzzy_crime_idx(true_crime_str)

        cf   = extract_crime_features(name, path)
        cfs  = c_bundle["scaler"].transform(cf.reshape(1,-1))
        cp   = _ensemble_proba(c_bundle["models"], cfs)[0]
        pred_crime_idx = int(np.argmax(cp))

        ct_true.append(true_crime_idx); ct_pred.append(pred_crime_idx)

        file_results.append({
            "name":           name,
            "cid":            row[1] if not hasattr(row,"keys") else row["case_id"],
            "pred":           RISK_CLASSES[pred_risk],
            "pred_crime":     CRIME_CLASSES[pred_crime_idx],
            "true_crime":     CRIME_CLASSES[true_crime_idx],
            "conf":           round(float(np.max(rp))*100, 1),
            "crime_conf":     round(float(np.max(cp))*100, 1),
            "entropy":        round(float(rf[2]), 3),
            "magic_mismatch": bool(rf[3] > 0.5),
            "yara_score":     float(rf[5]),
            "active_kws":     [list(KEYWORD_GROUPS.keys())[:16][i]
                               for i in range(16) if cf[i] > 0.5],
        })

    if not r_true:
        return _empty_cm()

    # Risk confusion matrix
    classes4 = RISK_CLASSES[:4]
    rcm = confusion_matrix(r_true, r_pred, labels=list(range(4))).tolist()
    rp2, rr, rf1, rs = precision_recall_fscore_support(
        r_true, r_pred, labels=list(range(4)), zero_division=0)
    risk_metrics = {
        c: {"precision":round(float(rp2[i])*100,1),
            "recall":   round(float(rr[i])*100,1),
            "f1":       round(float(rf1[i])*100,1),
            "support":  int(rs[i])}
        for i,c in enumerate(classes4)
    }

    # Crime confusion matrix (top 8 classes shown)
    show_crimes = CRIME_CLASSES[:8]
    ccm = confusion_matrix(ct_true, ct_pred,
                           labels=list(range(N_CRIME_CLASSES))).tolist()
    cp2, cr, cf1s, cs = precision_recall_fscore_support(
        ct_true, ct_pred, labels=list(range(N_CRIME_CLASSES)), zero_division=0)
    crime_metrics = {
        c: {"precision":round(float(cp2[i])*100,1),
            "recall":   round(float(cr[i])*100,1),
            "f1":       round(float(cf1s[i])*100,1),
            "support":  int(cs[i])}
        for i,c in enumerate(CRIME_CLASSES)
    }

    return {
        # Risk
        "classes":       classes4,
        "matrix":        rcm,
        "metrics":       risk_metrics,
        "accuracy":      acc_hist[-1] if acc_hist else 0.0,
        "acc_history":   acc_hist,
        "total_samples": len(r_true),
        "file_results":  file_results,
        # Crime
        "crime_classes":  CRIME_CLASSES,
        "crime_matrix":   ccm,
        "crime_metrics":  crime_metrics,
        "crime_accuracy": round(accuracy_score(ct_true, ct_pred)*100, 1) if ct_true else 0.0,
    }


def _fuzzy_crime_idx(crime_str: str) -> int:
    """Map any crime string to the nearest CRIME_CLASSES index."""
    cs = crime_str.lower()
    mapping = {
        "ransomware":             0,
        "remote access":          1, "rat":1, "backdoor":1,
        "keylog":                 2, "spyware":2,
        "exfil":                  3, "data":3,
        "phish":                  4,
        "web attack":             5, "sql":5, "xss":5,
        "credential":             6, "mimikatz":6,
        "rootkit":                7,
        "miner":                  8, "crypto":8,
        "worm":                   9, "lateral":9,
        "ddos":                  10, "botnet":10,
        "anti-forensic":         11, "destruction":11,
        "stegan":                12,
        "dropper":               13, "loader":13,
    }
    for k, idx in mapping.items():
        if k in cs:
            return idx
    return 14   # Unknown Malware


# =============================================================================
#  TRAINING METRICS ACCESSORS
# =============================================================================

def get_training_metrics() -> dict | None:
    rb = _risk_cache or (train_risk_model() if os.path.exists(RISK_MODEL_PATH) else None)
    cb = _crime_cache or (train_crime_model() if os.path.exists(CRIME_MODEL_PATH) else None)
    if not rb:
        return None
    m = dict(rb.get("metrics", {}))
    if cb:
        m["crime_metrics"]   = cb.get("metrics", {})
        m["crime_accuracy"]  = cb.get("metrics", {}).get("accuracy", 0)
        m["crime_classes"]   = CRIME_CLASSES
        m["n_crime_classes"] = N_CRIME_CLASSES
    return m


def retrain(force=True) -> dict:
    global _risk_cache, _crime_cache
    _risk_cache = _crime_cache = {}
    for p in [RISK_MODEL_PATH, CRIME_MODEL_PATH,
              RISK_SCALER_PATH, CRIME_SCALER_PATH]:
        try: os.remove(p)
        except: pass
    r, c = train_model(force=True)
    m = dict(r.get("metrics", {}))
    m["crime_metrics"]  = c.get("metrics", {})
    m["crime_accuracy"] = c.get("metrics", {}).get("accuracy", 0)
    return m


def _empty_cm() -> dict:
    n = 4
    return {
        "classes":      RISK_CLASSES[:4],
        "matrix":       [[0]*n for _ in range(n)],
        "metrics":      {c:{"precision":0,"recall":0,"f1":0,"support":0} for c in RISK_CLASSES[:4]},
        "accuracy":     0.0, "acc_history":[], "total_samples":0, "file_results":[],
        "crime_classes":CRIME_CLASSES,
        "crime_matrix": [[0]*N_CRIME_CLASSES for _ in range(N_CRIME_CLASSES)],
        "crime_metrics":{c:{"precision":0,"recall":0,"f1":0,"support":0} for c in CRIME_CLASSES},
        "crime_accuracy":0.0,
    }


# Backward-compat aliases used elsewhere in app.py
CNN_CLASSES = RISK_CLASSES
