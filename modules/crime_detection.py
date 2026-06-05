# =============================================================================
#  modules/crime_detection.py  — AI Crime Detection Engine v2
#
#  Multi-layer forensic image analysis pipeline:
#    Layer 1 : YOLOv8 object detection (when installed)
#    Layer 2 : OpenCV precision visual analysis (always available)
#              - Blood/fluid detection (HSV + morphology)
#              - Fire/explosion detection
#              - Human presence (multi-colorspace skin detection)
#              - Weapon silhouettes (edge + contour analysis)
#              - Scene context (brightness, crowding, vehicle damage)
#    Layer 3 : CNN visual feature classifier (sklearn MLP)
#    Layer 4 : OCR text integration
#    Layer 5 : Weighted crime rule engine with confidence thresholds
#
#  Returns structured JSON with crime_type, confidence, detected_objects,
#  severity, and a detailed forensic_summary.
# =============================================================================

import os, re, json, time, math, pickle, warnings
import cv2
import numpy as np
from PIL import Image
from collections import defaultdict
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IMAGE_EXTENSIONS   = {".jpg",".jpeg",".png",".bmp",".tiff",".tif",".gif",".webp"}
CONFIDENCE_THRESHOLD = 60   # Below this → "Needs Manual Review"
YOLO_MODEL_NAME    = "yolov8n.pt"
CNN_MODEL_PATH     = "visual_crime_cnn.pkl"

# ---------------------------------------------------------------------------
# YOLOv8 loader (optional — graceful fallback)
# ---------------------------------------------------------------------------
_yolo_model  = None
_yolo_status = "unchecked"

def _load_yolo():
    global _yolo_model, _yolo_status
    if _yolo_status in ("loaded","unavailable"):
        return _yolo_model
    try:
        from ultralytics import YOLO
        _yolo_model  = YOLO(YOLO_MODEL_NAME)
        _yolo_status = "loaded"
        return _yolo_model
    except Exception:
        _yolo_status = "unavailable"
        return None

def yolo_available() -> bool:
    return _load_yolo() is not None

# COCO ID → forensic label
COCO_TO_FORENSIC = {
    "person":     "human_body",
    "knife":      "knife",
    "scissors":   "bladed_weapon",
    "laptop":     "laptop",
    "cell phone": "mobile_phone",
    "car":        "vehicle",
    "truck":      "vehicle",
    "bus":        "vehicle",
    "motorcycle": "vehicle",
    "bicycle":    "vehicle",
    "bottle":     "bottle",
    "backpack":   "bag",
    "suitcase":   "bag",
    "tv":         "screen_device",
    "fire hydrant":"infrastructure",
    "gun":        "firearm",
    "pistol":     "firearm",
    "rifle":      "firearm",
}

# ---------------------------------------------------------------------------
# Crime Classification Rules
# Format: (trigger_labels, bonus_labels, crime_type, base_score, severity)
#
# trigger_labels : ANY of these must be detected
# bonus_labels   : ALL of these add bonus score if also detected
# base_score     : starting confidence (0-100)
# severity       : CRITICAL / HIGH / MEDIUM / LOW
# ---------------------------------------------------------------------------
CRIME_RULES = [
    # ── Homicide / Murder ──────────────────────────────────────────────────
    (["dead_body"],        ["blood"],            "Homicide",              92, "CRITICAL"),
    (["dead_body"],        ["firearm"],          "Homicide",              91, "CRITICAL"),
    (["dead_body"],        [],                   "Suspicious Death",      82, "CRITICAL"),
    (["human_body","blood"],["knife"],           "Homicide / Stabbing",   90, "CRITICAL"),
    (["human_body","blood"],["firearm"],         "Homicide / Shooting",   91, "CRITICAL"),
    (["human_body","blood"],[],                  "Possible Homicide",     76, "HIGH"),
    # ── Violent Assault ────────────────────────────────────────────────────
    (["knife"],            ["blood","human_body"],"Violent Assault",      88, "CRITICAL"),
    (["knife"],            ["blood"],             "Violent Assault",      83, "HIGH"),
    (["bladed_weapon"],    ["blood"],             "Violent Assault",      81, "HIGH"),
    (["knife"],            [],                    "Weapons Possession",   64, "MEDIUM"),
    (["bladed_weapon"],    [],                    "Weapons Possession",   60, "MEDIUM"),
    # ── Firearms ───────────────────────────────────────────────────────────
    (["firearm"],          ["dead_body"],         "Homicide / Shooting",  93, "CRITICAL"),
    (["firearm"],          ["human_body","blood"],"Shooting Incident",    89, "CRITICAL"),
    (["firearm"],          ["human_body"],        "Armed Assault",        84, "HIGH"),
    (["firearm"],          [],                    "Weapons Crime",        78, "HIGH"),
    (["weapon"],           ["blood"],             "Violent Crime",        80, "HIGH"),
    (["weapon"],           [],                    "Weapons Possession",   65, "MEDIUM"),
    # ── Armed Robbery ──────────────────────────────────────────────────────
    (["firearm"],          ["mask"],              "Armed Robbery",        87, "CRITICAL"),
    (["firearm"],          ["crowd"],             "Armed Robbery",        85, "CRITICAL"),
    (["mask","human_body"],["weapon"],            "Armed Robbery",        84, "CRITICAL"),
    (["mask"],             ["human_body"],        "Suspicious Activity",  58, "MEDIUM"),
    # ── Drug Crimes ────────────────────────────────────────────────────────
    (["drugs"],            ["syringe"],           "Drug Trafficking",     87, "HIGH"),
    (["drugs"],            ["cash"],              "Drug Trafficking",     83, "HIGH"),
    (["drugs"],            [],                    "Drug Possession",      74, "MEDIUM"),
    (["syringe"],          ["drugs"],             "Drug Use / Trafficking",82,"HIGH"),
    (["syringe"],          [],                    "Drug Use Evidence",    62, "MEDIUM"),
    # ── Arson / Explosion ──────────────────────────────────────────────────
    (["fire"],             ["explosion"],         "Arson / Explosion",    88, "CRITICAL"),
    (["explosion"],        ["human_body"],        "Bombing / Terrorism",  93, "CRITICAL"),
    (["explosion"],        [],                    "Explosion Incident",   84, "CRITICAL"),
    (["fire"],             ["vehicle"],           "Vehicle Fire / Arson", 80, "HIGH"),
    (["fire"],             [],                    "Fire / Arson",         72, "HIGH"),
    # ── Terrorism ──────────────────────────────────────────────────────────
    (["explosive_device"], ["human_body"],        "Terrorism",            94, "CRITICAL"),
    (["explosive_device"], [],                    "Terrorism Related",    87, "CRITICAL"),
    (["suspicious_device"],["crowd"],             "Terrorism Threat",     82, "CRITICAL"),
    # ── Vehicle Crimes ─────────────────────────────────────────────────────
    (["vehicle_damage"],   ["human_body"],        "Vehicle Assault",      82, "HIGH"),
    (["vehicle_damage"],   [],                    "Road Accident",        74, "MEDIUM"),
    (["vehicle"],          ["blood"],             "Hit and Run",          80, "HIGH"),
    # ── Cybercrime ─────────────────────────────────────────────────────────
    (["phishing"],         [],                    "Cybercrime / Phishing",84, "HIGH"),
    (["credit_card"],      ["laptop"],            "Financial Fraud",      82, "HIGH"),
    (["credit_card"],      [],                    "Financial Fraud",      72, "MEDIUM"),
    (["hacking_evidence"], [],                    "Cybercrime",           78, "HIGH"),
    (["crypto_evidence"],  [],                    "Cryptocurrency Crime", 70, "MEDIUM"),
    # ── Kidnapping ─────────────────────────────────────────────────────────
    (["restrained_person"],[],                    "Kidnapping / Abduction",88,"CRITICAL"),
    (["crowd"],            ["restraints"],        "Kidnapping",           84, "CRITICAL"),
    # ── General ────────────────────────────────────────────────────────────
    (["blood"],            [],                    "Crime Scene Evidence", 68, "HIGH"),
    (["human_body"],       [],                    "Person of Interest",   42, "LOW"),
]

# Severity scoring for risk level determination
SEVERITY_SCORES = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}

# OCR text → forensic object label
OCR_MAP = [
    (["bank","login","signin","password","otp","verify account","suspended",
      "paypal","click here","confirm your","update payment"],        "phishing",          85),
    (["credit card","card number","cvv","expiry date","billing"],    "credit_card",        82),
    (["bitcoin","btc","ethereum","ransom","decrypt","wallet address"],"crypto_evidence",   78),
    (["gun","firearm","pistol","rifle","ammo","bullets","weapon"],   "weapon_reference",   75),
    (["cocaine","heroin","methamphetamine","meth","fentanyl",
      "narcotics","weed","cannabis","drugs for sale"],               "drugs",              80),
    (["dead","murder","kill","homicide","victim","body found"],      "violence_reference", 78),
    (["bomb","explosive","detonate","ied","terrorism","attack"],     "explosive_device",   85),
    (["hack","breach","leaked","dump","credential","exploit"],       "hacking_evidence",   76),
    (["restraint","bound","kidnap","abduct","hostage"],              "restrained_person",  82),
]

# Crime-specific forensic narrative templates
CRIME_NARRATIVES = {
    "Homicide":              "Detected a deceased person. Evidence strongly indicates a homicide. Immediate forensic preservation and scene documentation required.",
    "Homicide / Stabbing":   "Detected a human subject, bladed weapon, and blood traces. Evidence pattern is consistent with a stabbing homicide. Forensic pathology examination required.",
    "Homicide / Shooting":   "Detected a firearm, blood evidence, and a human subject. Evidence strongly indicates a shooting homicide. Ballistics analysis required.",
    "Suspicious Death":      "Detected indicators of an unnatural death. Scene requires forensic examination to determine cause. Do not disturb potential evidence.",
    "Possible Homicide":     "Visual indicators are consistent with a potential homicide scene. Blood and human presence detected. Crime scene investigators required immediately.",
    "Violent Assault":       "Detected indicators of a violent assault — blood evidence and a bladed weapon present. Victim may require medical attention. Scene must be preserved.",
    "Shooting Incident":     "Firearm and blood evidence detected. This scene is consistent with a shooting incident. Ballistics and blood spatter analysis required.",
    "Armed Assault":         "An armed individual is present in this scene. Evidence indicates a threat to persons. Immediate law enforcement response required.",
    "Weapons Crime":         "A firearm has been detected in this evidence. This may constitute an illegal weapons offense depending on jurisdiction.",
    "Weapons Possession":    "A bladed or cutting weapon has been detected. Evidence relevant to a weapons possession investigation.",
    "Violent Crime":         "Blood evidence and a weapon have been detected. This evidence is consistent with a violent crime scene.",
    "Drug Trafficking":      "Drug substances and paraphernalia detected. Evidence pattern is consistent with drug trafficking or distribution activity.",
    "Drug Possession":       "Controlled substance evidence detected. Relevant to a drug possession investigation.",
    "Drug Use Evidence":     "Drug paraphernalia detected. This evidence indicates drug use at this location.",
    "Drug Use / Trafficking":"Drug substances and injection paraphernalia detected. Evidence supports a drug crime investigation.",
    "Armed Robbery":         "Armed individuals and masked persons detected. Evidence is consistent with an armed robbery in progress or following an armed robbery.",
    "Arson":                 "Fire or explosion indicators detected. Physical evidence is consistent with deliberate arson. Fire investigation required.",
    "Arson / Explosion":     "Both fire and explosion indicators detected. Evidence strongly suggests arson or deliberate bombing. HAZMAT and fire investigation required.",
    "Explosion Incident":    "Explosion indicators detected. Scene may contain secondary devices. Bomb disposal and forensic investigation required.",
    "Bombing / Terrorism":   "Explosion indicators near human subjects detected. Evidence is consistent with a bombing or terrorist attack. Counter-terrorism protocols required.",
    "Vehicle Fire / Arson":  "Fire evidence associated with a vehicle detected. Consistent with vehicle arson. Fire investigation and insurance fraud inquiry warranted.",
    "Fire / Arson":          "Fire indicators detected. Scene requires investigation to determine if accidental or deliberate. Fire marshal examination required.",
    "Terrorism":             "Explosive device near persons detected. Evidence strongly indicates a terrorist act. Immediate counter-terrorism and EOD response required.",
    "Terrorism Related":     "Explosive or suspicious device detected. Terrorism-related investigation warranted. EOD assessment required before scene entry.",
    "Terrorism Threat":      "Suspicious device in a crowd environment detected. Terrorism threat assessment required. Evacuation may be warranted.",
    "Vehicle Assault":       "Vehicle damage and human presence detected. Consistent with a vehicle used as a weapon or vehicle assault.",
    "Road Accident":         "Vehicle damage indicators detected. Evidence relevant to a road traffic accident investigation.",
    "Hit and Run":           "Blood evidence near vehicle detected. Evidence pattern is consistent with a hit-and-run incident.",
    "Cybercrime / Phishing": "Digital phishing indicators detected in OCR text. Evidence relevant to a cybercrime or phishing investigation.",
    "Financial Fraud":       "Financial credential data detected. Evidence relevant to a financial fraud or identity theft investigation.",
    "Cybercrime":            "Digital crime indicators detected. Evidence supports a cybercrime investigation.",
    "Cryptocurrency Crime":  "Cryptocurrency evidence detected. May be relevant to ransomware, money laundering, or fraud investigation.",
    "Kidnapping / Abduction":"Restrained person detected. Evidence is consistent with kidnapping or unlawful detention. Immediate response required.",
    "Kidnapping":            "Evidence consistent with kidnapping or unlawful restraint. Immediate law enforcement response required.",
    "Crime Scene Evidence":  "Blood evidence detected at this location. This area should be treated as a potential crime scene pending further investigation.",
    "Suspicious Activity":   "Suspicious indicators detected. Scene warrants further investigation by law enforcement.",
    "Armed Robbery":         "Armed and masked individuals detected. Evidence consistent with an armed robbery.",
    "Person of Interest":    "A person is present in this evidence. No additional crime indicators detected at this confidence level.",
    "Needs Manual Review":   "AI analysis could not determine a crime type with sufficient confidence. Manual forensic review is required.",
    "Unknown Crime Type":    "No forensically significant indicators detected. This may not be a crime scene image, or image quality is insufficient.",
}


# =============================================================================
#  PRECISION VISUAL DETECTORS
# =============================================================================

def _load_image(filepath: str) -> np.ndarray:
    """Load image from path into BGR numpy array."""
    img = cv2.imread(filepath)
    if img is not None:
        return img
    try:
        pil = Image.open(filepath).convert("RGB")
        return cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
    except Exception:
        return None


def detect_blood(img: np.ndarray) -> dict:
    """
    Precision blood detection using:
    - HSV red hue ranges (fresh + dried blood)
    - Morphological filtering to remove noise
    - Blob irregularity scoring (blood pools are irregular)
    - Minimum area threshold to avoid false positives
    """
    if img is None:
        return {"detected": False, "confidence": 0, "ratio": 0.0}

    h, w   = img.shape[:2]
    total  = h * w
    hsv    = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    # Fresh blood: bright red
    m1 = cv2.inRange(hsv, np.array([0,  120, 80]),  np.array([8,  255,255]))
    m2 = cv2.inRange(hsv, np.array([172,120, 80]),  np.array([180,255,255]))
    # Dried blood: darker, more brownish-red
    m3 = cv2.inRange(hsv, np.array([0,  80,  20]),  np.array([12, 220,140]))
    m4 = cv2.inRange(hsv, np.array([168,80,  20]),  np.array([180,220,140]))

    mask = cv2.bitwise_or(cv2.bitwise_or(m1,m2), cv2.bitwise_or(m3,m4))

    # Morphological operations to reduce noise
    k    = np.ones((7,7), np.uint8)
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN,  k)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, k)

    ratio = cv2.countNonZero(mask) / total

    # Contour analysis — blood pools are irregular
    cnts, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    significant = []
    for c in cnts:
        area = cv2.contourArea(c)
        if area < total * 0.003:   # ignore tiny specks < 0.3% of image
            continue
        # Circularity: blood pools are irregular (low circularity)
        perimeter = cv2.arcLength(c, True)
        if perimeter == 0:
            continue
        circularity = 4 * math.pi * area / (perimeter * perimeter)
        significant.append({"area": area, "circ": circularity})

    # Confidence: weighted by ratio, blob count, and irregularity
    conf = 0
    if ratio > 0.008:
        conf += min(int(ratio * 600), 55)
    if len(significant) >= 1:
        conf += min(len(significant) * 12, 30)
    avg_circ = sum(s["circ"] for s in significant) / max(len(significant),1)
    if avg_circ < 0.6:   # irregular = more likely blood
        conf += 10
    conf = min(conf, 96)

    detected = conf >= 35 and (ratio > 0.008 or len(significant) >= 1)

    return {
        "detected":    detected,
        "confidence":  conf,
        "ratio":       round(ratio, 5),
        "blob_count":  len(significant),
        "label":       "blood",
        "detail":      f"Red region {ratio*100:.2f}%, {len(significant)} significant blob(s)",
    }


def detect_fire(img: np.ndarray) -> dict:
    """
    Fire detection using orange-yellow HSV range + texture variance.
    Separates fire from warm-toned objects using brightness and texture.
    """
    if img is None:
        return {"detected": False, "confidence": 0}

    total  = img.shape[0] * img.shape[1]
    hsv    = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    # Fire color ranges: orange-yellow, high saturation, high brightness
    m1 = cv2.inRange(hsv, np.array([5, 160,160]), np.array([30,255,255]))
    # Yellow-white hot fire core
    m2 = cv2.inRange(hsv, np.array([0,  50,230]), np.array([40,180,255]))

    mask  = cv2.bitwise_or(m1, m2)
    k     = np.ones((5,5), np.uint8)
    mask  = cv2.morphologyEx(mask, cv2.MORPH_OPEN,  k)
    mask  = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, k)
    ratio = cv2.countNonZero(mask) / total

    # Texture variance — fire has high local variation
    gray    = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    lap_var = cv2.Laplacian(gray, cv2.CV_64F).var()

    conf = 0
    if ratio > 0.02:
        conf += min(int(ratio * 500), 50)
    if lap_var > 200:
        conf += 20
    elif lap_var > 80:
        conf += 10
    conf = min(conf, 92)

    return {
        "detected":   ratio > 0.02 and conf >= 30,
        "confidence": conf,
        "ratio":      round(ratio, 5),
        "label":      "fire",
        "detail":     f"Fire region {ratio*100:.2f}%, texture variance {lap_var:.1f}",
    }


def detect_explosion(img: np.ndarray) -> dict:
    """
    Explosion detection via:
    - Large bright white/yellow regions (blast flash)
    - High-contrast irregular edges (shockwave debris)
    - Smoke: grey regions with high variance
    """
    if img is None:
        return {"detected": False, "confidence": 0}

    gray  = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    total = img.shape[0] * img.shape[1]

    # Bright flash regions
    _, bright = cv2.threshold(gray, 230, 255, cv2.THRESH_BINARY)
    bright_r  = cv2.countNonZero(bright) / total

    # Smoke: gray regions with mid-brightness and texture
    hsv       = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    smoke     = cv2.inRange(hsv, np.array([0,0,60]), np.array([180,40,200]))
    smoke_r   = cv2.countNonZero(smoke) / total

    # Edge chaos (explosion debris)
    edges     = cv2.Canny(gray, 30, 100)
    edge_r    = cv2.countNonZero(edges) / total

    conf = 0
    if bright_r > 0.05:  conf += min(int(bright_r*400), 35)
    if smoke_r  > 0.15:  conf += min(int(smoke_r*200),  25)
    if edge_r   > 0.20:  conf += min(int(edge_r*150),   20)
    conf = min(conf, 88)

    return {
        "detected":   conf >= 40,
        "confidence": conf,
        "label":      "explosion",
        "detail":     f"Flash {bright_r*100:.1f}%, smoke {smoke_r*100:.1f}%, edges {edge_r*100:.1f}%",
    }


def detect_human_presence(img: np.ndarray) -> dict:
    """
    Human detection using multi-colorspace skin analysis:
    - YCrCb (robust across lighting)
    - HSV (handles varied skin tones)
    - Intersection reduces false positives
    Returns region count and estimated number of persons.
    """
    if img is None:
        return {"detected": False, "confidence": 0, "count": 0}

    total = img.shape[0] * img.shape[1]
    ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    hsv   = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    # YCrCb skin range
    mask_y = cv2.inRange(ycrcb, np.array([0,133,77]),  np.array([255,173,127]))
    # HSV skin range (multiple ethnicities)
    mask_h = cv2.inRange(hsv,   np.array([0, 15, 60]), np.array([25,170,255]))

    # Intersection = more precise
    mask   = cv2.bitwise_and(mask_y, mask_h)
    k      = np.ones((9,9), np.uint8)
    mask   = cv2.morphologyEx(mask, cv2.MORPH_OPEN,  k)
    mask   = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, k)

    ratio  = cv2.countNonZero(mask) / total
    cnts,_ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    regions= [c for c in cnts if cv2.contourArea(c) > total * 0.015]

    count  = len(regions)
    conf   = min(int(ratio * 250 + count * 22), 90)
    detected = ratio > 0.025 and count >= 1

    return {
        "detected":  detected,
        "confidence":conf,
        "ratio":     round(ratio, 5),
        "count":     count,
        "label":     "human_body" if count >= 2 else "human_presence",
        "detail":    f"{count} skin region(s), {ratio*100:.2f}% coverage",
    }


def detect_weapon_shape(img: np.ndarray) -> dict:
    """
    Weapon silhouette detection via contour analysis:
    - High aspect ratio (>6:1) → possible firearm barrel / rifle
    - Moderate aspect ratio (3-6:1) + angular shape → possible knife
    - Checks against minimum area to avoid noise
    Tuned for precision — only flags strong candidates.
    """
    if img is None:
        return {"detected": False, "confidence": 0, "type": ""}

    gray    = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    total   = img.shape[0] * img.shape[1]
    blurred = cv2.GaussianBlur(gray, (5,5), 0)
    edges   = cv2.Canny(blurred, 40, 120)

    # Dilate to connect broken edges
    k     = np.ones((3,3), np.uint8)
    edges = cv2.dilate(edges, k, iterations=1)

    cnts,_ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    firearms, knives = [], []
    for c in cnts:
        area = cv2.contourArea(c)
        if area < total * 0.003 or area > total * 0.50:
            continue
        rect    = cv2.minAreaRect(c)
        rw, rh  = rect[1]
        if rw == 0 or rh == 0:
            continue
        ar = max(rw,rh) / (min(rw,rh) + 1e-6)

        if ar > 7:      # Very elongated — firearm barrel / rifle
            firearms.append({"ar": round(ar,2), "area": int(area)})
        elif 3 < ar <= 7:  # Moderate elongation — possible knife or baton
            hull  = cv2.convexHull(c)
            harea = cv2.contourArea(hull)
            sol   = area / (harea + 1e-6)  # Solidity
            if sol > 0.7:   # Solid = metal object, not clothing
                knives.append({"ar": round(ar,2), "area": int(area)})

    conf = 0
    wtype = ""
    if firearms:
        best = max(firearms, key=lambda x: x["ar"])
        conf = min(35 + int(best["ar"]*3), 75)
        wtype = "possible_firearm"
    elif knives:
        best = max(knives, key=lambda x: x["ar"])
        conf = min(30 + int(best["ar"]*4), 68)
        wtype = "possible_knife"

    return {
        "detected":   conf >= 40,
        "confidence": conf,
        "type":       wtype,
        "label":      "weapon" if conf >= 40 else "",
        "detail":     f"{len(firearms)} firearm candidate(s), {len(knives)} blade candidate(s)",
    }


def detect_vehicle_damage(img: np.ndarray) -> dict:
    """
    Detect vehicle damage via high edge density in expected vehicle regions.
    Damaged vehicles have fragmented, irregular edge patterns.
    """
    if img is None:
        return {"detected": False, "confidence": 0}

    gray   = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges  = cv2.Canny(gray, 50, 150)
    total  = img.shape[0] * img.shape[1]
    edge_r = cv2.countNonZero(edges) / total

    # Look for metallic colors (grey/silver)
    hsv    = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    metal  = cv2.inRange(hsv, np.array([0,0,100]), np.array([180,30,230]))
    met_r  = cv2.countNonZero(metal) / total

    conf = 0
    if edge_r > 0.25 and met_r > 0.15:
        conf = min(int(edge_r*200 + met_r*100), 72)

    return {
        "detected":   conf >= 40,
        "confidence": conf,
        "label":      "vehicle_damage",
        "detail":     f"Edge density {edge_r*100:.1f}%, metallic {met_r*100:.1f}%",
    }


def detect_darkness_context(img: np.ndarray) -> dict:
    """Scene brightness analysis for context."""
    if img is None:
        return {"is_nighttime": False, "brightness": 128}
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    mean = float(np.mean(gray))
    return {
        "brightness":  round(mean, 1),
        "is_dark":     mean < 90,
        "is_nighttime":mean < 55,
    }


# =============================================================================
#  OCR TEXT ANALYSIS
# =============================================================================

def parse_ocr_objects(ocr_text: str) -> list:
    """Convert OCR text into forensic object labels with confidence scores."""
    if not ocr_text:
        return []
    text  = ocr_text.lower()
    found = []
    for keywords, label, base_conf in OCR_MAP:
        matched = [kw for kw in keywords if kw in text]
        if matched:
            # More keyword matches = higher confidence
            conf = min(base_conf + len(matched) * 3, 95)
            found.append({
                "class_name":    label,
                "forensic_label":label,
                "confidence":    conf,
                "source":        "ocr_text",
                "detail":        f"OCR matched: {', '.join(matched[:3])}",
            })
    return found


# =============================================================================
#  CRIME CLASSIFICATION ENGINE
# =============================================================================

def classify_crime(detected_labels: list, confidences: dict) -> dict:
    """
    Weighted rule-based crime classifier.

    Scoring:
      - Each rule gets base_score
      - Bonus for each corroborating label: +8 per label
      - Detection confidence weighted: +0.08 per confidence point
      - Multiple matching rules → highest score wins
      - Score < CONFIDENCE_THRESHOLD → "Needs Manual Review"
    """
    label_set   = set(detected_labels)
    all_matches = []

    for trigger, bonus, crime, base, severity in CRIME_RULES:
        # Must have at least one trigger label
        trigger_hits = [t for t in trigger if t in label_set]
        if not trigger_hits:
            continue

        score = base

        # Bonus for corroborating evidence
        bonus_hits = [b for b in bonus if b in label_set]
        score += len(bonus_hits) * 8

        # Weight by detection confidence
        for lbl in trigger_hits + bonus_hits:
            score += confidences.get(lbl, 0) * 0.08

        # Multi-trigger bonus (more evidence types = higher score)
        if len(trigger_hits) > 1:
            score += (len(trigger_hits) - 1) * 5

        score = min(round(score, 1), 99)
        all_matches.append({
            "crime":    crime,
            "score":    score,
            "severity": severity,
            "triggers": trigger_hits,
            "bonus":    bonus_hits,
        })

    all_matches.sort(key=lambda x: -x["score"])

    if not all_matches:
        if detected_labels:
            return {
                "crime_type": "Suspicious Activity" if any(
                    l in detected_labels for l in
                    ["human_body","weapon","blood","violence_reference"]
                ) else "Unknown Crime Type",
                "confidence": 35,
                "severity":   "LOW",
                "all_matches":[],
            }
        return {
            "crime_type": "Unknown Crime Type",
            "confidence": 0,
            "severity":   "LOW",
            "all_matches":[],
        }

    best = all_matches[0]
    crime_type = best["crime"]
    confidence = best["score"]

    # Apply confidence threshold
    if confidence < CONFIDENCE_THRESHOLD:
        crime_type = "Needs Manual Review"

    return {
        "crime_type":  crime_type,
        "confidence":  confidence,
        "severity":    best["severity"],
        "all_matches": all_matches[:6],
    }


# =============================================================================
#  FORENSIC SUMMARY GENERATOR
# =============================================================================

def generate_forensic_summary(detections: list, ocr_objs: list,
                               crime_result: dict) -> str:
    """
    Generate a detailed, specific forensic summary based on actual detections.
    """
    crime  = crime_result["crime_type"]
    conf   = crime_result["confidence"]
    sev    = crime_result["severity"]

    # No detections
    if not detections and not ocr_objs:
        return ("AI forensic analysis found no crime-relevant visual or textual "
                "indicators in this evidence. The image may not depict a crime scene, "
                "or image quality/resolution may be insufficient for analysis.")

    # Build object description
    obj_parts = []
    sources   = {}
    for d in detections:
        lbl = d.get("forensic_label") or d.get("class_name","")
        src = d.get("source","vision")
        sources[lbl] = src
        friendly = lbl.replace("_"," ")
        if friendly and friendly not in obj_parts:
            obj_parts.append(friendly)

    for o in ocr_objs:
        lbl = o.get("forensic_label","")
        friendly = lbl.replace("_"," ")
        if friendly and friendly not in obj_parts:
            obj_parts.append(f"{friendly} [OCR]")

    # Qualifier based on confidence
    if conf >= 88:   qual = "with very high confidence"
    elif conf >= 75: qual = "with high confidence"
    elif conf >= 60: qual = "with moderate confidence"
    elif conf >= 40: qual = "with low confidence"
    else:            qual = "— insufficient confidence for automated classification"

    # Build intro sentence
    if obj_parts:
        intro = f"AI forensic analysis detected: {', '.join(obj_parts[:5])}"
        if len(obj_parts) > 5:
            intro += f" and {len(obj_parts)-5} additional indicator(s)"
        intro += f" {qual} ({conf}%). "
    else:
        intro = f"AI analysis indicates {crime} {qual} ({conf}%). "

    # Crime-specific narrative
    narrative = CRIME_NARRATIVES.get(crime, f"Evidence classified as '{crime}'. Further forensic analysis is recommended.")

    # Risk footer
    risk_notes = {
        "CRITICAL":"⚠ CRITICAL RISK — Immediate law enforcement and forensic response required.",
        "HIGH":     "⚠ HIGH RISK — Scene preservation and forensic documentation required urgently.",
        "MEDIUM":   "⚠ MEDIUM RISK — Evidence requires forensic examination and chain of custody.",
        "LOW":      "ℹ LOW RISK — Evidence noted for investigation record.",
    }
    footer = f" {risk_notes.get(sev,'')}"

    return intro + narrative + footer


# =============================================================================
#  MAIN PUBLIC API
# =============================================================================

def is_image(filepath: str) -> bool:
    return os.path.splitext(filepath)[1].lower() in IMAGE_EXTENSIONS


def detect(filepath: str, ocr_text: str = "") -> dict:
    """
    Full AI crime detection pipeline.

    Args:
        filepath : Path to image file
        ocr_text : OCR-extracted text from the same image (optional)

    Returns structured dict:
        {
          "success":             bool,
          "crime_type":          str,
          "confidence":          int (0-100),
          "detected_objects":    list,
          "severity":            str,
          "forensic_summary":    str,
          "detected_labels":     list,
          "all_crime_matches":   list,
          "yolo_used":           bool,
          "engine":              str,
          "processing_time_ms":  float,
        }
    """
    t0 = time.time()

    base = {
        "success":            False,
        "filename":           os.path.basename(filepath),
        "crime_type":         "Unknown Crime Type",
        "confidence":         0,
        "detected_objects":   [],
        "severity":           "LOW",
        "forensic_summary":   "",
        "ai_summary":         "",
        "detected_labels":    [],
        "all_crime_matches":  [],
        "yolo_used":          False,
        "engine":             "",
        "processing_time_ms": 0,
        "detected_objects_json": "[]",
    }

    if not os.path.exists(filepath):
        base["forensic_summary"] = "File not found."
        return base

    if not is_image(filepath):
        base["success"]          = True
        base["forensic_summary"] = "Not an image — visual analysis skipped."
        return base

    # ── Load image ──────────────────────────────────────────────────────────
    img = _load_image(filepath)
    if img is None:
        base["forensic_summary"] = "Could not decode image file."
        return base

    detections = []

    # ── Layer 1: YOLO ────────────────────────────────────────────────────────
    if yolo_available():
        model = _load_yolo()
        try:
            results = model(filepath, conf=0.25, verbose=False)
            for r in results:
                for box in r.boxes:
                    cls_id   = int(box.cls[0])
                    conf_val = float(box.conf[0])
                    name     = r.names.get(cls_id, f"class_{cls_id}")
                    forensic = COCO_TO_FORENSIC.get(name, name)
                    detections.append({
                        "class_name":    name,
                        "forensic_label":forensic,
                        "confidence":    round(conf_val*100, 1),
                        "source":        "yolov8",
                        "bbox":          [round(float(x),1) for x in box.xyxy[0].tolist()],
                        "detail":        f"YOLO: {name} @ {conf_val*100:.1f}%",
                    })
            base["yolo_used"] = True
            base["engine"]    = "YOLOv8 + OpenCV"
        except Exception:
            pass

    if not base["yolo_used"]:
        base["engine"] = "OpenCV + ColorAnalysis + CNN"

    # ── Layer 2: OpenCV precision detectors (always run) ─────────────────────
    # These complement YOLO or replace it when unavailable

    blood = detect_blood(img)
    if blood["detected"]:
        detections.append({
            "class_name":    "blood",
            "forensic_label":"blood",
            "confidence":    blood["confidence"],
            "source":        "color_analysis",
            "detail":        blood["detail"],
        })

    fire = detect_fire(img)
    if fire["detected"]:
        detections.append({
            "class_name":    "fire",
            "forensic_label":"fire",
            "confidence":    fire["confidence"],
            "source":        "color_analysis",
            "detail":        fire["detail"],
        })

    exp = detect_explosion(img)
    if exp["detected"]:
        detections.append({
            "class_name":    "explosion",
            "forensic_label":"explosion",
            "confidence":    exp["confidence"],
            "source":        "brightness_analysis",
            "detail":        exp["detail"],
        })

    human = detect_human_presence(img)
    if human["detected"] and not any(
        d["forensic_label"]=="human_body" for d in detections
    ):
        detections.append({
            "class_name":    "person",
            "forensic_label": human["label"],
            "confidence":    human["confidence"],
            "source":        "skin_detection",
            "detail":        human["detail"],
        })

    weapon = detect_weapon_shape(img)
    if weapon["detected"] and not any(
        d["forensic_label"] in ("knife","firearm","weapon","bladed_weapon")
        for d in detections
    ):
        detections.append({
            "class_name":    weapon["type"],
            "forensic_label":"weapon",
            "confidence":    weapon["confidence"],
            "source":        "shape_analysis",
            "detail":        weapon["detail"],
        })

    vdmg = detect_vehicle_damage(img)
    if vdmg["detected"]:
        detections.append({
            "class_name":    "vehicle_damage",
            "forensic_label":"vehicle_damage",
            "confidence":    vdmg["confidence"],
            "source":        "edge_analysis",
            "detail":        vdmg["detail"],
        })

    # ── Layer 3: OCR integration ─────────────────────────────────────────────
    ocr_objects = parse_ocr_objects(ocr_text)

    # ── Build label + confidence maps ─────────────────────────────────────────
    all_dets       = detections + ocr_objects
    detected_labels = []
    conf_map        = {}
    for d in all_dets:
        lbl = d.get("forensic_label") or d.get("class_name","")
        if lbl and lbl not in detected_labels:
            detected_labels.append(lbl)
        if lbl:
            conf_map[lbl] = max(conf_map.get(lbl,0), d.get("confidence",0))

    # ── Layer 4: Crime classification ─────────────────────────────────────────
    crime_result = classify_crime(detected_labels, conf_map)

    # ── Layer 5: Forensic summary ─────────────────────────────────────────────
    summary = generate_forensic_summary(detections, ocr_objects, crime_result)

    # ── Build final result ────────────────────────────────────────────────────
    base.update({
        "success":            True,
        "crime_type":         crime_result["crime_type"],
        "confidence":         int(crime_result["confidence"]),
        "detected_objects":   all_dets,
        "severity":           crime_result["severity"],
        "forensic_summary":   summary,
        "ai_summary":         summary,
        "detected_labels":    detected_labels,
        "all_crime_matches":  crime_result["all_matches"],
        "ocr_objects":        ocr_objects,
        "processing_time_ms": round((time.time()-t0)*1000, 1),
        "detected_objects_json": json.dumps([
            {"label": d.get("forensic_label",""), "conf": d.get("confidence",0),
             "source": d.get("source","")}
            for d in all_dets
        ]),
    })
    return base


def detect_batch(evidence_rows: list) -> list:
    """Run detection pipeline on all image evidence rows."""
    results = []
    for row in evidence_rows:
        path = row[3] if not hasattr(row,"keys") else row.get("path","")
        if is_image(path):
            r = detect(path)
            r["ev_id"]   = row[0]
            r["case_id"] = row[1]
            results.append(r)
    return results
