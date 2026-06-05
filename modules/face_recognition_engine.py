# =============================================================================
#  modules/face_recognition_engine.py
#  Face Detection and Matching Engine for Forensic Evidence
#
#  Uses OpenCV for face detection (works without face_recognition library).
#  Auto-upgrades to face_recognition library if installed:
#    pip install face-recognition
#
#  Capabilities:
#    - Detect faces in images and video frames
#    - Generate compact face encodings (128-dim feature vector)
#    - Store face database in SQLite
#    - Match suspects across evidence
#    - Return similarity scores
# =============================================================================

import os, cv2, json, time, hashlib, base64, struct
import numpy as np
from collections import defaultdict

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
_FR_AVAILABLE = False
try:
    import face_recognition as _fr_lib
    _FR_AVAILABLE = True
except ImportError:
    pass

# OpenCV Haar cascade (always available)
_FACE_CASCADE = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
)
_PROFILE_CASCADE = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_profileface.xml"
)
_EYE_CASCADE = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_eye.xml"
)

# Similarity threshold — faces with distance below this are considered a match
MATCH_THRESHOLD   = 0.55    # face_recognition distance (lower = more similar)
SIMILARITY_THRESHOLD = 0.72  # 0-1 score (higher = more similar)

# Minimum face size (pixels) to accept
MIN_FACE_SIZE = (40, 40)

# Face database path
FACE_DB_PATH = "face_database"


# =============================================================================
#  Face detection
# =============================================================================

def detect_faces_in_image(filepath: str) -> list[dict]:
    """
    Detect all faces in an image file.

    Returns list of face dicts:
        {
          "face_id":      str,   unique hash of face region
          "bbox":         [x,y,w,h],
          "confidence":   float,
          "encoding":     list[float] (128-dim or 256-dim vector),
          "face_b64":     str,   base64 JPEG of cropped face
          "backend":      str,   "face_recognition" or "opencv_haar"
        }
    """
    if not os.path.exists(filepath):
        return []

    img_bgr = _load_image(filepath)
    if img_bgr is None:
        return []

    if _FR_AVAILABLE:
        return _detect_faces_fr(filepath, img_bgr)
    else:
        return _detect_faces_opencv(filepath, img_bgr)


def _load_image(filepath: str) -> np.ndarray | None:
    img = cv2.imread(filepath)
    if img is None:
        try:
            from PIL import Image
            pil = Image.open(filepath).convert("RGB")
            img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
        except Exception:
            return None
    return img


def _detect_faces_fr(filepath: str, img_bgr: np.ndarray) -> list[dict]:
    """Use face_recognition library (most accurate)."""
    import face_recognition as fr
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)

    locations  = fr.face_locations(img_rgb, model="hog")
    encodings  = fr.face_encodings(img_rgb, locations)

    faces = []
    for (top, right, bottom, left), enc in zip(locations, encodings):
        w = right - left
        h = bottom - top
        if w < MIN_FACE_SIZE[0] or h < MIN_FACE_SIZE[1]:
            continue

        face_crop = img_bgr[top:bottom, left:right]
        face_b64  = _crop_to_b64(face_crop)
        face_id   = _face_hash(enc.tolist())

        faces.append({
            "face_id":    face_id,
            "bbox":       [left, top, w, h],
            "confidence": 90,
            "encoding":   enc.tolist(),
            "face_b64":   face_b64,
            "backend":    "face_recognition",
        })
    return faces


def _detect_faces_opencv(filepath: str, img_bgr: np.ndarray) -> list[dict]:
    """
    OpenCV Haar cascade face detection + LBP feature encoding.
    Works without face_recognition library.
    """
    gray   = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    gray   = cv2.equalizeHist(gray)

    # Detect frontal faces
    frontal = _FACE_CASCADE.detectMultiScale(
        gray, scaleFactor=1.1, minNeighbors=5,
        minSize=MIN_FACE_SIZE, flags=cv2.CASCADE_SCALE_IMAGE
    )

    # Detect profile faces
    profile = _PROFILE_CASCADE.detectMultiScale(
        gray, scaleFactor=1.1, minNeighbors=5,
        minSize=MIN_FACE_SIZE
    )

    detections = []
    if len(frontal):
        detections.extend([("frontal", r) for r in frontal])
    if len(profile):
        detections.extend([("profile", r) for r in profile])

    # De-duplicate overlapping boxes
    detections = _nms_boxes(detections)

    faces = []
    for face_type, (x, y, w, h) in detections:
        face_crop = img_bgr[y:y+h, x:x+w]
        if face_crop.size == 0:
            continue

        enc       = _lbp_encoding(gray[y:y+h, x:x+w])
        face_b64  = _crop_to_b64(face_crop)
        face_id   = _face_hash(enc)

        # Estimate confidence from eye detection within face region
        face_gray = gray[y:y+h, x:x+w]
        eyes      = _EYE_CASCADE.detectMultiScale(face_gray, scaleFactor=1.1, minNeighbors=3)
        conf      = 85 if len(eyes) >= 2 else 70 if face_type == "frontal" else 60

        faces.append({
            "face_id":    face_id,
            "bbox":       [int(x), int(y), int(w), int(h)],
            "confidence": conf,
            "encoding":   enc,
            "face_b64":   face_b64,
            "backend":    "opencv_haar",
            "face_type":  face_type,
        })

    return faces


def _lbp_encoding(gray_face: np.ndarray, grid: int = 8) -> list:
    """
    Local Binary Pattern (LBP) encoding of a face region.
    Produces a 256-dim histogram feature vector.
    Compact, fast, and sufficient for approximate matching.
    """
    if gray_face.size == 0:
        return [0.0] * 256

    face_resized = cv2.resize(gray_face, (64, 64))
    lbp          = np.zeros_like(face_resized, dtype=np.uint8)

    for i in range(1, 63):
        for j in range(1, 63):
            center  = int(face_resized[i, j])
            binary  = 0
            neighbors = [
                face_resized[i-1, j-1], face_resized[i-1, j], face_resized[i-1, j+1],
                face_resized[i,   j+1], face_resized[i+1, j+1],
                face_resized[i+1, j],   face_resized[i+1, j-1], face_resized[i, j-1],
            ]
            for k, n in enumerate(neighbors):
                binary |= (1 << k) if int(n) >= center else 0
            lbp[i, j] = binary

    hist, _ = np.histogram(lbp.ravel(), bins=256, range=(0, 256))
    hist     = hist.astype(float)
    total    = hist.sum()
    if total > 0:
        hist /= total

    return hist.tolist()


def _nms_boxes(detections: list, overlap_thresh: float = 0.40) -> list:
    """Non-maximum suppression to remove overlapping face boxes."""
    if not detections:
        return []
    boxes = np.array([[x, y, x+w, y+h] for _, (x,y,w,h) in detections], dtype=float)
    areas = (boxes[:,2]-boxes[:,0]) * (boxes[:,3]-boxes[:,1])
    order = areas.argsort()[::-1]
    keep  = []
    while order.size:
        i = order[0]; keep.append(i)
        xx1 = np.maximum(boxes[i,0], boxes[order[1:],0])
        yy1 = np.maximum(boxes[i,1], boxes[order[1:],1])
        xx2 = np.minimum(boxes[i,2], boxes[order[1:],2])
        yy2 = np.minimum(boxes[i,3], boxes[order[1:],3])
        w   = np.maximum(0, xx2-xx1)
        h   = np.maximum(0, yy2-yy1)
        inter = w*h
        iou   = inter / (areas[i] + areas[order[1:]] - inter + 1e-6)
        order = order[1:][iou <= overlap_thresh]
    return [detections[i] for i in keep]


def _crop_to_b64(face_bgr: np.ndarray) -> str:
    """Convert face crop to base64 JPEG string."""
    try:
        face_resized = cv2.resize(face_bgr, (100, 100))
        _, buf = cv2.imencode(".jpg", face_resized, [cv2.IMWRITE_JPEG_QUALITY, 75])
        return base64.b64encode(buf.tobytes()).decode()
    except Exception:
        return ""


def _face_hash(encoding: list) -> str:
    """Generate a compact hash ID from face encoding."""
    data = json.dumps([round(v, 3) for v in encoding[:32]]).encode()
    return hashlib.sha256(data).hexdigest()[:16]


# =============================================================================
#  Face matching
# =============================================================================

def compute_similarity(enc_a: list, enc_b: list) -> float:
    """
    Compute face similarity score (0-1, higher = more similar).
    Uses cosine similarity for OpenCV encodings,
    face_recognition distance for FR encodings.
    """
    a = np.array(enc_a, dtype=float)
    b = np.array(enc_b, dtype=float)

    if len(a) != len(b):
        return 0.0

    if _FR_AVAILABLE and len(a) == 128:
        # Euclidean distance → similarity (face_recognition convention)
        dist = float(np.linalg.norm(a - b))
        sim  = max(0.0, 1.0 - dist / 0.8)
    else:
        # Cosine similarity for LBP histograms
        dot   = float(np.dot(a, b))
        norm  = float(np.linalg.norm(a) * np.linalg.norm(b))
        sim   = (dot / norm) if norm > 0 else 0.0

    return round(max(0.0, min(sim, 1.0)), 4)


def match_face(query_encoding: list,
               known_faces: list[dict],
               threshold: float = SIMILARITY_THRESHOLD) -> dict:
    """
    Match a query face encoding against a list of known faces.

    Args:
        query_encoding : 128-dim or 256-dim encoding from detect_faces
        known_faces    : list of face records from DB
        threshold      : minimum similarity to declare a match

    Returns:
        {
          "matched":      bool,
          "match_score":  float (0-1),
          "match_pct":    float (0-100),
          "person_id":    int or None,
          "face_id":      str or None,
          "evidence_id":  int or None,
          "all_scores":   list of {face_id, score, person_id}
        }
    """
    if not known_faces:
        return _no_match()

    scores = []
    for kf in known_faces:
        try:
            enc  = json.loads(kf["encoding"]) if isinstance(kf["encoding"], str) else kf["encoding"]
            sim  = compute_similarity(query_encoding, enc)
            scores.append({
                "face_id":    kf.get("face_id",""),
                "person_id":  kf.get("person_id"),
                "evidence_id":kf.get("evidence_id"),
                "score":      sim,
                "match_pct":  round(sim*100, 1),
            })
        except Exception:
            continue

    scores.sort(key=lambda x: -x["score"])

    if scores and scores[0]["score"] >= threshold:
        best = scores[0]
        return {
            "matched":     True,
            "match_score": best["score"],
            "match_pct":   best["match_pct"],
            "person_id":   best["person_id"],
            "face_id":     best["face_id"],
            "evidence_id": best["evidence_id"],
            "all_scores":  scores[:10],
        }

    return {**_no_match(), "all_scores": scores[:10],
            "best_score": scores[0]["score"] if scores else 0}


def _no_match() -> dict:
    return {"matched":False,"match_score":0,"match_pct":0,
            "person_id":None,"face_id":None,"evidence_id":None,"all_scores":[]}


# =============================================================================
#  Database helpers
# =============================================================================

def init_face_tables(conn):
    """Create face recognition tables (idempotent)."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS face_database (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        face_id     TEXT UNIQUE NOT NULL,
        person_id   INTEGER,
        person_name TEXT DEFAULT '',
        evidence_id INTEGER,
        case_id     TEXT DEFAULT '',
        encoding    TEXT NOT NULL,
        face_b64    TEXT DEFAULT '',
        timestamp   REAL,
        source      TEXT DEFAULT '',
        notes       TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS face_matches (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        query_face_id TEXT,
        matched_face_id TEXT,
        match_score  REAL,
        evidence_id  INTEGER,
        timestamp    REAL,
        confirmed    INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS persons (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT DEFAULT 'Unknown',
        alias       TEXT DEFAULT '',
        notes       TEXT DEFAULT '',
        created_at  REAL
    );
    """)
    conn.commit()


def save_faces(conn, faces: list[dict], evidence_id: int,
               case_id: str, source: str = "") -> list[str]:
    """
    Store detected faces in the face database.
    Returns list of saved face_ids.
    """
    saved = []
    for face in faces:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO face_database
                (face_id, evidence_id, case_id, encoding, face_b64, timestamp, source)
                VALUES (?,?,?,?,?,?,?)
            """, (
                face["face_id"],
                evidence_id,
                case_id,
                json.dumps(face["encoding"]),
                face.get("face_b64",""),
                time.time(),
                source,
            ))
            saved.append(face["face_id"])
        except Exception:
            pass
    conn.commit()
    return saved


def get_all_faces(conn) -> list[dict]:
    """Load all face records from DB."""
    rows = conn.execute("""
        SELECT fd.id, fd.face_id, fd.person_id, fd.person_name,
               fd.evidence_id, fd.case_id, fd.encoding, fd.face_b64,
               fd.timestamp, fd.source, p.name as pname
        FROM face_database fd
        LEFT JOIN persons p ON fd.person_id = p.id
        ORDER BY fd.timestamp DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_faces_by_evidence(conn, evidence_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM face_database WHERE evidence_id=? ORDER BY timestamp DESC",
        (evidence_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def label_person(conn, face_id: str, name: str, notes: str = "") -> int:
    """
    Create or get a person record and link it to a face.
    Returns person_id.
    """
    # Check if person exists
    row = conn.execute("SELECT id FROM persons WHERE name=?", (name,)).fetchone()
    if row:
        person_id = row[0]
    else:
        conn.execute(
            "INSERT INTO persons(name, notes, created_at) VALUES(?,?,?)",
            (name, notes, time.time())
        )
        person_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.execute(
        "UPDATE face_database SET person_id=?, person_name=? WHERE face_id=?",
        (person_id, name, face_id)
    )
    conn.commit()
    return person_id


def get_face_statistics(conn) -> dict:
    """Return statistics for the face recognition dashboard."""
    total_faces   = conn.execute("SELECT COUNT(*) FROM face_database").fetchone()[0]
    total_persons = conn.execute("SELECT COUNT(*) FROM persons").fetchone()[0]
    total_matches = conn.execute("SELECT COUNT(*) FROM face_matches").fetchone()[0]
    confirmed     = conn.execute("SELECT COUNT(*) FROM face_matches WHERE confirmed=1").fetchone()[0]
    unidentified  = conn.execute(
        "SELECT COUNT(*) FROM face_database WHERE person_id IS NULL"
    ).fetchone()[0]

    return {
        "total_faces":    total_faces,
        "total_persons":  total_persons,
        "total_matches":  total_matches,
        "confirmed":      confirmed,
        "unidentified":   unidentified,
        "backend":        "face_recognition" if _FR_AVAILABLE else "OpenCV Haar+LBP",
    }


# =============================================================================
#  High-level pipeline
# =============================================================================

def process_image_for_faces(filepath: str, evidence_id: int,
                             case_id: str, conn) -> dict:
    """
    Full pipeline: detect faces → match against DB → save new faces.

    Returns:
        {
          "faces_detected": int,
          "new_faces":      int,
          "matches":        list,
          "face_records":   list,
        }
    """
    faces   = detect_faces_in_image(filepath)
    if not faces:
        return {"faces_detected":0,"new_faces":0,"matches":[],"face_records":[]}

    known   = get_all_faces(conn)
    matches = []
    new_faces = 0

    for face in faces:
        match = match_face(face["encoding"], known)
        if match["matched"]:
            matches.append({
                "face_id":    face["face_id"],
                "person_id":  match["person_id"],
                "score":      match["match_score"],
                "match_pct":  match["match_pct"],
                "evidence_id":match["evidence_id"],
            })
            # Log match
            try:
                conn.execute("""
                    INSERT INTO face_matches
                    (query_face_id, matched_face_id, match_score, evidence_id, timestamp)
                    VALUES(?,?,?,?,?)
                """, (face["face_id"], match["face_id"],
                      match["match_score"], evidence_id, time.time()))
            except Exception:
                pass

    saved  = save_faces(conn, faces, evidence_id, case_id,
                         source=os.path.basename(filepath))
    new_faces = len(saved)
    conn.commit()

    return {
        "faces_detected": len(faces),
        "new_faces":      new_faces,
        "matches":        matches,
        "face_records":   faces,
        "backend":        "face_recognition" if _FR_AVAILABLE else "OpenCV Haar+LBP",
    }
