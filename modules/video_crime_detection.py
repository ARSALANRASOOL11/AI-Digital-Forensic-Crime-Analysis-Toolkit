# =============================================================================
#  modules/video_crime_detection.py
#  Video Evidence Crime Detection Engine
#
#  Pipeline:
#    1. Extract frames every N seconds using OpenCV
#    2. Run AI crime detection on each frame
#    3. Aggregate detections across all frames
#    4. Return unified crime report
#
#  Supports: MP4, AVI, MOV, MKV, WEBM, FLV
#  Handles:  Large files (chunk processing), corrupted videos, memory limits
# =============================================================================

import os, cv2, json, time, hashlib, tempfile, math
import numpy as np
from collections import defaultdict, Counter

# Supported video formats
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv", ".m4v"}

# Processing limits
MAX_FRAMES          = 120       # Maximum frames to analyse per video
FRAME_INTERVAL_SEC  = 3.0       # Extract one frame every N seconds
MAX_VIDEO_SIZE_MB   = 500       # Reject files larger than this
MIN_CONFIDENCE      = 30        # Minimum confidence to record a detection
THUMBNAIL_SIZE      = (320, 180)# Thumbnail dimensions for UI


def is_video(filepath: str) -> bool:
    """Return True if filepath is a supported video file."""
    return os.path.splitext(filepath)[1].lower() in VIDEO_EXTENSIONS


def _open_video(filepath: str) -> tuple:
    """
    Open a video file safely.
    Returns (VideoCapture, fps, total_frames, duration_sec) or raises.
    """
    cap = cv2.VideoCapture(filepath)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video file: {filepath}")

    fps           = cap.get(cv2.CAP_PROP_FPS) or 25.0
    total_frames  = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
    duration_sec  = total_frames / fps if fps > 0 else 0

    return cap, fps, total_frames, duration_sec


def extract_frames(filepath: str,
                   interval_sec: float = FRAME_INTERVAL_SEC,
                   max_frames: int = MAX_FRAMES) -> list[dict]:
    """
    Extract frames from video at regular intervals.

    Args:
        filepath     : path to video file
        interval_sec : seconds between extracted frames
        max_frames   : hard cap on number of frames extracted

    Returns:
        List of {"frame_no": int, "timestamp_sec": float,
                 "frame_path": str, "thumbnail_b64": str}
    """
    cap, fps, total_frames, duration = _open_video(filepath)

    frame_step    = max(1, int(fps * interval_sec))
    frames_to_get = min(max_frames, max(1, int(duration / interval_sec)))
    out_dir       = filepath + "_frames"
    os.makedirs(out_dir, exist_ok=True)

    extracted     = []
    frame_no      = 0
    saved         = 0

    try:
        while saved < frames_to_get:
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
            ret, frame = cap.read()
            if not ret:
                break

            ts_sec    = frame_no / fps
            fname     = os.path.join(out_dir, f"frame_{saved:04d}_{int(ts_sec)}s.jpg")
            cv2.imwrite(fname, frame, [cv2.IMWRITE_JPEG_QUALITY, 90])

            # Generate thumbnail (base64 for UI preview)
            thumb = cv2.resize(frame, THUMBNAIL_SIZE)
            _, buf = cv2.imencode(".jpg", thumb, [cv2.IMWRITE_JPEG_QUALITY, 60])
            import base64
            thumb_b64 = base64.b64encode(buf.tobytes()).decode()

            extracted.append({
                "frame_no":      frame_no,
                "frame_index":   saved,
                "timestamp_sec": round(ts_sec, 2),
                "timestamp_str": _fmt_time(ts_sec),
                "frame_path":    fname,
                "thumbnail_b64": thumb_b64,
            })

            frame_no += frame_step
            saved    += 1

    finally:
        cap.release()

    return extracted


def analyse_video(filepath: str,
                  interval_sec: float = FRAME_INTERVAL_SEC,
                  max_frames: int = MAX_FRAMES) -> dict:
    """
    Full video crime detection pipeline.

    Args:
        filepath     : absolute path to video file
        interval_sec : frame extraction interval in seconds
        max_frames   : maximum frames to analyse

    Returns structured result dict with crime type, confidence,
    detected objects, per-frame results, and forensic summary.
    """
    t_start  = time.time()
    filename = os.path.basename(filepath)

    # ── Validate file ────────────────────────────────────────────────────────
    if not os.path.exists(filepath):
        return _error_result(filename, "Video file not found")

    size_mb = os.path.getsize(filepath) / 1024 / 1024
    if size_mb > MAX_VIDEO_SIZE_MB:
        return _error_result(filename,
            f"Video too large ({size_mb:.0f} MB). Max is {MAX_VIDEO_SIZE_MB} MB")

    if not is_video(filepath):
        return _error_result(filename, "Unsupported video format")

    # ── Open video and get metadata ──────────────────────────────────────────
    try:
        cap, fps, total_frames, duration = _open_video(filepath)
        cap.release()
        width  = int(cv2.VideoCapture(filepath).get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cv2.VideoCapture(filepath).get(cv2.CAP_PROP_FRAME_HEIGHT))
    except Exception as e:
        return _error_result(filename, f"Cannot read video: {e}")

    video_meta = {
        "fps":           round(fps, 2),
        "total_frames":  total_frames,
        "duration_sec":  round(duration, 1),
        "duration_str":  _fmt_time(duration),
        "resolution":    f"{width}x{height}",
        "size_mb":       round(size_mb, 2),
    }

    # ── Extract frames ────────────────────────────────────────────────────────
    try:
        frames = extract_frames(filepath, interval_sec, max_frames)
    except Exception as e:
        return _error_result(filename, f"Frame extraction failed: {e}")

    if not frames:
        return _error_result(filename, "No frames could be extracted from video")

    # ── Run crime detection on each frame ─────────────────────────────────────
    try:
        from modules.crime_detection import detect
    except ImportError:
        return _error_result(filename, "crime_detection module not available")

    frame_results   = []
    all_detections  = []
    crime_votes     = Counter()
    severity_votes  = Counter()
    label_counter   = Counter()
    max_confidence  = 0
    key_frames      = []   # Frames with highest confidence

    for frame_info in frames:
        try:
            result = detect(frame_info["frame_path"])
        except Exception:
            continue

        crime      = result.get("crime_type", "Unknown Crime Type")
        confidence = result.get("confidence", 0)
        severity   = result.get("severity", "LOW")
        detections = result.get("detected_objects", [])

        # Skip very low-confidence frames
        if confidence < MIN_CONFIDENCE:
            crime = "No Crime"

        # Accumulate
        crime_votes[crime]    += 1
        severity_votes[severity] += 1
        for d in detections:
            lbl = d.get("forensic_label") or d.get("class_name","")
            if lbl:
                label_counter[lbl] += 1
                all_detections.append({
                    "label":      lbl,
                    "confidence": d.get("confidence", 0),
                    "timestamp":  frame_info["timestamp_str"],
                    "frame_idx":  frame_info["frame_index"],
                })

        frame_result = {
            "frame_index":   frame_info["frame_index"],
            "timestamp_sec": frame_info["timestamp_sec"],
            "timestamp_str": frame_info["timestamp_str"],
            "crime_type":    crime,
            "confidence":    confidence,
            "severity":      severity,
            "detections":    [d.get("forensic_label","") for d in detections],
            "thumbnail_b64": frame_info.get("thumbnail_b64",""),
        }
        frame_results.append(frame_result)

        if confidence > max_confidence:
            max_confidence = confidence

        if confidence >= 60:
            key_frames.append(frame_result)

    # ── Aggregate results ─────────────────────────────────────────────────────
    if not crime_votes:
        return _error_result(filename, "No crime analysis results from frames")

    # Weighted voting — weight by severity
    sev_weight = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    weighted_crimes = defaultdict(float)
    for fr in frame_results:
        w = sev_weight.get(fr["severity"], 1)
        if fr["crime_type"] != "No Crime":
            weighted_crimes[fr["crime_type"]] += w * (fr["confidence"]/100)

    if weighted_crimes:
        top_crime = max(weighted_crimes, key=weighted_crimes.get)
        # Normalise to 0-100
        raw_score = weighted_crimes[top_crime]
        max_raw   = max(weighted_crimes.values())
        confidence = min(round(raw_score / max(max_raw,1) * max_confidence, 1), 99)
    else:
        top_crime  = "No Crime"
        confidence = 0

    # Top detected objects across all frames
    top_objects = [
        {"label": lbl, "count": cnt, "label_friendly": lbl.replace("_"," ").title()}
        for lbl, cnt in label_counter.most_common(10)
        if lbl and cnt >= 1
    ]

    # Dominant severity
    severity = _dominant_severity(severity_votes)

    # ── Generate forensic summary ─────────────────────────────────────────────
    summary = _generate_video_summary(
        filename, top_crime, confidence, severity,
        top_objects, len(frames), duration, key_frames
    )

    # ── Cleanup extracted frame files ─────────────────────────────────────────
    _cleanup_frames(frames)

    processing_time = round(time.time() - t_start, 1)

    return {
        "success":          True,
        "filename":         filename,
        "crime_type":       top_crime,
        "confidence":       confidence,
        "severity":         severity,
        "detected_objects": top_objects,
        "frame_count":      len(frames),
        "key_frames":       key_frames[:5],
        "frame_results":    frame_results,
        "video_meta":       video_meta,
        "forensic_summary": summary,
        "summary":          summary,
        "processing_time_sec": processing_time,
        "crime_distribution":  dict(crime_votes.most_common(5)),
        "all_detections":      all_detections[:50],
        "detected_objects_json": json.dumps([o["label"] for o in top_objects]),
    }


def _dominant_severity(severity_votes: Counter) -> str:
    """Return the highest severity with meaningful vote count."""
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    for sev in order:
        if severity_votes.get(sev, 0) >= 1:
            return sev
    return "LOW"


def _generate_video_summary(filename: str, crime: str, confidence: float,
                             severity: str, objects: list, frame_count: int,
                             duration: float, key_frames: list) -> str:
    """Generate a detailed forensic summary for the video analysis."""
    obj_names = [o["label_friendly"] for o in objects[:5]]

    if not objects and crime in ("No Crime","Unknown Crime Type"):
        return (f"Video analysis of '{filename}' ({_fmt_time(duration)}, "
                f"{frame_count} frames sampled) found no forensically significant "
                f"crime indicators. No action required.")

    intro = (f"AI forensic video analysis of '{filename}' "
             f"({_fmt_time(duration)} duration, {frame_count} frames sampled) "
             f"detected: {', '.join(obj_names) if obj_names else 'suspicious activity'} "
             f"with {confidence:.0f}% confidence. ")

    narratives = {
        "Homicide":           "Multiple frames show indicators consistent with a homicide scene. Scene contains blood evidence and human subjects in compromising positions. Immediate forensic investigation required.",
        "Violent Assault":    "Video evidence shows indicators of a violent assault across multiple frames. Physical altercation and potential weapons detected. Evidence should be preserved for forensic examination.",
        "Armed Robbery":      "Video analysis detected armed individuals and threatening behaviour patterns consistent with an armed robbery. Law enforcement review required.",
        "Drug Trafficking":   "Drug-related objects detected across video frames. Evidence is consistent with drug trafficking or distribution activity.",
        "Arson":              "Fire indicators detected across multiple video frames. Evidence is consistent with deliberate arson. Fire investigation team required.",
        "Weapons Crime":      "Weapon objects detected in video frames. Evidence relevant to a weapons crime investigation.",
        "Road Accident":      "Vehicle damage and accident indicators detected across video frames. Relevant to a road traffic accident investigation.",
        "Terrorism":          "Explosive or terrorism-related indicators detected. Counter-terrorism protocols required immediately.",
        "Cybercrime":         "Digital crime indicators and suspicious screen content detected in video frames.",
        "Suspicious Activity":"Suspicious behaviour and objects detected across video frames. Scene warrants further investigation.",
    }

    narrative = narratives.get(crime,
        f"Video classified as '{crime}'. Forensic examination of key frames recommended.")

    risk_note = {
        "CRITICAL":"⚠ CRITICAL — Immediate law enforcement and forensic response required.",
        "HIGH":    "⚠ HIGH — Urgent forensic preservation and documentation required.",
        "MEDIUM":  "⚠ MEDIUM — Evidence requires forensic examination.",
        "LOW":     "ℹ LOW — Evidence noted for investigation record.",
    }.get(severity,"")

    if key_frames:
        ts_list = [f["timestamp_str"] for f in key_frames[:3]]
        key_note = f" Key evidence detected at timestamps: {', '.join(ts_list)}."
    else:
        key_note = ""

    return intro + narrative + key_note + f" {risk_note}"


def _fmt_time(seconds: float) -> str:
    """Format seconds as MM:SS or HH:MM:SS."""
    seconds = int(seconds)
    h, rem  = divmod(seconds, 3600)
    m, s    = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _cleanup_frames(frames: list):
    """Remove extracted frame files after analysis."""
    for f in frames:
        try:
            os.remove(f["frame_path"])
        except Exception:
            pass
    # Remove the directory
    if frames:
        try:
            frame_dir = os.path.dirname(frames[0]["frame_path"])
            if os.path.isdir(frame_dir):
                os.rmdir(frame_dir)
        except Exception:
            pass


def _error_result(filename: str, error: str) -> dict:
    return {
        "success":          False,
        "filename":         filename,
        "error":            error,
        "crime_type":       "Unknown Crime Type",
        "confidence":       0,
        "severity":         "LOW",
        "detected_objects": [],
        "frame_count":      0,
        "key_frames":       [],
        "frame_results":    [],
        "forensic_summary": f"Video analysis failed: {error}",
        "summary":          f"Video analysis failed: {error}",
        "detected_objects_json": "[]",
    }
