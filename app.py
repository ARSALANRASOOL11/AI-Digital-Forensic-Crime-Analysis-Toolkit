
# =============================================================================
#  app.py  — Cyber Forensic Intelligence System v4.0 (Refactored)
#  Improvements:
#    1. Split into modules/  (auth, database, analysis, yara_scanner,
#       upload_security, carver, virustotal, reports)
#    2. Secure file uploads (sanitize, size limit, magic check, chmod)
#    3. YARA rules engine   (pure-Python, 11 rule families)
#    4. Auth hardened       (scrypt hashing, CSRF, session timeout, RBAC)
#    5. CNN + confusion matrix + accuracy graph + precision/recall
#    6. VirusTotal API      (hash & URL lookup, configurable via env var)
#    7. HTML → templates/   CSS → static/css/  JS → static/js/
#    8. Better crime classification (13 categories)
#    9. Better PDF reports  (styled, multi-section, with chain-of-custody)
#   10. Logging & audit trail (every action, login, upload, export)
# =============================================================================

import os, time, zipfile, json, secrets
import sqlite3
from flask import (Flask, request, redirect, session, send_file,
                   jsonify, render_template, flash, abort, url_for, g)

from modules.auth          import (generate_csrf_token, csrf_protect,
                                   check_session_timeout, has_permission,
                                   login_required, admin_required, verify_password)
from modules.database      import (init_db, get_db, log_audit, log_custody, new_case_id)
from modules.upload_security import (secure_save, sha256_file, verify_file)
from modules.analysis      import (ai_risk_score, classify_crime_type,
                                   tag_evidence_category, extract_metadata)
from modules.yara_scanner  import scan_file
from modules.carver        import carve_deleted_files
from modules.virustotal    import lookup_hash, format_vt_summary
from modules.reports       import generate_case_report
from modules.mfa           import (generate_secret, get_totp, verify_totp,
                                generate_backup_codes, hash_backup_code,
                                verify_backup_code, generate_qr_png_b64,
                                get_totp_uri, setup_mfa_tables, get_user_mfa,
                                save_user_mfa)
from modules.encryption    import (encrypt_file, decrypt_file, is_encrypted,
                                encryption_info, get_file_hash)
from modules.autopsy_case  import (create_autopsy_case, add_evidence_to_case,
                                read_case_artifacts, open_in_autopsy,
                                AUTOPSY_AVAILABLE, find_autopsy)
from modules.evidence_graph import build_evidence_graph, graph_summary
from modules.sandbox        import analyse as sandbox_analyse
from modules.ai_assistant   import (chat as ai_chat, build_evidence_context,
                                get_ollama_status)

# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # uncomment for HTTPS

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

# Init MFA tables + case directory
try:
    _conn = get_db(); setup_mfa_tables(_conn); _conn.close()
except Exception: pass
CASES_DIR = "autopsy_cases"
os.makedirs(CASES_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Template context: always inject csrf_token helper + session info
# ---------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    return dict(csrf_token=generate_csrf_token, enumerate=enumerate)

@app.before_request
def update_session_activity():
    if "user" in session:
        session["_last_active"] = session.get("_last_active", time.time())


# =============================================================================
#  ERROR HANDLERS
# =============================================================================
@app.errorhandler(403)
def forbidden(e):
    return render_template("base.html", active_page="", error="Access denied."), 403

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for("dashboard"))


# =============================================================================
#  BUILT-IN AI ANALYST (keyword-based chat)
# =============================================================================
def built_in_analyst(question: str, ev_rows: list) -> str:
    q       = question.lower().strip()
    evidence = []
    for r in ev_rows:
        cid, name, path, h, t = r[1], r[2], r[3], r[4], r[5]
        try:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))
        except Exception:
            ts = str(t)
        vstatus = verify_file(path, h)
        risk    = ai_risk_score(name, path)
        evidence.append({"case_id": cid, "filename": name, "path": path,
                         "hash": h, "timestamp": ts, "integrity": vstatus,
                         "risk_level": risk["level"], "risk_score": risk["score"],
                         "reasons": risk["reasons"]})

    total = len(evidence)
    cases = list(dict.fromkeys(e["case_id"] for e in evidence))

    if total == 0:
        return "No evidence uploaded yet. Go to Upload Evidence to add files."
    if any(w in q for w in ["tamper","modified","changed","corrupt"]):
        tampered = [e for e in evidence if e["integrity"] == "TAMPERED"]
        if not tampered:
            return f"&#10004; <strong>No tampered files detected.</strong> All {total} files passed integrity verification."
        lines = "".join(f"<br>&#10008; <strong>{e['filename']}</strong> ({e['case_id']}) hash changed" for e in tampered)
        return f"&#9888; <strong>{len(tampered)} tampered file(s):</strong>" + lines
    if any(w in q for w in ["high risk","highrisk","dangerous","threat","malware","risky"]):
        hi  = [e for e in evidence if e["risk_level"] == "HIGH_RISK"]
        med = [e for e in evidence if e["risk_level"] == "MEDIUM_RISK"]
        if not hi and not med:
            return "&#10004; No high or medium risk files found."
        out = ""
        if hi:
            out += f"<strong>HIGH RISK ({len(hi)}):</strong>"
            for e in hi:
                out += f"<br>&#128308; <strong>{e['filename']}</strong> ({e['case_id']}) Score: {e['risk_score']}/100"
        if med:
            out += f"<br><br><strong>MEDIUM RISK ({len(med)}):</strong>"
            for e in med:
                out += f"<br>&#128992; <strong>{e['filename']}</strong> ({e['case_id']}) Score: {e['risk_score']}/100"
        return out
    if any(w in q for w in ["summarize","summary","overview","report"]):
        t_c = sum(1 for e in evidence if e["integrity"]  == "TAMPERED")
        h_c = sum(1 for e in evidence if e["risk_level"] == "HIGH_RISK")
        m_c = sum(1 for e in evidence if e["risk_level"] == "MEDIUM_RISK")
        cl  = sum(1 for e in evidence if e["risk_level"] == "CLEAN")
        avg = round(sum(e["risk_score"] for e in evidence) / total, 1)
        return (f"<strong>Evidence Summary:</strong><br>"
                f"Files: <strong>{total}</strong> | Cases: <strong>{len(cases)}</strong><br>"
                f"Tampered: <strong style='color:var(--danger)'>{t_c}</strong> | "
                f"High Risk: <strong style='color:var(--danger)'>{h_c}</strong> | "
                f"Medium Risk: <strong style='color:var(--warn)'>{m_c}</strong> | "
                f"Clean: <strong style='color:var(--safe)'>{cl}</strong><br>"
                f"Avg Risk Score: <strong>{avg}/100</strong>")
    # Default
    t_c = sum(1 for e in evidence if e["integrity"]  == "TAMPERED")
    h_c = sum(1 for e in evidence if e["risk_level"] == "HIGH_RISK")
    return (f"Analysed <strong>{total} file(s)</strong> across <strong>{len(cases)} case(s)</strong>. "
            + (f"<strong style='color:var(--danger)'>{t_c} tampered</strong>. " if t_c else "All files intact. ")
            + (f"<strong style='color:var(--danger)'>{h_c} high-risk</strong>." if h_c else "No high-risk files.")
            + "<br><br><em>Try: Which files are tampered? / Show high risk files / Summarize all evidence</em>")


# =============================================================================
#  AUTOPSY TIMELINE helper
# =============================================================================
def build_autopsy_timeline() -> list:
    conn = get_db()
    rows = conn.execute("SELECT case_id,filename,path,hash,timestamp FROM evidence ORDER BY timestamp ASC").fetchall()
    conn.close()
    events = []
    for r in rows:
        cid, name, path, h, t = r[0], r[1], r[2], r[3], r[4]
        try:
            ts = float(t)
        except Exception:
            ts = 0.0
        ts_str  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        vstatus = verify_file(path, h)
        risk    = ai_risk_score(name, path)
        events.append({
            "time": ts_str, "epoch": ts, "case_id": cid, "filename": name,
            "event_type": "UPLOAD", "integrity": vstatus,
            "risk_level": risk["level"], "risk_score": risk["score"],
            "detail": "; ".join(risk["reasons"][:2]),
        })
        if vstatus == "TAMPERED":
            events.append({
                "time": ts_str, "epoch": ts+1, "case_id": cid, "filename": name,
                "event_type": "TAMPER_DETECTED", "integrity": "TAMPERED",
                "risk_level": "HIGH_RISK", "risk_score": 100,
                "detail": "File hash changed after upload — evidence tampering detected",
            })
    events.sort(key=lambda e: e["epoch"])
    return events


# =============================================================================
#  AUTH ROUTES
# =============================================================================
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session and check_session_timeout():
        return redirect(url_for("dashboard"))

    timeout = request.args.get("timeout")
    error   = None

    if request.method == "POST":
        csrf_protect()
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")

        if not u or not p:
            error = "&#9888; Username and password are required."
        else:
            conn = get_db()
            row  = conn.execute(
                "SELECT username,password_hash,role,failed_logins,locked_until FROM users WHERE username=?", (u,)
            ).fetchone()
            conn.close()

            now = time.time()
            if row and row["locked_until"] and float(row["locked_until"]) > now:
                wait = int((float(row["locked_until"]) - now) / 60) + 1
                error = f"&#128274; Account locked. Try again in {wait} minute(s)."
                log_audit(u, "LOCKED_ACCOUNT_ATTEMPT", request.remote_addr)
            elif row and verify_password(p, row["password_hash"]):
                # Reset failed attempts
                conn2 = get_db()
                conn2.execute("UPDATE users SET failed_logins=0,locked_until=0 WHERE username=?", (u,))
                conn2.commit(); conn2.close()
                session.clear()
                # Check MFA
                from modules.mfa import get_user_mfa, setup_mfa_tables
                conn_mfa = get_db(); setup_mfa_tables(conn_mfa)
                mfa = get_user_mfa(conn_mfa, row["username"]); conn_mfa.close()
                if mfa["enabled"]:
                    session.clear()
                    session["mfa_pending_user"] = row["username"]
                    session["_csrf"] = secrets.token_hex(32)
                    log_audit(row["username"], "LOGIN_MFA_REQUIRED", request.remote_addr)
                    return redirect(url_for("mfa_verify"))
                session["user"]         = row["username"]
                session["role"]         = row["role"]
                session["_last_active"] = now
                session["_csrf"]        = secrets.token_hex(32)
                log_audit(row["username"], "LOGIN", request.remote_addr)
                return redirect(url_for("dashboard"))
            else:
                # Increment failed logins
                if row:
                    fails     = (row["failed_logins"] or 0) + 1
                    lock_until = (now + 15*60) if fails >= 5 else 0
                    conn3 = get_db()
                    conn3.execute(
                        "UPDATE users SET failed_logins=?,locked_until=? WHERE username=?",
                        (fails, lock_until, u)
                    )
                    conn3.commit(); conn3.close()
                log_audit(u, "FAILED_LOGIN", request.remote_addr)
                error = "&#9888; Invalid credentials. Access denied."

    return render_template("login.html", error=error, timeout=timeout, active_page="login")


@app.route("/logout")
def logout():
    log_audit(session.get("user", "?"), "LOGOUT", request.remote_addr)
    session.clear()
    return redirect(url_for("login"))


# =============================================================================
#  MANAGE USERS  (admin only)
# =============================================================================
@app.route("/manage_users", methods=["GET", "POST"])
@admin_required
def manage_users():
    from modules.auth import hash_password
    msg = None

    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action")
        if action == "add":
            uname = request.form.get("new_username", "").strip()
            pw    = request.form.get("new_password", "")
            role  = request.form.get("new_role", "forensic_analyst")
            if not uname or len(pw) < 8:
                flash("Username required and password must be ≥ 8 chars.", "error")
            else:
                try:
                    conn = get_db()
                    conn.execute(
                        "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                        (uname, hash_password(pw), role)
                    )
                    conn.commit(); conn.close()
                    log_audit(session["user"], f"CREATE_USER {uname}", request.remote_addr)
                    flash(f"User {uname} created successfully.", "success")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "error")
        elif action == "delete":
            uid = request.form.get("uid")
            if uid:
                conn = get_db()
                urow = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
                if urow and urow["username"] != "admin":
                    conn.execute("DELETE FROM users WHERE id=?", (uid,))
                    conn.commit()
                    log_audit(session["user"], f"DELETE_USER {urow['username']}", request.remote_addr)
                    flash("User deleted.", "success")
                conn.close()

    conn  = get_db()
    users = conn.execute("SELECT id,username,role,failed_logins FROM users ORDER BY id").fetchall()
    conn.close()

    return render_template("manage_users.html",
                           users=users, active_page="manage_users")


# =============================================================================
#  UPLOAD EVIDENCE
# =============================================================================
@app.route("/upload", methods=["GET", "POST"])
@login_required("upload")
def upload():
    upload_result = None

    if request.method == "POST":
        csrf_protect()
        f = request.files.get("file")
        try:
            cid  = new_case_id()
            path, original_name = secure_save(f, cid)
            h    = sha256_file(path)
            risk = ai_risk_score(original_name, path)
            crime_type  = classify_crime_type(original_name, path)
            ev_category = tag_evidence_category(original_name)
            yara_hits   = scan_file(path)

            # Optional VirusTotal lookup
            vt_result = ""
            if os.environ.get("VIRUSTOTAL_API_KEY"):
                vt_data   = lookup_hash(h)
                vt_result = format_vt_summary(vt_data)

            # --- Vision-based crime detection for images ---
            vision_result = {}
            detected_objects_json = "[]"
            ai_crime_type   = crime_type
            ai_summary      = ""
            vision_confidence = 0

            try:
                from modules.crime_detection import detect, is_image
                if is_image(path):
                    ocr_text = ""
                    try:
                        from modules.ocr_engine import analyse as ocr_analyse
                        ocr_r    = ocr_analyse(path)
                        ocr_text = ocr_r.get("full_text","") if ocr_r.get("success") else ""
                    except Exception:
                        pass
                    vision_result = detect(path, ocr_text=ocr_text)
                    if vision_result.get("success"):
                        ai_crime_type          = vision_result.get("crime_type", crime_type)
                        ai_summary             = vision_result.get("forensic_summary","")
                        detected_objects_json  = vision_result.get("detected_objects_json","[]")
                        vision_confidence      = vision_result.get("confidence", 0)
                        if ai_crime_type and ai_crime_type != "Unknown Crime Type":
                            crime_type = ai_crime_type
            except Exception:
                pass

            conn = get_db()
            # Extend schema if needed
            for col_def in [
                "detected_objects TEXT DEFAULT '[]'",
                "confidence_score INTEGER DEFAULT 0",
                "ai_crime_type TEXT DEFAULT ''",
                "ai_summary TEXT DEFAULT ''",
            ]:
                try: conn.execute(f"ALTER TABLE evidence ADD COLUMN {col_def}")
                except Exception: pass
            conn.commit()

            conn.execute(
                """INSERT INTO evidence(case_id,filename,path,hash,timestamp,
                   crime_type,evidence_category,virustotal_result,
                   detected_objects,confidence_score,ai_crime_type,ai_summary)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, original_name, path, h, str(time.time()),
                 crime_type, ev_category, vt_result,
                 detected_objects_json, vision_confidence,
                 ai_crime_type, ai_summary)
            )
            conn.commit(); conn.close()

            log_custody(cid, original_name, "UPLOAD", session.get("user",""),
                        f"SHA-256: {h[:16]}… Crime: {crime_type}")
            log_audit(session.get("user",""),
                      f"UPLOAD {cid}/{original_name}", request.remote_addr)

            upload_result = {
                "success":       True,
                "cid":           cid,
                "name":          original_name,
                "risk":          risk,
                "crime_type":    crime_type,
                "ev_category":   ev_category,
                "vt_result":     vt_result,
                "yara_hits":     yara_hits,
                "hash":          h,
                "vision":        vision_result,
                "ai_summary":    ai_summary,
                "ai_crime_type": ai_crime_type,
                "vision_confidence": vision_confidence,
            }
        except ValueError as e:
            upload_result = {"success": False, "error": str(e)}
        except Exception as e:
            upload_result = {"success": False, "error": f"Upload failed: {e}"}

    return render_template("upload.html", result=upload_result, active_page="upload")


# =============================================================================
#  DASHBOARD
# =============================================================================
@app.route("/dashboard")
@login_required("dashboard")
def dashboard():
    search       = request.args.get("search", "")
    crime_filter = request.args.get("crime_type", "")
    conn = get_db()

    if search and crime_filter:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE (case_id LIKE ? OR filename LIKE ?) AND crime_type=? ORDER BY id DESC",
            (f"%{search}%", f"%{search}%", crime_filter)
        ).fetchall()
    elif search:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE case_id LIKE ? OR filename LIKE ? OR crime_type LIKE ? ORDER BY id DESC",
            (f"%{search}%", f"%{search}%", f"%{search}%")
        ).fetchall()
    elif crime_filter:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE crime_type=? ORDER BY id DESC", (crime_filter,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()

    total        = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    cases_count  = conn.execute("SELECT COUNT(DISTINCT case_id) FROM evidence").fetchone()[0]
    all_cts      = [r[0] for r in conn.execute(
        "SELECT DISTINCT crime_type FROM evidence ORDER BY crime_type").fetchall() if r[0]]
    conn.close()

    # Group by case
    from collections import OrderedDict
    grouped = OrderedDict()
    for r in rows:
        grouped.setdefault(r[1], []).append(r)

    tampered = sum(1 for r in rows if verify_file(r[3], r[4]) == "TAMPERED")
    risky    = sum(1 for r in rows if ai_risk_score(r[2], r[3])["level"] in ("HIGH_RISK","MEDIUM_RISK"))

    return render_template("dashboard.html",
                           grouped=grouped, total=total, cases_count=cases_count,
                           tampered=tampered, risky=risky,
                           all_crime_types=all_cts, search=search,
                           crime_filter=crime_filter,
                           verify_file=verify_file, ai_risk_score=ai_risk_score,
                           time=time, active_page="dashboard")


# =============================================================================
#  METADATA ANALYSIS
# =============================================================================
@app.route("/metadata")
@app.route("/metadata/<cid>/<path:filename>")
@login_required("metadata")
def metadata(cid=None, filename=None):
    conn     = get_db()
    all_rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()

    selected = None
    if cid and filename:
        match = next((r for r in all_rows if r[1] == cid and r[2] == filename), None)
        if match:
            meta       = extract_metadata(match[2], match[3])
            risk       = ai_risk_score(match[2], match[3])
            yara_hits  = scan_file(match[3])
            selected   = {"row": match, "meta": meta, "risk": risk, "yara": yara_hits}
            log_audit(session["user"], f"VIEW_METADATA {cid}/{filename}", request.remote_addr)

    return render_template("metadata.html",
                           all_rows=all_rows, selected=selected,
                           cid=cid, filename=filename,
                           ai_risk_score=ai_risk_score,
                           active_page="metadata")


# =============================================================================
#  AUTOPSY TIMELINE
# =============================================================================
@app.route("/autopsy")
@login_required("autopsy")
def autopsy():
    events = build_autopsy_timeline()
    return render_template("autopsy.html", events=events, active_page="autopsy")


# =============================================================================
#  AI INVESTIGATOR CHAT
# =============================================================================
@app.route("/chat")
@login_required("chat")
def chat_page():
    return render_template("chat.html", active_page="chat")


@app.route("/api/chat", methods=["POST"])
@login_required("chat")
def api_chat():
    csrf_protect()
    user_msg = (request.json or {}).get("message", "").strip()
    if not user_msg:
        return jsonify({"reply": "Please type a question."})
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    reply = built_in_analyst(user_msg, rows)
    return jsonify({"reply": reply})


# =============================================================================
#  INTEGRITY VERIFICATION
# =============================================================================
@app.route("/verify", methods=["GET", "POST"])
@login_required("verify")
def verify():
    result = None
    if request.method == "POST":
        csrf_protect()
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("No file selected.", "error")
        else:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(delete=False, dir=UPLOAD_FOLDER, suffix="_verify")
            uploaded.save(tmp.name)
            new_hash = sha256_file(tmp.name)
            os.unlink(tmp.name)

            conn    = get_db()
            record  = conn.execute(
                "SELECT case_id,filename,hash,timestamp FROM evidence WHERE filename=? ORDER BY id DESC LIMIT 1",
                (uploaded.filename,)
            ).fetchone()
            conn.close()

            if record:
                intact = (record["hash"] == new_hash)
                diff   = "".join(
                    f'<span style="color:var(--danger);font-weight:bold">{b}</span>'
                    if a != b else f'<span style="color:var(--text)">{b}</span>'
                    for a, b in zip(record["hash"], new_hash)
                )
                result = {
                    "found":       True,
                    "intact":      intact,
                    "cid":         record["case_id"],
                    "name":        record["filename"],
                    "stored_hash": record["hash"],
                    "new_hash":    new_hash,
                    "diff_html":   diff,
                    "timestamp":   record["timestamp"],
                }
                log_audit(session["user"],
                          f"VERIFY {'OK' if intact else 'TAMPERED'} {record['case_id']}/{uploaded.filename}",
                          request.remote_addr)
            else:
                result = {"found": False, "name": uploaded.filename}

    return render_template("verify.html", result=result, active_page="verify")


# =============================================================================
#  CNN / ML ANALYSIS
# =============================================================================
# ml_analysis route moved below (upgraded CNN)


# =============================================================================
#  PDF REPORT
# =============================================================================
@app.route("/report/<cid>")
@login_required("report")
def report(cid):
    conn = get_db()
    rows     = conn.execute("SELECT * FROM evidence WHERE case_id=?", (cid,)).fetchall()
    custody  = conn.execute(
        "SELECT filename,action,actor,timestamp,detail FROM custody_log WHERE case_id=? ORDER BY timestamp",
        (cid,)
    ).fetchall()
    notes    = conn.execute(
        "SELECT author,note,timestamp FROM case_notes WHERE case_id=? ORDER BY timestamp",
        (cid,)
    ).fetchall()
    conn.close()

    out_path = os.path.join("reports", f"{cid}_report.pdf")
    os.makedirs("reports", exist_ok=True)
    generate_case_report(cid, rows, custody, notes, out_path)

    log_custody(cid, "—", "EXPORT", session.get("user",""), "PDF report generated")
    log_audit(session.get("user",""), f"EXPORT_PDF {cid}", request.remote_addr)
    return send_file(out_path, as_attachment=True)


# =============================================================================
#  ZIP EXPORT
# =============================================================================
@app.route("/export/<cid>")
@login_required("export")
def export(cid):
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence WHERE case_id=?", (cid,)).fetchall()
    conn.close()

    os.makedirs("exports", exist_ok=True)
    zname = os.path.join("exports", f"{cid}_export.zip")
    with zipfile.ZipFile(zname, "w") as z:
        for r in rows:
            if os.path.exists(r[3]):
                z.write(r[3], arcname=r[2])

    log_custody(cid, "—", "EXPORT", session.get("user",""), "ZIP export generated")
    log_audit(session.get("user",""), f"EXPORT_ZIP {cid}", request.remote_addr)
    return send_file(zname, as_attachment=True)


# =============================================================================
#  VIRUSTOTAL LOOKUP  (API endpoint)
# =============================================================================
@app.route("/api/virustotal/<file_hash>")
@login_required("dashboard")
def vt_lookup(file_hash):
    result = lookup_hash(file_hash)
    return jsonify(result)


# =============================================================================
#  INVESTIGATOR NOTES
# =============================================================================
@app.route("/notes", methods=["GET","POST"])
@app.route("/notes/<cid>", methods=["GET","POST"])
@login_required("notes")
def notes(cid=None):
    if request.method == "POST":
        csrf_protect()
        ncid = request.form.get("case_id","").strip()
        note = request.form.get("note","").strip()
        if ncid and note:
            conn = get_db()
            conn.execute(
                "INSERT INTO case_notes(case_id,author,note,timestamp) VALUES(?,?,?,?)",
                (ncid, session["user"], note, str(time.time()))
            )
            conn.commit(); conn.close()
            log_custody(ncid, "—", "NOTE_ADDED", session["user"], note[:80])
            log_audit(session["user"], f"ADD_NOTE {ncid}", request.remote_addr)
            flash("Note saved.", "success")
            cid = ncid

    conn       = get_db()
    all_cases  = [r[0] for r in conn.execute("SELECT DISTINCT case_id FROM evidence ORDER BY case_id").fetchall()]
    note_rows  = conn.execute(
        "SELECT author,note,timestamp FROM case_notes WHERE case_id=? ORDER BY timestamp DESC" if cid else
        "SELECT author,note,timestamp FROM case_notes ORDER BY timestamp DESC LIMIT 50",
        (cid,) if cid else ()
    ).fetchall()
    conn.close()

    return render_template("notes.html",
                           all_cases=all_cases, note_rows=note_rows,
                           cid=cid, time=time, active_page="notes")


# =============================================================================
#  CHAIN OF CUSTODY
# =============================================================================
@app.route("/custody")
@app.route("/custody/<cid>")
@login_required("custody")
def custody(cid=None):
    conn = get_db()
    if cid:
        rows = conn.execute(
            "SELECT case_id,filename,action,actor,timestamp,detail FROM custody_log WHERE case_id=? ORDER BY timestamp DESC",
            (cid,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT case_id,filename,action,actor,timestamp,detail FROM custody_log ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
    conn.close()
    log_audit(session["user"], f"VIEW_CUSTODY{' ' + cid if cid else ''}", request.remote_addr)
    return render_template("custody.html", rows=rows, cid=cid, time=time, active_page="custody")


# =============================================================================
#  AUDIT TRAIL
# =============================================================================
@app.route("/audit")
@login_required("audit")
def audit():
    conn = get_db()
    rows = conn.execute(
        "SELECT username,event,timestamp,ip FROM audit_log ORDER BY timestamp DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return render_template("audit.html", rows=rows, time=time, active_page="audit")


# =============================================================================
#  FILE CARVING
# =============================================================================
@app.route("/carve")
@app.route("/carve/<int:ev_id>")
@login_required("carve")
def carve(ev_id=None):
    conn     = get_db()
    all_rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()

    selected = carved = None
    if ev_id:
        match = next((r for r in all_rows if r[0] == ev_id), None)
        if match:
            selected = match
            carved   = carve_deleted_files(match[3])
            log_custody(match[1], match[2], "CARVE", session["user"], "File carving initiated")
            log_audit(session["user"], f"CARVE {match[1]}/{match[2]}", request.remote_addr)

    return render_template("carve.html",
                           all_rows=all_rows, selected=selected, carved=carved,
                           ev_id=ev_id, active_page="carve")


# =============================================================================
#  RUN
# =============================================================================
from modules.volatility_engine import analyse_memory, run_plugin, VOLATILITY3_AVAILABLE, supported_formats
from modules.autopsy_export    import parse_export, get_timeline, get_iocs
from modules.cnn_model         import (predict as cnn_predict_nn, train_model,
                                       compute_live_confusion_matrix,
                                       get_training_metrics, retrain, CNN_CLASSES as CNN_CLS)
from modules.threat_intel      import (lookup_hash_all, lookup_ip_all, lookup_url_all,
                                       lookup_domain_all, available_sources)
from modules.ioc_extractor     import extract_iocs, ioc_summary

# Pre-train CNN on startup (uses cache if already trained)
try:
    train_model()
except Exception:
    pass


# =============================================================================
#  VOLATILITY — Memory Forensics
# =============================================================================

@app.route("/volatility", methods=["GET", "POST"])
@login_required("upload")
def volatility():
    result   = None
    plugin   = request.args.get("plugin", "pslist")
    mem_path = None

    if request.method == "POST":
        csrf_protect()
        uploaded = request.files.get("memfile")
        if not uploaded or not uploaded.filename:
            flash("No memory image selected.", "error")
        else:
            try:
                from modules.upload_security import sanitize_filename
                safe_name = sanitize_filename(uploaded.filename)
                dest = os.path.join(UPLOAD_FOLDER, "mem_" + safe_name)
                uploaded.save(dest)
                os.chmod(dest, 0o640)
                plugin   = request.form.get("plugin", "pslist")
                profile  = request.form.get("profile", "")
                all_plug = request.form.get("run_all") == "1"

                if all_plug:
                    result = analyse_memory(dest, profile)
                    result["mode"] = "full"
                else:
                    r = run_plugin(dest, plugin, profile)
                    result = {"mode": "single", "plugin": plugin,
                              "data": r, "file": safe_name,
                              "engine": "volatility3" if VOLATILITY3_AVAILABLE else "built-in parser"}

                log_audit(session["user"],
                          f"VOLATILITY {safe_name} plugin={plugin}", request.remote_addr)
            except Exception as e:
                flash(f"Memory analysis error: {e}", "error")

    PLUGINS = ["pslist","netscan","malfind","cmdline","dlllist",
               "hashdump","strings","filescan","svcscan"]
    return render_template("volatility.html",
                           result=result, plugin=plugin,
                           plugins=PLUGINS,
                           vol3_available=VOLATILITY3_AVAILABLE,
                           supported_formats=supported_formats(),
                           active_page="volatility")


# =============================================================================
#  AUTOPSY EXPORT PARSER
# =============================================================================

@app.route("/autopsy_import", methods=["GET", "POST"])
@login_required("autopsy")
def autopsy_import():
    result = None

    if request.method == "POST":
        csrf_protect()
        uploaded = request.files.get("autopsy_file")
        if not uploaded or not uploaded.filename:
            flash("No Autopsy export file selected.", "error")
        else:
            try:
                from modules.upload_security import sanitize_filename
                safe_name = sanitize_filename(uploaded.filename)
                dest      = os.path.join(UPLOAD_FOLDER, "autopsy_" + safe_name)
                uploaded.save(dest)
                result = parse_export(dest)
                result["filename"] = safe_name
                log_audit(session["user"],
                          f"AUTOPSY_IMPORT {safe_name}", request.remote_addr)
            except Exception as e:
                flash(f"Autopsy import error: {e}", "error")

    return render_template("autopsy_import.html",
                           result=result, active_page="autopsy")


# =============================================================================
#  CNN / ML — Neural Network (upgraded)
# =============================================================================

@app.route("/ml_analysis")
@login_required("ml_analysis")
def ml_analysis():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()

    # Live confusion matrix using real MLP
    cm_data   = compute_live_confusion_matrix(rows)
    train_met = get_training_metrics()

    # Loss/accuracy history from training
    if train_met:
        acc_hist  = train_met.get("acc_history", [])
        loss_hist = train_met.get("loss_history", [])
    else:
        acc_hist  = cm_data.get("acc_history", [])
        loss_hist = []

    return render_template("ml_analysis.html",
                           cm_data=cm_data,
                           train_metrics=train_met,
                           evidence_rows=rows,
                           file_predictions=cm_data.get("file_results", []),
                           cm_data_json=json.dumps(cm_data),
                           acc_history_json=json.dumps(acc_hist),
                           loss_history_json=json.dumps(loss_hist),
                           pr_metrics_json=json.dumps(cm_data.get("metrics", {})),
                           classes_json=json.dumps(cm_data.get("classes", [])),
                           active_page="ml_analysis")


@app.route("/api/retrain", methods=["POST"])
@admin_required
def api_retrain():
    csrf_protect()
    try:
        met = retrain()
        log_audit(session["user"], "CNN_RETRAIN", request.remote_addr)
        return jsonify({"success": True, "accuracy": met.get("accuracy"), "n_iter": met.get("n_iter")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# =============================================================================
#  THREAT INTELLIGENCE
# =============================================================================

@app.route("/threat_intel", methods=["GET", "POST"])
@login_required("dashboard")
def threat_intel():
    result  = None
    sources = available_sources()

    if request.method == "POST":
        csrf_protect()
        ioc_type = request.form.get("ioc_type", "hash")
        ioc_val  = request.form.get("ioc_value", "").strip()

        if not ioc_val:
            flash("Please enter an IOC value.", "error")
        else:
            try:
                if ioc_type == "hash":
                    result = lookup_hash_all(ioc_val)
                elif ioc_type == "ip":
                    result = lookup_ip_all(ioc_val)
                elif ioc_type == "url":
                    result = lookup_url_all(ioc_val)
                elif ioc_type == "domain":
                    result = lookup_domain_all(ioc_val)
                else:
                    result = lookup_hash_all(ioc_val)

                result["queried_type"] = ioc_type
                log_audit(session["user"],
                          f"TI_LOOKUP {ioc_type}:{ioc_val[:40]}", request.remote_addr)
            except Exception as e:
                flash(f"Threat intelligence error: {e}", "error")

    return render_template("threat_intel.html",
                           result=result, sources=sources,
                           active_page="threat_intel")


@app.route("/api/ti/hash/<file_hash>")
@login_required("dashboard")
def api_ti_hash(file_hash):
    return jsonify(lookup_hash_all(file_hash))


# =============================================================================
#  IOC EXTRACTION
# =============================================================================

@app.route("/ioc_extract", methods=["GET", "POST"])
@login_required("metadata")
def ioc_extract():
    result   = None
    ev_rows  = []

    if request.method == "POST":
        csrf_protect()
        ev_id = request.form.get("ev_id")
        if ev_id:
            conn = get_db()
            row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
            conn.close()
            if row:
                try:
                    result = extract_iocs(row[3])
                    result["case_id"]  = row[1]
                    result["filename"] = row[2]
                    # Auto-trigger TI lookups for extracted hashes
                    ti_results = []
                    for h in result["iocs"].get("sha256", [])[:3]:
                        ti = lookup_hash_all(h["value"])
                        ti_results.append(ti)
                    result["ti_results"] = ti_results
                    log_audit(session["user"],
                              f"IOC_EXTRACT {row[1]}/{row[2]}", request.remote_addr)
                except Exception as e:
                    flash(f"IOC extraction error: {e}", "error")

    conn    = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    conn.close()

    return render_template("ioc_extract.html",
                           result=result, ev_rows=ev_rows,
                           active_page="ioc_extract")



# =============================================================================
#  MFA — Setup & Verify
# =============================================================================
@app.route("/mfa/setup", methods=["GET","POST"])
@login_required("dashboard")
def mfa_setup():
    conn = get_db()
    mfa  = get_user_mfa(conn, session["user"])
    conn.close()
    msg  = None

    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","")

        if action == "generate":
            secret   = generate_secret()
            backups  = generate_backup_codes()
            hashed_b = [hash_backup_code(c) for c in backups]
            conn2    = get_db()
            save_user_mfa(conn2, session["user"], secret, False, hashed_b, False)
            conn2.close()
            qr_b64   = generate_qr_png_b64(secret, session["user"])
            uri      = get_totp_uri(secret, session["user"])
            log_audit(session["user"], "MFA_SETUP_STARTED", request.remote_addr)
            return render_template("mfa_setup.html", secret=secret,
                                   qr_b64=qr_b64, uri=uri,
                                   backup_codes=backups, step="verify",
                                   active_page="mfa_setup")

        elif action == "verify":
            code   = request.form.get("totp_code","").strip()
            conn3  = get_db()
            mfa2   = get_user_mfa(conn3, session["user"])
            if verify_totp(mfa2["secret"], code):
                save_user_mfa(conn3, session["user"], mfa2["secret"],
                              True, mfa2["backup_codes"], True)
                conn3.close()
                flash("✅ MFA enabled successfully! Use Google Authenticator to log in.", "success")
                log_audit(session["user"], "MFA_ENABLED", request.remote_addr)
                return redirect(url_for("dashboard"))
            conn3.close()
            flash("❌ Invalid code. Please try again.", "error")

        elif action == "disable":
            conn4 = get_db()
            save_user_mfa(conn4, session["user"], "", False, [], False)
            conn4.close()
            flash("MFA disabled.", "warn")
            log_audit(session["user"], "MFA_DISABLED", request.remote_addr)

    conn5 = get_db()
    mfa   = get_user_mfa(conn5, session["user"])
    conn5.close()
    return render_template("mfa_setup.html", mfa=mfa, step="status",
                           active_page="mfa_setup")


@app.route("/mfa/verify", methods=["GET","POST"])
def mfa_verify():
    if "mfa_pending_user" not in session:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        csrf_protect()
        code = request.form.get("totp_code","").strip()
        backup_code = request.form.get("backup_code","").strip()
        username = session["mfa_pending_user"]
        conn = get_db()
        mfa  = get_user_mfa(conn, username)
        valid = False
        if code and verify_totp(mfa["secret"], code):
            valid = True
        elif backup_code:
            ok, remaining = verify_backup_code(backup_code, mfa["backup_codes"])
            if ok:
                save_user_mfa(conn, username, mfa["secret"],
                              True, remaining, True)
                valid = True
        conn.close()
        if valid:
            row = get_db().execute(
                "SELECT username,role FROM users WHERE username=?", (username,)
            ).fetchone()
            get_db().close()
            session.clear()
            session["user"]         = username
            session["role"]         = row["role"] if row else "analyst"
            session["_last_active"] = time.time()
            session["_csrf"]        = secrets.token_hex(32)
            log_audit(username, "MFA_LOGIN_OK", request.remote_addr)
            return redirect(url_for("dashboard"))
        error = "Invalid code. Try again or use a backup code."
        log_audit(username, "MFA_FAILED", request.remote_addr)
    return render_template("mfa_verify.html", error=error, active_page="mfa_verify")


# =============================================================================
#  EVIDENCE ENCRYPTION
# =============================================================================
@app.route("/encrypt", methods=["GET","POST"])
@login_required("upload")
def encrypt():
    result = None
    if request.method == "POST":
        csrf_protect()
        action  = request.form.get("action","encrypt")
        ev_id   = request.form.get("ev_id","")
        password = request.form.get("password","")
        conn    = get_db()
        row     = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
        conn.close()
        if row:
            path = row[3]
            if action == "encrypt":
                dest = path + ".enc"
                r    = encrypt_file(path, dest, password or None)
                if r["success"]:
                    log_audit(session["user"], f"ENCRYPT {row[1]}/{row[2]}", request.remote_addr)
                    log_custody(row[1], row[2], "ENCRYPTED", session["user"],
                                r["algorithm"][:60])
                result = {"action":"encrypt","row":row, **r}
            elif action == "decrypt":
                if is_encrypted(path):
                    dest = path.replace(".enc","_dec")
                    r    = decrypt_file(path, dest, password or None)
                    log_audit(session["user"], f"DECRYPT {row[1]}/{row[2]}", request.remote_addr)
                    result = {"action":"decrypt","row":row, **r}
                else:
                    result = {"action":"decrypt","row":row,
                              "success":False,"error":"File is not encrypted"}
        else:
            flash("Evidence record not found.", "error")

    conn    = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename,path FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    ev_rows = [(r[0],r[1],r[2],r[3],is_encrypted(r[3])) for r in ev_rows]
    return render_template("encrypt.html", ev_rows=ev_rows, result=result,
                           active_page="encrypt")


# =============================================================================
#  AUTOPSY CASE INTEGRATION
# =============================================================================
@app.route("/autopsy_case", methods=["GET","POST"])
@login_required("autopsy")
def autopsy_case_view():
    result = None
    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","create")
        if action == "create":
            cname  = request.form.get("case_name","").strip()
            examiner = request.form.get("examiner", session["user"])
            desc   = request.form.get("description","")
            if not cname:
                flash("Case name required.", "error")
            else:
                r = create_autopsy_case(cname, examiner, desc, CASES_DIR)
                if r["success"]:
                    log_audit(session["user"],
                              f"AUTOPSY_CREATE {cname}", request.remote_addr)
                    flash(f"✅ Case created: {r['aut_file']}", "success")
                    result = {"action":"created", **r}
                else:
                    flash(f"Error: {r.get('error')}", "error")
        elif action == "read":
            db_path = request.form.get("db_path","")
            if os.path.exists(db_path):
                artifacts = read_case_artifacts(db_path)
                result    = {"action":"artifacts", "artifacts": artifacts,
                             "db_path": db_path}
                log_audit(session["user"], f"AUTOPSY_READ {db_path[-30:]}", request.remote_addr)
            else:
                flash("Database file not found.", "error")

    # List existing cases
    existing_cases = []
    for root, dirs, files in os.walk(CASES_DIR):
        for f in files:
            if f.endswith(".db"):
                existing_cases.append(os.path.join(root, f))

    return render_template("autopsy_case.html",
                           result=result,
                           existing_cases=existing_cases,
                           autopsy_available=AUTOPSY_AVAILABLE,
                           active_page="autopsy_case")


# =============================================================================
#  EVIDENCE RELATIONSHIP GRAPH
# =============================================================================
@app.route("/graph")
@login_required("dashboard")
def evidence_graph_view():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    graph = build_evidence_graph(rows)
    log_audit(session["user"], "VIEW_GRAPH", request.remote_addr)
    return render_template("evidence_graph.html",
                           graph_json=json.dumps(graph),
                           stats=graph["stats"],
                           summary=graph_summary(graph),
                           active_page="graph")


# =============================================================================
#  MALWARE SANDBOX
# =============================================================================
@app.route("/sandbox")
@app.route("/sandbox/<int:ev_id>")
@login_required("upload")
def malware_sandbox(ev_id=None):
    conn    = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    result  = None
    selected = None
    if ev_id:
        conn = get_db()
        row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
        conn.close()
        if row:
            selected = row
            result   = sandbox_analyse(row[3])
            log_audit(session["user"], f"SANDBOX {row[1]}/{row[2]}", request.remote_addr)
            log_custody(row[1], row[2], "SANDBOX", session["user"],
                        f"verdict={result.get('verdict')}")
    return render_template("sandbox.html", ev_rows=ev_rows, result=result,
                           selected=selected, ev_id=ev_id, active_page="sandbox")


# =============================================================================
#  AI INVESTIGATION ASSISTANT (Ollama)
# =============================================================================
@app.route("/ai_assistant")
@login_required("dashboard")
def ai_assistant_page():
    ollama_status = get_ollama_status()
    return render_template("ai_assistant.html",
                           ollama_status=ollama_status,
                           active_page="ai_assistant")


@app.route("/api/ai_chat", methods=["POST"])
@login_required("dashboard")
def api_ai_chat():
    csrf_protect()
    data     = request.json or {}
    question = data.get("message","").strip()
    history  = data.get("history", [])
    if not question:
        return jsonify({"reply":"Please ask a question.", "source":"fallback","model":""})
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    ctx   = build_evidence_context(rows)
    reply = ai_chat(question, history, ctx)
    return jsonify(reply)


# =============================================================================
#  DASHBOARD ANALYTICS
# =============================================================================
@app.route("/analytics")
@login_required("dashboard")
def analytics():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    audit_rows = conn.execute(
        "SELECT event, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 500"
    ).fetchall()
    conn.close()

    from collections import Counter, defaultdict
    crime_counts = Counter(r[6] for r in rows if r[6])
    risk_counts  = Counter()
    cat_counts   = Counter(r[7] for r in rows if r[7])

    # Risk distribution
    for r in rows:
        if os.path.exists(r[3]):
            try:
                lvl = ai_risk_score(r[2],r[3])["level"]
                risk_counts[lvl] += 1
            except Exception:
                risk_counts["UNKNOWN"] += 1

    # Timeline growth (evidence per day)
    daily = defaultdict(int)
    for r in rows:
        try:
            day = time.strftime("%Y-%m-%d", time.localtime(float(r[5])))
            daily[day] += 1
        except Exception:
            pass

    # Audit events by type
    event_counts = Counter()
    for ev, ts in audit_rows:
        key = ev.split()[0] if ev else "OTHER"
        event_counts[key] += 1

    analytics_data = {
        "crime_types":    dict(crime_counts.most_common(10)),
        "risk_levels":    dict(risk_counts),
        "evidence_cats":  dict(cat_counts.most_common(8)),
        "daily_growth":   {k: daily[k] for k in sorted(daily)[-30:]},
        "audit_events":   dict(event_counts.most_common(8)),
        "total_evidence": len(rows),
        "total_cases":    len(set(r[1] for r in rows)),
    }
    return render_template("analytics.html",
                           data=analytics_data,
                           data_json=json.dumps(analytics_data),
                           active_page="analytics")



# =============================================================================
#  FEATURE ROUTES — 10 Major New Features
# =============================================================================
from modules.ocr_engine       import analyse as ocr_analyse
from modules.crime_classifier import classify as content_classify, train_ml_classifier
from modules.correlation_engine import correlate as correlate_evidence
from modules.timeline_engine  import reconstruct_timeline
from modules.mitre_attack     import map_all_evidence, map_file as mitre_map_file, generate_report as mitre_report
from modules.malware_analysis import analyse as malware_analyse
from modules.ti_correlation   import correlate_evidence as ti_correlate
from modules.evidence_signing import sign_evidence, verify_evidence, get_public_key_pem
from modules.siem_integration import (siem_status_all, elastic_index_all,
                                       generate_all_sigma_rules, wazuh_send_alert)

# Pre-train crime classifier
try: train_ml_classifier()
except Exception: pass

# --- DB schema additions ---
def _extend_schema():
    conn = get_db()
    for stmt in [
        "ALTER TABLE evidence ADD COLUMN signed_by TEXT DEFAULT ''",
        "ALTER TABLE evidence ADD COLUMN signature TEXT DEFAULT ''",
        "ALTER TABLE evidence ADD COLUMN sig_payload TEXT DEFAULT ''",
        "ALTER TABLE evidence ADD COLUMN content_crime TEXT DEFAULT ''",
        "ALTER TABLE evidence ADD COLUMN ocr_text TEXT DEFAULT ''",
    ]:
        try: conn.execute(stmt)
        except Exception: pass
    conn.commit(); conn.close()
try: _extend_schema()
except Exception: pass


@app.route("/ocr_analysis", methods=["GET","POST"])
@login_required("upload")
def ocr_analysis():
    result  = None
    ev_rows = []
    conn = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    if request.method == "POST":
        csrf_protect()
        ev_id = request.form.get("ev_id")
        if ev_id:
            conn = get_db()
            row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
            conn.close()
            if row:
                result = ocr_analyse(row[3])
                result["case_id"]  = row[1]
                result["ev_id"]    = ev_id
                if result.get("success") and result.get("full_text"):
                    conn2 = get_db()
                    conn2.execute("UPDATE evidence SET ocr_text=? WHERE id=?",
                                  (result["full_text"][:2000], ev_id))
                    conn2.commit(); conn2.close()
                log_audit(session["user"], f"OCR_ANALYSIS {row[1]}/{row[2]}", request.remote_addr)
    return render_template("ocr_analysis.html", result=result, ev_rows=ev_rows, active_page="ocr")


@app.route("/content_classify", methods=["GET","POST"])
@login_required("upload")
def content_classification():
    result  = None
    conn = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    if request.method == "POST":
        csrf_protect()
        ev_id = request.form.get("ev_id")
        if ev_id:
            conn = get_db()
            row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
            conn.close()
            if row:
                result = content_classify(row[3])
                result["case_id"]  = row[1]
                result["filename"] = row[2]
                conn2 = get_db()
                conn2.execute("UPDATE evidence SET content_crime=? WHERE id=?",
                              (result.get("predicted_crime",""), ev_id))
                conn2.commit(); conn2.close()
                log_audit(session["user"], f"CONTENT_CLASSIFY {row[1]}/{row[2]}", request.remote_addr)
    return render_template("content_classify.html", result=result, ev_rows=ev_rows, active_page="content_classify")


@app.route("/correlation")
@login_required("dashboard")
def correlation_view():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    result = correlate_evidence(rows)
    log_audit(session["user"], "CORRELATION_VIEW", request.remote_addr)
    return render_template("correlation.html",
                           result=result,
                           result_json=json.dumps(result),
                           active_page="correlation")


@app.route("/attack_timeline")
@login_required("dashboard")
def attack_timeline():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    cust = conn.execute("SELECT case_id,filename,action,actor,timestamp,detail FROM custody_log ORDER BY timestamp").fetchall()
    conn.close()
    result = reconstruct_timeline(rows, cust)
    log_audit(session["user"], "TIMELINE_VIEW", request.remote_addr)
    return render_template("attack_timeline.html",
                           result=result,
                           result_json=json.dumps(result),
                           active_page="attack_timeline")


@app.route("/mitre")
@app.route("/mitre/<int:ev_id>")
@login_required("dashboard")
def mitre_view(ev_id=None):
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    if ev_id:
        row = next((r for r in rows if r[0]==ev_id), None)
        if row:
            single = mitre_map_file(row[3])
            single["filename"] = row[2]; single["case_id"] = row[1]
            result = {"file_mappings":[single],"all_techniques":single["techniques"],
                      "tactic_counts":{},"top_techniques":single["techniques"][:5],
                      "navigator_layer":{},"tactic_colors":{}}
        else:
            result = map_all_evidence(rows)
    else:
        result = map_all_evidence(rows)
    log_audit(session["user"], "MITRE_VIEW", request.remote_addr)
    return render_template("mitre_attack.html",
                           result=result,
                           result_json=json.dumps(result),
                           ev_rows=rows, ev_id=ev_id,
                           active_page="mitre")


@app.route("/malware_analysis_adv")
@app.route("/malware_analysis_adv/<int:ev_id>")
@login_required("upload")
def malware_analysis_adv(ev_id=None):
    conn    = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    result  = None
    if ev_id:
        conn = get_db()
        row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
        conn.close()
        if row:
            result = malware_analyse(row[3])
            result["case_id"] = row[1]
            log_audit(session["user"], f"MALWARE_ANALYSIS {row[1]}/{row[2]}", request.remote_addr)
            log_custody(row[1], row[2], "MALWARE_ANALYSIS", session["user"],
                        f"verdict={result.get('verdict')}")
    return render_template("malware_analysis_adv.html",
                           result=result, ev_rows=ev_rows, ev_id=ev_id,
                           result_json=json.dumps(result) if result else "{}",
                           active_page="malware_adv")


@app.route("/ti_center")
@login_required("dashboard")
def ti_center():
    conn = get_db()
    rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    result = ti_correlate(rows)
    log_audit(session["user"], "TI_CENTER", request.remote_addr)
    return render_template("ti_center.html",
                           result=result,
                           active_page="ti_center")


@app.route("/sign_evidence", methods=["GET","POST"])
@login_required("upload")
def sign_evidence_view():
    result  = None
    conn    = get_db()
    ev_rows = conn.execute("SELECT id,case_id,filename,path FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","sign")
        ev_id  = request.form.get("ev_id")
        if ev_id:
            conn = get_db()
            row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
            conn.close()
            if row:
                if action == "sign":
                    r = sign_evidence(row[3], session["user"], row[1])
                    if r["success"]:
                        conn2 = get_db()
                        conn2.execute("UPDATE evidence SET signed_by=?,signature=?,sig_payload=? WHERE id=?",
                                      (session["user"], r["signature"], r["payload"], ev_id))
                        conn2.commit(); conn2.close()
                        log_audit(session["user"], f"SIGN_EVIDENCE {row[1]}/{row[2]}", request.remote_addr)
                        log_custody(row[1], row[2], "SIGNED", session["user"], f"RSA-PSS signature applied")
                    result = {**r, "action":"sign","filename":row[2],"case_id":row[1]}
                elif action == "verify":
                    sig  = row[8] if len(row) > 8 else ""
                    payl = row[9] if len(row) > 9 else ""
                    if sig and payl:
                        r = verify_evidence(row[3], sig, payl)
                    else:
                        r = {"valid":False,"error":"No signature on record for this file"}
                    result = {**r, "action":"verify","filename":row[2],"case_id":row[1]}
    pubkey = get_public_key_pem()
    return render_template("sign_evidence.html",
                           ev_rows=ev_rows, result=result, pubkey=pubkey,
                           active_page="sign_evidence")


@app.route("/siem", methods=["GET","POST"])
@login_required("dashboard")
def siem_view():
    status = siem_status_all()
    sigma_rules = []
    index_result = None
    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","")
        conn   = get_db()
        rows   = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
        conn.close()
        if action == "generate_sigma":
            sigma_rules = generate_all_sigma_rules(rows)
            log_audit(session["user"], f"SIEM_SIGMA_GENERATE {len(sigma_rules)} rules", request.remote_addr)
        elif action == "elastic_index":
            index_result = elastic_index_all(rows)
            log_audit(session["user"], "SIEM_ELASTIC_INDEX", request.remote_addr)
    return render_template("siem.html",
                           status=status, sigma_rules=sigma_rules,
                           index_result=index_result,
                           active_page="siem")


@app.route("/api/sigma/<int:ev_id>")
@login_required("dashboard")
def api_sigma_rule(ev_id):
    from modules.siem_integration import generate_sigma_rule
    conn = get_db()
    row  = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"Not found"}), 404
    crime = row[6] if len(row)>6 else "Unknown Malware"
    rule  = generate_sigma_rule(crime, {"filename":row[2],"case_id":row[1],"iocs":{}})
    return rule, 200, {"Content-Type":"text/plain"}



# =============================================================================
#  FEATURE ROUTES: Video Crime Detection, Face Recognition, Evidence Encryption
# =============================================================================
from modules.video_crime_detection   import analyse_video, is_video, VIDEO_EXTENSIONS
from modules.face_recognition_engine import (detect_faces_in_image, match_face,
                                              init_face_tables, save_faces,
                                              get_all_faces, get_faces_by_evidence,
                                              label_person, get_face_statistics,
                                              process_image_for_faces)
from modules.evidence_encryption     import (encrypt_file as ev_encrypt,
                                              decrypt_file as ev_decrypt,
                                              is_encrypted as ev_is_encrypted,
                                              encryption_info, init_encryption_tables,
                                              log_encryption_action, get_encryption_stats,
                                              batch_encrypt_existing)

# --- Init new tables on startup ---
try:
    _c = get_db()
    init_face_tables(_c)
    init_encryption_tables(_c)
    _c.close()
except Exception: pass

# Add video columns to evidence table
def _add_video_columns():
    conn = get_db()
    for col, dflt in [
        ("video_analysis", "''"),
        ("video_crime",    "''"),
        ("video_conf",     "0"),
        ("face_count",     "0"),
        ("is_encrypted",   "0"),
        ("enc_sha256",     "''"),
        ("enc_algorithm",  "''"),
    ]:
        try: conn.execute(f"ALTER TABLE evidence ADD COLUMN {col} TEXT DEFAULT {dflt}")
        except Exception: pass
    conn.commit(); conn.close()
try: _add_video_columns()
except Exception: pass


# ─── VIDEO CRIME DETECTION ───────────────────────────────────────────────────

@app.route("/video_analysis", methods=["GET","POST"])
@login_required("upload")
def video_analysis():
    result  = None
    conn    = get_db()
    ev_rows = conn.execute(
        "SELECT id,case_id,filename FROM evidence ORDER BY id DESC"
    ).fetchall()
    conn.close()

    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","analyse")

        if action == "upload_video":
            f = request.files.get("file")
            try:
                cid  = new_case_id()
                path, original_name = secure_save(f, cid)
                if not is_video(path):
                    result = {"success":False,"error":"Not a supported video format. Supported: "+", ".join(sorted(VIDEO_EXTENSIONS))}
                else:
                    h = sha256_file(path)
                    # Run video analysis
                    vresult = analyse_video(path)
                    v_json  = json.dumps(vresult)

                    conn2 = get_db()
                    for col in ["video_analysis","video_crime","video_conf","face_count"]:
                        try: conn2.execute(f"ALTER TABLE evidence ADD COLUMN {col} TEXT DEFAULT ''")
                        except Exception: pass

                    conn2.execute("""
                        INSERT INTO evidence(case_id,filename,path,hash,timestamp,
                            crime_type,evidence_category,video_analysis,video_crime,video_conf)
                        VALUES(?,?,?,?,?,?,?,?,?,?)
                    """, (cid, original_name, path, h, str(time.time()),
                          vresult.get("crime_type","Unknown"),
                          "Video Evidence", v_json,
                          vresult.get("crime_type",""), vresult.get("confidence",0)))
                    conn2.commit(); conn2.close()

                    log_audit(session["user"], f"VIDEO_UPLOAD {cid}/{original_name}", request.remote_addr)
                    log_custody(cid, original_name, "VIDEO_UPLOAD", session["user"],
                                f"Crime: {vresult.get('crime_type','Unknown')}")
                    result = vresult
                    result["cid"] = cid
            except Exception as e:
                result = {"success":False,"error":str(e)}

        elif action == "analyse_existing":
            ev_id = request.form.get("ev_id")
            if ev_id:
                conn3 = get_db()
                row   = conn3.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
                conn3.close()
                if row and is_video(row["path"] if hasattr(row,"keys") else row[3]):
                    path = row["path"] if hasattr(row,"keys") else row[3]
                    vresult = analyse_video(path)
                    v_json  = json.dumps(vresult)
                    conn4   = get_db()
                    conn4.execute("UPDATE evidence SET video_analysis=?,video_crime=?,video_conf=? WHERE id=?",
                                  (v_json, vresult.get("crime_type",""), vresult.get("confidence",0), ev_id))
                    conn4.commit(); conn4.close()
                    result = vresult
                    log_audit(session["user"], f"VIDEO_ANALYSE ev_id={ev_id}", request.remote_addr)

    return render_template("video_analysis.html",
                           result=result, ev_rows=ev_rows,
                           video_exts=sorted(VIDEO_EXTENSIONS),
                           active_page="video_analysis")


@app.route("/api/video_result/<int:ev_id>")
@login_required("dashboard")
def api_video_result(ev_id):
    conn = get_db()
    row  = conn.execute("SELECT video_analysis FROM evidence WHERE id=?", (ev_id,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return jsonify({"error":"No video analysis for this evidence"})
    try:
        return jsonify(json.loads(row[0]))
    except Exception:
        return jsonify({"error":"Invalid video analysis data"})


# ─── FACE RECOGNITION ────────────────────────────────────────────────────────

@app.route("/face_recognition", methods=["GET","POST"])
@login_required("dashboard")
def face_recognition_view():
    conn    = get_db()
    stats   = get_face_statistics(conn)
    faces   = get_all_faces(conn)
    persons = conn.execute("SELECT * FROM persons ORDER BY name").fetchall()
    ev_rows = conn.execute("SELECT id,case_id,filename FROM evidence ORDER BY id DESC").fetchall()
    result  = None

    if request.method == "POST":
        csrf_protect()
        action = request.form.get("action","")

        if action == "scan_evidence":
            ev_id = request.form.get("ev_id")
            if ev_id:
                row = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
                if row:
                    path = row["path"] if hasattr(row,"keys") else row[3]
                    cid  = row["case_id"] if hasattr(row,"keys") else row[1]
                    r    = process_image_for_faces(path, int(ev_id), cid, conn)
                    result = {"action":"scan","ev_id":ev_id, **r}
                    log_audit(session["user"], f"FACE_SCAN ev_id={ev_id}", request.remote_addr)

        elif action == "label_face":
            face_id   = request.form.get("face_id","")
            name      = request.form.get("person_name","").strip()
            notes     = request.form.get("notes","")
            if face_id and name:
                pid = label_person(conn, face_id, name, notes)
                result = {"action":"label","face_id":face_id,"person_id":pid,"name":name}
                log_audit(session["user"], f"FACE_LABEL {face_id} → {name}", request.remote_addr)

        elif action == "scan_all":
            img_rows = conn.execute(
                "SELECT id,case_id,path FROM evidence WHERE path LIKE '%.jpg' OR path LIKE '%.jpeg' OR path LIKE '%.png'"
            ).fetchall()
            total_faces = 0
            for row in img_rows[:20]:
                ev_id = row[0]; cid = row[1]; path = row[2]
                if os.path.exists(path):
                    r = process_image_for_faces(path, ev_id, cid, conn)
                    total_faces += r.get("faces_detected",0)
            result = {"action":"scan_all","total_faces":total_faces}
            log_audit(session["user"], "FACE_SCAN_ALL", request.remote_addr)

        faces   = get_all_faces(conn)
        stats   = get_face_statistics(conn)

    conn.close()
    return render_template("face_recognition.html",
                           stats=stats, faces=faces, persons=persons,
                           ev_rows=ev_rows, result=result,
                           active_page="face_recognition")


@app.route("/face_search", methods=["POST"])
@login_required("dashboard")
def face_search():
    csrf_protect()
    uploaded = request.files.get("face_image")
    if not uploaded:
        return jsonify({"error":"No image uploaded"})
    import tempfile
    tmp = tempfile.mktemp(suffix=".jpg")
    uploaded.save(tmp)
    try:
        faces = detect_faces_in_image(tmp)
        if not faces:
            return jsonify({"found":False,"message":"No faces detected in uploaded image"})
        conn   = get_db()
        known  = get_all_faces(conn)
        conn.close()
        results = []
        for face in faces:
            m = match_face(face["encoding"], known)
            results.append({
                "face_id":   face["face_id"],
                "matched":   m["matched"],
                "match_pct": m.get("match_pct",0),
                "person_id": m.get("person_id"),
                "all_scores":[{"face_id":s["face_id"],"pct":s["match_pct"]}
                               for s in m.get("all_scores",[])[:5]],
            })
        log_audit(session.get("user",""), "FACE_SEARCH", request.remote_addr)
        return jsonify({"found":True,"faces":results})
    finally:
        try: os.unlink(tmp)
        except: pass


# ─── EVIDENCE ENCRYPTION ─────────────────────────────────────────────────────

@app.route("/encryption_dashboard")
@login_required("dashboard")
def encryption_dashboard():
    conn  = get_db()
    stats = get_encryption_stats(conn)
    logs  = conn.execute(
        "SELECT el.*, e.filename, e.case_id FROM encryption_log el "
        "LEFT JOIN evidence e ON el.evidence_id=e.id "
        "ORDER BY el.timestamp DESC LIMIT 100"
    ).fetchall()
    ev_rows = conn.execute("SELECT id,case_id,filename,path,is_encrypted FROM evidence ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("encryption_dashboard.html",
                           stats=stats, logs=logs, ev_rows=ev_rows,
                           active_page="encryption_dashboard")


@app.route("/api/encrypt_evidence", methods=["POST"])
@login_required("upload")
def api_encrypt_evidence():
    csrf_protect()
    ev_id    = request.form.get("ev_id")
    password = request.form.get("password","")
    conn     = get_db()
    row      = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success":False,"error":"Evidence not found"})

    path = row["path"] if hasattr(row,"keys") else row[3]
    if ev_is_encrypted(path):
        conn.close()
        return jsonify({"success":False,"error":"File already encrypted"})

    result = ev_encrypt(path, path+".enc", password or None)
    if result["success"]:
        try:
            os.remove(path)
            os.rename(path+".enc", path)
        except Exception as e:
            conn.close()
            return jsonify({"success":False,"error":str(e)})

        conn.execute("UPDATE evidence SET is_encrypted='1',enc_sha256=?,enc_algorithm=? WHERE id=?",
                     (result["sha256_original"], result["algorithm"], ev_id))
        log_encryption_action(conn, int(ev_id), "ENCRYPT", session["user"],
                               request.remote_addr,
                               sha256_before=result.get("sha256_original",""),
                               algorithm=result["algorithm"])
        conn.commit()
        log_audit(session["user"], f"ENCRYPT ev_id={ev_id}", request.remote_addr)

    conn.close()
    return jsonify({"success":result["success"],
                    "algorithm":result.get("algorithm",""),
                    "error":result.get("error","")})


@app.route("/api/decrypt_evidence", methods=["POST"])
@login_required("upload")
def api_decrypt_evidence():
    csrf_protect()
    ev_id    = request.form.get("ev_id")
    password = request.form.get("password","")
    conn     = get_db()
    row      = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success":False,"error":"Evidence not found"})

    path = row["path"] if hasattr(row,"keys") else row[3]
    if not ev_is_encrypted(path):
        conn.close()
        return jsonify({"success":False,"error":"File is not encrypted"})

    tmp_path = path+"_dec_tmp"
    result   = ev_decrypt(path, tmp_path, password or None)
    if result["success"]:
        try:
            os.remove(path)
            os.rename(tmp_path, path)
        except Exception as e:
            conn.close()
            return jsonify({"success":False,"error":str(e)})
        conn.execute("UPDATE evidence SET is_encrypted='0' WHERE id=?", (ev_id,))
        log_encryption_action(conn, int(ev_id), "DECRYPT", session["user"],
                               request.remote_addr,
                               sha256_after=result.get("sha256",""),
                               success=True)
        conn.commit()
        log_audit(session["user"], f"DECRYPT ev_id={ev_id}", request.remote_addr)
    else:
        log_encryption_action(conn, int(ev_id), "DECRYPT_FAIL", session["user"],
                               request.remote_addr, success=False)
        conn.commit()

    conn.close()
    return jsonify({"success":result["success"],
                    "integrity":result.get("integrity",""),
                    "tampered":result.get("tampered",False),
                    "error":result.get("error","")})


@app.route("/api/batch_encrypt", methods=["POST"])
@login_required("upload")
def api_batch_encrypt():
    csrf_protect()
    conn   = get_db()
    result = batch_encrypt_existing(conn, UPLOAD_FOLDER, session["user"])
    conn.close()
    log_audit(session["user"], f"BATCH_ENCRYPT {result['encrypted']} files", request.remote_addr)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
