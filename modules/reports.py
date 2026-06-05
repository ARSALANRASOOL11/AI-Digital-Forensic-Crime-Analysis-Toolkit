# =============================================================================
#  modules/reports.py  — PDF report generation (improved)
# =============================================================================

import os, time
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors

from modules.upload_security import verify_file
from modules.analysis import ai_risk_score

PAGE_W, PAGE_H = letter

# Brand colours
C_BG      = HexColor("#020b18")
C_ACCENT  = HexColor("#00ffe7")
C_ACCENT2 = HexColor("#0088ff")
C_DANGER  = HexColor("#ff3c3c")
C_WARN    = HexColor("#ffb800")
C_SAFE    = HexColor("#00ff88")
C_TEXT    = HexColor("#c8dff0")
C_MUTED   = HexColor("#4a7090")
C_SURFACE = HexColor("#041525")


def _header(pdf, cid: str, title: str):
    # Dark header bar
    pdf.setFillColor(C_BG)
    pdf.rect(0, PAGE_H - 90, PAGE_W, 90, fill=1, stroke=0)
    # Accent line
    pdf.setFillColor(C_ACCENT)
    pdf.rect(0, PAGE_H - 92, PAGE_W, 2, fill=1, stroke=0)
    # Title
    pdf.setFillColor(C_ACCENT)
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, PAGE_H - 32, "CYBER FORENSIC INTELLIGENCE SYSTEM")
    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(C_TEXT)
    pdf.drawString(50, PAGE_H - 48, title)
    pdf.drawString(50, PAGE_H - 62, f"Case: {cid}  |  Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    pdf.setFillColor(C_MUTED)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(50, PAGE_H - 76, "CONFIDENTIAL — FOR LAW ENFORCEMENT USE ONLY")


def _footer(pdf, page_num: int):
    pdf.setFillColor(C_MUTED)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(50, 25, "CFIS v4.0 — Forensic Report")
    pdf.drawRightString(PAGE_W - 50, 25, f"Page {page_num}")
    pdf.setFillColor(C_SURFACE)
    pdf.rect(0, 0, PAGE_W, 20, fill=1, stroke=0)


def _section_title(pdf, y: float, text: str) -> float:
    pdf.setFillColor(C_ACCENT2)
    pdf.rect(50, y - 2, PAGE_W - 100, 20, fill=1, stroke=0)
    pdf.setFillColor(white)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(55, y + 4, text.upper())
    return y - 28


def _kv_row(pdf, y: float, key: str, value: str, alt: bool = False) -> float:
    if alt:
        pdf.setFillColor(HexColor("#071e33"))
        pdf.rect(50, y - 3, PAGE_W - 100, 16, fill=1, stroke=0)
    pdf.setFillColor(C_MUTED)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(55, y + 1, key + ":")
    pdf.setFillColor(C_TEXT)
    pdf.setFont("Helvetica", 8)
    # Truncate long values
    display = value[:120] + ("…" if len(value) > 120 else "")
    pdf.drawString(200, y + 1, display)
    return y - 16


def generate_case_report(cid: str, ev_rows: list, custody_rows: list,
                         note_rows: list, output_path: str) -> str:
    """Generate a styled multi-page PDF report. Returns output_path."""
    pdf = canvas.Canvas(output_path, pagesize=letter)
    page_num = 1
    _header(pdf, cid, "Evidence Intelligence Report")
    y = PAGE_H - 110

    # ---- Executive Summary ----
    y = _section_title(pdf, y, "Executive Summary")
    total      = len(ev_rows)
    tampered_c = sum(1 for r in ev_rows if verify_file(r[3], r[4]) == "TAMPERED")
    high_c     = sum(1 for r in ev_rows if ai_risk_score(r[2], r[3])["level"] == "HIGH_RISK")

    summary_items = [
        ("Total Evidence Files", str(total)),
        ("Tampered Files",       str(tampered_c)),
        ("High-Risk Files",      str(high_c)),
        ("Report Generated",     time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())),
        ("Case ID",              cid),
    ]
    for i, (k, v) in enumerate(summary_items):
        if y < 80:
            _footer(pdf, page_num); pdf.showPage(); page_num += 1
            _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
        y = _kv_row(pdf, y, k, v, alt=(i % 2 == 0))

    y -= 10

    # ---- Evidence Records ----
    y = _section_title(pdf, y, f"Evidence Records ({total} files)")

    for idx, r in enumerate(ev_rows):
        rid, rcid2, name, path, h, t = r[0], r[1], r[2], r[3], r[4], r[5]
        crime_type = r[6] if len(r) > 6 else "Unclassified"
        ev_cat     = r[7] if len(r) > 7 else "Unknown"
        vt_result  = r[8] if len(r) > 8 else ""

        try:
            ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(t)))
        except Exception:
            ts = str(t)

        vstatus = verify_file(path, h)
        risk    = ai_risk_score(name, path)

        if y < 140:
            _footer(pdf, page_num); pdf.showPage(); page_num += 1
            _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
            y = _section_title(pdf, y, "Evidence Records (continued)")

        # File card background
        pdf.setFillColor(C_SURFACE)
        pdf.rect(50, y - 82, PAGE_W - 100, 88, fill=1, stroke=0)
        pdf.setStrokeColor(C_ACCENT if vstatus == "MATCHED" else C_DANGER)
        pdf.setLineWidth(1)
        pdf.rect(50, y - 82, PAGE_W - 100, 88, fill=0, stroke=1)

        pdf.setFillColor(C_ACCENT)
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(57, y - 8, f"[{idx+1}] {name}")

        items = [
            ("SHA-256",    h),
            ("Integrity",  vstatus),
            ("AI Risk",    f"{risk['level']} ({risk['score']}/100)"),
            ("Crime Type", crime_type),
            ("Category",   ev_cat),
            ("Uploaded",   ts),
            ("VT Result",  vt_result or "Not checked"),
            ("Reasons",    "; ".join(risk["reasons"][:2])),
        ]
        row_y = y - 22
        for ki, (k, v) in enumerate(items):
            pdf.setFillColor(C_MUTED); pdf.setFont("Helvetica-Bold", 7.5)
            pdf.drawString(57, row_y, k + ":")
            pdf.setFillColor(C_TEXT); pdf.setFont("Helvetica", 7.5)
            pdf.drawString(170, row_y, str(v)[:110])
            row_y -= 11
            if ki == 3:  # two-column mid-point
                pass

        y -= 96

    # ---- Chain of Custody ----
    if custody_rows:
        if y < 120:
            _footer(pdf, page_num); pdf.showPage(); page_num += 1
            _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
        y = _section_title(pdf, y, "Chain of Custody")
        for fname2, action, actor, ts2, detail in custody_rows:
            try:
                ts2_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts2)))
            except Exception:
                ts2_str = str(ts2)
            if y < 70:
                _footer(pdf, page_num); pdf.showPage(); page_num += 1
                _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
            y = _kv_row(pdf, y, f"{ts2_str} [{action}] {actor}", detail[:80])

    # ---- Notes ----
    if note_rows:
        if y < 120:
            _footer(pdf, page_num); pdf.showPage(); page_num += 1
            _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
        y = _section_title(pdf, y, "Investigator Notes")
        for author, note_text, ts3 in note_rows:
            try:
                ts3_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts3)))
            except Exception:
                ts3_str = str(ts3)
            if y < 70:
                _footer(pdf, page_num); pdf.showPage(); page_num += 1
                _header(pdf, cid, "Evidence Intelligence Report"); y = PAGE_H - 110
            y = _kv_row(pdf, y, f"{ts3_str} [{author}]", note_text[:100])

    _footer(pdf, page_num)
    pdf.save()
    return output_path
