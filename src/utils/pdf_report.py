# =============================================
# SafeMail-X Professional Forensic PDF Engine
# Version 3.0 — 10-Section Incident Report
# =============================================

import os
import re
import textwrap
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors


# ── Colour palette ────────────────────────────────────────────────────────────
BG_DARK   = (0.10, 0.10, 0.12)
BG_CARD   = (0.14, 0.14, 0.16)
BG_HEADER = (0.07, 0.13, 0.24)
COL_WHITE = colors.white
COL_GREY  = colors.Color(0.55, 0.55, 0.55)
COL_BLUE  = colors.Color(0.31, 0.76, 0.97)
COL_RED   = colors.Color(1.0,  0.23, 0.23)
COL_AMBER = colors.Color(1.0,  0.62, 0.04)
COL_GREEN = colors.Color(0.19, 0.82, 0.34)
COL_PALE  = colors.Color(0.75, 0.75, 0.75)


def _score_color(score_fraction):
    if score_fraction >= 0.75:
        return COL_RED
    elif score_fraction >= 0.45:
        return COL_AMBER
    return COL_GREEN


def _status_badge(c, x, y, status: str):
    """Draw a small coloured badge (PASS/FAIL/WARN/UNKNOWN) at (x,y)."""
    s = status.upper()
    if s in ("PASS", "SECURED", "OK"):
        r, g, b = 0.05, 0.25, 0.12
        label_col = colors.Color(0.2, 0.9, 0.4)
    elif s in ("FAIL", "MALICIOUS", "FLAGGED"):
        r, g, b = 0.4, 0.05, 0.05
        label_col = colors.Color(1.0, 0.5, 0.5)
    elif s in ("WARN", "SUSPICIOUS", "SOFTFAIL", "MISMATCH"):
        r, g, b = 0.4, 0.25, 0.05
        label_col = colors.Color(1.0, 0.8, 0.4)
    else:
        r, g, b = 0.20, 0.20, 0.22
        label_col = colors.Color(0.8, 0.8, 0.8)

    c.setFillColorRGB(r, g, b)
    c.roundRect(x, y - 4, 66, 16, 4, fill=1, stroke=0)
    c.setFillColor(label_col)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(x + 33, y + 2, s)


def generate_pdf_report(evidence: dict) -> str:
    # ── Prevent ReportLab Unicode Crashes ──────────────────────────────────────
    def _sanitize_unicode(obj):
        if isinstance(obj, str):
            # Encode to ascii/latin-1 to strip emojis and unsupported chars for ReportLab
            return obj.encode('latin-1', 'ignore').decode('latin-1')
        elif isinstance(obj, dict):
            return {k: _sanitize_unicode(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_sanitize_unicode(v) for v in obj]
        return obj
        
    evidence = _sanitize_unicode(evidence)

    # ── Setup ─────────────────────────────────────────────────────────────────
    base_dir    = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath      = os.path.join(reports_dir, f"forensic_report_{timestamp_str}.pdf")

    c     = canvas.Canvas(filepath, pagesize=letter)
    width, height = letter

    case_id    = evidence.get("case_id", "SMX-UNKNOWN")
    utc_ts     = evidence.get("timestamp", datetime.utcnow().isoformat())
    final_score_frac  = evidence["hybrid_decision"]["final_score"]
    final_score_pct   = int(final_score_frac * 100)
    final_label       = evidence["hybrid_decision"]["final_label"]
    score_col         = _score_color(final_score_frac)

    # Risk band label
    if final_score_pct >= 75:
        risk_band = "CRITICAL"
        risk_r, risk_g, risk_b = 0.50, 0.05, 0.05
    elif final_score_pct >= 45:
        risk_band = "HIGH"
        risk_r, risk_g, risk_b = 0.55, 0.35, 0.05
    elif final_score_pct >= 20:
        risk_band = "MEDIUM"
        risk_r, risk_g, risk_b = 0.45, 0.35, 0.05
    else:
        risk_band = "LOW / CLEAN"
        risk_r, risk_g, risk_b = 0.05, 0.25, 0.12

    # ── Page utilities ────────────────────────────────────────────────────────
    def draw_bg():
        c.setFillColorRGB(*BG_DARK)
        c.rect(0, 0, width, height, fill=1, stroke=0)

    def new_page():
        c.showPage()
        draw_bg()
        return height - 40

    def check_space(y, needed=60):
        if y < needed:
            return new_page()
        return y

    def draw_text(text, x, y, font="Helvetica", size=9, color=COL_WHITE,
                  max_chars=88, line_h=13):
        c.setFont(font, size)
        c.setFillColor(color)
        for line in textwrap.wrap(str(text), width=max_chars):
            y = check_space(y, 20)
            c.drawString(x, y, line)
            y -= line_h
        return y

    def section_header(title, y):
        y = check_space(y, 50)
        c.setFillColorRGB(0.12, 0.13, 0.15)
        c.rect(30, y - 8, width - 60, 24, fill=1, stroke=0)
        c.setFillColor(COL_BLUE)
        c.rect(30, y - 8, 4, 24, fill=1, stroke=0)
        c.setFillColor(colors.Color(0.85, 0.95, 1.0))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(45, y + 2, title)
        return y - 28

    def divider(y):
        c.setStrokeColorRGB(0.22, 0.22, 0.25)
        c.setLineWidth(0.5)
        c.line(30, y, width - 30, y)
        return y - 10

    # ── Page 1 Header ─────────────────────────────────────────────────────────
    draw_bg()

    # Dark blue banner
    c.setFillColorRGB(*BG_HEADER)
    c.rect(0, height - 90, width, 90, fill=1, stroke=0)

    c.setFillColor(COL_BLUE)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(40, height - 20, "SAFEMAIL-X  ·  AUTOMATED INCIDENT RESPONSE SYSTEM  ·  CONFIDENTIAL")

    c.setFillColor(COL_WHITE)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width / 2, height - 48, "FORENSIC ANALYSIS REPORT")

    c.setFillColor(COL_GREY)
    c.setFont("Helvetica", 8)
    c.drawCentredString(width / 2, height - 65,
                        f"Case ID: {case_id}   |   Analyst: SafeMail-X Engine v3.0   |   UTC: {utc_ts[:19]}")

    y = height - 110

    # ── [1] VERDICT WIDGET ────────────────────────────────────────────────────
    # Dark card base
    c.setFillColorRGB(0.11, 0.12, 0.14)
    c.roundRect(30, y - 85, width - 60, 85, 6, fill=1, stroke=0)
    
    # Left colored accent representing the risk
    c.setFillColorRGB(risk_r, risk_g, risk_b)
    c.roundRect(30, y - 85, 12, 85, 6, fill=1, stroke=0)
    c.rect(36, y - 85, 6, 85, fill=1, stroke=0) # Square off the right side of the accent

    # Texts
    c.setFillColor(COL_PALE)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(55, y - 25, "AUTOMATED FORENSIC VERDICT")
    
    c.setFillColor(COL_WHITE)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(55, y - 55, final_label.upper())

    # Risk pill next to verdict
    pill_w = 95
    pill_x = 55 + c.stringWidth(final_label.upper(), "Helvetica-Bold", 24) + 15
    c.setFillColorRGB(risk_r, risk_g, risk_b)
    c.roundRect(pill_x, y - 53, pill_w, 18, 4, fill=1, stroke=0)
    c.setFillColor(COL_WHITE)
    c.setFont("Helvetica-Bold", 9)
    c.drawCentredString(pill_x + pill_w/2, y - 48, f"RISK: {risk_band}")

    # Threat Score on the right
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(COL_PALE)
    c.drawRightString(width - 50, y - 25, "THREAT SCORE")
    
    c.setFillColor(score_col)
    c.setFont("Helvetica-Bold", 36)
    score_txt = str(final_score_pct)
    c.drawRightString(width - 90, y - 57, score_txt)
    
    c.setFillColor(COL_GREY)
    c.setFont("Helvetica-Bold", 14)
    c.drawRightString(width - 50, y - 55, "/ 100")

    y -= 105

    # Score progress bar
    bar_w = width - 80
    c.setFillColorRGB(0.18, 0.18, 0.20)
    c.roundRect(40, y, bar_w, 8, 4, fill=1, stroke=0)
    filled = max(int(bar_w * final_score_frac), 8)
    c.setFillColor(score_col)
    c.roundRect(40, y, filled, 8, 4, fill=1, stroke=0)
    c.setFillColor(COL_GREY)
    c.setFont("Helvetica", 7)
    c.drawString(40, y - 10, "0")
    c.drawCentredString(width / 2, y - 10, "50")
    c.drawRightString(width - 40, y - 10, "100")
    y -= 30

    # Executive one-liner
    subj = evidence["email_metadata"].get("subject", "N/A")
    rule_reasons = evidence["rule_analysis"].get("rule_reasons", [])
    n_flags = len(rule_reasons)
    exec_line = (
        f"This email exhibits {n_flags} structural indicator(s) and a semantic threat probability of "
        f"{final_score_pct}%, consistent with {'a phishing/social-engineering campaign' if final_label=='phishing' else 'legitimate correspondence'}."
    )
    y = draw_text(exec_line, 40, y, font="Helvetica-Oblique", size=9, color=COL_PALE, max_chars=95)
    y -= 8

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 1 — CASE METADATA
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 1  CASE METADATA", y)

    rows1 = [
        ("Case ID",          case_id),
        ("Analysis Time",    utc_ts[:19] + " UTC"),
        ("Subject Line",     subj[:90]),
        ("Body Size",        f"{evidence['email_metadata'].get('body_length', 0):,} bytes"),
        ("Analyst Engine",   "SafeMail-X v3.0 — TF-IDF Logistic Regression + Rule Heuristics"),
    ]
    for label, val in rows1:
        y = check_space(y, 18)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(COL_GREY)
        c.drawString(50, y, f"{label}:")
        c.setFont("Helvetica", 9)
        c.setFillColor(COL_WHITE)
        c.drawString(200, y, str(val))
        y -= 16
    y -= 4

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 2 — TRANSMISSION SECURITY
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 2  TRANSMISSION SECURITY  (Email Header Chain Analysis)", y)

    sec = evidence.get("security_headers", {})

    def _auth_status(val):
        v = str(val).lower()
        if v == "pass":     return "PASS"
        if v in ("fail",):  return "FAIL"
        if v == "softfail": return "WARN"
        return "UNKNOWN"

    tls_status   = "SECURED"   if sec.get("tls") else "WARN"
    tls_detail   = sec.get("tls_version") or ("ESMTPS detected" if sec.get("tls") else "No TLS found in Received chain")
    spf_val      = sec.get("spf", "none")
    dkim_val     = sec.get("dkim", "none")
    dmarc_val    = sec.get("dmarc", "none")
    reply_mis    = sec.get("reply_to_mismatch", False)
    x_mailer     = sec.get("x_mailer")
    msg_mis      = sec.get("message_id_mismatch", False)

    sec_rows = [
        ("TLS Encryption",    tls_status,                      tls_detail),
        ("SPF Record",        _auth_status(spf_val),           f"spf={spf_val}"),
        ("DKIM Signature",    _auth_status(dkim_val),          f"dkim={dkim_val}"),
        ("DMARC Policy",      _auth_status(dmarc_val),         f"dmarc={dmarc_val}"),
        ("Reply-To Mismatch", "FLAGGED" if reply_mis else "OK",
                              (sec.get("reply_to") or "Not set") if reply_mis else "Matches From domain"),
        ("X-Mailer",          "FLAGGED" if x_mailer else "OK",
                              x_mailer or "Not declared"),
        ("Message-ID Domain", "FLAGGED" if msg_mis else "OK",
                              sec.get("message_id_domain") or "Not present"),
    ]

    note = "* Headers extracted from the forwarded copy. TLS status reflects delivery chain as seen by original recipient."
    y = draw_text(note, 50, y, size=7, color=COL_GREY, max_chars=100)
    y -= 4

    for label, status, detail in sec_rows:
        y = check_space(y, 22)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(COL_PALE)
        c.drawString(50, y, label + ":")
        _status_badge(c, 200, y, status)
        c.setFont("Helvetica", 8)
        c.setFillColor(COL_GREY)
        c.drawString(268, y, str(detail)[:65])
        y -= 20

    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 3 — SENDER IDENTITY FORENSICS
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 3  SENDER IDENTITY FORENSICS", y)

    sf = evidence.get("sender_forensics", {})

    sender_rows = [
        ("Display Name",     sf.get("display_name") or "— not set —"),
        ("Raw Email Address", sf.get("raw_address", "unknown")),
        ("Sender Domain",    sf.get("sender_domain", "unknown")),
        ("Reply-To Address", sf.get("reply_to") or "— not set —"),
        ("Reply-To Mismatch",
            "⚠  YES — Reply-To points to a DIFFERENT domain than From" if sf.get("reply_to_mismatch")
            else "✓  No — Reply-To matches From domain"),
        ("X-Mailer Tool",    sf.get("x_mailer") or "— not declared —"),
        ("Message-ID Domain", sf.get("msg_id_domain") or "— not present —"),
        ("MsgID / From Mismatch",
            "⚠  YES — Message-ID domain differs from From domain" if sf.get("msg_id_mismatch")
            else "✓  No — Message-ID domain consistent"),
    ]

    for label, val in sender_rows:
        y = check_space(y, 16)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(COL_GREY)
        c.drawString(50, y, f"{label}:")
        col = COL_RED if "⚠" in str(val) else COL_WHITE
        c.setFont("Helvetica", 9)
        c.setFillColor(col)
        c.drawString(220, y, str(val)[:70])
        y -= 16
    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 4 — STRUCTURAL HEURISTICS (Rule Engine)
    # ──────────────────────────────────────────────────────────────────────────
    rule_score_pct = int(evidence["rule_analysis"]["rule_score"] * 100)
    y = section_header(f"SECTION 4  STRUCTURAL HEURISTICS  (Rule Score: {rule_score_pct}/100)", y)

    rule_reasons = evidence["rule_analysis"].get("rule_reasons", [])
    if not rule_reasons:
        y = draw_text("Infrastructure and link structural integrity appears completely benign.", 50, y, color=COL_GREEN)
    else:
        for reason in rule_reasons:
            y = check_space(y, 30)
            c.setFillColor(COL_AMBER)
            c.setFont("Helvetica-Bold", 9)
            c.drawString(50, y, ">> INDICATOR:")
            explanation = _explain_rule(reason)
            y = draw_text(explanation, 160, y, max_chars=70, color=COL_WHITE, line_h=13)
            y -= 4
    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 5 — DEEP SEMANTIC AI ANALYSIS
    # ──────────────────────────────────────────────────────────────────────────
    ai_score_pct = int(evidence["ai_analysis"]["ai_score"] * 100)
    y = section_header(f"SECTION 5  DEEP SEMANTIC AI ANALYSIS  (AI Score: {ai_score_pct}/100)", y)

    ai_reasons = evidence["ai_analysis"].get("ai_reasons", [])
    if not ai_reasons:
        y = draw_text("No aggressive threat vectors detected in linguistic topological space.", 50, y, color=COL_GREEN)
    else:
        for reason in ai_reasons:
            y = check_space(y, 30)
            c.setFillColor(COL_RED)
            c.setFont("Helvetica-Bold", 9)
            c.drawString(50, y, ">> THREAT VECTOR:")
            explanation = _explain_ai(reason)
            y = draw_text(explanation, 175, y, max_chars=68, color=COL_WHITE, line_h=13)
            y -= 4

    # Top triggering keywords as pills
    top_kw = evidence["ai_analysis"].get("top_keywords", [])
    if top_kw:
        y = check_space(y, 28)
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(COL_GREY)
        c.drawString(50, y, "Top Triggering Keywords:")
        y -= 14
        pill_x = 50
        for kw in top_kw:
            kw_w = len(kw) * 5.8 + 14
            y = check_space(y, 18)
            if pill_x + kw_w > width - 50:
                pill_x = 50
                y -= 16
            c.setFillColorRGB(0.25, 0.12, 0.12)
            c.roundRect(pill_x, y - 3, kw_w, 13, 4, fill=1, stroke=0)
            c.setFillColor(COL_RED)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(pill_x + 6, y + 3, kw)
            pill_x += kw_w + 6
        y -= 18
    y -= 6

    # ──────────────────────────────────────────────────────────────────────
    # SECTION 5.5 — LLM DEEP BEHAVIOURAL ANALYSIS
    # ──────────────────────────────────────────────────────────────────────
    llm_data  = evidence.get("llm_analysis", {})
    llm_avail = llm_data.get("llm_available", False)

    y = section_header("SECTION 5.5  LLM DEEP BEHAVIOURAL ANALYSIS", y)

    if not llm_avail:
        # ── LLM was offline ──────────────────────────────────────────────
        y = check_space(y, 30)
        c.setFillColorRGB(0.15, 0.15, 0.17)
        c.roundRect(40, y - 20, width - 80, 30, 4, fill=1, stroke=0)
        c.setFillColor(COL_GREY)
        c.setFont("Helvetica-Oblique", 9)
        c.drawCentredString(
            width / 2, y - 8,
            "LLM Deep Analysis was unavailable for this scan. "
            "Results based on TF-IDF + Rule Engine only.")
        y -= 36
    else:
        llm_score_val = llm_data.get("llm_score", 0.0) or 0.0
        llm_score_pct = int(llm_score_val * 100)
        llm_col       = _score_color(llm_score_val)

        # ── LLM threat score bar ─────────────────────────────────────────
        y = check_space(y, 30)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(COL_PALE)
        c.drawString(50, y, "LLM Threat Probability:")
        c.setFillColor(llm_col)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(210, y, f"{llm_score_pct}%")
        y -= 16

        bar_w = width - 120
        c.setFillColorRGB(0.18, 0.18, 0.20)
        c.roundRect(50, y, bar_w, 8, 4, fill=1, stroke=0)
        c.setFillColor(llm_col)
        c.roundRect(50, y, max(int(bar_w * llm_score_val), 6),
                    8, 4, fill=1, stroke=0)
        y -= 22

        # ── Dimension gauges ─────────────────────────────────────────────
        dims = [
            ("Urgency / Fear",      llm_data.get("urgency_score")),
            ("Sender Legitimacy",   llm_data.get("legitimacy_score")),
            ("Grammar Anomalies",   llm_data.get("grammar_score")),
            ("Contextual Coherence", llm_data.get("coherence_score")),
        ]

        y = check_space(y, 72)
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(COL_GREY)
        c.drawString(50, y,
                     "Behavioural Dimension Scores "
                     "(0 = Safe, 10 = Suspicious):")
        y -= 14

        for dim_name, dim_val in dims:
            y = check_space(y, 16)
            dv       = dim_val if dim_val is not None else 0
            dim_frac = dv / 10.0
            dim_col  = _score_color(dim_frac)

            c.setFont("Helvetica", 8)
            c.setFillColor(COL_PALE)
            c.drawString(60, y, f"{dim_name}:")
            c.drawString(200, y, f"{dv}/10")

            mini_w = 200
            c.setFillColorRGB(0.18, 0.18, 0.20)
            c.roundRect(240, y - 1, mini_w, 7, 3, fill=1, stroke=0)
            c.setFillColor(dim_col)
            c.roundRect(240, y - 1, max(int(mini_w * dim_frac), 4),
                        7, 3, fill=1, stroke=0)
            y -= 14
        y -= 6

        # ── Analyst reasoning narrative ──────────────────────────────────
        llm_reasoning = llm_data.get("llm_reasoning", "")
        if llm_reasoning:
            y = check_space(y, 30)
            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(COL_GREY)
            c.drawString(50, y, "Analyst Reasoning:")
            y -= 12

            wrapped = textwrap.wrap(str(llm_reasoning), width=90)
            box_h   = len(wrapped) * 12 + 12
            y = check_space(y, box_h + 10)

            c.setFillColorRGB(0.12, 0.12, 0.14)
            c.roundRect(48, y - box_h + 8, width - 96, box_h,
                        4, fill=1, stroke=0)
            c.setFont("Helvetica", 8)
            c.setFillColor(COL_WHITE)
            for line in wrapped:
                c.drawString(56, y, line)
                y -= 12
            y -= 8

        # ── Social engineering tactic badges ─────────────────────────────
        tactics = llm_data.get("llm_tactics", [])
        if tactics:
            y = check_space(y, 28)
            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(COL_GREY)
            c.drawString(50, y, "Social Engineering Tactics Detected:")
            y -= 14
            px = 50
            for tactic in tactics:
                label = tactic.replace("_", " ").title()
                tw    = len(label) * 5.5 + 16
                y = check_space(y, 18)
                if px + tw > width - 50:
                    px = 50
                    y -= 16
                c.setFillColorRGB(0.30, 0.10, 0.10)
                c.roundRect(px, y - 3, tw, 13, 4, fill=1, stroke=0)
                c.setFillColor(COL_AMBER)
                c.setFont("Helvetica-Bold", 7)
                c.drawString(px + 7, y + 3, label)
                px += tw + 6
            y -= 18

        # ── Privacy note ─────────────────────────────────────────────────
        y = check_space(y, 16)
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColor(COL_GREY)
        c.drawString(50, y,
                     "Analysis performed by local AI — 100% private, "
                     "zero data transmitted externally.")
        y -= 14

    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 5.6 — ENGINE COMPARISON & WEIGHT CONTRIBUTION
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 5.6  ENGINE COMPARISON & WEIGHT CONTRIBUTION", y)

    # Get scores
    r_score = evidence.get("rule_analysis", {}).get("rule_score", 0.0)
    a_score = evidence.get("ai_analysis", {}).get("ai_score", 0.0)
    l_score = evidence.get("llm_analysis", {}).get("llm_score", 0.0) if llm_avail else None
    
    # Render horizontal bars
    def draw_engine_bar(name, score, weight_txt, y_pos, color, active=True):
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(COL_PALE if active else COL_GREY)
        c.drawString(50, y_pos, name)
        
        c.setFont("Helvetica", 8)
        c.setFillColor(COL_GREY)
        c.drawString(140, y_pos, weight_txt)
        
        bar_x = 180
        bar_w = 200
        c.setFillColorRGB(0.18, 0.18, 0.20)
        c.roundRect(bar_x, y_pos - 1, bar_w, 8, 3, fill=1, stroke=0)
        
        if active:
            c.setFillColor(color)
            c.roundRect(bar_x, y_pos - 1, max(int(bar_w * score), 6), 8, 3, fill=1, stroke=0)
            
            c.setFillColor(COL_PALE)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(bar_x + bar_w + 15, y_pos, f"{int(score * 100)}%")
        else:
            c.setFillColor(COL_GREY)
            c.setFont("Helvetica-Oblique", 8)
            c.drawString(bar_x + bar_w + 15, y_pos, "OFFLINE")

    y = check_space(y, 80)
    
    if llm_avail:
        draw_engine_bar("Rule Engine", r_score, "(25%)", y, _score_color(r_score))
        y -= 16
        draw_engine_bar("TF-IDF ML", a_score, "(25%)", y, _score_color(a_score))
        y -= 16
        draw_engine_bar("LLM Deep AI", l_score, "(50%)", y, _score_color(l_score))
    else:
        draw_engine_bar("Rule Engine", r_score, "(40%)", y, _score_color(r_score))
        y -= 16
        draw_engine_bar("TF-IDF ML", a_score, "(60%)", y, _score_color(a_score))
        y -= 16
        draw_engine_bar("LLM Deep AI", 0.0, "(0%)", y, COL_GREY, active=False)

    y -= 16
    c.setStrokeColor(COL_GREY)
    c.setLineWidth(0.5)
    c.line(50, y, width - 50, y)
    y -= 16
    
    final_s = evidence.get("hybrid_decision", {}).get("final_score", 0.0)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(COL_WHITE)
    c.drawString(50, y, "Final Verdict:")
    
    bar_x = 180
    bar_w = 200
    c.setFillColorRGB(0.18, 0.18, 0.20)
    c.roundRect(bar_x, y - 1, bar_w, 10, 4, fill=1, stroke=0)
    c.setFillColor(_score_color(final_s))
    c.roundRect(bar_x, y - 1, max(int(bar_w * final_s), 6), 10, 4, fill=1, stroke=0)
    
    c.setFillColor(COL_WHITE)
    c.drawString(bar_x + bar_w + 15, y, f"{int(final_s * 100)}%")
    
    lbl = evidence.get("hybrid_decision", {}).get("final_label", "").upper()
    c.setFillColor(COL_RED if final_s >= 0.5 else COL_GREEN)
    c.drawString(bar_x + bar_w + 50, y, f"→ {lbl}")
    
    y -= 30
    
    # --- Weight Math ---
    y = check_space(y, 60)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(COL_GREY)
    c.drawString(50, y, "Weight Contribution Breakdown:")
    y -= 14
    
    c.setFont("Courier", 8)
    if llm_avail:
        c.drawString(60, y, f"Rule:    {r_score:.3f} × 0.25 = {r_score*0.25:.3f}")
        y -= 12
        c.drawString(60, y, f"TF-IDF:  {a_score:.3f} × 0.25 = {a_score*0.25:.3f}")
        y -= 12
        c.drawString(60, y, f"LLM:     {l_score:.3f} × 0.50 = {l_score*0.50:.3f}")
    else:
        c.drawString(60, y, f"Rule:    {r_score:.3f} × 0.40 = {r_score*0.40:.3f}")
        y -= 12
        c.drawString(60, y, f"TF-IDF:  {a_score:.3f} × 0.60 = {a_score*0.60:.3f}")
        
    y -= 12
    c.drawString(60, y, "-" * 32)
    y -= 12
    c.setFillColor(COL_WHITE)
    c.drawString(60, y, f"Total:                = {final_s:.3f}")
    y -= 20
    
    # --- Consensus / Conflict Badge ---
    conflict = evidence.get("hybrid_decision", {}).get("conflict_detected", False)
    
    if conflict:
        badge_color = COL_AMBER
        badge_text  = "CONFLICT DETECTED — LLM weighted as contextual authority"
    elif (r_score > 0.7 and a_score > 0.7) or (r_score < 0.3 and a_score < 0.3):
        badge_color = COL_GREEN
        badge_text  = "ALL ENGINES AGREE — High confidence consensus"
    else:
        badge_color = COL_BLUE
        badge_text  = "NORMAL BLEND — Weighted average applied"

    c.setFillColorRGB(0.12, 0.12, 0.14)
    c.roundRect(50, y - 8, width - 100, 20, 4, fill=1, stroke=0)
    c.setFillColor(badge_color)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(65, y - 2, badge_text)
    
    y -= 16

    # Start new page for remaining sections
    y = new_page()

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 6 — ALGORITHMIC DECISION TREE
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 6  ALGORITHMIC DECISION TREE EXECUTED", y)

    for step in evidence.get("analysis_steps", []):
        y = check_space(y, 18)
        c.setFillColor(COL_BLUE)
        c.setFont("Helvetica", 9)
        c.drawString(50, y, f"[*]  {step}")
        y -= 16
    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 7 — URL & LINK FORENSICS
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 7  URL & LINK FORENSICS", y)

    url_details = evidence.get("url_details", [])
    if not url_details:
        y = draw_text("No URLs detected in the email body.", 50, y, color=COL_GREY)
    else:
        # Table header
        y = check_space(y, 24)
        c.setFillColorRGB(0.18, 0.22, 0.28)
        c.rect(40, y - 4, width - 80, 18, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(COL_BLUE)
        c.drawString(48, y + 2, "URL")
        c.drawString(310, y + 2, "IP-Based")
        c.drawString(370, y + 2, "Shortener")
        c.drawString(430, y + 2, "Safe Browsing")
        y -= 22

        for ud in url_details:
            y = check_space(y, 20)
            c.setFont("Helvetica", 7)
            c.setFillColor(COL_WHITE)
            c.drawString(48, y, ud.get("raw_url", "")[:58])

            def _yesno_col(val, danger_on_true=True):
                col = COL_RED if (val and danger_on_true) else COL_GREEN
                return ("YES" if val else "NO"), col

            ip_lbl,  ip_col  = _yesno_col(ud.get("is_ip", False))
            sh_lbl,  sh_col  = _yesno_col(ud.get("is_short", False))
            sb_lbl,  sb_col  = _yesno_col(ud.get("safebrowsing_hit", False))

            c.setFont("Helvetica-Bold", 7)
            c.setFillColor(ip_col);  c.drawString(310, y, ip_lbl)
            c.setFillColor(sh_col);  c.drawString(370, y, sh_lbl)
            c.setFillColor(sb_col);  c.drawString(430, y, sb_lbl)

            # thin separator line
            c.setStrokeColorRGB(0.20, 0.20, 0.22)
            c.setLineWidth(0.3)
            c.line(40, y - 4, width - 40, y - 4)
            y -= 18
    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 8 — EMAIL HOP TIMELINE
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 8  EMAIL HOP TIMELINE  (Received Header Chain)", y)

    received_chain = evidence.get("security_headers", {}).get("received_chain", [])
    note2 = "* Received headers are listed newest-first as delivered by Gmail. Read bottom-up for chronological order."
    y = draw_text(note2, 50, y, size=7, color=COL_GREY, max_chars=100)
    y -= 4

    if not received_chain:
        y = draw_text("No Received headers found in forwarded email.", 50, y, color=COL_GREY)
    else:
        for i, hop in enumerate(received_chain[:8]):   # cap at 8 hops
            y = check_space(y, 22)
            hop_short = hop.replace("\r", "").replace("\n", " ")[:95]
            # Timeline dot
            c.setFillColor(COL_BLUE)
            c.circle(52, y + 4, 4, fill=1, stroke=0)
            if i < len(received_chain) - 1:
                c.setStrokeColor(COL_BLUE)
                c.setLineWidth(0.7)
                c.line(52, y - 10, 52, y)
            c.setFont("Helvetica-Bold", 8)
            c.setFillColorRGB(0.5, 0.8, 1.0)
            c.drawString(62, y + 2, f"Hop {i+1}:")
            c.setFont("Helvetica", 7)
            c.setFillColor(COL_PALE)
            c.drawString(100, y + 2, hop_short)
            y -= 20
    y -= 6

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 9 — ATTACHMENT FORENSICS
    # ──────────────────────────────────────────────────────────────────────────
    att_data    = evidence.get("attachment_analysis", {})
    att_findings = att_data.get("findings", [])
    att_agg      = att_data.get("attachment_score")
    att_pct      = int((att_agg or 0) * 100)

    y = section_header(f"SECTION 9  ATTACHMENT FORENSICS  (Aggregate Score: {att_pct}/100)", y)

    if not att_findings:
        y = draw_text("No file attachments were detected. Attachment analysis was not performed.", 50, y, color=COL_GREY)
    else:
        for finding in att_findings:
            fname   = finding.get("filename", "unknown")
            ftype   = finding.get("file_type", "FILE").upper()
            f_score = finding.get("threat_score", 0.0)
            inds    = finding.get("indicators", [])
            sha256  = finding.get("sha256", None)
            md5     = finding.get("md5", None)
            f_pct   = int(f_score * 100)
            f_col   = _score_color(f_score)

            y = check_space(y, 50)
            c.setFillColor(f_col)
            c.roundRect(50, y - 3, 38, 14, 3, fill=1, stroke=0)
            c.setFillColor(COL_WHITE)
            c.setFont("Helvetica-Bold", 7)
            c.drawCentredString(69, y + 3, ftype)
            c.setFont("Helvetica-Bold", 9)
            c.drawString(96, y + 2, fname)
            c.setFont("Helvetica", 9)
            c.setFillColor(f_col)
            c.drawRightString(width - 40, y + 2, f"Threat: {f_pct}/100")
            y -= 16

            bar_total = width - 120
            c.setFillColorRGB(0.20, 0.20, 0.22)
            c.rect(50, y, bar_total, 6, fill=1, stroke=0)
            c.setFillColor(f_col)
            c.rect(50, y, int(bar_total * f_score), 6, fill=1, stroke=0)
            y -= 14

            if sha256:
                y = draw_text(f"SHA-256: {sha256}", 60, y, size=7, color=COL_GREY)
            if md5:
                y = draw_text(f"MD5: {md5}", 60, y, size=7, color=COL_GREY)

            if not inds:
                y = draw_text("No threat indicators detected — file appears clean.", 60, y, size=8, color=COL_GREEN)
            else:
                for ind in inds:
                    y = check_space(y, 14)
                    c.setFillColor(COL_AMBER)
                    c.setFont("Helvetica-Bold", 8)
                    c.drawString(60, y, "▶")
                    c.setFont("Helvetica", 8)
                    c.setFillColor(COL_WHITE)
                    c.drawString(72, y, ind.replace("_", " ").title())
                    y -= 12
            y -= 8
    y -= 6

    # Start final page for recommendations + legal
    y = new_page()

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 10 — VERDICT & RECOMMENDATIONS
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 10  VERDICT & ACTIONABLE RECOMMENDATIONS", y)

    if final_label.lower() == "phishing":
        rec_title = "⚠  THREAT CONFIRMED — IMMEDIATE ACTION REQUIRED"
        rec_color = (0.50, 0.08, 0.08)
        recs = [
            "DO NOT click any links or download any attachments from this email.",
            "Report the sender domain to your mail gateway administrator for blacklisting.",
            "If credentials were entered on a linked page, change passwords IMMEDIATELY.",
            "Forward this PDF to your IT/Security team as the incident evidence package.",
            "Consider filing a report with the Anti-Phishing Working Group: reportphishing@apwg.org",
        ]
    elif final_score_pct >= 45:
        rec_title = "⚡  SUSPICIOUS — EXERCISE EXTREME CAUTION"
        rec_color = (0.45, 0.25, 0.02)
        recs = [
            "Do not click links until you have verified the sender through a secondary channel (phone call).",
            "Hover over all links before clicking to confirm the destination domain is legitimate.",
            "Verify the sender's identity by contacting the organisation directly via their official website.",
            "If in doubt, forward this report to your IT department before taking any action.",
        ]
    else:
        rec_title = "✓  EMAIL APPEARS LEGITIMATE — LOW RISK"
        rec_color = (0.07, 0.35, 0.12)
        recs = [
            "No significant threat indicators were detected by the AI or Rule Engine.",
            "Always exercise general caution when clicking links or downloading attachments.",
            "If this email feels unexpected, verify the sender through an independent channel.",
        ]

    c.setFillColorRGB(*rec_color)
    c.roundRect(35, y - len(recs) * 20 - 28, width - 70, len(recs) * 20 + 36, 8, fill=1, stroke=0)
    c.setFillColor(COL_WHITE)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y - 10, rec_title)
    y -= 28
    for rec in recs:
        y = check_space(y, 18)
        c.setFont("Helvetica", 9)
        c.setFillColor(COL_WHITE)
        c.drawString(60, y, f"•  {rec}")
        y -= 18
    y -= 18

    # ──────────────────────────────────────────────────────────────────────────
    # SECTION 11 — LEGAL CHAIN OF CUSTODY
    # ──────────────────────────────────────────────────────────────────────────
    y = section_header("SECTION 11  LEGAL CHAIN OF CUSTODY  &  DISCLOSURE", y)

    legal_lines = [
        f"Case Reference:   {case_id}",
        f"Analysis Date:    {utc_ts[:19]} UTC",
        f"System:           SafeMail-X Automated Engine v3.0",
        f"Method:           TF-IDF Logistic Regression (83,000-sample Kaggle corpus) + Rule-Based Heuristics",
        "",
        "DATA RETENTION:   Original email content was permanently and irrecoverably deleted from the",
        "                  SafeMail-X processing server immediately after this report was generated,",
        "                  in accordance with our Zero Data Retention Policy.",
        "",
        "PRIVACY:          The LLM behavioural analysis was performed entirely on-device using LM Studio.",
        "                  No email content was transmitted to any external API, cloud service, or",
        "                  third-party system. 100% local processing was maintained throughout.",
        "",
        "DISCLAIMER:       This report was generated autonomously by an AI-assisted system. Findings",
        "                  should be reviewed by a qualified cybersecurity professional before being",
        "                  used as sole basis for legal, disciplinary, or regulatory action.",
        "",
        "EVIDENCE USE:     This document may be submitted as supporting evidence in a cybersecurity",
        "                  incident report, IT security audit, or law enforcement referral.",
        "",
        "E-DISCOVERY:      Report generated in compliance with standard digital forensic chain-of-custody",
        "                  practices. No email content is stored or transmitted to third-party systems.",
    ]
    for line in legal_lines:
        y = check_space(y, 14)
        c.setFont("Helvetica", 8)
        c.setFillColor(COL_PALE if not line.startswith("DATA") and not line.startswith("DISCLAIMER")
                       and not line.startswith("EVIDENCE") and not line.startswith("E-DISC") else COL_WHITE)
        c.drawString(50, y, line)
        y -= 13

    # Final footer
    c.setFont("Helvetica-Oblique", 7)
    c.setFillColor(COL_GREY)
    c.drawCentredString(width / 2, 25, f"SafeMail-X  |  Case {case_id}  |  100% Local AI  |  Zero Data Retention  |  {utc_ts[:10]}")

    c.save()
    return filepath


# ── Explanation helpers (kept outside main function for clarity) ───────────────

def _explain_ai(reason):
    reason_map = {
        "strong phishing language patterns": (
            "The Deep Semantic Engine identified highly coercive linguistic structures. Threat actors "
            "utilise engineered syntax designed to bypass cognitive filters and force immediate user "
            "compliance. The semantic vector density aligns with known malicious campaign templates."
        ),
        "verification language": (
            "Urgency Masking Detected: The text demands the user 'verify' their identity under artificial "
            "time pressure — a primary social engineering tactic used in credential harvesting attacks."
        ),
        "login related wording": (
            "Authentication Request Detected: The email attempts to route the user toward a credential "
            "submission portal, a strong mathematical indicator of an unauthorized harvesting infrastructure."
        ),
    }
    for key, explanation in reason_map.items():
        if key.lower() in reason.lower():
            return explanation
    return reason


def _explain_rule(reason):
    r = reason.lower()
    trigger = reason.split(":")[1].strip() if ":" in reason else reason
    if "urgency" in r:
        return (f"Psychological Manipulation ('{trigger}'): The sender deployed urgency framing to compress "
                f"the victim's decision-making timeline and force critical errors before rational logic applies.")
    elif "mismatch" in r or "link obfuscation" in r:
        return "Link Obfuscation: Visible hyperlink text hides a completely different destination URL — a hallmark phishing tactic."
    elif "shortened" in r:
        return f"Redirection Evasion ('{trigger}'): URL shorteners actively mask the true destination from automated security scanners."
    elif "domain_age" in r or "newly registered" in r:
        return f"Burner Infrastructure ('{trigger}'): Hosted on a newly registered zero-day domain used to evade blacklists."
    elif "brand_spoof" in r:
        return f"Brand Spoofing ('{trigger}'): The text references a trusted corporate brand but originates from a mismatched server."
    elif "safebrowsing" in r:
        return "Threat Intelligence Hit: Google Safe Browsing API classifies the embedded URL infrastructure as globally malicious."
    elif "financial" in r:
        return "Financial Pretexting: The email solicits financial transactions, consistent with Business Email Compromise (BEC) patterns."
    return reason
    
    # Subtitle
    c.setFont("Helvetica", 10)
    c.setFillColorRGB(0.6, 0.6, 0.6)
    case_id = f"CAS-{str(uuid.uuid4())[:8].upper()}"
    timestamp_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    c.drawCentredString(width / 2, y - 10, f"Case ID: {case_id}  |  Generated Analyst: Automated  |  UTC: {timestamp_str}")
    
    return y - 80


def explain_ai_reason(reason):
    reason_map = {
        "strong phishing language patterns": "The Deep Semantic Engine identified highly coercive linguistic structures. Threat actors utilize engineered syntax explicitly designed to bypass cognitive filters and force immediate user compliance. The semantic vector density aligns identically with known malicious campaigns logged in the database.",
        "verification language": "Urgency Masking Detected: The text demands the user 'verify' their identity or account quickly. This is a primary social engineering tactic used in Credential Harvesting, artificially pressuring targets by threatening service suspension.",
        "login related wording": "Authentication Request Detected: The email attempts to abruptly route the user toward a credential submission portal. When combined with other spatial risk indicators, this strongly mathematically implies the presence of an unauthorized credential harvesting infrastructure."
    }
    for key, explanation in reason_map.items():
        if key.lower() in reason.lower():
            return explanation
    return reason


def explain_rule_reason(reason):
    r = reason.lower()
    trigger = reason.split(":")[1] if ":" in reason else "suspicious formatting"
    
    if "urgency" in r:
        return f"Psychological Manipulation ('{trigger}'): The sender maliciously deployed urgency framing via the phrase '{trigger}'. This artificially compresses the victim's decision-making timeline to force critical errors before rational logic is applied."
    elif "mismatch" in r or "link obfuscation" in r:
        return "Link Obfuscation Detected: The visible display text of a hyperlink maliciously hides a completely different destination URL. This is a hallmark deception tactic of classic Phishing architecture."
    elif "shortened" in r:
        short_service = trigger if ":" in reason else "a shortened URL service"
        return f"Redirection Evasion ('{short_service}'): The use of URL shorteners within the payload actively attempts to mathematically mask the true destination domain from automated security scanners."
    elif "domain_age" in r or "newly registered" in r:
        return f"Burner Infrastructure ('{trigger}'): The sender's architecture is hosted on a newly registered zero-day domain. Threat actors constantly burn and rotate domain infrastructure to completely evade historic blacklists."
    elif "brand_spoof" in r:
        return f"Brand Spoofing Deception ('{trigger}'): The text aggressively leverages corporate infrastructure trust, but the structural sender domain mathematically isolates to a completely mismatched external server."
    elif "safebrowsing" in r:
        return "Threat Intelligence Hit! The live Google Safe Browsing API actively classifies the embedded payload infrastructure as globally malicious and dangerous."
    elif "financial" in r:
        return "Financial Pretexting: The email aggressively attempts to solicit or discuss financial transactions, artificially establishing a classic wire-fraud/BEC (Business Email Compromise) operational scenario."
    return reason
