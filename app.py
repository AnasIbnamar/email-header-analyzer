from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from analyzer import run_full_analysis
from database import init_db, save_scan, get_all_scans, get_scan_by_id, delete_scan
import os

app = Flask(__name__)
init_db()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_headers = ""

    if "eml_file" in request.files:
        f = request.files["eml_file"]
        if f and f.filename.endswith(".eml"):
            raw_bytes = f.read()
            try:
                raw_headers = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                raw_headers = raw_bytes.decode("latin-1", errors="replace")

    if not raw_headers:
        raw_headers = request.form.get("headers", "").strip()

    if not raw_headers:
        return render_template("index.html", error="Please paste headers or upload a .eml file.")

    report = run_full_analysis(raw_headers)
    scan_id = save_scan(report)
    return render_template("result.html", report=report, scan_id=scan_id)


@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    report = get_scan_by_id(scan_id)
    if not report:
        return redirect(url_for("history"))
    return render_template("result.html", report=report, scan_id=scan_id)


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id):
    delete_scan(scan_id)
    return redirect(url_for("history"))


@app.route("/scan/<int:scan_id>/pdf")
def download_pdf(scan_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER
    import io

    report = get_scan_by_id(scan_id)
    if not report:
        return redirect(url_for("history"))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm)

    TEAL  = colors.HexColor("#00e5c3")
    RED   = colors.HexColor("#ff4d6a")
    AMBER = colors.HexColor("#ffb547")
    GREEN = colors.HexColor("#3ddc84")
    GRAY  = colors.HexColor("#7a8aa0")
    LIGHT = colors.HexColor("#e8edf5")
    BG2   = colors.HexColor("#0d1525")
    LINE  = colors.HexColor("#1a2a40")

    score = report["risk_score"]
    score_color  = RED if score >= 70 else AMBER if score >= 40 else GREEN
    verdict_text = "HIGH RISK" if score >= 70 else "SUSPICIOUS" if score >= 40 else "CLEAN"

    def style(name, **kw):
        return ParagraphStyle(name, **kw)

    title_s  = style("t",   fontSize=22, textColor=LIGHT, fontName="Helvetica-Bold", spaceAfter=4)
    sub_s    = style("s",   fontSize=10, textColor=GRAY,  fontName="Helvetica", spaceAfter=16)
    brand_s  = style("b",   fontSize=14, textColor=TEAL,  fontName="Helvetica-Bold", spaceAfter=4)
    sec_s    = style("sec", fontSize=8,  textColor=TEAL,  fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=8)
    lbl_s    = style("lbl", fontSize=8,  textColor=GRAY,  fontName="Helvetica")
    val_s    = style("val", fontSize=9,  textColor=LIGHT, fontName="Helvetica")
    warn_s   = style("w",   fontSize=9,  textColor=colors.HexColor("#ffb3be"), fontName="Helvetica", leftIndent=10)
    score_s  = style("sc",  fontSize=48, textColor=score_color, fontName="Helvetica-Bold", alignment=TA_CENTER)
    verdict_s= style("vd",  fontSize=16, textColor=score_color, fontName="Helvetica-Bold", alignment=TA_CENTER)

    story = []

    story.append(Paragraph("HeaderScan", brand_s))
    story.append(Paragraph("Threat Analysis Report", title_s))
    story.append(Paragraph(report["parsed"].get("subject") or "No subject", sub_s))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Spacer(1, 0.4*cm))

    score_tbl = Table([[
        Paragraph(str(score), score_s),
        Paragraph(f"{verdict_text}<br/><font size=9 color='#7a8aa0'>Risk Score /100</font>", verdict_s)
    ]], colWidths=[4*cm, 13*cm])
    score_tbl.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",    (0,0), (-1,-1), BG2),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING",   (0,0), (-1,-1), 16),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.5*cm))

    if report["spoofing_warnings"]:
        story.append(Paragraph("SPOOFING INDICATORS", sec_s))
        story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
        story.append(Spacer(1, 0.2*cm))
        for w in report["spoofing_warnings"]:
            story.append(Paragraph(f"! {w}", warn_s))
            story.append(Spacer(1, 0.15*cm))

    provider = report.get("provider")
    if provider and provider.get("name") != "Unknown":
        story.append(Paragraph("EMAIL PROVIDER", sec_s))
        story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
        story.append(Spacer(1, 0.2*cm))
        pcolor = RED if provider["risk"] == "high" else AMBER if provider["risk"] == "medium" else GREEN
        story.append(Paragraph(
            f'<font color="#{pcolor.hexval()[2:]}"><b>{provider["name"]}</b></font> '
            f'— {provider["detail"]}', val_s))
        story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("01 — EMAIL IDENTITY", sec_s))
    story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
    story.append(Spacer(1, 0.2*cm))

    id_rows = [
        ["FROM",        report["parsed"].get("from") or "—"],
        ["REPLY-TO",    report["parsed"].get("reply_to") or "—"],
        ["RETURN-PATH", report["parsed"].get("return_path") or "—"],
        ["TO",          report["parsed"].get("to") or "—"],
        ["DATE",        report["parsed"].get("date") or "—"],
        ["MESSAGE-ID",  report["parsed"].get("message_id") or "—"],
    ]
    id_tbl = Table([
        [Paragraph(r[0], lbl_s), Paragraph(str(r[1])[:80], val_s)]
        for r in id_rows
    ], colWidths=[3*cm, 14*cm])
    id_tbl.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LINEBELOW",     (0,0), (-1,-2), 0.3, LINE),
    ]))
    story.append(id_tbl)

    story.append(Paragraph("02 — AUTHENTICATION", sec_s))
    story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
    story.append(Spacer(1, 0.2*cm))

    spf_v  = report["spf"].get("verdict", "")
    dmarc_v= report["dmarc"].get("policy", "")
    dkim_p = report["dkim"].get("present", False)

    auth_tbl = Table([
        [Paragraph("SPF",   lbl_s), Paragraph(report["spf"].get("status") or "—",  val_s), Paragraph(spf_v, lbl_s)],
        [Paragraph("DMARC", lbl_s), Paragraph(report["dmarc"].get("status") or "—", val_s), Paragraph(f"p={dmarc_v}" if dmarc_v else "—", lbl_s)],
        [Paragraph("DKIM",  lbl_s), Paragraph("present" if dkim_p else "missing",   val_s), Paragraph("", lbl_s)],
    ], colWidths=[2.5*cm, 8*cm, 6.5*cm])
    auth_tbl.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LINEBELOW",     (0,0), (-1,-2), 0.3, LINE),
    ]))
    story.append(auth_tbl)

    if report["parsed"].get("received_chain"):
        story.append(Paragraph("03 — DELIVERY CHAIN", sec_s))
        story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
        story.append(Spacer(1, 0.2*cm))
        for i, hop in enumerate(report["parsed"]["received_chain"]):
            story.append(Paragraph(
                f'<b>Hop {i+1}</b>  FROM {hop.get("from_host") or "?"} '
                f'→ BY {hop.get("by_host") or "?"}  '
                f'IPs: {", ".join(hop.get("ips", [])) or "none"}', val_s))
            story.append(Spacer(1, 0.15*cm))

    if report.get("geo"):
        story.append(Paragraph("04 — IP REPUTATION", sec_s))
        story.append(HRFlowable(width="100%", thickness=0.3, color=LINE))
        story.append(Spacer(1, 0.2*cm))
        for g in report["geo"]:
            abuse    = g.get("abuse", {})
            verdict  = abuse.get("verdict", "unknown")
            ascore   = abuse.get("abuse_score", 0)
            ip_color = RED if verdict == "malicious" else AMBER if verdict == "suspicious" else GREEN
            story.append(Paragraph(
                f'<font color="#{ip_color.hexval()[2:]}"><b>{g["ip"]}</b></font>  '
                f'Score: {ascore}%  Reports: {abuse.get("total_reports", 0)}  '
                f'Country: {abuse.get("country") or g.get("country") or "—"}  '
                f'ISP: {abuse.get("isp") or g.get("isp") or "—"}', val_s))
            story.append(Spacer(1, 0.15*cm))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Generated by HeaderScan — email-header-analyzer-nw4o.onrender.com",
        style("ft", fontSize=8, textColor=GRAY, fontName="Helvetica", alignment=TA_CENTER)))

    doc.build(story)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=headerscan-report-{scan_id}.pdf"
    return response


@app.route("/test-abuse")
def test_abuse():
    try:
        key = os.getenv("ABUSEIPDB_API_KEY")
        if not key:
            return "NO KEY FOUND"
        import requests
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "80.82.77.33", "maxAgeInDays": 90},
            timeout=8
        )
        return f"Status: {response.status_code} | {response.text[:500]}"
    except Exception as e:
        return f"ERROR: {str(e)}"


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if request.is_json:
        data = request.get_json()
        raw_headers = data.get("headers", "").strip()
    else:
        raw_headers = request.form.get("headers", "").strip()

    if not raw_headers:
        return jsonify({
            "error": "Missing 'headers' field",
            "usage": "POST /api/analyze with JSON body: {\"headers\": \"raw email headers\"}"
        }), 400

    try:
        report = run_full_analysis(raw_headers)
        scan_id = save_scan(report)
        return jsonify({
            "scan_id": scan_id,
            "risk_score": report["risk_score"],
            "verdict": "high_risk" if report["risk_score"] >= 70 else "suspicious" if report["risk_score"] >= 40 else "clean",
            "subject": report["parsed"].get("subject", ""),
            "from": report["parsed"].get("from", ""),
            "spoofing_warnings": report["spoofing_warnings"],
            "authentication": {
                "spf":  {"status": report["spf"]["status"],  "verdict": report["spf"]["verdict"],  "record": report["spf"]["record"]},
                "dmarc":{"status": report["dmarc"]["status"],"policy":  report["dmarc"]["policy"], "verdict": report["dmarc"]["verdict"]},
                "dkim": {"present": report["dkim"]["present"],"domain": report["dkim"]["domain"]}
            },
            "ip_reputation": [
                {
                    "ip":            g["ip"],
                    "country":       g.get("country"),
                    "city":          g.get("city"),
                    "isp":           g.get("isp"),
                    "abuse_score":   g.get("abuse", {}).get("abuse_score", 0),
                    "total_reports": g.get("abuse", {}).get("total_reports", 0),
                    "verdict":       g.get("abuse", {}).get("verdict", "unknown"),
                    "is_tor":        g.get("abuse", {}).get("is_tor", False)
                }
                for g in report["geo"]
            ],
            "delivery_chain": [
                {
                    "hop": i + 1,
                    "from": hop["from_host"],
                    "by":   hop["by_host"],
                    "ips":  hop["ips"],
                    "timestamp": hop["timestamp"]
                }
                for i, hop in enumerate(report["parsed"]["received_chain"])
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    scans = get_all_scans()
    return jsonify({"scans": scans, "total": len(scans)})


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    report = get_scan_by_id(scan_id)
    if not report:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(report)


@app.route("/api", methods=["GET"])
def api_docs():
    return render_template("api_docs.html")


if __name__ == "__main__":
    app.run(debug=True)