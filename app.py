from flask import Flask, render_template, request, redirect, url_for, jsonify
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

    # Check if a .eml file was uploaded
    if "eml_file" in request.files:
        f = request.files["eml_file"]
        if f and f.filename.endswith(".eml"):
            raw_bytes = f.read()
            try:
                raw_headers = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                raw_headers = raw_bytes.decode("latin-1", errors="replace")

    # Fall back to pasted headers if no file uploaded
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
    """
    REST API endpoint for email header analysis.
    Accepts JSON: {"headers": "raw header string"}
    Returns: full analysis report as JSON
    """
    # Accept both JSON and form data
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

        # Build clean API response
        return jsonify({
            "scan_id": scan_id,
            "risk_score": report["risk_score"],
            "verdict": "high_risk" if report["risk_score"] >= 70 else "suspicious" if report["risk_score"] >= 40 else "clean",
            "subject": report["parsed"].get("subject", ""),
            "from": report["parsed"].get("from", ""),
            "spoofing_warnings": report["spoofing_warnings"],
            "authentication": {
                "spf": {
                    "status": report["spf"]["status"],
                    "verdict": report["spf"]["verdict"],
                    "record": report["spf"]["record"]
                },
                "dmarc": {
                    "status": report["dmarc"]["status"],
                    "policy": report["dmarc"]["policy"],
                    "verdict": report["dmarc"]["verdict"]
                },
                "dkim": {
                    "present": report["dkim"]["present"],
                    "domain": report["dkim"]["domain"]
                }
            },
            "ip_reputation": [
                {
                    "ip": g["ip"],
                    "country": g.get("country"),
                    "city": g.get("city"),
                    "isp": g.get("isp"),
                    "abuse_score": g.get("abuse", {}).get("abuse_score", 0),
                    "total_reports": g.get("abuse", {}).get("total_reports", 0),
                    "verdict": g.get("abuse", {}).get("verdict", "unknown"),
                    "is_tor": g.get("abuse", {}).get("is_tor", False)
                }
                for g in report["geo"]
            ],
            "delivery_chain": [
                {
                    "hop": i + 1,
                    "from": hop["from_host"],
                    "by": hop["by_host"],
                    "ips": hop["ips"],
                    "timestamp": hop["timestamp"]
                }
                for i, hop in enumerate(report["parsed"]["received_chain"])
            ]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    """Return scan history as JSON."""
    scans = get_all_scans()
    return jsonify({"scans": scans, "total": len(scans)})


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Return a specific scan by ID as JSON."""
    report = get_scan_by_id(scan_id)
    if not report:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(report)


@app.route("/api", methods=["GET"])
def api_docs():
    """API documentation page."""
    return render_template("api_docs.html")

if __name__ == "__main__":
    app.run(debug=True)