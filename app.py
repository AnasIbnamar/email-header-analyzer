from flask import Flask, render_template, request, redirect, url_for
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


if __name__ == "__main__":
    app.run(debug=True)