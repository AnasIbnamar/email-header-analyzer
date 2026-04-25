from flask import Flask, render_template, request
from analyzer import run_full_analysis
import os

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    raw_headers = request.form.get("headers", "").strip()
    if not raw_headers:
        return render_template("index.html", error="Please paste some email headers.")
    report = run_full_analysis(raw_headers)
    return render_template("result.html", report=report)


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