from flask import Flask, render_template, request
from analyzer import run_full_analysis

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


if __name__ == "__main__":
    app.run(debug=True)

@app.route("/test-api")
def test_api():
    import os
    key = os.getenv("ABUSEIPDB_API_KEY")
    if key:
        return f"Key found: {key[:8]}..."
    return "No key found"

@app.route("/test-abuse")
def test_abuse():
    from analyzer import check_abuseipdb
    result = check_abuseipdb("80.82.77.33")
    return str(result)