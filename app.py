from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Email Header Analyzer — Phase 1 complete!"

if __name__ == "__main__":
    app.run(debug=True)