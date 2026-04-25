from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import analyze_url
from database import init_db, save_scan, get_history

app = Flask(__name__)
CORS(app)

init_db()


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "PhishGuard API is running"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()

    if len(url) > 500:
        return jsonify({"error": "URL is too long"}), 400

    analysis = analyze_url(url)

    save_scan(
        url=url,
        result=analysis["result"],
        risk_score=analysis["risk_score"],
        reasons=analysis["reasons"]
    )

    return jsonify({
        "url": url,
        "result": analysis["result"],
        "risk_score": analysis["risk_score"],
        "reasons": analysis["reasons"]
    })


@app.route("/history", methods=["GET"])
def history():
    return jsonify(get_history())


if __name__ == "__main__":
    app.run(debug=True)