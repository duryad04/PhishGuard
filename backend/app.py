import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import analyze_url
from database import init_db, save_scan, get_history, clear_history

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

handler = RotatingFileHandler("phishguard.log", maxBytes=100000, backupCount=3)
handler.setLevel(logging.WARNING)
app.logger.addHandler(handler)

init_db()


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "PhishGuard API is running"})


@app.route("/analyze", methods=["POST"])
@limiter.limit("30 per minute")
def analyze():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()

    if len(url) > 500:
        return jsonify({"error": "URL is too long"}), 400

    try:
        analysis = analyze_url(url)
    except Exception as e:
        app.logger.error(f"Analysis error: {e}")
        return jsonify({"error": "Analysis failed unexpectedly"}), 500

    if analysis["risk_score"] >= 60:
        app.logger.warning(f"High-risk URL scanned: {url} | Score: {analysis['risk_score']}")

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
@limiter.limit("30 per minute")
def history():
    return jsonify(get_history())


@app.route("/clear", methods=["DELETE"])
@limiter.limit("5 per minute")
def clear():
    clear_history()
    return jsonify({"message": "History cleared"})


if __name__ == "__main__":
    app.run(debug=False)