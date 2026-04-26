# Import necessary modules
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import analyze_url  # Custom module for analyzing URLs
from database import init_db, save_scan, get_history, clear_history  # Database operations

# Initialize Flask app
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS) for the frontend
CORS(app, origins=["http://localhost:5173"])

# Set up rate limiting to prevent abuse
limiter = Limiter(
    get_remote_address,  # Function to get the client's IP address
    app=app,  # Attach to the Flask app
    default_limits=["200 per day", "50 per hour"]  # Default rate limits
)

# Configure logging with a rotating file handler
handler = RotatingFileHandler("phishguard.log", maxBytes=100000, backupCount=3)
handler.setLevel(logging.WARNING)  # Log warnings and above
app.logger.addHandler(handler)

# Initialize the database
init_db()

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# Define the home route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "PhishGuard API is running"})

# Define the analyze route for URL analysis
@app.route("/analyze", methods=["POST"])
@limiter.limit("30 per minute")  # Limit to 30 requests per minute
def analyze():
    # Parse JSON data from the request
    data = request.get_json()

    # Validate the input
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()  # Remove leading/trailing whitespace

    # Check if the URL length exceeds the limit
    if len(url) > 500:
        return jsonify({"error": "URL is too long"}), 400

    try:
        # Analyze the URL using the custom detector module
        analysis = analyze_url(url)
    except Exception as e:
        # Log any unexpected errors during analysis
        app.logger.error(f"Analysis error: {e}")
        return jsonify({"error": "Analysis failed unexpectedly"}), 500

    # Log a warning for high-risk URLs
    if analysis["risk_score"] >= 60:
        app.logger.warning(f"High-risk URL scanned: {url} | Score: {analysis['risk_score']}")

    # Save the scan result to the database
    save_scan(
        url=url,
        result=analysis["result"],
        risk_score=analysis["risk_score"],
        reasons=analysis["reasons"]
    )

    # Return the analysis result as a JSON response
    return jsonify({
        "url": url,
        "result": analysis["result"],
        "risk_score": analysis["risk_score"],
        "reasons": analysis["reasons"]
    })

# Define the history route to fetch scan history
@app.route("/history", methods=["GET"])
@limiter.limit("30 per minute")  # Limit to 30 requests per minute
def history():
    return jsonify(get_history())  # Fetch and return scan history from the database

# Define the clear route to delete scan history
@app.route("/clear", methods=["DELETE"])
@limiter.limit("5 per minute")  # Limit to 5 requests per minute
def clear():
    clear_history()  # Clear the scan history in the database
    return jsonify({"message": "History cleared"})

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=False)  # Disable debug mode for production