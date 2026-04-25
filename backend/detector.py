import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "confirm", "password", "signin",
    "free", "gift", "reward", "urgent"
]


def analyze_url(url):
    reasons = []
    risk_score = 0

    url = url.strip()

    if not url:
        return {
            "result": "Invalid",
            "risk_score": 100,
            "reasons": ["URL cannot be empty"]
        }

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        reasons.append("URL did not include http or https")
        risk_score += 10

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if parsed.scheme == "http":
        reasons.append("URL uses HTTP instead of HTTPS")
        risk_score += 20

    if len(url) > 75:
        reasons.append("URL is unusually long")
        risk_score += 15

    if "@" in url:
        reasons.append("URL contains @ symbol")
        risk_score += 25

    if "-" in domain:
        reasons.append("Domain contains hyphen")
        risk_score += 10

    if domain.count(".") >= 3:
        reasons.append("URL has too many subdomains")
        risk_score += 15

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_pattern, domain):
        reasons.append("URL uses an IP address instead of a domain name")
        risk_score += 30

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            reasons.append(f"Suspicious keyword found: {keyword}")
            risk_score += 8

    if re.search(r"%[0-9a-fA-F]{2}", url):
        reasons.append("URL contains encoded characters")
        risk_score += 10

    if len(path) > 50:
        reasons.append("URL path is unusually long")
        risk_score += 10

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        result = "Dangerous"
    elif risk_score >= 30:
        result = "Suspicious"
    else:
        result = "Safe"

    if not reasons:
        reasons.append("No major phishing indicators detected")

    return {
        "result": result,
        "risk_score": risk_score,
        "reasons": reasons
    }