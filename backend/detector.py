import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "confirm", "password", "signin",
    "free", "gift", "reward", "urgent"
]

BRAND_NAMES = ["paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook"]

TRUSTED_DOMAINS = [
    "paypal.com", "google.com", "amazon.com", "apple.com",
    "microsoft.com", "netflix.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "github.com", "linkedin.com",
    "youtube.com", "wikipedia.org"
]


def is_valid_url(url):
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        # Real domains must contain a dot (e.g. google.com)
        if '.' not in result.netloc:
            return False
        return True
    except Exception:
        return False


def is_ssrf_safe(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return False
        blocked_prefixes = [
            '169.254.', '10.', '192.168.', '172.16.', '172.17.',
            '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
            '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        for prefix in blocked_prefixes:
            if host.startswith(prefix):
                return False
        return True
    except Exception:
        return False


def check_brand_impersonation(domain):
    for brand in BRAND_NAMES:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            return brand
    return None


def analyze_url(url):
    reasons = []
    risk_score = 0

    url = url.strip()

    if not url:
        return {"result": "Invalid", "risk_score": 100, "reasons": ["URL cannot be empty"]}

    # Strip HTML tags before any processing
    url = re.sub(r'<[^>]+>', '', url)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        reasons.append("URL did not include http or https")
        risk_score += 10

    # Whitelist validation — reject non-URLs early
    if not is_valid_url(url):
        return {"result": "Invalid", "risk_score": 100, "reasons": ["Input is not a valid URL"]}

    # SSRF guard — block internal/private addresses
    if not is_ssrf_safe(url):
        return {"result": "Dangerous", "risk_score": 100, "reasons": ["URL points to an internal or private network address"]}

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Remove www. prefix for comparison
    bare_domain = domain[4:] if domain.startswith("www.") else domain

    # Trusted domain early exit
    if bare_domain in TRUSTED_DOMAINS:
        return {"result": "Safe", "risk_score": 0, "reasons": ["Domain is a verified trusted website"]}

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

    # Brand impersonation check (weighted higher)
    impersonated_brand = check_brand_impersonation(domain)
    if impersonated_brand:
        reasons.append(f"Domain impersonates a known brand: {impersonated_brand}")
        risk_score += 40

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

    return {"result": result, "risk_score": risk_score, "reasons": reasons}