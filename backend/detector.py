# Import necessary modules
import re  # Regular expressions for pattern matching
from urllib.parse import urlparse  # For parsing URLs

# List of suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "confirm", "password", "signin",
    "free", "gift", "reward", "urgent"
]

# List of well-known brand names that are often impersonated
BRAND_NAMES = ["paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook"]

# List of trusted top-level domains (TLDs)
TRUSTED_TLDS = [".com", ".org", ".net", ".io", ".co"]

# List of trusted domains that are considered safe
TRUSTED_DOMAINS = [
    "paypal.com", "google.com", "amazon.com", "apple.com",
    "microsoft.com", "netflix.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "github.com", "linkedin.com",
    "youtube.com", "wikipedia.org"
]

# Function to validate if a URL is well-formed
def is_valid_url(url):
    try:
        result = urlparse(url)  # Parse the URL
        if result.scheme not in ('http', 'https'):  # Check for valid scheme
            return False
        if not result.netloc:  # Check for valid domain
            return False
        if '.' not in result.netloc:  # Ensure domain contains a dot
            return False
        return True
    except Exception:
        return False

# Function to check if a URL is safe from SSRF (Server-Side Request Forgery)
def is_ssrf_safe(url):
    try:
        parsed = urlparse(url)  # Parse the URL
        host = parsed.hostname or ""  # Extract the hostname
        # Block localhost and private IP ranges
        if host in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return False
        blocked_prefixes = [
            '169.254.', '10.', '192.168.', '172.16.', '172.17.',
            '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
            '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        for prefix in blocked_prefixes:
            if host.startswith(prefix):  # Check if the host starts with a blocked prefix
                return False
        return True
    except Exception:
        return False

# Function to check if a domain impersonates a known brand
def check_brand_impersonation(domain):
    bare = domain[4:] if domain.startswith("www.") else domain  # Remove 'www.' prefix
    for brand in BRAND_NAMES:
        if brand in bare:  # Check if the brand name is in the domain
            if not any(bare == f"{brand}{tld}" for tld in TRUSTED_TLDS):  # Ensure it's not a trusted domain
                return brand
    return None

# Function to analyze a URL for phishing indicators
def analyze_url(url):
    reasons = []  # List to store reasons for the risk score
    risk_score = 0  # Initialize risk score

    url = url.strip()  # Remove leading/trailing whitespace

    if not url:
        return {"result": "Invalid", "risk_score": 100, "reasons": ["URL cannot be empty"]}

    url = re.sub(r'<[^>]+>', '', url)  # Remove any HTML tags

    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # Add http if missing
        reasons.append("URL did not include http or https")
        risk_score += 10

    if not is_valid_url(url):
        return {"result": "Invalid", "risk_score": 100, "reasons": ["Input is not a valid URL"]}

    if not is_ssrf_safe(url):
        return {"result": "Dangerous", "risk_score": 100, "reasons": ["URL points to an internal or private network address"]}

    parsed = urlparse(url)  # Parse the URL
    domain = parsed.netloc.lower()  # Extract and normalize the domain
    path = parsed.path.lower()  # Extract and normalize the path

    bare_domain = domain[4:] if domain.startswith("www.") else domain  # Remove 'www.' prefix

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

    risk_score = min(risk_score, 100)  # Cap the risk score at 100

    # Determine the result based on the risk score
    if risk_score >= 60:
        result = "Dangerous"
    elif risk_score >= 30:
        result = "Suspicious"
    else:
        result = "Safe"

    if not reasons:
        reasons.append("No major phishing indicators detected")

    return {"result": result, "risk_score": risk_score, "reasons": reasons}