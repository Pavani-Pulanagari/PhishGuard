from urllib.parse import urlparse
import ipaddress
import re


def analyze_url(url):
    """
    Analyze a URL and return a phishing risk score
    with reasons for the score.
    """

    score = 0
    reasons = []

    # Add scheme if the user doesn't provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. Check HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("The website does not use HTTPS.")

    # 2. Check URL length
    if len(url) > 75:
        score += 10
        reasons.append("The URL is unusually long.")

    if len(url) > 120:
        score += 10
        reasons.append("The URL is extremely long.")

    # 3. Check for IP address
    try:
        ipaddress.ip_address(hostname)
        score += 25
        reasons.append("The URL uses an IP address instead of a domain name.")
    except ValueError:
        pass

    # 4. Check @ symbol
    if "@" in url:
        score += 20
        reasons.append("The URL contains an @ symbol.")

    # 5. Check suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "signin",
        "confirm",
        "payment",
        "wallet",
        "free",
        "claim",
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 5, 20)
        reasons.append(
            "The URL contains suspicious keywords: "
            + ", ".join(found_words)
        )

    # 6. Check number of subdomains
    parts = hostname.split(".")

    if len(parts) >= 4:
        score += 15
        reasons.append("The domain contains an unusually large number of subdomains.")

    # 7. Check hyphens
    if hostname.count("-") >= 3:
        score += 10
        reasons.append("The domain contains many hyphens.")

    # 8. Check special characters
    special_characters = re.findall(r"[^a-zA-Z0-9./:?&=_%-]", url)

    if len(special_characters) >= 3:
        score += 10
        reasons.append("The URL contains many unusual characters.")

    # Keep score between 0 and 100
    score = min(score, 100)

    # Determine result
    if score >= 60:
        status = "PHISHING"
    elif score >= 30:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return {
        "status": status,
        "score": score,
        "reasons": reasons,
        "url": url,
    }