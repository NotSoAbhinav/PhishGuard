import re
import math
import difflib
from urllib.parse import urlparse

def get_entropy(text):
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum(p * math.log(p, 2) for p in probabilities)
    return float(entropy)

def get_vowel_ratio(text):
    if not text:
        return 0.0
    vowels = set("aeiou")
    count = sum(1 for c in text.lower() if c in vowels)
    return float(count / len(text))

def check_consecutive_chars(url):
    # Check for duplicate hyphens, triple dots, or 3+ digits in a row
    if "--" in url:
        return 1
    if "..." in url:
        return 1
    if re.search(r"\d{3,}", url):
        return 1
    return 0

def check_typosquatting(domain):
    parts = domain.split(".")
    tld_excludes = {"com", "net", "org", "co", "uk", "in", "us", "info", "xyz", "tk", "ml", "cf", "gq", "club", "top", "support", "gov", "edu", "mil", "net", "tv", "me"}
    
    brands = ["paypal", "google", "microsoft", "netflix", "amazon", "apple", "facebook", "chase", "bankofamerica", "yahoo", "github", "linkedin", "wellsfargo"]
    
    for part in parts:
        if part in tld_excludes:
            continue
        subparts = part.split("-")
        for subpart in subparts:
            if not subpart:
                continue
            for brand in brands:
                if subpart == brand:
                    continue
                ratio = difflib.SequenceMatcher(None, subpart, brand).ratio()
                if 0.75 <= ratio < 1.0:
                    return 1
    return 0

def check_repeating_chars(text):
    for i in range(len(text) - 2):
        if text[i] == text[i+1] == text[i+2] and text[i].isalpha():
            return 1
    return 0

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    url_lower = url.lower()

    features = []

    # 1. URL length
    features.append(len(url))

    # 2. Domain length
    features.append(len(domain))

    # 3. Path length
    features.append(len(path))

    # 4. Number of dots in URL
    features.append(url.count("."))

    # 5. Number of hyphens in URL
    features.append(url.count("-"))

    # 6. Number of hyphens in Domain
    features.append(domain.count("-"))

    # 7. Subdomain count
    dots_in_domain = domain.count(".")
    if domain.startswith("www."):
        subdomains = max(0, dots_in_domain - 2)
    else:
        subdomains = max(0, dots_in_domain - 1)
    features.append(subdomains)

    # 8. HTTPS usage
    features.append(1 if parsed.scheme == "https" else 0)

    # 9. IP address in URL domain
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$"
    features.append(1 if re.match(ip_pattern, domain) else 0)

    # 10. @ symbol in URL
    features.append(1 if "@" in url else 0)

    # 11. Double slash redirection
    features.append(1 if "//" in path else 0)

    # 12. URL Shortener Used
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "is.gd", "buff.ly", "adf.ly", "bit.do", "ow.ly", "goo.gl"]
    is_shortener = 0
    for s in shorteners:
        if domain == s or domain.endswith("." + s):
            is_shortener = 1
            break
    features.append(is_shortener)

    # 13. Non-standard port
    features.append(1 if ":" in domain and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", domain) else 0)

    # 14. Suspicious TLD
    suspicious_tlds = [".xyz", ".tk", ".ml", ".cf", ".gq", ".club", ".info", ".top", ".support", ".date", ".win", ".loan", ".stream", ".bid", ".gift", ".download"]
    is_suspicious_tld = 0
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            is_suspicious_tld = 1
            break
    features.append(is_suspicious_tld)

    # 15. Digit ratio in URL (float)
    digits = sum(1 for char in url if char.isdigit())
    features.append(float(digits / len(url) if len(url) > 0 else 0))

    # 16. Brand Spoofing Check
    brands = ["paypal", "google", "microsoft", "netflix", "amazon", "apple", "facebook", "chase", "bankofamerica", "yahoo", "github", "linkedin", "wellsfargo"]
    brand_spoofed = 0
    for brand in brands:
        if brand in url_lower:
            allowed_suffixes = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.in", f"{brand}.co.uk", f"{brand}.edu", f"{brand}.gov", f"{brand}.us", f"{brand}.tv", f"{brand}.me"]
            is_official = False
            for suffix in allowed_suffixes:
                if domain == suffix or domain.endswith("." + suffix):
                    is_official = True
                    break
            if not is_official:
                brand_spoofed = 1
                break
    features.append(brand_spoofed)

    # 17. Shannon Entropy of Domain (float)
    features.append(get_entropy(domain))

    # 18. Vowel Ratio in Domain (float)
    features.append(get_vowel_ratio(domain))

    # 19. Sensitive Keyword in Domain Host
    keywords = ["login", "verify", "secure", "account", "bank", "update", "signin", "billing", "support"]
    keyword_in_host = 0
    for kw in keywords:
        if kw in domain:
            keyword_in_host = 1
            break
    features.append(keyword_in_host)

    # 20. Consecutive Characters Check
    features.append(check_consecutive_chars(url))

    # 21. Typosquatting Check (1 if lookalike of major brand, 0 otherwise)
    features.append(check_typosquatting(domain))

    # 22. Digit Count in Domain (integer)
    domain_digits = sum(1 for char in domain if char.isdigit())
    features.append(domain_digits)

    # 23. Query Parameter Count (integer)
    features.append(url.count("=") + url.count("&"))

    # 24. Repeating Character Check (1 if letter repeats 3+ times consecutively)
    features.append(check_repeating_chars(url_lower))

    return features