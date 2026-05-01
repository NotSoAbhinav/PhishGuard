import re
from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = []

    # URL length
    features.append(len(url))

    # Domain length
    features.append(len(domain))

    # Number of dots
    features.append(url.count("."))

    # HTTPS usage
    features.append(1 if parsed.scheme == "https" else 0)

    # IP address in URL
    features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    # Suspicious symbols
    features.append(1 if "@" in url else 0)
    features.append(1 if "-" in domain else 0)

    # Subdomain count
    features.append(domain.count("."))

    # Suspicious keywords
    keywords = ["login", "verify", "secure", "account", "bank", "update"]
    features.append(sum(1 for k in keywords if k in url.lower()))

    # Path length
    features.append(len(path))

    return features