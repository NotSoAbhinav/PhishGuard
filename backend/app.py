from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import threading
import csv
import json
from urllib.parse import urlparse
from functools import wraps

from logger import log_result
from history import add_history, get_history 
from cache import get_cached, set_cache, clear_cache
from feature_extractor import extract_features
from train_model import train_and_save_model

app = Flask(__name__)
CORS(app)

# Load API Key from environment
API_KEY = os.environ.get("PHISHGUARD_API_KEY", "default-dev-key")
if API_KEY == "default-dev-key":
    print("WARNING: PHISHGUARD_API_KEY environment variable is not set. Using 'default-dev-key' for local testing.")

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key or key != API_KEY:
            return jsonify({"error": "Unauthorized. Missing or invalid X-API-Key header."}), 401
        return f(*args, **kwargs)
    return decorated

db_lock = threading.Lock()
model_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(model_dir, "model.pkl")
metadata_path = os.path.join(model_dir, "model_metadata.json")

# In-memory SaaS statistics tracker
stats = {
    "total_scans": 0,
    "threats_detected": 0,
    "cache_hits": 0,
    "total_risk_sum": 0.0
}

# Load model and versioning metadata
model_metadata = {}
if os.path.exists(model_path) and os.path.exists(metadata_path):
    print(f"Loading model from {model_path}...")
    model = pickle.load(open(model_path, "rb"))
    with open(metadata_path, "r") as f:
        model_metadata = json.load(f)
else:
    print("Baseline model not found. Training version 3.0.0 model...")
    model, _ = train_and_save_model(model_path=model_path, version="3.0.0")
    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            model_metadata = json.load(f)

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "PhishGuard SaaS API is running.",
        "model_features": 24,
        "model_version": model_metadata.get("version", "3.0.0")
    })

@app.route("/stats")
@require_api_key
def stats_endpoint():
    total = stats["total_scans"]
    phish = stats["threats_detected"]
    hits = stats["cache_hits"]
    avg_risk = (stats["total_risk_sum"] / total) if total > 0 else 0.0
    rate = (phish / total) if total > 0 else 0.0
    
    total_requests = total + hits
    cache_rate = (hits / total_requests) if total_requests > 0 else 0.0
    
    return jsonify({
        "total_scans": total,
        "threats_detected": phish,
        "threat_rate": round(rate * 100, 1),
        "cache_hit_rate": round(cache_rate * 100, 1),
        "avg_risk_score": round(avg_risk, 1),
        "model_version": model_metadata.get("version", "3.0.0"),
        "trained_samples": model_metadata.get("samples_count", 200),
        "cv_accuracy": round(model_metadata.get("cv_accuracy", 1.0) * 100, 2)
    })

@app.route("/analyze", methods=["POST"])
@require_api_key
def analyze():
    global stats
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    url = url.strip()
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format. Please include scheme (e.g. http:// or https://)"}), 400
    
    # Check cache
    cached = get_cached(url)
    if cached:
        cached["cached"] = True
        stats["cache_hits"] += 1
        return jsonify(cached)

    # Extract features (24 features)
    features = extract_features(url)

    # Prediction
    prediction = model.predict([features])[0]

    # Risk score (probability of phishing)
    prob = model.predict_proba([features])[0][1]
    risk_score = int(prob * 100)

    if risk_score > 75:
        confidence = "High"
    elif risk_score > 40:
        confidence = "Medium"
    else:
        confidence = "Low"

    result = "phishing" if prediction == 1 else "safe"

    # Log & update SaaS stats
    log_result(url, result, risk_score)
    stats["total_scans"] += 1
    stats["total_risk_sum"] += risk_score
    if result == "phishing":
        stats["threats_detected"] += 1

    # History
    add_history({
        "url": url,
        "result": result,
        "risk_score": risk_score
    })

    # Raw features breakdown for the advanced Inspector Table
    feature_names = [
        "URL Length", "Domain Length", "Path Length", "Dots in URL", 
        "Hyphens in URL", "Hyphens in Domain", "Subdomain Count", "HTTPS Scheme", 
        "IP Address Presence", "@ Symbol", "Double Slash Redirection", "URL Shortener", 
        "Non-Standard Port", "Suspicious TLD", "Digit Ratio", "Brand Spoofing", 
        "Shannon Entropy", "Vowel Ratio", "Host Keyword", "Consecutive Characters",
        "Typosquatting", "Domain Digit Count", "Query Parameters", "Consecutive Repeating Letters"
    ]
    
    features_breakdown = []
    for name, val in zip(feature_names, features):
        status = "Safe"
        if name == "Brand Spoofing" and val == 1:
            status = "Critical"
        elif name == "IP Address Presence" and val == 1:
            status = "Critical"
        elif name == "Double Slash Redirection" and val == 1:
            status = "Critical"
        elif name == "@ Symbol" and val == 1:
            status = "Critical"
        elif name == "Typosquatting" and val == 1:
            status = "Critical"
        elif name == "HTTPS Scheme" and val == 0:
            status = "Warning"
        elif name == "URL Shortener" and val == 1:
            status = "Warning"
        elif name == "Suspicious TLD" and val == 1:
            status = "Warning"
        elif name == "Non-Standard Port" and val == 1:
            status = "Warning"
        elif name == "Shannon Entropy" and val > 4.0:
            status = "Warning"
        elif name == "Host Keyword" and val == 1:
            status = "Warning"
        elif name == "Consecutive Characters" and val == 1:
            status = "Warning"
        elif name == "Domain Digit Count" and val > 2:
            status = "Warning"
        elif name == "Consecutive Repeating Letters" and val == 1:
            status = "Warning"
        elif name == "Subdomain Count" and val >= 2:
            status = "Info"
        elif name == "URL Length" and val > 75:
            status = "Info"
        elif name == "Vowel Ratio" and (val < 0.25 or val > 0.55):
            status = "Info"
        elif name == "Query Parameters" and val > 3:
            status = "Info"
            
        features_breakdown.append({
            "name": name,
            "value": round(val, 4) if isinstance(val, float) else val,
            "status": status
        })

    # Rule-Based Explanations
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []

    # Map the explanations from the 24 features
    if features[7] == 1: # IP address
        reasons.append({"severity": "critical", "message": "Uses numerical IP address instead of domain name (high threat indicators)."})
    if features[15] == 1: # Brand spoofing
        reasons.append({"severity": "critical", "message": "Brand spoofing: URL mimics a major brand name on an unofficial domain."})
    if features[20] == 1: # Typosquatting
        reasons.append({"severity": "critical", "message": "Typosquatting: Domain name is visually similar to a major brand (e.g. PayPal, Netflix)."})
    if features[10] == 1: # // in path
        reasons.append({"severity": "critical", "message": "Contains '//' redirection pattern inside the URL path."})
    if features[9] == 1: # @ symbol
        reasons.append({"severity": "critical", "message": "Contains '@' symbol, masking the destination domain."})
    if features[7] == 0: # HTTPS usage
        reasons.append({"severity": "warning", "message": "Insecure connection: URL does not use HTTPS encryption."})
    if features[11] == 1: # Shortener
        reasons.append({"severity": "warning", "message": "Uses a known URL shortening service (hides original endpoint)."})
    if features[13] == 1: # Suspicious TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        reasons.append({"severity": "warning", "message": f"Uses suspicious TLD (.{tld}) often associated with low-cost phishing sites."})
    if features[12] == 1: # Port
        reasons.append({"severity": "warning", "message": "Specifies non-standard connection port."})
    if features[16] > 4.0: # High Entropy
        reasons.append({"severity": "warning", "message": f"High domain entropy ({features[16]:.2f}): indicates high randomness (DGA signature)."})
    if features[18] == 1: # Host keyword
        reasons.append({"severity": "warning", "message": "Sensitive security keyword detected inside the domain host name."})
    if features[19] == 1: # Consecutive chars
        reasons.append({"severity": "warning", "message": "Suspicious consecutive character patterns (e.g. repeated dashes/dots/digits)."})
    if features[21] > 2: # Domain digits
        reasons.append({"severity": "warning", "message": f"Domain name contains multiple numbers ({features[21]} digits), typical of generated spam domains."})
    if features[23] == 1: # Consecutive repeating letters
        reasons.append({"severity": "warning", "message": "Domain contains triple-consecutive repeating letters (common typosquatting technique)."})
    if features[3] > 3: # dots
        reasons.append({"severity": "info", "message": f"High number of dots ({features[3]}) in URL."})
    if features[6] >= 2: # subdomains
        reasons.append({"severity": "info", "message": f"Multiple subdomains ({features[6]}) detected in host."})
    if features[5] >= 2: # hyphens in domain
        reasons.append({"severity": "info", "message": f"Multiple hyphens ({features[5]}) in domain host."})
    if features[0] > 75: # length
        reasons.append({"severity": "info", "message": f"URL is unusually long ({features[0]} characters)."})
    if features[17] < 0.25 or features[17] > 0.55: # Vowel ratio
        reasons.append({"severity": "info", "message": f"Unusual vowel-to-consonant ratio ({features[17] * 100:.1f}%) in domain."})
    if features[14] > 0.15: # Digit ratio
        reasons.append({"severity": "info", "message": f"High ratio of digits ({features[14] * 100:.1f}%) in URL."})
    if features[22] > 3: # Query parameters
        reasons.append({"severity": "info", "message": f"Contains multiple query parameters ({features[22]}), typical of landing pages."})

    response_data = {
        "url": url,
        "result": result,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": reasons,
        "features_breakdown": features_breakdown,
        "model_version": model_metadata.get("version", "3.0.0"),
        "cached": False
    }

    set_cache(url, response_data)
    return jsonify(response_data)

@app.route("/history")
@require_api_key
def history():
    return jsonify(get_history())

@app.route("/feedback", methods=["POST"])
@require_api_key
def feedback():
    global model, model_metadata
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    url = data.get("url")
    label = data.get("label")

    if not url or label is None:
        return jsonify({"error": "URL and label are required"}), 400

    url = url.strip()
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    if label not in [0, 1]:
        return jsonify({"error": "Label must be 0 or 1"}), 400

    dataset_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "urls.csv")

    try:
        with db_lock:
            with open(dataset_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([url, label])
    except Exception as e:
        return jsonify({"error": f"Failed to save feedback: {str(e)}"}), 500

    # Determine incremented patch version (e.g. 3.0.0 -> 3.0.1)
    current_ver = model_metadata.get("version", "3.0.0")
    try:
        parts = current_ver.split(".")
        if len(parts) == 3:
            parts[2] = str(int(parts[2]) + 1)
            new_ver = ".".join(parts)
        else:
            new_ver = "3.0.1"
    except Exception:
        new_ver = "3.0.1"

    # Background retraining
    def retrain_task(version_str):
        global model, model_metadata
        try:
            print(f"Background retraining started. Target version: {version_str}...")
            new_model, _ = train_and_save_model(dataset_path=dataset_path, model_path=model_path, version=version_str)
            model = new_model
            # Reload metadata
            if os.path.exists(metadata_path):
                with open(metadata_path, "r") as f:
                    model_metadata = json.load(f)
            clear_cache()
            print(f"Model successfully evolved to version {version_str}.")
        except Exception as err:
            print(f"Error during background retraining: {err}")

    threading.Thread(target=retrain_task, args=(new_ver,)).start()

    return jsonify({
        "status": "success",
        "message": "Feedback recorded. Model is retraining in the background.",
        "target_version": new_ver,
        "url": url,
        "label": label
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)