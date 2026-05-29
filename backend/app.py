from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import threading
import csv
import json
from urllib.parse import urlparse
from functools import wraps
import base64
import urllib.request
import urllib.error

from logger import log_result
from history import add_history, get_history, clear_history
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
dataset_path = os.path.join(os.path.dirname(model_dir), "dataset", "urls.csv")

def push_to_github(file_path, github_repo, github_path, commit_message, pat, branch="model-sync"):
    """
    Pushes a local file to a GitHub repository using the GitHub Contents API.
    """
    url = f"https://api.github.com/repos/{github_repo}/contents/{github_path}"
    get_url = f"{url}?ref={branch}"
    headers = {
        "Authorization": f"token {pat}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PhishGuard-App"
    }
    
    # 1. Get file SHA if it exists on the specified branch
    req = urllib.request.Request(get_url, headers=headers)
    sha = None
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode())
            sha = res_data.get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404: # 404 means file doesn't exist yet, which is fine
            print(f"Error fetching file SHA from GitHub ({github_path}) on branch {branch}: {e.code} - {e.read().decode()}")
            return False
    except Exception as e:
        print(f"Connection error fetching SHA from GitHub ({github_path}) on branch {branch}: {e}")
        return False
    
    # 2. Base64 encode local file contents
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        encoded_content = base64.b64encode(file_content).decode('utf-8')
    except Exception as e:
        print(f"Error reading file to push ({file_path}): {e}")
        return False
    
    # 3. Create payload
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": branch
    }
    if sha:
        payload["sha"] = sha
        
    # 4. PUT request to update/create file
    req_put = urllib.request.Request(
        url, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={**headers, "Content-Type": "application/json"},
        method="PUT"
    )
    
    try:
        with urllib.request.urlopen(req_put) as response:
            if response.status in [200, 201]:
                print(f"Successfully pushed {github_path} to branch {branch}!")
                return True
            else:
                print(f"Failed to push {github_path} to branch {branch}. Status: {response.status}")
                return False
    except urllib.error.HTTPError as e:
        print(f"HTTP error pushing {github_path} to branch {branch}: {e.code} - {e.read().decode()}")
        return False
    except Exception as e:
        print(f"Connection error pushing {github_path} to branch {branch}: {e}")
        return False

def pull_from_github(github_repo, github_path, local_path, pat, branch="model-sync"):
    """
    Downloads a file from GitHub contents API and writes it locally.
    """
    url = f"https://api.github.com/repos/{github_repo}/contents/{github_path}?ref={branch}"
    headers = {
        "Authorization": f"token {pat}",
        "Accept": "application/vnd.github.v3.raw",
        "User-Agent": "PhishGuard-App"
    }
    
    req = urllib.request.Request(url, headers=headers)
    try:
        print(f"Sync: Downloading {github_path} from branch '{branch}'...")
        with urllib.request.urlopen(req) as response:
            content = response.read()
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(content)
            print(f"Sync: Successfully downloaded and updated {local_path}")
            return True
    except Exception as e:
        print(f"Sync: Failed to download {github_path} from GitHub: {e}")
        return False

# Sync latest data & model from GitHub if credentials are set
pat = os.environ.get("GITHUB_PAT")
repo = os.environ.get("GITHUB_REPO")
branch = os.environ.get("GITHUB_SYNC_BRANCH", "model-sync")

if pat and repo:
    print("Syncing latest model and dataset from GitHub at startup...")
    pull_from_github(repo, "dataset/urls.csv", dataset_path, pat, branch=branch)
    pull_from_github(repo, "backend/model_metadata.json", metadata_path, pat, branch=branch)
    pull_from_github(repo, "backend/model.pkl", model_path, pat, branch=branch)

# In-memory SaaS statistics tracker
stats = {
    "total_scans": 0,
    "threats_detected": 0,
    "cache_hits": 0,
    "total_risk_sum": 0.0
}

# Load model and versioning metadata
model_metadata = {}
try:
    if os.path.exists(model_path) and os.path.exists(metadata_path):
        print(f"Loading model from {model_path}...")
        model = pickle.load(open(model_path, "rb"))
        with open(metadata_path, "r") as f:
            model_metadata = json.load(f)
    else:
        raise FileNotFoundError("Baseline model files not found")
except Exception as e:
    print(f"Model load failed: {e}. Attempting startup retraining...")
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
        "message": "PhishGuard API is running.",
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
    
    # Load pending count by comparing current dataset samples with model samples
    pending_count = 0
    trained_samples = model_metadata.get("samples_count", 200)
    if os.path.exists(dataset_path):
        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
                current_samples = len(rows) - 1
                pending_count = max(0, current_samples - trained_samples)
        except Exception:
            pass
            
    sync_threshold = int(os.environ.get("GITHUB_SYNC_THRESHOLD", 10))
    
    return jsonify({
        "total_scans": total,
        "threats_detected": phish,
        "threat_rate": round(rate * 100, 1),
        "cache_hit_rate": round(cache_rate * 100, 1),
        "avg_risk_score": round(avg_risk, 1),
        "model_version": model_metadata.get("version", "3.0.0"),
        "trained_samples": model_metadata.get("samples_count", 200),
        "cv_accuracy": round(model_metadata.get("cv_accuracy", 1.0) * 100, 2),
        "pending_feedback_count": pending_count,
        "github_sync_threshold": sync_threshold
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
    if features[8] == 1: # IP address
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

    try:
        with db_lock:
            with open(dataset_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([url, label])
    except Exception as e:
        return jsonify({"error": f"Failed to save feedback: {str(e)}"}), 500

    # Determine current total samples in dataset
    current_samples = 0
    try:
        with open(dataset_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            current_samples = len(rows) - 1 # Exclude header
    except Exception as e:
        print(f"Error reading dataset line count: {e}")
        current_samples = model_metadata.get("samples_count", 200)

    # Get sample count active model was trained on
    trained_samples = model_metadata.get("samples_count", 200)
    
    # Calculate difference
    diff = current_samples - trained_samples
    sync_threshold = int(os.environ.get("GITHUB_SYNC_THRESHOLD", 10))
    should_retrain = diff >= sync_threshold

    pat = os.environ.get("GITHUB_PAT")
    repo = os.environ.get("GITHUB_REPO", "NotSoAbhinav/PhishGuard")
    branch = os.environ.get("GITHUB_SYNC_BRANCH", "model-sync")

    # Background sync & retrain task
    def sync_and_retrain_task(current_ver, retrain_flag):
        global model, model_metadata
        try:
            # 1. Backup dataset immediately to prevent data loss on container sleep
            if pat:
                print(f"Auto-Sync: Pushing updated dataset urls.csv immediately to branch '{branch}'...")
                commit_msg_data = "Sync dataset feedback URL [skip ci]"
                push_to_github(dataset_path, repo, "dataset/urls.csv", commit_msg_data, pat, branch=branch)
            else:
                print("WARNING: GITHUB_PAT env variable is not set. Skipping dataset push sync.")

            # 2. Retrain model only if threshold reached
            if retrain_flag:
                try:
                    parts = current_ver.split(".")
                    if len(parts) == 3:
                        parts[2] = str(int(parts[2]) + 1)
                        new_ver = ".".join(parts)
                    else:
                        new_ver = "3.0.1"
                except Exception:
                    new_ver = "3.0.1"

                print(f"Background retraining started. Target version: {new_ver}...")
                new_model, _ = train_and_save_model(dataset_path=dataset_path, model_path=model_path, version=new_ver)
                model = new_model
                
                # Reload metadata
                if os.path.exists(metadata_path):
                    with open(metadata_path, "r") as f:
                        model_metadata = json.load(f)
                clear_cache()
                print(f"Model successfully evolved to version {new_ver}.")
                
                # 3. Push updated model & metadata
                if pat:
                    print(f"Pushing updated model and metadata to branch '{branch}'...")
                    commit_msg_model = f"Auto-evolve model and sync dataset to v{new_ver} [skip ci]"
                    push_to_github(metadata_path, repo, "backend/model_metadata.json", commit_msg_model, pat, branch=branch)
                    push_to_github(model_path, repo, "backend/model.pkl", commit_msg_model, pat, branch=branch)
                    print(f"GitHub Auto-Sync model update complete on branch '{branch}'.")
        except Exception as err:
            print(f"Error in sync_and_retrain_task: {err}")

    current_ver = model_metadata.get("version", "3.0.0")
    threading.Thread(target=sync_and_retrain_task, args=(current_ver, should_retrain)).start()

    if should_retrain:
        # Predict the target version for the response
        try:
            parts = current_ver.split(".")
            if len(parts) == 3:
                parts[2] = str(int(parts[2]) + 1)
                new_ver = ".".join(parts)
            else:
                new_ver = "3.0.1"
        except Exception:
            new_ver = "3.0.1"

        return jsonify({
            "status": "success",
            "message": "Feedback threshold reached. Model is retraining and syncing in the background.",
            "target_version": new_ver,
            "url": url,
            "label": label,
            "pending_feedback_count": 0,
            "github_sync_threshold": sync_threshold,
            "synced": True
        })
    else:
        return jsonify({
            "status": "success",
            "message": "Feedback recorded & synced. Model update queued.",
            "target_version": current_ver,
            "url": url,
            "label": label,
            "pending_feedback_count": diff,
            "github_sync_threshold": sync_threshold,
            "synced": False
        })

@app.route("/history/clear", methods=["POST"])
@require_api_key
def clear_history_endpoint():
    clear_history()
    return jsonify({"status": "success", "message": "History cleared successfully."})

if __name__ == "__main__":
    app.run(debug=True, port=5000)