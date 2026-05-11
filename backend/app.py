from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
from logger import log_result
from urllib.parse import urlparse
from history import add_history, get_history 

from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)

# Load trained model
model = pickle.load(open("model.pkl", "rb"))

@app.route("/")
def home():
    return "PhishGuard API Running"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    # Extract features
    features = extract_features(url)

    # Prediction
    prediction = model.predict([features])[0]

    # Risk score (probability)
    prob = model.predict_proba([features])[0][1]
    risk_score = int(prob * 100)

    if risk_score > 80:
        confidence = "High"
    elif risk_score > 50:
        confidence = "Medium"
    else:
        confidence = "Low"

    result = "phishing" if prediction == 1 else "safe"

    #logging
    log_result(url, result, risk_score)

    # history
    add_history({
    "url": url,
    "result": result,
    "risk_score": risk_score
    })

    # Explanation engine
    reasons = []

    if "login" in url:
        reasons.append("Contains suspicious keyword: login")

    if "verify" in url:
        reasons.append("Contains suspicious keyword: verify")

    if "@" in url:
        reasons.append("Contains '@' symbol (possible redirection)")

    if "http://" in url:
        reasons.append("Not using HTTPS (insecure connection)")

    if len(url) > 75:
        reasons.append("URL is unusually long")

    if url.count(".") > 3:
        reasons.append("Too many subdomains")

    # Response
    return jsonify({
        "url": url,
        "result": result,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": reasons
    })

@app.route("/history")
def history():
    return jsonify(get_history())

if __name__ == "__main__":
    app.run(debug=True)