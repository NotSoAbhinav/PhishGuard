from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)

# Load trained model
model = pickle.load(open("model.pkl", "rb"))

@app.route("/")
def home():
    return "PhishGuard API Running"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    # Extract features
    features = extract_features(url)

    # Prediction
    prediction = model.predict([features])[0]

    # Risk score (probability)
    prob = model.predict_proba([features])[0][1]
    risk_score = int(prob * 100)

    result = "phishing" if prediction == 1 else "safe"

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
        "reasons": reasons
    })

if __name__ == "__main__":
    app.run(debug=True)