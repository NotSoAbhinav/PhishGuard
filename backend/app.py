from flask import Flask, request, jsonify
import pickle

from feature_extractor import extract_features

app = Flask(__name__)

# Load trained model
model = pickle.load(open("model.pkl", "rb"))

@app.route("/")
def home():
    return "PhishGuard API is running"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    features = extract_features(url)
    prediction = model.predict([features])[0]

    result = "phishing" if prediction == 1 else "safe"

    return jsonify({
        "url": url,
        "result": result
    })

if __name__ == "__main__":
    app.run(debug=True)