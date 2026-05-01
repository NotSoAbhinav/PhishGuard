# PhishGuard 🔐

PhishGuard is a hybrid phishing detection system that analyzes URLs using machine learning and rule-based heuristics to identify malicious, suspicious, and safe links with explainable results.

---

## 🚀 Overview

Phishing attacks are one of the most common cybersecurity threats, tricking users into revealing sensitive information through malicious links.

PhishGuard addresses this by combining:

* **Machine Learning (Random Forest)** for pattern recognition
* **Rule-Based Heuristics** for security insights
* **Explainable Output** to highlight why a URL is risky

---

## 🧠 Features

* 🔍 URL analysis and classification
* 🤖 Machine learning–based prediction
* ⚙️ Rule-based risk scoring
* 📊 Explainable results (reasons for detection)
* 🌐 REST API for integration
* 💻 Simple web interface

---

## 🏗️ Tech Stack

**Backend**

* Python (Flask)
* Scikit-learn

**Frontend**

* HTML, CSS, JavaScript

**Other**

* Feature Engineering
* REST API Architecture

---

## ⚙️ How It Works

1. User inputs a URL
2. System extracts structural and lexical features
3. Rule engine evaluates suspicious patterns
4. ML model predicts phishing probability
5. Combined result is returned with explanation

---

## 📁 Project Structure

```
phishguard/
│
├── backend/
│   ├── app.py
│   ├── train_model.py
│   ├── feature_extractor.py
│   └── model.pkl
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── dataset/
├── README.md
└── LICENSE
```

---

## 🔌 API Usage

### Endpoint

```
POST /analyze
```

### Request

```json
{
  "url": "http://example.com"
}
```

### Response

```json
{
  "result": "phishing",
  "reasons": [
    "Contains suspicious keyword: login",
    "Uses HTTP instead of HTTPS"
  ]
}
```

---

## 🧪 Model Details

* Algorithm: Random Forest Classifier
* Input: Extracted URL features
* Output: Binary classification (Safe / Phishing)

---

## 🚧 Status

Currently under development. Core features are being implemented.

---

## 📌 Future Improvements

* Browser extension for real-time detection
* Domain age & WHOIS analysis
* Advanced feature engineering
* Dashboard with analytics
* API key authentication

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

Abhinav Mishra
B.Tech CSE (Cybersecurity & Digital Forensics)

---
