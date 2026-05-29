# PhishGuard 🔐

[![Live Demo](https://img.shields.io/badge/Live%20Demo-https%3A%2F%2Fphish--guardx.vercel.app-10b981?style=for-the-badge&logo=vercel)](https://phish-guardx.vercel.app)
[![Project Presentation](https://img.shields.io/badge/Project%20Presentation-System%20Design%20%26%20MLOps-blueviolet?style=for-the-badge&logo=github)](PROJECT_PRESENTATION.md)
[![Python Version](https://img.shields.io/badge/Python-3.13.7-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

PhishGuard is an intelligent, self-evolving machine learning phishing detector designed to analyze structural URL features and identify malicious links in real-time. It features an interactive cybersecurity dashboard, explainable AI diagnostics, and a dynamic feedback loop that retrains and hot-swaps the underlying model in memory without server downtime.

---

## 🛠️ Technology Stack

* **Frontend**: ![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=flat-square&logo=html5&logoColor=white) ![CSS3](https://img.shields.io/badge/css3-%231572B6.svg?style=flat-square&logo=css3&logoColor=white) ![JavaScript](https://img.shields.io/badge/javascript-%23F7DF1E.svg?style=flat-square&logo=javascript&logoColor=black) ![Chart.js](https://img.shields.io/badge/chart.js-%23F5788D.svg?style=flat-square&logo=chartdotjs&logoColor=white)
* **Backend**: ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=flat-square&logo=flask&logoColor=white) ![Gunicorn](https://img.shields.io/badge/gunicorn-%2329BEB0.svg?style=flat-square&logo=gunicorn&logoColor=white)
* **Machine Learning**: ![Scikit-Learn](https://img.shields.io/badge/scikit--learn-%23F7931E.svg?style=flat-square&logo=scikit-learn&logoColor=white) ![Pandas](https://img.shields.io/badge/pandas-%23150458.svg?style=flat-square&logo=pandas&logoColor=white) ![NumPy](https://img.shields.io/badge/numpy-%23013243.svg?style=flat-square&logo=numpy&logoColor=white)
* **Deployment**: ![Vercel](https://img.shields.io/badge/vercel-%23000000.svg?style=flat-square&logo=vercel&logoColor=white) ![Render](https://img.shields.io/badge/Render-%2346E3B7.svg?style=flat-square&logo=render&logoColor=white)

---

## 🎯 Key Features

* **Self-Evolving Retraining Loop**: Users can submit correction feedback directly from the dashboard. The server appends this correction, runs retraining in a background thread, and hot-reloads the updated model in memory instantly.
* **Explainable AI (XAI)**: Exposes raw metric values for **24 advanced features** (structural, brand spoofing, entropy, etc.) in an expandable Inspector Table.
* **Heuristic Insights**: Maps mathematical probabilities back to clear, human-readable security risk cards (Critical, Warning, Info alerts).
* **Interactive Threshold Configuration**: Features a local sensitivity slider allowing users to adjust security strictness (Strict vs. Balanced vs. Permissive policy stances) dynamically.
* **Session Analytics**: Displays real-time safe vs. threat ratios inside the session using responsive Chart.js doughnut charts.
* **Secure API Endpoints**: Protected via `X-API-Key` headers to block unauthorized analysis or stats queries.

---

## ⚙️ System Architecture

PhishGuard splits concerns between a static edge-hosted client and a persistent ML container:

```mermaid
graph TD
    A[Client Browser: Vercel] -->|1. Submit URL Scan| B[Flask API: Render]
    B -->|2. Feature Extraction| C[24-Feature Analyzer]
    C -->|3. ML Evaluation| D[Random Forest Model]
    D -->|4. Return Score & Metrics| B
    B -->|5. Render Dashboard Gauges| A
    
    A -->|6. Submit Correction Feedback| E[Feedback Loop]
    E -->|7. Append to Dataset| F[dataset/urls.csv]
    F -->|8. Background Retraining| G[Model Evolution Engine]
    G -->|9. Update & Hot-Reload| D
```

---

## 📊 The 24-Feature Extraction Engine

PhishGuard analyzes URLs based on 24 distinct features engineered to capture mathematical and semantic anomalies:

| Category | Feature Name | Description |
| :--- | :--- | :--- |
| **Length Metrics** | URL, Domain, & Path Lengths | Phishing links are often abnormally long. |
| **Structure** | Dots, Hyphens, Subdomains | Counts separators to flag deep obfuscations. |
| **Connection** | HTTPS Scheme, Non-Standard Ports | Verifies protocol security and network entry. |
| **Obfuscation** | IP Address, @ Symbol, Double Slash | Identifies cloaking techniques designed to mask destinations. |
| **Heuristics** | Brand Spoofing, TLDs, Shorteners | Sequence matcher to flag lookalike major brands and low-cost TLDs. |
| **Complexity** | Shannon Entropy, Vowel Ratio | Detects randomized Domain Generation Algorithms (DGA). |
| **Parameters** | Digit Ratios, Query Parameters | Tracks data payload complexity. |

---

## 🚀 Local Installation & Setup

### Prerequisites
* Python 3.13+
* Node.js / NPM (if running a local live server)

### 1. Clone the Repository
```bash
git clone https://github.com/NotSoAbhinav/PhishGuard.git
cd PhishGuard
```

### 2. Configure and Start Backend API
```bash
# Set up environment variables (Optional: defaults to dev keys)
# export PHISHGUARD_API_KEY=your_secret_key

# Install dependencies
pip install -r requirements.txt

# Run the local Flask server
python backend/app.py
```
The API is now running locally at `http://127.0.0.1:5000`.

### 3. Open the Frontend
Since the frontend uses Vanilla HTML/CSS/JS, you can open `frontend/index.html` directly in your browser or run a simple local live-server (e.g. `npx live-server frontend`).
* **Local Fallback**: The client script automatically falls back to `http://127.0.0.1:5000` and `default-dev-key` when running offline, making development immediate and friction-free.

---

## 🌐 Production Deployment

PhishGuard is deployed in a split-free cloud architecture:

1. **Backend (Render Web Service)**: Runs the Python environment and Gunicorn to host the Flask REST API.
2. **Frontend (Vercel)**: Serves the static HTML/CSS/JS files. During Vercel's build phase, it runs `replace_api_url.py` to securely replace credentials placeholders in `script.js` with environment variables.
