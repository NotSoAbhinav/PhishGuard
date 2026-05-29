import urllib.request
import json
import time
import sys

API_BASE = "http://127.0.0.1:5000"

def make_request(path, data=None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    
    req_data = None
    if data:
        req_data = json.dumps(data).encode("utf-8")
        
    req = urllib.request.Request(url, data=req_data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def verify_pipeline():
    print("Step 1: Checking API status...")
    status = make_request("/")
    if not status:
        print("API is offline! Make sure the server is running.")
        sys.exit(1)
    print(f"API is online: {status}")

    test_url = "http://brand-new-unseen-phishing-alert.xyz/verify-login"
    print(f"\nStep 2: Performing initial analysis on: {test_url}")
    result_before = make_request("/analyze", {"url": test_url})
    if not result_before:
        print("Failed to run initial scan.")
        sys.exit(1)
    
    print(f"Initial Scan Result: {result_before['result']} | Risk Score: {result_before['risk_score']}%")

    print("\nStep 3: Submitting correction feedback (label = 1, i.e., Phishing)...")
    feedback_response = make_request("/feedback", {"url": test_url, "label": 1})
    if not feedback_response:
        print("Failed to submit feedback.")
        sys.exit(1)
    print(f"Feedback Response: {feedback_response}")

    print("\nStep 4: Waiting 5 seconds for model to retrain and hot-reload in the background...")
    time.sleep(5)

    print(f"\nStep 5: Scanning the URL again to verify evolution: {test_url}")
    result_after = make_request("/analyze", {"url": test_url})
    if not result_after:
        print("Failed to run second scan.")
        sys.exit(1)
        
    print(f"Evolved Scan Result: {result_after['result']} | Risk Score: {result_after['risk_score']}%")
    
    if result_after['result'] == "phishing" or result_after['risk_score'] >= result_before['risk_score']:
        print("\nSUCCESS: The model successfully evolved based on user feedback!")
    else:
        print("\nFAILURE: The model prediction did not update.")

if __name__ == "__main__":
    verify_pipeline()
