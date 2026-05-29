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
    
    initial_version = status.get("model_version", "unknown")
    print(f"API is online. Initial model version: {initial_version}")

    test_url = "http://evolving-version-test-domain.xyz/verify-login"
    print(f"\nStep 2: Performing initial analysis on: {test_url}")
    result_before = make_request("/analyze", {"url": test_url})
    if not result_before:
        print("Failed to run initial scan.")
        sys.exit(1)
    
    print(f"Initial Scan Version: {result_before.get('model_version')} | Risk: {result_before['risk_score']}%")

    print("\nStep 3: Querying stats endpoint...")
    stats_before = make_request("/stats")
    if stats_before:
        print(f"Stats: Total Scans={stats_before.get('total_scans')}, Detections={stats_before.get('threats_detected')}, Version={stats_before.get('model_version')}")

    print("\nStep 4: Submitting correction feedback (label = 1)...")
    feedback_response = make_request("/feedback", {"url": test_url, "label": 1})
    if not feedback_response:
        print("Failed to submit feedback.")
        sys.exit(1)
    print(f"Feedback Response: {feedback_response}")
    target_version = feedback_response.get("target_version")

    print("\nStep 5: Waiting 6 seconds for background retraining and hot-reloading...")
    time.sleep(6)

    print(f"\nStep 6: Pinging root again to inspect hot-reloaded version...")
    status_after = make_request("/")
    after_version = status_after.get("model_version", "unknown")
    print(f"Post-feedback model version: {after_version}")
    
    print(f"\nStep 7: Re-scanning the URL: {test_url}")
    result_after = make_request("/analyze", {"url": test_url})
    if not result_after:
        print("Failed to run second scan.")
        sys.exit(1)
    print(f"Scan Version: {result_after.get('model_version')} | Risk: {result_after['risk_score']}%")

    if after_version == target_version:
        print("\nSUCCESS: Model successfully evolved and version incremented from {} to {}!".format(initial_version, after_version))
    else:
        print("\nFAILURE: Model version did not increment correctly. Expected: {}, Got: {}".format(target_version, after_version))

if __name__ == "__main__":
    verify_pipeline()
