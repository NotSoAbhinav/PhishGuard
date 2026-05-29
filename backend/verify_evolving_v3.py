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
    features_count = status.get("model_features", "unknown")
    print(f"API is online. Model version: {initial_version} | Feature count: {features_count}")
    
    if features_count != 24:
        print(f"FAILURE: Expected 24 features, got {features_count}")
        sys.exit(1)

    # Test typosquatted URL
    test_url = "http://paypa1-verify-login.net"
    print(f"\nStep 2: Performing analysis on typosquatted URL: {test_url}")
    result = make_request("/analyze", {"url": test_url})
    if not result:
        print("Failed to run scan.")
        sys.exit(1)
    
    print(f"Result: {result['result']} | Risk Score: {result['risk_score']}%")
    
    # Check for typosquatting indicator in features breakdown
    features_breakdown = result.get("features_breakdown", [])
    typo_feat = next((f for f in features_breakdown if f["name"] == "Typosquatting"), None)
    if typo_feat:
        print(f"Typosquatting feature status: Value={typo_feat['value']}, Status={typo_feat['status']}")
    else:
        print("FAILURE: Typosquatting feature not found in feature breakdown!")
        sys.exit(1)
        
    # Check for typosquatting alert in reasons
    reasons = result.get("reasons", [])
    typo_reason = next((r for r in reasons if "Typosquatting" in r["message"]), None)
    if typo_reason:
        print(f"Typosquatting warning found: '{typo_reason['message']}' (Severity: {typo_reason['severity']})")
    else:
        print("FAILURE: Typosquatting warning not found in heuristics!")
        sys.exit(1)

    print("\nStep 3: Submitting correction feedback (label = 1)...")
    feedback_response = make_request("/feedback", {"url": test_url, "label": 1})
    if not feedback_response:
        print("Failed to submit feedback.")
        sys.exit(1)
    print(f"Feedback Response: {feedback_response}")
    target_version = feedback_response.get("target_version")

    print("\nStep 4: Waiting 6 seconds for background retraining and hot-reloading...")
    time.sleep(6)

    print(f"\nStep 5: Pinging root again to inspect hot-reloaded version...")
    status_after = make_request("/")
    after_version = status_after.get("model_version", "unknown")
    print(f"Post-feedback model version: {after_version}")

    if after_version == target_version:
        print("\nSUCCESS: Model successfully evolved and version incremented from {} to {}!".format(initial_version, after_version))
    else:
        print("\nFAILURE: Model version did not increment correctly. Expected: {}, Got: {}".format(target_version, after_version))

if __name__ == "__main__":
    verify_pipeline()
