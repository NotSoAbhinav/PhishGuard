import urllib.request
import urllib.error
import json
import sys

API_BASE = "http://127.0.0.1:5000"

def make_request(path, data=None, api_key=None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
        
    req_data = None
    if data:
        req_data = json.dumps(data).encode("utf-8")
        
    req = urllib.request.Request(url, data=req_data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Read the error JSON body if possible
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = e.reason
        return e.code, body
    except Exception as e:
        print(f"Request connection error: {e}")
        return 0, str(e)

def run_security_tests():
    print("Starting API Security Tests...")
    
    # 1. Test public root endpoint (Should succeed without key)
    print("\nTest 1: Public root health check (No API Key)...")
    status, body = make_request("/")
    print(f"Status: {status} | Body: {body}")
    if status != 200:
        print("FAILURE: Public root endpoint failed.")
        sys.exit(1)
    
    # 2. Test protected endpoints without API Key
    print("\nTest 2: Protected /analyze endpoint (No API Key)...")
    status, body = make_request("/analyze", {"url": "https://google.com"})
    print(f"Status: {status} | Body: {body}")
    if status != 401:
        print("FAILURE: Endpoint allowed unauthorized request.")
        sys.exit(1)
        
    print("\nTest 3: Protected /stats endpoint (No API Key)...")
    status, body = make_request("/stats")
    print(f"Status: {status} | Body: {body}")
    if status != 401:
        print("FAILURE: Endpoint allowed unauthorized request.")
        sys.exit(1)

    # 3. Test protected endpoints with Invalid API Key
    print("\nTest 4: Protected /analyze endpoint (Invalid API Key)...")
    status, body = make_request("/analyze", {"url": "https://google.com"}, api_key="wrong-key-123")
    print(f"Status: {status} | Body: {body}")
    if status != 401:
        print("FAILURE: Endpoint accepted invalid API key.")
        sys.exit(1)

    # 4. Test protected endpoints with Correct API Key (default-dev-key in dev environment)
    print("\nTest 5: Protected /analyze endpoint (Correct API Key)...")
    status, body = make_request("/analyze", {"url": "https://google.com"}, api_key="default-dev-key")
    print(f"Status: {status} | Body: {body}")
    if status != 200:
        print("FAILURE: Failed to query endpoint with correct API key.")
        sys.exit(1)

    print("\nTest 6: Protected /stats endpoint (Correct API Key)...")
    status, body = make_request("/stats", api_key="default-dev-key")
    print(f"Status: {status} | Body: {body}")
    if status != 200:
        print("FAILURE: Failed to query stats with correct API key.")
        sys.exit(1)

    print("\nSUCCESS: All API security tests passed! Unauthorized queries are blocked and authorized queries succeed.")

if __name__ == "__main__":
    run_security_tests()
