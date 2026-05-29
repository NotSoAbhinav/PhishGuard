import os
import sys

def main():
    print("=== PhishGuard CI/CD: Injecting Environment Variables ===")
    
    api_url = os.environ.get("PHISHGUARD_API_URL", "")
    api_key = os.environ.get("PHISHGUARD_API_KEY", "")
    
    if not api_url:
        print("WARNING: PHISHGUARD_API_URL environment variable is missing!")
    else:
        print(f"Target API Base URL: {api_url}")
        
    if not api_key:
        print("WARNING: PHISHGUARD_API_KEY environment variable is missing!")
    else:
        print("Target API Key: [Configured]")
        
    js_path = os.path.join("frontend", "script.js")
    if not os.path.exists(js_path):
        print(f"Error: Frontend script not found at {js_path}")
        sys.exit(1)
        
    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Replace placeholders
    if api_url:
        content = content.replace("__API_BASE__", api_url)
    if api_key:
        content = content.replace("__API_KEY__", api_key)
        
    with open(js_path, "w", encoding="utf-8") as f:
        f.write(content)
        
    print(f"Successfully processed {js_path}")
    print("=========================================================")

if __name__ == "__main__":
    main()
