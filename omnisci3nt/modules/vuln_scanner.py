import requests
from urllib.parse import urlparse, urljoin
import concurrent.futures
import os
import re
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def log(msg):
    print(msg)
    with open("scan_results.txt", "a") as f:
        f.write(msg + "\n")

def check_idor(base_url):
    log("[*] Checking for potential IDOR...")
    urls = [f"{base_url}/user/1", f"{base_url}/user/2"]
    responses = []

    for url in urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200:
                responses.append((url, r.text.strip()))
        except:
            continue

    if len(responses) == 2 and responses[0][1] != responses[1][1]:
        log(f"[⚠️ ] Potential IDOR found: {responses[0][0]} and {responses[1][0]}")
    else:
        log("[✔ ] IDOR: No clear signs of user-specific data exposure.")

def check_sensitive_files(base_url):
    log("[*] Checking for Exposed Sensitive Files...")
    sensitive_files = [
        (".env", ["SECRET", "DB_", "PASSWORD"]),
        (".git/config", ["repository", "[core]"]),
        ("config.php", ["<?php", "define", "DB_"]),
        ("backup.zip", []),
    ]

    for path, signatures in sensitive_files:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and any(sig in r.text for sig in signatures):
                log(f"[❌ ] Sensitive content found: {url}")
            elif r.status_code == 200 and path.endswith(".zip") and len(r.content) > 100:
                log(f"[❌ ] Downloadable backup found: {url}")
        except:
            continue
    log("[✔ ] Sensitive file scan done.")

def check_xss(base_url):
    log("[*] Checking for Reflected XSS...")
    test_url = f"{base_url}/search?q=<script>alert(1)</script>"
    try:
        r = requests.get(test_url, headers=HEADERS, timeout=5)
        if "<script>alert(1)</script>" in r.text:
            log(f"[❌ ] Reflected XSS possible at: {test_url}")
        else:
            log("[✔ ] XSS: No reflection found.")
    except:
        pass

def check_open_redirect(base_url):
    log("[*] Checking for Open Redirect...")
    test_paths = [
        "/redirect?url=https://google.com",
        "/out?target=https://google.com",
    ]

    for path in test_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, allow_redirects=False, timeout=5)
            if r.status_code in [301, 302] and "google.com" in r.headers.get("Location", ""):
                log(f"[⚠️ ] Possible Open Redirect at: {url}")
        except:
            continue
    log("[✔ ] Open Redirect scan done.")

def check_clickjacking(base_url):
    log("[*] Checking for Clickjacking protection...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        if 'X-Frame-Options' not in r.headers:
            log(f"[⚠️ ] Clickjacking possible: No X-Frame-Options header found at {base_url}")
        else:
            log("[✔ ] Clickjacking protection is present.")
    except:
        pass

def check_cors(base_url):
    log("[*] Checking for insecure CORS configuration...")
    try:
        r = requests.options(base_url, headers={**HEADERS, "Origin": "https://evil.com"}, timeout=5)
        if r.headers.get("Access-Control-Allow-Origin") == "*" or "evil.com" in r.headers.get("Access-Control-Allow-Origin", ""):
            log(f"[⚠️ ] CORS Misconfiguration: {base_url} allows requests from arbitrary origins.")
        else:
            log("[✔ ] CORS config looks safe.")
    except:
        pass

def check_host_header_injection(base_url):
    log("[*] Checking for Host Header Injection...")
    try:
        r = requests.get(base_url, headers={"Host": "evil.com", **HEADERS}, timeout=5)
        if "evil.com" in r.text:
            log(f"[⚠️ ] Potential Host Header Injection found at {base_url}")
        else:
            log("[✔ ] No signs of host header injection.")
    except:
        pass

def run_all_checks(base_url):
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.submit(check_idor, base_url)
        executor.submit(check_sensitive_files, base_url)
        executor.submit(check_xss, base_url)
        executor.submit(check_open_redirect, base_url)
        executor.submit(check_clickjacking, base_url)
        executor.submit(check_cors, base_url)
        executor.submit(check_host_header_injection, base_url)

def run_vuln_scanner(base_url):
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"
    parsed = urlparse(base_url)
    domain = parsed.netloc or parsed.path

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    outfile = f"scan_results.txt"

    if os.path.exists(outfile):
        os.remove(outfile)

    log("\n=== Vulnerability Scan Started ===")
    log(f"Target: {domain}")
    log(f"Time: {timestamp}\n")

    run_all_checks(base_url)

    log("\n=== Scan Complete ===\n")
