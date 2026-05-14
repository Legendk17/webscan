import requests
import re
import time
import socket
from urllib.parse import urlparse, urljoin, quote

TIMEOUT = 8
HEADERS = {"User-Agent": "SecureScan/2.0"}

def make_finding(category, title, severity, description, evidence="", remediation="", cwe="", owasp_id=""):
    return {
        "category": category, "title": title, "severity": severity,
        "description": description, "evidence": evidence[:300],
        "remediation": remediation, "cwe": cwe, "owasp_id": owasp_id
    }

# ── A01: Broken Access Control ──────────────────────────────
def check_a01(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Admin panel exposure
    admin_paths = ["/admin", "/administrator", "/admin/", "/wp-admin", "/dashboard",
                   "/control", "/management", "/superadmin", "/backend", "/cms"]
    for path in admin_paths:
        try:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 100:
                if not any(kw in r.url for kw in ["login", "signin", "auth"]):
                    findings.append(make_finding("A01", f"Admin panel exposed: {path}", "high",
                        "Admin interface is publicly accessible without authentication.",
                        f"URL: {r.url} returned HTTP {r.status_code}",
                        "Restrict access to admin panels via IP allowlisting or VPN.",
                        "CWE-284", "A01"))
        except Exception:
            pass

    # Directory traversal
    traversal_payloads = ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
                          "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
    for payload in traversal_payloads:
        for param in ["file", "path", "include", "page", "doc"]:
            try:
                r = s.get(f"{target}?{param}={payload}", timeout=TIMEOUT)
                if "root:x:" in r.text or "daemon:" in r.text:
                    findings.append(make_finding("A01", "Path Traversal Vulnerability", "critical",
                        f"Directory traversal allows reading /etc/passwd via ?{param}= parameter.",
                        f"Payload: {payload}",
                        "Validate and sanitize all file path inputs. Use allowlists.",
                        "CWE-22", "A01"))
                    break
            except Exception:
                pass

    # HTTP method tampering
    try:
        for method in ["PUT", "DELETE", "TRACE"]:
            r = s.request(method, target, timeout=TIMEOUT)
            if r.status_code not in (405, 403, 501, 400):
                findings.append(make_finding("A01", f"Dangerous HTTP Method Allowed: {method}", "medium",
                    f"HTTP method {method} is accepted by the server.",
                    f"Server responded with HTTP {r.status_code}",
                    "Disable unused HTTP methods in server configuration.",
                    "CWE-749", "A01"))
    except Exception:
        pass

    # Forced browsing - check for files that should be protected
    protected_paths = ["/api/users", "/api/admin", "/api/config", "/api/keys",
                       "/users.json", "/config.json", "/admin.json"]
    for path in protected_paths:
        try:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 50:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "xml" in ct:
                    findings.append(make_finding("A01", f"Unprotected API endpoint: {path}", "high",
                        "Sensitive API endpoint is accessible without authentication.",
                        f"URL: {target.rstrip('/')}{path} returned HTTP 200",
                        "Implement proper authentication and authorization on all API endpoints.",
                        "CWE-284", "A01"))
        except Exception:
            pass

    return findings

# ── A02: Cryptographic Failures ───────────────────────────────
def check_a02(target, ssl_data):
    findings = []

    if ssl_data.get("error"):
        findings.append(make_finding("A02", "SSL/TLS Not Available", "high",
            "The target does not support HTTPS or has a certificate error.",
            ssl_data.get("error", ""), "Enable HTTPS with a valid certificate.", "CWE-311", "A02"))
        return findings

    if ssl_data.get("expired"):
        findings.append(make_finding("A02", "Expired SSL Certificate", "critical",
            "The SSL certificate has expired, causing browser security warnings.",
            f"Expired on: {ssl_data.get('notAfter', '')}",
            "Renew the SSL certificate immediately.", "CWE-298", "A02"))

    if ssl_data.get("weak_protocol"):
        findings.append(make_finding("A02", f"Weak TLS Protocol: {ssl_data.get('protocol')}", "high",
            "An outdated TLS/SSL protocol version is in use.",
            f"Protocol: {ssl_data.get('protocol')}",
            "Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.", "CWE-326", "A02"))

    if ssl_data.get("weak_cipher"):
        findings.append(make_finding("A02", "Weak Cipher Suite", "medium",
            "A weak cipher suite is being used for encryption.",
            f"Cipher: {ssl_data.get('cipher', '')}",
            "Configure server to use strong cipher suites (AES-GCM, ChaCha20).", "CWE-327", "A02"))

    if not ssl_data.get("forward_secrecy"):
        findings.append(make_finding("A02", "No Forward Secrecy", "medium",
            "The cipher suite does not provide forward secrecy.",
            f"Cipher: {ssl_data.get('cipher', '')}",
            "Use ECDHE or DHE key exchange for perfect forward secrecy.", "CWE-311", "A02"))

    if ssl_data.get("self_signed"):
        findings.append(make_finding("A02", "Self-Signed Certificate", "high",
            "The SSL certificate is self-signed and not trusted by browsers.",
            f"Subject == Issuer: {ssl_data.get('subject', '')}",
            "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.).", "CWE-295", "A02"))

    # HTTP accessible
    try:
        http_url = target.replace("https://", "http://")
        r = requests.get(http_url, timeout=5, allow_redirects=False, headers=HEADERS)
        if r.status_code == 200:
            findings.append(make_finding("A02", "Site Accessible Over HTTP", "medium",
                "The website serves content over unencrypted HTTP.",
                f"HTTP URL returned status: {r.status_code}",
                "Redirect all HTTP traffic to HTTPS.", "CWE-311", "A02"))
    except Exception:
        pass

    return findings

# ── A03: Injection ────────────────────────────────────────────
def check_a03(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # SQL Injection
    sqli_error_patterns = [
        r"you have an error in your sql syntax",
        r"warning.*mysql.*",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg::syntaxerror",
        r"ora-\d{5}",
        r"sqlite3::.*exception",
        r"microsoft sql native client",
        r"odbc.*driver.*error",
    ]
    sqli_payloads = {
        "error_based": ["'", '"', "1'", "1\"", "';--", "'--"],
        "boolean_based": ["' OR '1'='1", "' OR 1=1--", "' AND 1=2--"],
        "time_based": ["'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--"],
        "union_based": ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
    }

    params_to_test = crawl.get("parameters_found", []) or ["id", "q", "search", "page", "cat"]

    for tech, payloads in sqli_payloads.items():
        for payload in payloads[:2]:
            for param in params_to_test[:5]:
                try:
                    start = time.time()
                    r = s.get(f"{target}?{param}={quote(payload)}", timeout=10)
                    elapsed = time.time() - start
                    text_lower = r.text.lower()

                    if tech == "time_based" and elapsed > 4.5:
                        findings.append(make_finding("A03", f"Time-Based SQL Injection — ?{param}=", "critical",
                            f"Time-based blind SQLi detected. Server delayed {elapsed:.1f}s.",
                            f"Payload: {payload}", "Use parameterized queries/prepared statements.", "CWE-89", "A03"))
                        break
                    elif any(re.search(p, text_lower) for p in sqli_error_patterns):
                        findings.append(make_finding("A03", f"Error-Based SQL Injection — ?{param}=", "critical",
                            "SQL error message returned — database errors exposed via user input.",
                            f"Payload: {payload}", "Use parameterized queries. Never expose DB errors.", "CWE-89", "A03"))
                        break
                except Exception:
                    pass

    # XSS
    xss_payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    for payload in xss_payloads[:2]:
        for param in params_to_test[:5]:
            try:
                r = s.get(f"{target}?{param}={quote(payload)}", timeout=TIMEOUT)
                if payload in r.text or payload.lower() in r.text.lower():
                    if "Content-Security-Policy" not in r.headers:
                        findings.append(make_finding("A03", f"Reflected XSS — ?{param}=", "high",
                            "XSS payload reflected in response without encoding.",
                            f"Payload: {payload}", "Encode output. Implement a Content Security Policy.", "CWE-79", "A03"))
                        break
            except Exception:
                pass

    # Command Injection
    cmd_payloads = ["; ls", "; id", "| id", "`id`", "$(id)", "; cat /etc/passwd"]
    cmd_indicators = ["root:", "uid=", "daemon", "bin/bash"]
    for param in params_to_test[:3]:
        for payload in cmd_payloads[:3]:
            try:
                r = s.get(f"{target}?{param}={quote(payload)}", timeout=TIMEOUT)
                if any(ind in r.text for ind in cmd_indicators):
                    findings.append(make_finding("A03", "OS Command Injection", "critical",
                        "Command injection payload returned system output.",
                        f"Payload: {payload}", "Never pass user input to shell commands. Use subprocess safely.", "CWE-78", "A03"))
                    break
            except Exception:
                pass

    # SSTI
    ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    for payload in ssti_payloads:
        for param in params_to_test[:3]:
            try:
                r = s.get(f"{target}?{param}={quote(payload)}", timeout=TIMEOUT)
                if "49" in r.text and payload not in r.text:
                    findings.append(make_finding("A03", "Server-Side Template Injection (SSTI)", "critical",
                        "Template expression evaluated server-side.",
                        f"Payload: {payload} → output contains 49",
                        "Never pass user input into template engines unsanitized.", "CWE-94", "A03"))
                    break
            except Exception:
                pass

    # CRLF Injection
    try:
        crlf_payload = "%0d%0aSet-Cookie:injected=1"
        r = s.get(f"{target}?redirect={crlf_payload}", timeout=TIMEOUT, allow_redirects=False)
        if "injected=1" in r.headers.get("Set-Cookie", ""):
            findings.append(make_finding("A03", "CRLF Injection", "high",
                "CRLF characters allow HTTP header injection.",
                "Set-Cookie: injected=1 appeared in response",
                "Strip \\r\\n from all user-controlled values used in HTTP headers.", "CWE-93", "A03"))
    except Exception:
        pass

    # Host Header Injection
    try:
        r = s.get(target, timeout=TIMEOUT, headers={**HEADERS, "Host": "evil.com"})
        if "evil.com" in r.text:
            findings.append(make_finding("A03", "Host Header Injection", "medium",
                "Server reflects the Host header value in the response.",
                "Response contains 'evil.com' when Host: evil.com sent",
                "Validate the Host header against a whitelist of allowed domains.", "CWE-113", "A03"))
    except Exception:
        pass

    return findings

# ── A04: Insecure Design ──────────────────────────────────────
def check_a04(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Rate limiting on login
    login_paths = ["/login", "/api/login", "/signin", "/auth/login", "/wp-login.php"]
    for path in login_paths:
        url = target.rstrip("/") + path
        try:
            responses = []
            for _ in range(8):
                r = s.post(url, data={"username": "admin", "password": "wrongpassword123"}, timeout=5)
                responses.append(r.status_code)
            if all(c not in (429, 403, 423) for c in responses[-3:]):
                findings.append(make_finding("A04", f"No Rate Limiting on Login: {path}", "high",
                    "Login endpoint does not rate-limit failed attempts — brute force risk.",
                    f"8 rapid failed POSTs to {path} without 429/lockout",
                    "Implement rate limiting, account lockout, and CAPTCHA on login.", "CWE-307", "A04"))
                break
        except Exception:
            pass

    # Predictable resource IDs
    for path in crawl.get("pages_visited", [])[:10]:
        if re.search(r'/\d+$', path):
            try:
                parts = path.rsplit("/", 1)
                id_val = int(parts[1])
                r1 = s.get(path, timeout=TIMEOUT)
                r2 = s.get(parts[0] + "/" + str(id_val - 1), timeout=TIMEOUT)
                if r1.status_code == 200 and r2.status_code == 200:
                    findings.append(make_finding("A04", "Predictable/Sequential Resource IDs", "medium",
                        "Resources use sequential integer IDs — IDOR risk.",
                        f"IDs {id_val-1} and {id_val} both return HTTP 200",
                        "Use UUIDs or other non-sequential identifiers.", "CWE-330", "A04"))
                break
            except Exception:
                pass

    return findings

# ── A05: Security Misconfiguration ───────────────────────────
def check_a05(target, http_data):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Directory listing
    try:
        for path in ["/uploads/", "/images/", "/files/", "/static/", "/assets/", "/backup/"]:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT)
            if r.status_code == 200 and ("Index of" in r.text or "Directory listing" in r.text or
                                          "<title>Directory" in r.text):
                findings.append(make_finding("A05", f"Directory Listing Enabled: {path}", "medium",
                    "Web server exposes directory listing, revealing file structure.",
                    f"Path {path} shows directory contents",
                    "Disable directory listing in web server configuration.", "CWE-548", "A05"))
    except Exception:
        pass

    # Verbose error pages
    try:
        r = s.get(f"{target}/this_page_does_not_exist_xyz", timeout=TIMEOUT)
        if r.status_code == 404:
            verbose_indicators = ["stack trace", "traceback", "line number", "exception",
                                  "mysql", "sql syntax", "at com.", "at org.", "debug"]
            if any(ind in r.text.lower() for ind in verbose_indicators):
                findings.append(make_finding("A05", "Verbose Error Pages", "medium",
                    "Error pages reveal server internals (stack traces, DB info).",
                    r.text[:200],
                    "Configure custom error pages. Disable debug mode in production.", "CWE-209", "A05"))
    except Exception:
        pass

    # Debug endpoints
    debug_paths = ["/_debug", "/debug", "/status", "/_status", "/health",
                   "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
                   "/__debug__", "/metrics", "/info", "/trace", "/env",
                   "/api/debug", "/diagnostics"]
    for path in debug_paths:
        try:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 100:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or any(kw in r.text.lower() for kw in ["heap", "memory", "env", "classpath", "beans"]):
                    findings.append(make_finding("A05", f"Debug/Actuator Endpoint Exposed: {path}", "high",
                        "Debug or actuator endpoint is publicly accessible.",
                        f"{path} returned HTTP 200 with {len(r.text)} bytes",
                        "Disable or restrict access to debug/management endpoints.", "CWE-215", "A05"))
        except Exception:
            pass

    # Default credentials
    default_creds = [
        ("/wp-login.php", {"log": "admin", "pwd": "admin"}, "WordPress"),
        ("/admin/login", {"username": "admin", "password": "admin"}, "Generic Admin"),
    ]
    for path, creds, service in default_creds:
        try:
            r = s.post(target.rstrip("/") + path, data=creds, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and "login" not in r.url.lower() and len(r.text) > 200:
                findings.append(make_finding("A05", f"Default Credentials — {service}", "critical",
                    f"Default admin credentials work for {service}.",
                    f"POST {path} with default creds returned HTTP 200",
                    "Change all default passwords immediately.", "CWE-1188", "A05"))
        except Exception:
            pass

    # CORS
    cors = http_data.get("cors", {})
    for finding in cors.get("findings", []):
        findings.append(make_finding("A05", f"CORS Misconfiguration", finding.get("sev", "medium"),
            finding.get("msg", ""), "", "Restrict CORS to trusted origins only.", "CWE-942", "A05"))

    # Disclosure headers
    disclosure = http_data.get("disclosure_headers", {})
    if disclosure:
        findings.append(make_finding("A05", "Server Information Disclosure", "low",
            "HTTP headers reveal server/framework version information.",
            str(disclosure),
            "Remove or obscure Server, X-Powered-By headers.", "CWE-200", "A05"))

    return findings

# ── A06: Vulnerable Components ────────────────────────────────
def check_a06(target, tech_data):
    findings = []
    versions = tech_data.get("versions", {})

    # Known vulnerable version ranges (simplified)
    known_vulns = {
        "WordPress": {"range": (0, 6.3), "cve": "CVE-2023-2745", "desc": "XSS vulnerability"},
        "jQuery": {"range": (0, 3.5), "cve": "CVE-2020-11023", "desc": "XSS via HTML manipulation"},
        "Bootstrap": {"range": (0, 4.3), "cve": "CVE-2019-8331", "desc": "XSS in tooltip/popover"},
    }

    for tech, version_str in versions.items():
        try:
            parts = version_str.split(".")
            ver_float = float(f"{parts[0]}.{''.join(parts[1:3])}" if len(parts) > 1 else parts[0])
            if tech in known_vulns:
                vuln = known_vulns[tech]
                if vuln["range"][0] <= ver_float < vuln["range"][1]:
                    findings.append(make_finding("A06", f"Outdated {tech} v{version_str}", "high",
                        f"{tech} version {version_str} has known vulnerabilities.",
                        f"{vuln['cve']}: {vuln['desc']}",
                        f"Upgrade {tech} to the latest stable version.", "CWE-1035", "A06"))
        except Exception:
            pass

    # Check for npm package files
    try:
        r = requests.get(target.rstrip("/") + "/package.json", timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200 and "dependencies" in r.text:
            findings.append(make_finding("A06", "package.json Exposed", "medium",
                "package.json is publicly accessible, revealing all dependencies.",
                r.text[:200],
                "Block access to package.json via web server configuration.", "CWE-200", "A06"))
    except Exception:
        pass

    return findings

# ── A07: Authentication Failures ──────────────────────────────
def check_a07(target, http_data):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Username enumeration
    login_paths = ["/login", "/api/login", "/signin", "/wp-login.php"]
    for path in login_paths:
        url = target.rstrip("/") + path
        try:
            r_valid = s.post(url, data={"username": "admin", "password": "wr0ngP4ss"}, timeout=TIMEOUT)
            r_invalid = s.post(url, data={"username": "zxqnotexist987", "password": "wr0ngP4ss"}, timeout=TIMEOUT)
            if r_valid.status_code == r_invalid.status_code:
                # Check response body difference
                if len(r_valid.text) != len(r_invalid.text):
                    diff = abs(len(r_valid.text) - len(r_invalid.text))
                    if diff > 20:
                        findings.append(make_finding("A07", "Username Enumeration", "medium",
                            "Login endpoint returns different responses for valid vs invalid usernames.",
                            f"Response size diff: {diff} bytes for valid vs invalid user",
                            "Return identical responses for all failed login attempts.", "CWE-204", "A07"))
                        break
        except Exception:
            pass

    # Cookie security
    cookies = http_data.get("cookies", [])
    for cookie in cookies:
        issues = cookie.get("issues", [])
        if issues:
            sev = "high" if any("Secure" in i for i in issues) else "medium"
            findings.append(make_finding("A07", f"Insecure Cookie: {cookie.get('name', 'unknown')}", sev,
                f"Cookie lacks security attributes: {', '.join(issues)}",
                f"Cookie: {cookie.get('name')} | Issues: {', '.join(issues)}",
                "Set Secure, HttpOnly, and SameSite attributes on all cookies.", "CWE-614", "A07"))

    # Session token in URL
    try:
        r = s.get(target, timeout=TIMEOUT)
        if re.search(r"[?&](session|sess|token|auth|sid|jsessionid)=[a-zA-Z0-9]+", r.url, re.I):
            findings.append(make_finding("A07", "Session Token in URL", "high",
                "Session identifier appears in the URL — exposed in logs and history.",
                r.url,
                "Store session tokens in cookies, never in URLs.", "CWE-598", "A07"))
    except Exception:
        pass

    # JWT checks
    try:
        r = s.get(target, timeout=TIMEOUT)
        auth_header = r.headers.get("Authorization", "")
        all_headers = str(dict(r.headers))
        if "eyJ" in all_headers:
            token = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", all_headers)
            if token:
                # Check if alg=none attack works
                findings.append(make_finding("A07", "JWT Token Exposed in Headers", "medium",
                    "A JWT token is visible in HTTP response headers.",
                    token.group(0)[:50] + "...",
                    "Avoid sending JWTs in response headers unnecessarily.", "CWE-522", "A07"))
    except Exception:
        pass

    return findings

# ── A08: Software Integrity ───────────────────────────────────
def check_a08(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Missing SRI on external scripts
    try:
        r = s.get(target, timeout=TIMEOUT)
        external_scripts = re.findall(
            r'<script[^>]+src=["\']https?://(?!' + re.escape(urlparse(target).hostname or "") + r')[^"\']+["\'][^>]*>',
            r.text, re.I
        )
        missing_sri = []
        for script in external_scripts:
            if "integrity=" not in script.lower():
                src = re.search(r'src=["\']([^"\']+)["\']', script, re.I)
                if src:
                    missing_sri.append(src.group(1))
        if missing_sri:
            findings.append(make_finding("A08", "Missing Subresource Integrity (SRI)", "medium",
                f"{len(missing_sri)} external script(s) loaded without SRI integrity checks.",
                "; ".join(missing_sri[:3]),
                "Add integrity= and crossorigin= attributes to external scripts/styles.", "CWE-353", "A08"))
    except Exception:
        pass

    # CI/CD exposure
    ci_paths = ["/.travis.yml", "/Jenkinsfile", "/.circleci/config.yml",
                "/.github/workflows/deploy.yml", "/bitbucket-pipelines.yml"]
    for path in ci_paths:
        try:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 50:
                findings.append(make_finding("A08", f"CI/CD Configuration Exposed: {path}", "medium",
                    "CI/CD configuration file is publicly accessible — may contain secrets.",
                    r.text[:200],
                    "Block access to CI/CD config files via web server rules.", "CWE-312", "A08"))
        except Exception:
            pass

    # Jenkins
    try:
        r = s.get(target.rstrip("/") + "/jenkins/", timeout=TIMEOUT)
        if r.status_code == 200 and "jenkins" in r.text.lower():
            findings.append(make_finding("A08", "Jenkins Instance Exposed", "high",
                "Jenkins CI/CD server is publicly accessible.",
                f"Jenkins UI detected at /jenkins/",
                "Restrict Jenkins to internal network or VPN only.", "CWE-284", "A08"))
    except Exception:
        pass

    return findings

# ── A09: Logging Failures ─────────────────────────────────────
def check_a09(target, http_data):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Stack trace / verbose errors
    try:
        r = s.get(f"{target}/nonexistent_page_xyz_123", timeout=TIMEOUT)
        body = r.text.lower()
        if any(kw in body for kw in ["traceback", "stack trace", "at com.", "exception in thread"]):
            findings.append(make_finding("A09", "Stack Trace Exposed in Error Pages", "medium",
                "Unhandled errors expose server-side stack traces to users.",
                r.text[:300],
                "Implement custom error handling. Log errors server-side, not in responses.", "CWE-209", "A09"))
    except Exception:
        pass

    # No lockout on login (check for missing 429)
    login_paths = ["/login", "/api/login", "/signin"]
    for path in login_paths:
        url = target.rstrip("/") + path
        try:
            got_lockout = False
            for _ in range(10):
                r = s.post(url, data={"username": "admin@test.com", "password": "test123"}, timeout=5)
                if r.status_code in (429, 423, 403):
                    got_lockout = True
                    break
            if not got_lockout:
                found_login = s.get(url, timeout=5).status_code < 400
                if found_login:
                    findings.append(make_finding("A09", "No Account Lockout / Rate Limit", "medium",
                        "Login endpoint does not lock accounts or rate-limit after multiple failures.",
                        f"10 rapid POST requests to {path} without lockout",
                        "Implement progressive delays, CAPTCHA, and account lockout.", "CWE-307", "A09"))
            break
        except Exception:
            pass

    return findings

# ── A10: SSRF ────────────────────────────────────────────────
def check_a10(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "http://0.0.0.0/",
    ]

    ssrf_params = ["url", "uri", "src", "dest", "redirect", "next", "target",
                   "link", "image", "callback", "webhook", "feed", "host",
                   "fetch", "load", "ref", "proxy"]

    indicators = ["ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
                  "computeMetadata", "root:x:", "127.0.0.1", "localhost"]

    params = crawl.get("parameters_found", [])
    test_params = list(set(ssrf_params) & set(params)) or ssrf_params[:4]

    for payload in ssrf_payloads[:3]:
        for param in test_params[:4]:
            try:
                r = s.get(f"{target}?{param}={quote(payload)}", timeout=8)
                if any(ind in r.text for ind in indicators):
                    findings.append(make_finding("A10", "Server-Side Request Forgery (SSRF)", "critical",
                        f"SSRF payload caused server to fetch internal resource.",
                        f"Param: {param}, Payload: {payload}",
                        "Validate/allowlist all URLs fetched server-side. Block internal IPs.", "CWE-918", "A10"))
                    break
            except Exception:
                pass

    # Check for URL-accepting forms
    for form in crawl.get("forms", [])[:5]:
        for inp in form.get("inputs", []):
            if inp.get("name", "").lower() in ssrf_params:
                findings.append(make_finding("A10", f"SSRF-Susceptible Form Parameter: {inp['name']}", "medium",
                    f"Form has URL-accepting parameter '{inp['name']}' — potential SSRF vector.",
                    f"Form action: {form.get('action', '')}",
                    "Validate all URL inputs server-side. Use allowlists.", "CWE-918", "A10"))

    return findings


# ── XSS Testing Engine ────────────────────────────────────────
def check_xss(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    xss_payloads = {
        "reflected": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "';alert(1);//",
        ],
        "dom": [
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
        ]
    }

    params = crawl.get("parameters_found", []) or ["q", "search", "s", "query", "input"]

    for xss_type, payloads in xss_payloads.items():
        for payload in payloads[:3]:
            for param in params[:5]:
                try:
                    r = s.get(f"{target}?{param}={quote(payload)}", timeout=TIMEOUT)
                    if payload in r.text:
                        has_csp = "Content-Security-Policy" in r.headers
                        severity = "medium" if has_csp else "high"
                        findings.append(make_finding("A03", f"{xss_type.title()} XSS — ?{param}=", severity,
                            f"XSS payload reflected unencoded in server response.",
                            f"Payload: {payload}",
                            "Encode all output. Implement strict CSP.", "CWE-79", "A03"))
                        break
                except Exception:
                    pass

    # Test forms for stored XSS surface
    for form in crawl.get("forms", [])[:5]:
        text_inputs = [i for i in form.get("inputs", []) if i.get("type", "text") in ("text", "textarea", "search")]
        if text_inputs:
            findings.append(make_finding("A03", "Potential Stored XSS Surface", "info",
                f"Form at {form.get('action', '?')} has {len(text_inputs)} text input(s) — test for stored XSS.",
                f"Action: {form.get('action')}, Method: {form.get('method')}",
                "Validate and encode all form inputs on storage and display.", "CWE-79", "A03"))

    return findings

# ── Open Redirect Testing ─────────────────────────────────────
def check_open_redirect(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    redirect_params = ["redirect", "next", "url", "return", "goto", "link", "target", "dest", "destination", "redir"]
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "%2F%2Fevil.com",
        "http://evil.com@legit.com",
    ]

    params = crawl.get("parameters_found", [])
    test_params = list(set(redirect_params) & set(params)) or redirect_params[:4]

    for param in test_params:
        for payload in redirect_payloads[:3]:
            try:
                r = s.get(f"{target}?{param}={quote(payload)}", timeout=TIMEOUT, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append(make_finding("A01", f"Open Redirect — ?{param}=", "medium",
                            "Server redirects to attacker-controlled URL.",
                            f"Location: {location}",
                            "Validate redirect URLs against an allowlist of trusted domains.", "CWE-601", "A01"))
                        break
            except Exception:
                pass

    return findings

# ── API Security ──────────────────────────────────────────────
def check_api_security(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    # Swagger / OpenAPI discovery
    api_doc_paths = [
        "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/api/docs", "/openapi.json", "/openapi.yaml",
        "/v1/swagger.json", "/v2/api-docs", "/docs/api",
    ]
    for path in api_doc_paths:
        try:
            r = s.get(target.rstrip("/") + path, timeout=TIMEOUT)
            if r.status_code == 200 and any(kw in r.text for kw in ["swagger", "openapi", "paths", "definitions"]):
                findings.append(make_finding("A05", f"API Documentation Exposed: {path}", "medium",
                    "Swagger/OpenAPI documentation is publicly accessible.",
                    f"Found at: {target.rstrip('/')}{path}",
                    "Restrict API documentation to authenticated users or internal networks.", "CWE-200", "A05"))
        except Exception:
            pass

    # GraphQL introspection
    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query"]
    introspection_query = '{"query":"{ __schema { types { name } } }"}'
    for path in graphql_paths:
        try:
            r = s.post(target.rstrip("/") + path, data=introspection_query,
                       headers={**HEADERS, "Content-Type": "application/json"}, timeout=TIMEOUT)
            if r.status_code == 200 and "__schema" in r.text:
                findings.append(make_finding("A05", f"GraphQL Introspection Enabled: {path}", "medium",
                    "GraphQL introspection is enabled — full schema exposed.",
                    "Response contains __schema data",
                    "Disable GraphQL introspection in production.", "CWE-200", "A05"))
        except Exception:
            pass

    # Missing auth on API endpoints
    api_endpoints = crawl.get("api_endpoints", [])
    for ep in api_endpoints[:10]:
        try:
            url = urljoin(target, ep) if not ep.startswith("http") else ep
            r = s.get(url, timeout=TIMEOUT)
            if r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct and len(r.text) > 50:
                    findings.append(make_finding("A01", f"Unauthenticated API Access: {ep}", "high",
                        "API endpoint returns data without requiring authentication.",
                        f"URL: {url} → HTTP 200 with JSON",
                        "Implement authentication on all API endpoints.", "CWE-284", "A01"))
        except Exception:
            pass

    return findings

# ── Upload Security ───────────────────────────────────────────
def check_upload_security(target, crawl):
    findings = []
    s = requests.Session()
    s.headers.update(HEADERS)

    upload_forms = crawl.get("upload_forms", [])
    if upload_forms:
        findings.append(make_finding("A05", f"File Upload Form(s) Detected", "info",
            f"{len(upload_forms)} file upload form(s) found — may allow dangerous file types.",
            "; ".join([f.get("url", "") for f in upload_forms[:3]]),
            "Validate file types by content (magic bytes), not extension. Scan uploads for malware.", "CWE-434", "A05"))

        # Try to upload web shell (SVG XSS payload as safe test)
        for form in upload_forms[:2]:
            action = form.get("action", target)
            try:
                svg_payload = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
                files = {"file": ("test.svg", svg_payload, "image/svg+xml")}
                r = s.post(action, files=files, timeout=TIMEOUT)
                if r.status_code in (200, 201) and ("svg" in r.text.lower() or "upload" in r.text.lower()):
                    findings.append(make_finding("A05", "SVG Upload XSS Risk", "high",
                        "Upload form may accept SVG files — XSS via SVG payload.",
                        f"Form action: {action}",
                        "Block SVG uploads or sanitize SVG content server-side.", "CWE-434", "A05"))
            except Exception:
                pass

    return findings

# ── Main OWASP Scanner ────────────────────────────────────────
def run_owasp_scan(target, crawl):
    all_findings = []

    # Pre-fetch SSL and HTTP data for A02 and A07
    ssl_data = {}
    http_data = {"cookies": [], "cors": {"findings": []}, "disclosure_headers": {}}
    tech_data = {"versions": {}}

    try:
        from modules.ssl_checker import check_ssl
        ssl_data = check_ssl(target)
    except Exception:
        pass

    try:
        from modules.http_analyzer import analyze_http
        http_data = analyze_http(target)
    except Exception:
        pass

    try:
        from modules.tech_fingerprint import fingerprint_tech
        tech_data = fingerprint_tech(target)
    except Exception:
        pass

    checkers = [
        ("A01", lambda: check_a01(target, crawl)),
        ("A02", lambda: check_a02(target, ssl_data)),
        ("A03", lambda: check_a03(target, crawl) + check_xss(target, crawl)),
        ("A04", lambda: check_a04(target, crawl)),
        ("A05", lambda: check_a05(target, http_data) + check_upload_security(target, crawl) + check_api_security(target, crawl)),
        ("A06", lambda: check_a06(target, tech_data)),
        ("A07", lambda: check_a07(target, http_data)),
        ("A08", lambda: check_a08(target, crawl)),
        ("A09", lambda: check_a09(target, http_data)),
        ("A10", lambda: check_a10(target, crawl) + check_open_redirect(target, crawl)),
    ]

    results_by_category = {}
    for cat, fn in checkers:
        try:
            cat_findings = fn()
            results_by_category[cat] = cat_findings
            all_findings.extend(cat_findings)
        except Exception as e:
            results_by_category[cat] = []

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "findings": all_findings,
        "by_category": results_by_category,
        "total_issues": len(all_findings),
        "critical_count": sev_counts["critical"],
        "high_count": sev_counts["high"],
        "medium_count": sev_counts["medium"],
        "low_count": sev_counts["low"],
        "info_count": sev_counts["info"],
    }
