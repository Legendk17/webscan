import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 8
HEADERS = {"User-Agent": "SecureScan/2.0"}

SECRET_PATTERNS = [
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "regex": r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]", "severity": "critical"},
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"name": "Firebase Config", "regex": r"firebase\.initializeApp\s*\(\s*\{", "severity": "high"},
    {"name": "Stripe Secret Key", "regex": r"sk_live_[0-9a-zA-Z]{24}", "severity": "critical"},
    {"name": "Stripe Public Key", "regex": r"pk_live_[0-9a-zA-Z]{24}", "severity": "medium"},
    {"name": "GitHub Token", "regex": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{82}", "severity": "critical"},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "severity": "high"},
    {"name": "Private Key", "regex": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Password in code", "regex": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "severity": "high"},
    {"name": "API Key Generic", "regex": r"(?i)api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "severity": "high"},
    {"name": "Secret Generic", "regex": r"(?i)(secret|token)\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "severity": "medium"},
    {"name": "Bearer Token", "regex": r"Bearer [A-Za-z0-9\-_.=]{20,}", "severity": "medium"},
    {"name": "MongoDB URI", "regex": r"mongodb(\+srv)?://[^\s'\"]+", "severity": "critical"},
    {"name": "Database URL", "regex": r"(mysql|postgres|postgresql|redis)://[^\s'\"]+", "severity": "critical"},
    {"name": "SendGrid API Key", "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "severity": "critical"},
    {"name": "Slack Token", "regex": r"xox[baprs]-[0-9A-Za-z\-]+", "severity": "high"},
    {"name": "Twilio Key", "regex": r"SK[0-9a-fA-F]{32}", "severity": "high"},
    {"name": "Internal IP", "regex": r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "severity": "low"},
]

ENDPOINT_PATTERNS = [
    r'["\']/(api|v\d|rest|graphql|admin|internal|private|service)/[^\s\'"<>]{1,100}["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    r'url\s*:\s*["\']([^"\']{5,100})["\']',
    r'href\s*=\s*["\']([^"\']{5,100})["\']',
    r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
]

DOM_XSS_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.assign", "location.replace",
    "document.location", "window.location", "src=", "href=",
    "document.cookie", "localStorage.setItem", "sessionStorage.setItem",
]

WEBSOCKET_PATTERNS = [
    r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
    r'io\s*\(\s*["\']([^"\']+)["\']',
    r'socket\.connect\s*\(',
]

def analyze_single_js(url, session):
    try:
        r = session.get(url, timeout=TIMEOUT)
        if not r.ok or "javascript" not in r.headers.get("Content-Type", "text/javascript"):
            ct = r.headers.get("Content-Type", "")
            if "json" in ct or "html" in ct:
                return None
        content = r.text

        # Find secrets
        secrets = []
        for pat in SECRET_PATTERNS:
            matches = re.findall(pat["regex"], content)
            for m in matches:
                match_str = m if isinstance(m, str) else m[0] if m else ""
                # Mask sensitive values
                masked = match_str[:8] + "..." + match_str[-4:] if len(match_str) > 12 else match_str[:4] + "..."
                secrets.append({
                    "type": pat["name"],
                    "severity": pat["severity"],
                    "value_masked": masked,
                    "js_file": url
                })

        # Find endpoints
        endpoints = set()
        for pat in ENDPOINT_PATTERNS:
            matches = re.findall(pat, content, re.I)
            for m in matches:
                ep = m if isinstance(m, str) else (m[1] if len(m) > 1 else m[0])
                if len(ep) > 3 and not ep.startswith("//"):
                    endpoints.add(ep)

        # Find DOM XSS sinks
        sinks = []
        for sink in DOM_XSS_SINKS:
            if sink in content:
                # Find context
                idx = content.find(sink)
                ctx = content[max(0, idx-30):idx+len(sink)+50].strip()
                sinks.append({"sink": sink, "context": ctx[:100]})

        # Find WebSocket usage
        ws_urls = []
        for pat in WEBSOCKET_PATTERNS:
            ws_urls.extend(re.findall(pat, content))

        # Detect hardcoded credentials
        creds = []
        cred_patterns = [
            r'(?i)username\s*[=:]\s*["\']([^"\']{3,30})["\']',
            r'(?i)user\s*[=:]\s*["\']([^"\']{3,30})["\']',
        ]
        for cp in cred_patterns:
            matches = re.findall(cp, content)
            creds.extend(matches[:3])

        return {
            "url": url,
            "size": len(content),
            "secrets": secrets,
            "endpoints": list(endpoints)[:20],
            "dom_sinks": sinks[:10],
            "websocket_urls": ws_urls,
            "hardcoded_creds": creds
        }
    except Exception:
        return None

def analyze_js(target, js_files=None):
    if not js_files:
        # Try to discover JS files from the target
        js_files = []
        try:
            r = requests.get(target, timeout=TIMEOUT, headers=HEADERS)
            js_files = re.findall(r'src\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text, re.I)
            from urllib.parse import urljoin
            js_files = [urljoin(target, j) for j in js_files if not j.startswith("//")][:15]
        except Exception:
            pass

    all_secrets = []
    all_endpoints = []
    all_sinks = []
    all_ws = []
    file_results = []
    all_creds = []

    with requests.Session() as session:
        session.headers.update(HEADERS)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_single_js, url, session): url for url in js_files[:15]}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_secrets.extend(result["secrets"])
                    all_endpoints.extend(result["endpoints"])
                    all_sinks.extend(result["dom_sinks"])
                    all_ws.extend(result["websocket_urls"])
                    all_creds.extend(result["hardcoded_creds"])
                    if result["secrets"] or result["dom_sinks"]:
                        file_results.append(result)

    # Deduplicate
    seen_endpoints = set()
    unique_endpoints = []
    for ep in all_endpoints:
        if ep not in seen_endpoints:
            seen_endpoints.add(ep)
            unique_endpoints.append(ep)

    findings = []
    if all_secrets:
        findings.append({"sev": "critical", "msg": f"{len(all_secrets)} secret(s) found in JavaScript files"})
    crit_sinks = [s for s in all_sinks if s["sink"] in ["document.write", "innerHTML", "eval("]]
    if crit_sinks:
        findings.append({"sev": "high", "msg": f"{len(crit_sinks)} dangerous DOM XSS sink(s) found"})

    return {
        "js_files_analyzed": len(js_files),
        "secrets": all_secrets[:30],
        "endpoints": unique_endpoints[:40],
        "dom_sinks": all_sinks[:20],
        "websocket_urls": list(set(all_ws)),
        "hardcoded_creds": all_creds[:10],
        "file_results": file_results[:10],
        "findings": findings,
        "critical_secrets": sum(1 for s in all_secrets if s["severity"] == "critical")
    }
