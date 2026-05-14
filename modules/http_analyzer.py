import requests
import re
from urllib.parse import urlparse

TIMEOUT = 8
HEADERS_UA = {"User-Agent": "SecureScan/2.0"}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS connections", "severity": "high",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS and data injection", "severity": "high",
        "recommendation": "Define a strict CSP policy restricting script/style sources"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking", "severity": "medium",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME sniffing", "severity": "medium",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information", "severity": "low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access", "severity": "low",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (deprecated)", "severity": "low",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (legacy browsers)"
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Cross-origin isolation", "severity": "low",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp"
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Cross-origin opener isolation", "severity": "low",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin"
    },
}

def analyze_csp(csp_value):
    issues = []
    if not csp_value:
        return issues
    if "unsafe-inline" in csp_value:
        issues.append("CSP allows 'unsafe-inline' — XSS risk")
    if "unsafe-eval" in csp_value:
        issues.append("CSP allows 'unsafe-eval' — code injection risk")
    if "*" in csp_value:
        issues.append("CSP contains wildcard (*) — too permissive")
    if "default-src" not in csp_value:
        issues.append("CSP missing default-src directive")
    return issues

def analyze_cors(target):
    findings = []
    try:
        r = requests.get(target, timeout=TIMEOUT, headers={
            **HEADERS_UA, "Origin": "https://evil.com"
        })
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            findings.append({"sev": "medium", "msg": "CORS allows all origins (*)"})
        elif acao == "https://evil.com":
            findings.append({"sev": "high", "msg": "CORS reflects arbitrary Origin — misconfigured"})
        if acac.lower() == "true" and acao == "*":
            findings.append({"sev": "critical", "msg": "CORS: Allow-Credentials + wildcard origin — critical misconfiguration"})
        return {"value": acao, "credentials": acac, "findings": findings}
    except Exception:
        return {"value": "", "credentials": "", "findings": []}

def analyze_cookies(cookies):
    results = []
    for c in cookies:
        issues = []
        if not c.secure:
            issues.append("Missing Secure flag")
        if not c.has_nonstandard_attr("HttpOnly"):
            issues.append("Missing HttpOnly flag")
        samesite = c.get_nonstandard_attr("SameSite") or ""
        if not samesite:
            issues.append("Missing SameSite attribute")
        elif samesite.lower() == "none" and not c.secure:
            issues.append("SameSite=None without Secure flag")
        results.append({
            "name": c.name,
            "secure": c.secure,
            "httponly": c.has_nonstandard_attr("HttpOnly"),
            "samesite": samesite,
            "issues": issues
        })
    return results

def analyze_http(target):
    try:
        r = requests.get(target, timeout=TIMEOUT, headers=HEADERS_UA, allow_redirects=True)
        resp_headers = r.headers

        headers_result = {}
        missing_high = 0
        missing_medium = 0
        missing_low = 0

        for hname, meta in SECURITY_HEADERS.items():
            val = resp_headers.get(hname)
            headers_result[hname] = {
                "present": val is not None,
                "value": val,
                "severity": meta["severity"],
                "desc": meta["desc"],
                "recommendation": meta["recommendation"]
            }
            if val is None:
                if meta["severity"] == "high": missing_high += 1
                elif meta["severity"] == "medium": missing_medium += 1
                else: missing_low += 1

        missing_headers_count = missing_high + missing_medium + missing_low

        # CSP analysis
        csp = resp_headers.get("Content-Security-Policy", "")
        csp_issues = analyze_csp(csp)

        # CORS analysis
        cors = analyze_cors(target)

        # Cookie analysis
        try:
            cookie_analysis = analyze_cookies(r.cookies)
        except Exception:
            cookie_analysis = []

        # Dangerous methods
        dangerous_methods = []
        try:
            for method in ["PUT", "DELETE", "TRACE", "OPTIONS"]:
                mr = requests.request(method, target, timeout=5, headers=HEADERS_UA)
                if mr.status_code < 400 and mr.status_code != 405:
                    dangerous_methods.append(method)
        except Exception:
            pass

        # Caching headers
        cache_control = resp_headers.get("Cache-Control", "")
        pragma = resp_headers.get("Pragma", "")
        cache_issues = []
        if "private" not in cache_control.lower() and "no-store" not in cache_control.lower():
            cache_issues.append("Sensitive pages may be cached by proxies")

        # Compression
        content_encoding = resp_headers.get("Content-Encoding", "")

        # Redirect chain
        redirect_chain = [str(r.url) for r in r.history] if r.history else []

        # Information disclosure headers
        disclosure = {}
        for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            if resp_headers.get(h):
                disclosure[h] = resp_headers.get(h)

        # MIME sniffing
        mime_ok = resp_headers.get("X-Content-Type-Options", "").lower() == "nosniff"

        # Framing
        frame_opt = resp_headers.get("X-Frame-Options", "")
        csp_frame = "frame-ancestors" in csp.lower()

        return {
            "headers": headers_result,
            "missing_headers_count": missing_headers_count,
            "missing_high": missing_high,
            "missing_medium": missing_medium,
            "missing_low": missing_low,
            "csp": csp,
            "csp_issues": csp_issues,
            "cors": cors,
            "cookies": cookie_analysis,
            "dangerous_methods": dangerous_methods,
            "cache_control": cache_control,
            "cache_issues": cache_issues,
            "content_encoding": content_encoding,
            "redirect_chain": redirect_chain,
            "disclosure_headers": disclosure,
            "mime_sniffing_protected": mime_ok,
            "framing_protected": bool(frame_opt or csp_frame),
            "status_code": r.status_code
        }

    except Exception as e:
        return {"error": str(e), "headers": {}, "missing_headers_count": 0,
                "csp_issues": [], "cors": {}, "cookies": [], "dangerous_methods": []}
