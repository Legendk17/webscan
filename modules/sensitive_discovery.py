import requests
import re
from urllib.parse import urljoin, urlparse

TIMEOUT = 8
HEADERS = {"User-Agent": "SecureScan/2.0"}

SENSITIVE_PATTERNS = [
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "regex": r"(?i)aws_secret_access_key[^\n]{0,30}", "severity": "critical"},
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"name": "Stripe Key", "regex": r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24}", "severity": "critical"},
    {"name": "GitHub Token", "regex": r"ghp_[A-Za-z0-9]{36}", "severity": "critical"},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "severity": "high"},
    {"name": "Private Key Header", "regex": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Firebase Config", "regex": r"apiKey:\s*['\"][A-Za-z0-9\-_]{20,}['\"]", "severity": "high"},
    {"name": "MongoDB URI", "regex": r"mongodb(\+srv)?://[^<>\s]{10,}", "severity": "critical"},
    {"name": "Database URL", "regex": r"(postgres|mysql|redis)://[^<>\s]{10,}", "severity": "critical"},
    {"name": "Email Address", "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "severity": "info"},
    {"name": "Phone Number", "regex": r"\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "severity": "info"},
    {"name": "Internal IP", "regex": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "severity": "medium"},
    {"name": "AWS ARN", "regex": r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:", "severity": "medium"},
    {"name": "Hardcoded Password", "regex": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"<>\s]{6,}['\"]", "severity": "high"},
    {"name": "SSH Key Fingerprint", "regex": r"[A-Za-z0-9+/]{43}=\s+[a-zA-Z0-9@.\-]+", "severity": "medium"},
    {"name": "Credit Card (Visa)", "regex": r"\b4[0-9]{12}(?:[0-9]{3})?\b", "severity": "critical"},
    {"name": "Credit Card (MC)", "regex": r"\b5[1-5][0-9]{14}\b", "severity": "critical"},
    {"name": "Social Security Number", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "severity": "critical"},
    {"name": "API Endpoint Disclosure", "regex": r"['\"/](api|v\d|graphql|rest)/[a-zA-Z0-9/_\-]{5,50}", "severity": "low"},
    {"name": "Stack Trace", "regex": r"(Traceback \(most recent call|at \w+\([\w./]+:\d+\)|\bException\b.*?at\s+[\w.]+)", "severity": "medium"},
    {"name": "SQL Error", "regex": r"(SQL syntax|mysql_fetch|pg_query|ORA-\d+|SQLSTATE)", "severity": "high"},
    {"name": "PHP Error", "regex": r"(Fatal error|Warning:|Notice:) .{0,100} on line \d+", "severity": "high"},
    {"name": "WordPress Debug", "regex": r"WP_DEBUG|wordpress_logged_in|wp_nonce", "severity": "low"},
    {"name": "Cloud Storage URL", "regex": r"s3\.amazonaws\.com/[^\s<>\"']{5,}", "severity": "medium"},
    {"name": "Firebase URL", "regex": r"[a-z0-9\-]+\.firebaseio\.com", "severity": "medium"},
]

def mask_match(match):
    if len(match) <= 8:
        return match[:2] + "***"
    return match[:6] + "..." + match[-4:]

def scan_page(url, session):
    findings = []
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        content = r.text
        seen = set()
        for pat in SENSITIVE_PATTERNS:
            matches = re.findall(pat["regex"], content, re.I | re.M)
            for m in matches[:3]:
                match_str = m if isinstance(m, str) else " ".join(m)
                key = (pat["name"], match_str[:20])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "type": pat["name"],
                        "severity": pat["severity"],
                        "value": mask_match(match_str),
                        "source_url": url
                    })
    except Exception:
        pass
    return findings

def find_sensitive_info(target):
    found = []
    pages_to_scan = [target]

    # Also scan common error pages
    for path in ["/nonexistent-page-xyz", "/error", "/?debug=1", "/?test=1"]:
        pages_to_scan.append(target.rstrip("/") + path)

    with requests.Session() as session:
        session.headers.update(HEADERS)
        for url in pages_to_scan[:5]:
            findings = scan_page(url, session)
            found.extend(findings)

    # Deduplicate
    seen = set()
    unique = []
    for f in found:
        key = (f["type"], f["value"][:15])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda x: sev_order.get(x["severity"], 5))

    by_severity = {}
    for f in unique:
        by_severity.setdefault(f["severity"], []).append(f)

    critical_types = [f for f in unique if f["severity"] in ("critical", "high")]

    findings_summary = []
    if critical_types:
        findings_summary.append({"sev": "critical", "msg": f"{len(critical_types)} high/critical sensitive data items exposed"})
    errors = [f for f in unique if f["type"] in ("Stack Trace", "SQL Error", "PHP Error")]
    if errors:
        findings_summary.append({"sev": "high", "msg": f"Server error details exposed ({len(errors)} instances)"})

    return {
        "found": unique,
        "by_severity": by_severity,
        "critical_count": sum(1 for f in unique if f["severity"] == "critical"),
        "high_count": sum(1 for f in unique if f["severity"] == "high"),
        "findings": findings_summary
    }
