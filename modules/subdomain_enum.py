import socket
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

TIMEOUT = 4
HEADERS = {"User-Agent": "SecureScan/2.0"}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "api", "dev", "staging",
    "test", "beta", "admin", "portal", "vpn", "remote", "secure", "blog",
    "shop", "store", "forum", "wiki", "help", "support", "docs", "cdn",
    "static", "assets", "media", "img", "images", "video", "upload",
    "auth", "login", "sso", "oauth", "dashboard", "app", "apps",
    "mobile", "m", "wap", "git", "gitlab", "github", "jira", "confluence",
    "jenkins", "ci", "cd", "build", "prod", "production", "live",
    "old", "new", "demo", "preview", "uat", "qa", "internal",
    "intranet", "extranet", "data", "db", "database", "mysql", "postgres",
    "redis", "mongo", "elastic", "kibana", "grafana", "monitor",
    "status", "health", "metrics", "logs", "backup", "archive",
    "smtp", "imap", "pop3", "mail2", "email", "news", "rss",
    "download", "downloads", "software", "update", "updates",
    "report", "reports", "analytics", "stats", "tracking",
    "payment", "billing", "invoice", "account", "accounts",
    "search", "map", "maps", "chat", "msg", "message",
    "dev2", "test2", "stage", "preprod", "sandbox"
]

TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", ["There isn't a GitHub Pages site here", "404 There is no GitHub Pages site"]),
    ("AWS S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Azure", ["404 Web Site not found", "microsoft azure"]),
    ("Heroku", ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    ("Shopify", ["Sorry, this shop is currently unavailable"]),
    ("Fastly", ["Fastly error: unknown domain"]),
    ("Ghost", ["The thing you were looking for is no longer here"]),
    ("Pantheon", ["The gods are wise", "pantheonsite.io"]),
    ("Squarespace", ["This domain is not connected to a website yet"]),
    ("Tumblr", ["Whatever you were looking for doesn't currently exist"]),
]

def check_subdomain(subdomain, root_domain):
    fqdn = f"{subdomain}.{root_domain}"
    try:
        ip = socket.gethostbyname(fqdn)

        result = {"subdomain": fqdn, "ip": ip, "status": "active", "takeover_risk": None}

        # Check for takeover
        try:
            r = requests.get(f"https://{fqdn}", timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
            body = r.text.lower()
            for vendor, fingerprints in TAKEOVER_FINGERPRINTS:
                if any(fp.lower() in body for fp in fingerprints):
                    result["takeover_risk"] = vendor
                    break
            result["http_status"] = r.status_code
        except requests.exceptions.SSLError:
            result["http_status"] = "SSL_ERROR"
        except Exception:
            try:
                r = requests.get(f"http://{fqdn}", timeout=TIMEOUT, headers=HEADERS)
                result["http_status"] = r.status_code
            except Exception:
                result["http_status"] = "UNREACHABLE"

        return result
    except socket.gaierror:
        return None
    except Exception:
        return None

def get_cert_transparency(domain):
    subdomains = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10, headers=HEADERS
        )
        if r.ok:
            data = r.json()
            for entry in data[:200]:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(domain) and line != domain:
                        sub = line.replace(f".{domain}", "")
                        if sub and "." not in sub:
                            subdomains.add(sub)
    except Exception:
        pass
    return subdomains

def enumerate_subdomains(target):
    parsed = urlparse(target)
    domain = parsed.hostname or target.replace("https://","").replace("http://","").split("/")[0]
    root_domain = ".".join(domain.split(".")[-2:])

    # Collect candidates
    candidates = set(COMMON_SUBDOMAINS)

    # Add from cert transparency
    ct_subs = get_cert_transparency(root_domain)
    candidates.update(ct_subs)

    found = []
    takeover_risks = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(check_subdomain, sub, root_domain): sub for sub in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                if result.get("takeover_risk"):
                    takeover_risks.append(result)

    found.sort(key=lambda x: x["subdomain"])

    findings = []
    if takeover_risks:
        for t in takeover_risks:
            findings.append({"sev": "high", "msg": f"Subdomain takeover risk: {t['subdomain']} ({t['takeover_risk']})"})

    # Interesting subdomains
    interesting_keywords = ["admin", "api", "internal", "dev", "staging", "test", "vpn", "git", "jenkins", "backup", "db"]
    interesting = [f for f in found if any(kw in f["subdomain"] for kw in interesting_keywords)]
    if interesting:
        findings.append({"sev": "medium", "msg": f"{len(interesting)} sensitive subdomain(s) discovered (dev/admin/api)"})

    return {
        "root_domain": root_domain,
        "found": found,
        "total": len(found),
        "takeover_risks": takeover_risks,
        "interesting": interesting,
        "ct_discovered": len(ct_subs),
        "brute_discovered": len(found) - len(ct_subs),
        "findings": findings
    }
