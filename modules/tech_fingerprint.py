import requests
import re

HEADERS = {"User-Agent": "SecureScan/2.0"}
TIMEOUT = 8

TECH_SIGNATURES = [
    # CMS
    {"name": "WordPress", "category": "CMS", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"wordpress"},
        {"type": "body", "regex": r'wp-content|wp-includes|wordpress'},
        {"type": "body", "regex": r'"WordPress"'},
    ]},
    {"name": "Drupal", "category": "CMS", "patterns": [
        {"type": "header", "key": "x-generator", "regex": r"drupal"},
        {"type": "body", "regex": r"Drupal\.settings|drupal\.js|/sites/default/files"},
    ]},
    {"name": "Joomla", "category": "CMS", "patterns": [
        {"type": "body", "regex": r"/media/jui/|Joomla!|joomla"},
        {"type": "header", "key": "x-content-encoded-by", "regex": r"joomla"},
    ]},
    {"name": "Magento", "category": "CMS", "patterns": [
        {"type": "body", "regex": r"Mage\.|/skin/frontend/|magento"},
    ]},
    {"name": "Shopify", "category": "CMS", "patterns": [
        {"type": "body", "regex": r"cdn\.shopify\.com|Shopify\.theme"},
    ]},

    # Frameworks
    {"name": "Laravel", "category": "Framework", "patterns": [
        {"type": "cookie", "regex": r"laravel_session|XSRF-TOKEN"},
        {"type": "header", "key": "x-powered-by", "regex": r"php"},
    ]},
    {"name": "Django", "category": "Framework", "patterns": [
        {"type": "header", "key": "x-frame-options", "regex": r"sameorigin"},
        {"type": "cookie", "regex": r"csrftoken|sessionid"},
    ]},
    {"name": "Rails", "category": "Framework", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"phusion|passenger"},
        {"type": "cookie", "regex": r"_session_id"},
    ]},
    {"name": "Express.js", "category": "Framework", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"express"},
    ]},
    {"name": "Next.js", "category": "Framework", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"next\.js"},
        {"type": "body", "regex": r"__NEXT_DATA__|/_next/"},
    ]},
    {"name": "React", "category": "JS Framework", "patterns": [
        {"type": "body", "regex": r"react\.production|__reactFiber|ReactDOM"},
    ]},
    {"name": "Vue.js", "category": "JS Framework", "patterns": [
        {"type": "body", "regex": r"vue\.min\.js|__vue__|Vue\.js"},
    ]},
    {"name": "Angular", "category": "JS Framework", "patterns": [
        {"type": "body", "regex": r"ng-version|angular\.js|ng-app"},
    ]},

    # Web Servers
    {"name": "Apache", "category": "Web Server", "patterns": [
        {"type": "header", "key": "server", "regex": r"apache"},
    ]},
    {"name": "Nginx", "category": "Web Server", "patterns": [
        {"type": "header", "key": "server", "regex": r"nginx"},
    ]},
    {"name": "IIS", "category": "Web Server", "patterns": [
        {"type": "header", "key": "server", "regex": r"iis|microsoft-iis"},
    ]},
    {"name": "Cloudflare", "category": "CDN/WAF", "patterns": [
        {"type": "header", "key": "server", "regex": r"cloudflare"},
        {"type": "header", "key": "cf-ray", "regex": r".*"},
    ]},
    {"name": "AWS CloudFront", "category": "CDN", "patterns": [
        {"type": "header", "key": "x-amz-cf-id", "regex": r".*"},
        {"type": "header", "key": "via", "regex": r"cloudfront"},
    ]},
    {"name": "Fastly", "category": "CDN", "patterns": [
        {"type": "header", "key": "x-served-by", "regex": r"cache"},
        {"type": "header", "key": "x-fastly-request-id", "regex": r".*"},
    ]},

    # Languages
    {"name": "PHP", "category": "Language", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"php"},
        {"type": "header", "key": "set-cookie", "regex": r"phpsessid"},
    ]},
    {"name": "ASP.NET", "category": "Language", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"asp\.net"},
        {"type": "header", "key": "x-aspnet-version", "regex": r".*"},
    ]},
    {"name": "Python", "category": "Language", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"python|flask|django|tornado"},
    ]},
    {"name": "Node.js", "category": "Language", "patterns": [
        {"type": "header", "key": "x-powered-by", "regex": r"node|express"},
    ]},

    # Analytics / Marketing
    {"name": "Google Analytics", "category": "Analytics", "patterns": [
        {"type": "body", "regex": r"google-analytics\.com/analytics\.js|gtag\(|UA-\d+"},
    ]},
    {"name": "Google Tag Manager", "category": "Analytics", "patterns": [
        {"type": "body", "regex": r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+"},
    ]},

    # Auth
    {"name": "Auth0", "category": "Auth Provider", "patterns": [
        {"type": "body", "regex": r"auth0\.com|auth0\.js"},
    ]},
    {"name": "Okta", "category": "Auth Provider", "patterns": [
        {"type": "body", "regex": r"okta\.com|okta-auth-js"},
    ]},

    # WAF
    {"name": "ModSecurity", "category": "WAF", "patterns": [
        {"type": "header", "key": "server", "regex": r"mod_security|modsecurity"},
    ]},
    {"name": "Sucuri WAF", "category": "WAF", "patterns": [
        {"type": "header", "key": "x-sucuri-id", "regex": r".*"},
    ]},
    {"name": "Akamai", "category": "CDN/WAF", "patterns": [
        {"type": "header", "key": "x-check-cacheable", "regex": r".*"},
        {"type": "header", "key": "x-akamai-transformed", "regex": r".*"},
    ]},

    # JS Libraries
    {"name": "jQuery", "category": "JS Library", "patterns": [
        {"type": "body", "regex": r"jquery\.min\.js|jquery-\d+\.\d+|jQuery v\d+"},
    ]},
    {"name": "Bootstrap", "category": "CSS Framework", "patterns": [
        {"type": "body", "regex": r"bootstrap\.min\.css|bootstrap\.min\.js"},
    ]},
    {"name": "Tailwind CSS", "category": "CSS Framework", "patterns": [
        {"type": "body", "regex": r"tailwindcss|tailwind\.css"},
    ]},
]

def fingerprint_tech(target):
    detected = []
    raw_headers = {}
    cookies_str = ""
    server_info = {}

    try:
        r = requests.get(target, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
        raw_headers = dict(r.headers)
        body = r.text[:50000]
        cookies_str = "; ".join([f"{c.name}={c.value}" for c in r.cookies])
        server_info = {
            "status_code": r.status_code,
            "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "content_type": r.headers.get("Content-Type", ""),
        }

        for tech in TECH_SIGNATURES:
            for pattern in tech["patterns"]:
                matched = False
                if pattern["type"] == "header":
                    val = r.headers.get(pattern["key"], "")
                    if re.search(pattern["regex"], val, re.I):
                        matched = True
                elif pattern["type"] == "body":
                    if re.search(pattern["regex"], body, re.I):
                        matched = True
                elif pattern["type"] == "cookie":
                    if re.search(pattern["regex"], cookies_str, re.I):
                        matched = True
                if matched:
                    if not any(d["name"] == tech["name"] for d in detected):
                        detected.append({"name": tech["name"], "category": tech["category"]})
                    break

        # Version detection
        versions = {}
        wp_ver = re.search(r'wordpress[^"\']*?(\d+\.\d+[\.\d]*)', body, re.I)
        if wp_ver:
            versions["WordPress"] = wp_ver.group(1)
        jq_ver = re.search(r'jquery[^\'"]*?v?(\d+\.\d+[\.\d]*)', body, re.I)
        if jq_ver:
            versions["jQuery"] = jq_ver.group(1)
        bs_ver = re.search(r'bootstrap[^\'"]*?v?(\d+\.\d+[\.\d]*)', body, re.I)
        if bs_ver:
            versions["Bootstrap"] = bs_ver.group(1)

    except Exception as e:
        return {"detected": [], "error": str(e), "server_info": {}, "versions": {}}

    by_category = {}
    for d in detected:
        by_category.setdefault(d["category"], []).append(d["name"])

    return {
        "detected": detected,
        "by_category": by_category,
        "versions": versions,
        "server_info": server_info,
        "headers_snapshot": {k: v for k, v in raw_headers.items() if k.lower() in [
            "server","x-powered-by","x-generator","via","x-cache","cf-ray"
        ]}
    }
