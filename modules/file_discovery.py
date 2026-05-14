import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 6
HEADERS = {"User-Agent": "SecureScan/2.0"}

SENSITIVE_PATHS = [
    # Environment & Config
    {"path": "/.env", "severity": "critical", "category": "Environment"},
    {"path": "/.env.local", "severity": "critical", "category": "Environment"},
    {"path": "/.env.production", "severity": "critical", "category": "Environment"},
    {"path": "/.env.backup", "severity": "critical", "category": "Environment"},
    {"path": "/config.php", "severity": "high", "category": "Config"},
    {"path": "/configuration.php", "severity": "high", "category": "Config"},
    {"path": "/config.yml", "severity": "high", "category": "Config"},
    {"path": "/config.yaml", "severity": "high", "category": "Config"},
    {"path": "/config.json", "severity": "high", "category": "Config"},
    {"path": "/settings.py", "severity": "high", "category": "Config"},
    {"path": "/application.properties", "severity": "high", "category": "Config"},
    {"path": "/web.config", "severity": "high", "category": "Config"},
    {"path": "/appsettings.json", "severity": "high", "category": "Config"},

    # Git & VCS
    {"path": "/.git/HEAD", "severity": "critical", "category": "VCS"},
    {"path": "/.git/config", "severity": "critical", "category": "VCS"},
    {"path": "/.gitignore", "severity": "medium", "category": "VCS"},
    {"path": "/.svn/entries", "severity": "high", "category": "VCS"},
    {"path": "/.hg/hgrc", "severity": "high", "category": "VCS"},

    # Database & Backups
    {"path": "/backup.zip", "severity": "critical", "category": "Backup"},
    {"path": "/backup.tar.gz", "severity": "critical", "category": "Backup"},
    {"path": "/backup.sql", "severity": "critical", "category": "Backup"},
    {"path": "/db.sql", "severity": "critical", "category": "Backup"},
    {"path": "/database.sql", "severity": "critical", "category": "Backup"},
    {"path": "/dump.sql", "severity": "critical", "category": "Backup"},
    {"path": "/data.sql", "severity": "critical", "category": "Backup"},
    {"path": "/site.zip", "severity": "critical", "category": "Backup"},
    {"path": "/www.zip", "severity": "critical", "category": "Backup"},
    {"path": "/public.zip", "severity": "critical", "category": "Backup"},
    {"path": "/htdocs.zip", "severity": "critical", "category": "Backup"},

    # PHP Info & Debug
    {"path": "/phpinfo.php", "severity": "high", "category": "Debug"},
    {"path": "/info.php", "severity": "high", "category": "Debug"},
    {"path": "/test.php", "severity": "medium", "category": "Debug"},
    {"path": "/debug.php", "severity": "high", "category": "Debug"},
    {"path": "/_profiler", "severity": "medium", "category": "Debug"},
    {"path": "/adminer.php", "severity": "critical", "category": "Admin"},
    {"path": "/phpmyadmin", "severity": "critical", "category": "Admin"},
    {"path": "/phpmyadmin/", "severity": "critical", "category": "Admin"},
    {"path": "/pma", "severity": "critical", "category": "Admin"},
    {"path": "/myadmin", "severity": "critical", "category": "Admin"},

    # Admin Panels
    {"path": "/admin", "severity": "medium", "category": "Admin"},
    {"path": "/admin/", "severity": "medium", "category": "Admin"},
    {"path": "/administrator", "severity": "medium", "category": "Admin"},
    {"path": "/wp-admin", "severity": "medium", "category": "Admin"},
    {"path": "/wp-login.php", "severity": "medium", "category": "Admin"},
    {"path": "/cp", "severity": "medium", "category": "Admin"},
    {"path": "/controlpanel", "severity": "medium", "category": "Admin"},

    # Logs
    {"path": "/error.log", "severity": "high", "category": "Logs"},
    {"path": "/error_log", "severity": "high", "category": "Logs"},
    {"path": "/access.log", "severity": "high", "category": "Logs"},
    {"path": "/debug.log", "severity": "high", "category": "Logs"},
    {"path": "/application.log", "severity": "high", "category": "Logs"},
    {"path": "/laravel.log", "severity": "high", "category": "Logs"},
    {"path": "/storage/logs/laravel.log", "severity": "high", "category": "Logs"},

    # Editor Backups
    {"path": "/index.php~", "severity": "medium", "category": "Editor Backup"},
    {"path": "/index.php.bak", "severity": "medium", "category": "Editor Backup"},
    {"path": "/config.php.bak", "severity": "high", "category": "Editor Backup"},
    {"path": "/config.php~", "severity": "high", "category": "Editor Backup"},
    {"path": "/wp-config.php.bak", "severity": "critical", "category": "Editor Backup"},
    {"path": "/.DS_Store", "severity": "low", "category": "Editor Backup"},

    # API Keys / Credentials
    {"path": "/credentials.json", "severity": "critical", "category": "Credentials"},
    {"path": "/serviceaccount.json", "severity": "critical", "category": "Credentials"},
    {"path": "/firebase.json", "severity": "high", "category": "Credentials"},
    {"path": "/google-services.json", "severity": "high", "category": "Credentials"},

    # CI/CD
    {"path": "/.travis.yml", "severity": "medium", "category": "CI/CD"},
    {"path": "/.circleci/config.yml", "severity": "medium", "category": "CI/CD"},
    {"path": "/.github/workflows", "severity": "medium", "category": "CI/CD"},
    {"path": "/Jenkinsfile", "severity": "medium", "category": "CI/CD"},

    # Package files
    {"path": "/package.json", "severity": "low", "category": "Package"},
    {"path": "/composer.json", "severity": "low", "category": "Package"},
    {"path": "/requirements.txt", "severity": "low", "category": "Package"},
    {"path": "/Gemfile", "severity": "low", "category": "Package"},

    # Misc
    {"path": "/server-status", "severity": "medium", "category": "Server Info"},
    {"path": "/server-info", "severity": "medium", "category": "Server Info"},
    {"path": "/_cat/indices", "severity": "high", "category": "Elasticsearch"},
    {"path": "/_nodes", "severity": "high", "category": "Elasticsearch"},
]

SENSITIVE_CONTENT = [
    r"password\s*=\s*['\"]?[^\s'\"]{4,}",
    r"secret\s*=\s*['\"]?[^\s'\"]{4,}",
    r"api[_-]?key\s*=\s*['\"]?[^\s'\"]{8,}",
    r"DB_PASSWORD",
    r"mysql_connect",
    r"phpMyAdmin",
    r"\$_POST\[",
    r"AKIA[0-9A-Z]{16}",
]

def check_path(base_url, item, session):
    url = base_url.rstrip("/") + item["path"]
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
        if r.status_code in (200, 206, 301, 302) and r.status_code != 404:
            size = len(r.content)
            preview = r.text[:300].replace("\n", " ").strip() if r.text else ""
            # Check if it's actually a real file (not just a 200 redirect to homepage)
            is_real = size > 10 and not (
                r.status_code in (301, 302) and "login" in r.headers.get("Location", "")
            )
            if is_real:
                import re
                has_sensitive_content = any(
                    re.search(p, r.text, re.I) for p in SENSITIVE_CONTENT
                )
                return {
                    "url": url,
                    "path": item["path"],
                    "status": r.status_code,
                    "size": size,
                    "severity": "critical" if has_sensitive_content else item["severity"],
                    "category": item["category"],
                    "preview": preview[:200],
                    "has_sensitive_content": has_sensitive_content
                }
    except Exception:
        pass
    return None

def discover_files(target):
    base_url = target.rstrip("/")
    found = []
    checked = 0

    with requests.Session() as session:
        session.headers.update(HEADERS)
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(check_path, base_url, item, session): item
                       for item in SENSITIVE_PATHS}
            for future in as_completed(futures):
                checked += 1
                result = future.result()
                if result:
                    found.append(result)

    found.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

    by_category = {}
    for f in found:
        by_category.setdefault(f["category"], []).append(f)

    return {
        "found": found,
        "checked": checked,
        "by_category": by_category,
        "critical_count": sum(1 for f in found if f["severity"] == "critical"),
        "high_count": sum(1 for f in found if f["severity"] == "high"),
    }
