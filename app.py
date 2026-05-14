import uuid
import threading
import datetime
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "securescan-pro-2024"

# In-memory scan storage
scans = {}
targets_db = []

def run_full_scan(scan_id, target, options):
    from modules.crawler import crawl_target
    from modules.tech_fingerprint import fingerprint_tech
    from modules.port_scanner import scan_ports
    from modules.ssl_checker import check_ssl
    from modules.http_analyzer import analyze_http
    from modules.dns_security import check_dns
    from modules.file_discovery import discover_files
    from modules.js_analyzer import analyze_js
    from modules.sensitive_discovery import find_sensitive_info
    from modules.subdomain_enum import enumerate_subdomains
    from modules.cloud_checker import check_cloud
    from modules.owasp_scanner import run_owasp_scan

    scans[scan_id]["status"] = "running"
    scans[scan_id]["started_at"] = datetime.datetime.utcnow().isoformat()

    def update(step, pct, msg):
        scans[scan_id]["step"] = step
        scans[scan_id]["progress"] = pct
        scans[scan_id]["logs"].append({"time": datetime.datetime.utcnow().strftime("%H:%M:%S"), "msg": msg})

    try:
        update("crawling", 5, f"Starting crawler on {target}")
        crawl = crawl_target(target)
        scans[scan_id]["results"]["crawl"] = crawl
        update("crawling", 12, f"Crawled {crawl.get('pages_found', 0)} pages, {crawl.get('forms_found', 0)} forms")

        update("fingerprint", 15, "Running technology fingerprinting")
        tech = fingerprint_tech(target)
        scans[scan_id]["results"]["tech"] = tech
        update("fingerprint", 20, f"Detected {len(tech.get('detected', []))} technologies")

        update("ports", 22, "Scanning open ports and grabbing banners")
        ports = scan_ports(target)
        scans[scan_id]["results"]["ports"] = ports
        update("ports", 30, f"Found {len(ports.get('open_ports', []))} open ports")

        update("ssl", 32, "Analyzing SSL/TLS configuration")
        ssl = check_ssl(target)
        scans[scan_id]["results"]["ssl"] = ssl
        update("ssl", 38, "SSL analysis complete")

        update("http", 40, "Analyzing HTTP security headers and cookies")
        http = analyze_http(target)
        scans[scan_id]["results"]["http"] = http
        update("http", 46, f"HTTP analysis done — {http.get('missing_headers_count', 0)} missing headers")

        update("dns", 48, "Checking DNS security records (SPF, DKIM, DMARC)")
        dns = check_dns(target)
        scans[scan_id]["results"]["dns"] = dns
        update("dns", 54, "DNS security check complete")

        update("files", 55, "Discovering exposed files and backups")
        files = discover_files(target)
        scans[scan_id]["results"]["files"] = files
        update("files", 61, f"Found {len(files.get('found', []))} exposed files")

        update("js", 62, "Analyzing JavaScript files for secrets and endpoints")
        js = analyze_js(target, crawl.get("js_files", []))
        scans[scan_id]["results"]["js"] = js
        update("js", 67, f"JS analysis: {len(js.get('endpoints', []))} endpoints, {len(js.get('secrets', []))} potential secrets")

        update("sensitive", 68, "Scanning for sensitive information exposure")
        sensitive = find_sensitive_info(target)
        scans[scan_id]["results"]["sensitive"] = sensitive
        update("sensitive", 73, f"Sensitive scan: {len(sensitive.get('found', []))} findings")

        update("subdomains", 74, "Enumerating subdomains")
        subdomains = enumerate_subdomains(target)
        scans[scan_id]["results"]["subdomains"] = subdomains
        update("subdomains", 79, f"Found {len(subdomains.get('found', []))} subdomains")

        update("cloud", 80, "Checking cloud storage and metadata exposure")
        cloud = check_cloud(target)
        scans[scan_id]["results"]["cloud"] = cloud
        update("cloud", 85, "Cloud security check complete")

        update("owasp", 86, "Running OWASP Top 10 vulnerability checks")
        owasp = run_owasp_scan(target, crawl)
        scans[scan_id]["results"]["owasp"] = owasp
        update("owasp", 96, f"OWASP scan: {owasp.get('total_issues', 0)} issues found")

        # Calculate score
        scans[scan_id]["results"]["score"] = calculate_score(scans[scan_id]["results"])
        scans[scan_id]["status"] = "complete"
        scans[scan_id]["completed_at"] = datetime.datetime.utcnow().isoformat()
        update("complete", 100, "Scan complete!")

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        update("error", 0, f"Scan error: {str(e)}")


def calculate_score(results):
    score = 100
    findings = []

    # SSL
    ssl = results.get("ssl", {})
    if ssl.get("error"):
        score -= 20; findings.append({"sev": "high", "msg": "SSL/TLS not available or error"})
    elif ssl.get("expired"):
        score -= 15; findings.append({"sev": "high", "msg": "SSL certificate expired"})
    elif ssl.get("weak_protocol"):
        score -= 10; findings.append({"sev": "medium", "msg": f"Weak TLS protocol: {ssl.get('protocol')}"})

    # Headers
    http = results.get("http", {})
    mc = http.get("missing_headers_count", 0)
    score -= min(mc * 4, 20)
    if mc > 0:
        findings.append({"sev": "medium", "msg": f"{mc} security headers missing"})

    # Ports
    ports = results.get("ports", {})
    risky = [p for p in ports.get("open_ports", []) if p.get("risky")]
    score -= min(len(risky) * 5, 20)
    if risky:
        findings.append({"sev": "medium", "msg": f"{len(risky)} risky port(s) open"})

    # OWASP
    owasp = results.get("owasp", {})
    score -= min(owasp.get("critical_count", 0) * 15, 30)
    score -= min(owasp.get("high_count", 0) * 8, 20)
    score -= min(owasp.get("medium_count", 0) * 3, 10)
    for f in owasp.get("findings", [])[:5]:
        findings.append({"sev": f.get("severity", "info"), "msg": f.get("title", "")})

    # Files
    exposed = results.get("files", {}).get("found", [])
    if exposed:
        score -= min(len(exposed) * 5, 15)
        findings.append({"sev": "high", "msg": f"{len(exposed)} sensitive file(s) exposed"})

    # Sensitive info
    sens = results.get("sensitive", {}).get("found", [])
    if sens:
        score -= min(len(sens) * 5, 15)
        findings.append({"sev": "critical", "msg": f"{len(sens)} sensitive data item(s) found"})

    # DNS
    dns = results.get("dns", {})
    if not dns.get("spf"): score -= 3; findings.append({"sev": "low", "msg": "Missing SPF record"})
    if not dns.get("dmarc"): score -= 3; findings.append({"sev": "low", "msg": "Missing DMARC record"})

    score = max(0, min(100, score))
    if score >= 85: grade, gc = "A", "grade-a"
    elif score >= 70: grade, gc = "B", "grade-b"
    elif score >= 50: grade, gc = "C", "grade-c"
    elif score >= 30: grade, gc = "D", "grade-d"
    else: grade, gc = "F", "grade-f"

    critical = sum(1 for f in findings if f["sev"] == "critical")
    high = sum(1 for f in findings if f["sev"] == "high")
    medium = sum(1 for f in findings if f["sev"] == "medium")
    low = sum(1 for f in findings if f["sev"] == "low")

    return {"score": score, "grade": grade, "grade_class": gc,
            "findings": findings, "critical": critical, "high": high,
            "medium": medium, "low": low}


@app.route("/")
def index():
    total = len(scans)
    complete = sum(1 for s in scans.values() if s["status"] == "complete")
    recent = sorted([s for s in scans.values() if s["status"] == "complete"],
                    key=lambda x: x.get("completed_at", ""), reverse=True)[:5]
    return render_template("index.html", total_scans=total, complete_scans=complete, recent=recent)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target.startswith("http"):
            target = "https://" + target
        scan_id = str(uuid.uuid4())[:8]
        scans[scan_id] = {
            "id": scan_id, "target": target, "status": "queued",
            "progress": 0, "step": "queued", "logs": [],
            "results": {}, "created_at": datetime.datetime.utcnow().isoformat()
        }
        t = threading.Thread(target=run_full_scan, args=(scan_id, target, {}), daemon=True)
        t.start()
        return redirect(url_for("results", scan_id=scan_id))
    return render_template("scan.html")


@app.route("/results/<scan_id>")
def results(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return redirect(url_for("index"))
    return render_template("results.html", scan=scan)


@app.route("/api/status/<scan_id>")
def api_status(scan_id):
    scan = scans.get(scan_id, {})
    return jsonify({
        "status": scan.get("status", "not_found"),
        "progress": scan.get("progress", 0),
        "step": scan.get("step", ""),
        "logs": scan.get("logs", [])[-20:],
        "results": scan.get("results", {}) if scan.get("status") == "complete" else {}
    })


@app.route("/history")
def history():
    all_scans = sorted(scans.values(), key=lambda x: x.get("created_at", ""), reverse=True)
    return render_template("history.html", scans=all_scans)


@app.route("/targets", methods=["GET", "POST"])
def targets():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            targets_db.append({
                "id": str(uuid.uuid4())[:8],
                "url": request.form.get("url", ""),
                "name": request.form.get("name", ""),
                "tags": request.form.get("tags", ""),
                "notes": request.form.get("notes", ""),
                "added": datetime.datetime.utcnow().strftime("%Y-%m-%d")
            })
        elif action == "delete":
            tid = request.form.get("id")
            targets_db[:] = [t for t in targets_db if t["id"] != tid]
        return redirect(url_for("targets"))
    return render_template("targets.html", targets=targets_db)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/api/export/<scan_id>/<fmt>")
def export(scan_id, fmt):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    if fmt == "json":
        return jsonify(scan), 200, {
            "Content-Disposition": f"attachment; filename=scan_{scan_id}.json"
        }
    return jsonify({"error": "format not supported"}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
