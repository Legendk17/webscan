import requests
import re
import socket
from urllib.parse import urlparse

TIMEOUT = 6
HEADERS = {"User-Agent": "SecureScan/2.0"}

def check_s3(domain):
    findings = []
    # Try common S3 bucket patterns
    bucket_names = [
        domain.replace(".", "-"),
        domain.split(".")[0],
        domain.replace("www.", ""),
    ]
    for name in bucket_names:
        for url in [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]:
            try:
                r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
                if r.status_code == 200:
                    findings.append({"type": "AWS S3", "url": url, "severity": "critical",
                                     "detail": "Public S3 bucket accessible", "status": r.status_code})
                elif r.status_code == 403:
                    findings.append({"type": "AWS S3", "url": url, "severity": "medium",
                                     "detail": "S3 bucket exists but access denied (bucket name exposed)", "status": r.status_code})
            except Exception:
                pass
    return findings

def check_firebase(domain):
    findings = []
    name = domain.split(".")[0].replace("www", "").strip("-")
    for suffix in ["", "-prod", "-dev", "-staging", "-app"]:
        url = f"https://{name}{suffix}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code == 200:
                data = r.text[:200]
                if data and data != "null":
                    findings.append({"type": "Firebase", "url": url, "severity": "critical",
                                     "detail": "Firebase database publicly readable", "status": 200})
            elif r.status_code == 401:
                findings.append({"type": "Firebase", "url": url, "severity": "low",
                                 "detail": "Firebase database exists but requires auth", "status": 401})
        except Exception:
            pass
    return findings

def check_azure(domain):
    findings = []
    name = domain.split(".")[0]
    azure_urls = [
        f"https://{name}.blob.core.windows.net",
        f"https://{name}.azurewebsites.net",
        f"https://{name}.azurecontainer.io",
    ]
    for url in azure_urls:
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code in (200, 403, 400):
                detail = "Azure Blob storage accessible" if r.status_code == 200 else "Azure resource exists"
                sev = "high" if r.status_code == 200 else "low"
                findings.append({"type": "Azure", "url": url, "severity": sev,
                                 "detail": detail, "status": r.status_code})
        except Exception:
            pass
    return findings

def check_gcp(domain):
    findings = []
    name = domain.split(".")[0]
    gcp_urls = [
        f"https://storage.googleapis.com/{name}",
        f"https://{name}.storage.googleapis.com",
    ]
    for url in gcp_urls:
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code == 200:
                findings.append({"type": "GCP Storage", "url": url, "severity": "critical",
                                 "detail": "GCP storage bucket publicly accessible", "status": 200})
            elif r.status_code == 403:
                findings.append({"type": "GCP Storage", "url": url, "severity": "medium",
                                 "detail": "GCP bucket exists but access denied", "status": 403})
        except Exception:
            pass
    return findings

def check_cloud_metadata(target):
    metadata_paths = [
        ("/latest/meta-data/", "AWS EC2 Metadata"),
        ("/computeMetadata/v1/", "GCP Metadata"),
        ("/metadata/instance", "Azure IMDS"),
        ("/opc/v1/instance/", "Oracle Cloud Metadata"),
    ]
    # These are SSRF indicators — we check if the server reflects metadata-like content
    findings = []
    for path, service in metadata_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code == 200 and any(kw in r.text.lower() for kw in
                ["ami-id", "instance-id", "local-ipv4", "iam", "project-id"]):
                findings.append({"type": service, "url": url, "severity": "critical",
                                 "detail": f"Cloud metadata endpoint accessible via: {path}"})
        except Exception:
            pass
    return findings

def check_elasticsearch(target):
    parsed = urlparse(target)
    host = parsed.hostname
    findings = []
    for port in [9200, 9300]:
        url = f"http://{host}:{port}/_cat/indices?v"
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code == 200 and ("green" in r.text or "yellow" in r.text or "index" in r.text):
                findings.append({"type": "Elasticsearch", "url": url, "severity": "critical",
                                 "detail": "Elasticsearch indices publicly accessible"})
        except Exception:
            pass
    return findings

def check_grafana(target):
    parsed = urlparse(target)
    host = parsed.hostname
    findings = []
    for port in [3000]:
        url = f"http://{host}:{port}/api/org"
        try:
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if r.status_code == 200 and "id" in r.text:
                findings.append({"type": "Grafana", "url": url, "severity": "high",
                                 "detail": "Grafana API accessible without authentication"})
        except Exception:
            pass
    return findings

def check_cloud(target):
    parsed = urlparse(target)
    domain = parsed.hostname or target.replace("https://","").replace("http://","").split("/")[0]

    all_findings = []
    all_findings.extend(check_s3(domain))
    all_findings.extend(check_firebase(domain))
    all_findings.extend(check_azure(domain))
    all_findings.extend(check_gcp(domain))
    all_findings.extend(check_cloud_metadata(target))
    all_findings.extend(check_elasticsearch(target))
    all_findings.extend(check_grafana(target))

    critical = [f for f in all_findings if f["severity"] == "critical"]
    high = [f for f in all_findings if f["severity"] == "high"]

    findings = []
    if critical:
        findings.append({"sev": "critical", "msg": f"{len(critical)} critical cloud exposure(s) found"})
    if high:
        findings.append({"sev": "high", "msg": f"{len(high)} high-severity cloud issue(s)"})

    return {
        "checks_performed": ["S3", "Firebase", "Azure Blob", "GCP Storage",
                              "Cloud Metadata (SSRF)", "Elasticsearch", "Grafana"],
        "exposures": all_findings,
        "critical_count": len(critical),
        "high_count": len(high),
        "findings": findings
    }
