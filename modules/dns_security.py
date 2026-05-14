import socket
import re
import requests
from urllib.parse import urlparse

TIMEOUT = 6

def dns_txt_lookup(domain):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        return [str(r) for r in answers]
    except Exception:
        return []

def dns_mx_lookup(domain):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange) for r in answers]
    except Exception:
        return []

def dns_a_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def check_zone_transfer(domain):
    try:
        import dns.resolver, dns.zone, dns.query
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(ns.target)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                if zone:
                    return {"vulnerable": True, "ns": ns_host, "records": list(zone.nodes.keys())[:20]}
            except Exception:
                pass
        return {"vulnerable": False}
    except Exception:
        return {"vulnerable": False}

def check_subdomain_takeover(domain):
    vulnerable_cnames = [
        ("amazonaws.com", "AWS S3 bucket not configured"),
        ("azurewebsites.net", "Azure app not configured"),
        ("github.io", "GitHub Pages not configured"),
        ("herokupapp.com", "Heroku app not configured"),
        ("fastly.net", "Fastly CDN not configured"),
        ("shopify.com", "Shopify store not configured"),
        ("bitbucket.io", "Bitbucket Pages not configured"),
    ]
    takeover_risks = []
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            for r in answers:
                cname = str(r.target).lower()
                for vendor, msg in vulnerable_cnames:
                    if vendor in cname:
                        # Try to reach the CNAME target
                        try:
                            resp = requests.get(f"https://{cname.rstrip('.')}", timeout=5)
                            if resp.status_code in (404, 200) and any(
                                kw in resp.text.lower() for kw in
                                ["no such app", "not found", "there is no app", "bucket does not exist"]
                            ):
                                takeover_risks.append({"cname": cname, "reason": msg})
                        except Exception:
                            takeover_risks.append({"cname": cname, "reason": msg + " (CNAME exists, target unreachable)"})
        except Exception:
            pass
    except Exception:
        pass
    return takeover_risks

def check_dns(target):
    parsed = urlparse(target)
    domain = parsed.hostname or target.replace("https://","").replace("http://","").split("/")[0]
    root_domain = ".".join(domain.split(".")[-2:])

    txt_records = dns_txt_lookup(domain) or dns_txt_lookup(root_domain)
    mx_records = dns_mx_lookup(domain) or dns_mx_lookup(root_domain)
    ip = dns_a_lookup(domain)

    # SPF check
    spf = None
    for t in txt_records:
        if "v=spf1" in t.lower():
            spf = t
            break

    # DMARC check
    dmarc = None
    dmarc_txts = dns_txt_lookup(f"_dmarc.{root_domain}")
    for t in dmarc_txts:
        if "v=dmarc1" in t.lower():
            dmarc = t
            break

    # DKIM check (check common selectors)
    dkim = None
    for selector in ["default", "google", "mail", "k1", "s1", "s2", "dkim"]:
        dkim_txts = dns_txt_lookup(f"{selector}._domainkey.{root_domain}")
        for t in dkim_txts:
            if "v=dkim1" in t.lower() or "p=" in t.lower():
                dkim = t
                break
        if dkim:
            break

    # DNSSEC check
    dnssec = False
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "DNSKEY")
        dnssec = True
    except Exception:
        pass

    # Zone transfer test
    zone_transfer = check_zone_transfer(root_domain)

    # Subdomain takeover
    takeover_risks = check_subdomain_takeover(domain)

    # SPF analysis
    spf_issues = []
    if spf:
        if "+all" in spf:
            spf_issues.append("SPF uses +all — allows ALL servers to send (critical)")
        if "~all" in spf:
            spf_issues.append("SPF uses ~all (softfail) — should use -all")
    else:
        spf_issues.append("No SPF record found")

    # DMARC analysis
    dmarc_issues = []
    if dmarc:
        if "p=none" in dmarc.lower():
            dmarc_issues.append("DMARC policy is 'none' — no enforcement")
        if "rua=" not in dmarc.lower():
            dmarc_issues.append("DMARC missing reporting URI (rua=)")
    else:
        dmarc_issues.append("No DMARC record found")

    findings = []
    if not spf:
        findings.append({"sev": "medium", "msg": "Missing SPF record — email spoofing risk"})
    if not dmarc:
        findings.append({"sev": "medium", "msg": "Missing DMARC record — phishing risk"})
    if not dkim:
        findings.append({"sev": "low", "msg": "No DKIM record found for common selectors"})
    if not dnssec:
        findings.append({"sev": "low", "msg": "DNSSEC not enabled"})
    if zone_transfer.get("vulnerable"):
        findings.append({"sev": "critical", "msg": "DNS zone transfer allowed — full DNS exposure"})
    for t in takeover_risks:
        findings.append({"sev": "high", "msg": f"Subdomain takeover risk: {t['cname']}"})
    for issue in spf_issues:
        if "critical" in issue.lower():
            findings.append({"sev": "high", "msg": issue})

    return {
        "domain": domain,
        "root_domain": root_domain,
        "ip": ip,
        "spf": spf,
        "spf_issues": spf_issues,
        "dmarc": dmarc,
        "dmarc_issues": dmarc_issues,
        "dkim": dkim,
        "dnssec": dnssec,
        "mx_records": mx_records[:10],
        "txt_records": txt_records[:10],
        "zone_transfer": zone_transfer,
        "takeover_risks": takeover_risks,
        "findings": findings
    }
