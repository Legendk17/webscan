import requests
import re
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

HEADERS = {"User-Agent": "SecureScan/2.0 Security Scanner"}
TIMEOUT = 8
MAX_PAGES = 40
MAX_DEPTH = 3

class LinkParser(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.links = set()
        self.forms = []
        self.scripts = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            href = urljoin(self.base, attrs["href"])
            if urlparse(href).netloc == urlparse(self.base).netloc:
                self.links.add(href)
        elif tag == "form":
            self.current_form = {
                "action": urljoin(self.base, attrs.get("action", "")),
                "method": attrs.get("method", "get").upper(),
                "inputs": []
            }
        elif tag == "input" and self.current_form:
            self.current_form["inputs"].append({
                "name": attrs.get("name", ""),
                "type": attrs.get("type", "text"),
                "value": attrs.get("value", "")
            })
        elif tag == "script":
            src = attrs.get("src", "")
            if src:
                self.scripts.append(urljoin(self.base, src))

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


def crawl_target(target):
    visited = set()
    to_visit = [(target, 0)]
    all_links = set()
    all_forms = []
    all_scripts = []
    js_routes = []
    api_endpoints = []
    websocket_urls = []
    upload_forms = []
    graphql_hints = []
    ajax_patterns = []
    sitemap_found = False
    robots_found = False
    robots_disallowed = []
    parameters = set()
    errors = []

    session = requests.Session()
    session.headers.update(HEADERS)

    # Check robots.txt
    try:
        r = session.get(target.rstrip("/") + "/robots.txt", timeout=TIMEOUT)
        if r.status_code == 200:
            robots_found = True
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    p = line.split(":", 1)[1].strip()
                    if p:
                        robots_disallowed.append(p)
                        to_visit.append((target.rstrip("/") + p, 1))
    except Exception:
        pass

    # Check sitemap.xml
    for sm_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        try:
            r = session.get(target.rstrip("/") + sm_path, timeout=TIMEOUT)
            if r.status_code == 200 and "xml" in r.headers.get("Content-Type", ""):
                sitemap_found = True
                urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                for u in urls[:20]:
                    if urlparse(u).netloc == urlparse(target).netloc:
                        to_visit.append((u, 1))
        except Exception:
            pass

    while to_visit and len(visited) < MAX_PAGES:
        url, depth = to_visit.pop(0)
        if url in visited or depth > MAX_DEPTH:
            continue
        visited.add(url)

        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            content_type = r.headers.get("Content-Type", "")
            if "html" not in content_type:
                continue

            parser = LinkParser(url)
            parser.feed(r.text)

            for link in parser.links:
                all_links.add(link)
                if link not in visited:
                    to_visit.append((link, depth + 1))
                # Extract parameters
                if "?" in link:
                    for param in re.findall(r"[?&]([^=&]+)=", link):
                        parameters.add(param)

            all_forms.extend(parser.forms)
            all_scripts.extend(parser.scripts)

            # Detect upload forms
            for form in parser.forms:
                for inp in form.get("inputs", []):
                    if inp.get("type") == "file":
                        upload_forms.append({"url": url, "action": form.get("action")})

            # Find JS routes
            js_in_html = re.findall(r'(?:fetch|axios|xhr)\s*\(["\']([^"\']+)["\']', r.text)
            js_routes.extend(js_in_html)

            # Detect WebSocket
            ws_matches = re.findall(r'new\s+WebSocket\s*\(["\']([^"\']+)["\']', r.text)
            websocket_urls.extend(ws_matches)

            # Detect GraphQL
            if "graphql" in r.text.lower() or "/graphql" in url.lower():
                graphql_hints.append(url)

            # Detect AJAX
            ajax = re.findall(r'url\s*:\s*["\']([^"\']+)["\']', r.text)
            ajax_patterns.extend(ajax[:5])

            # Detect API endpoints in HTML
            apis = re.findall(r'["\']/(api|v1|v2|rest|graphql)/[^"\'<>\s]{1,80}["\']', r.text)
            api_endpoints.extend(set(a[0] + "/" + a[1] if isinstance(a, tuple) else a for a in apis))

        except Exception as e:
            errors.append(str(e))

    # Deduplicate
    api_endpoints = list(set(api_endpoints))[:30]
    js_routes = list(set(js_routes))[:30]
    websocket_urls = list(set(websocket_urls))

    return {
        "pages_found": len(visited),
        "links_found": len(all_links),
        "forms_found": len(all_forms),
        "js_files": list(set(all_scripts))[:30],
        "upload_forms": upload_forms,
        "forms": all_forms[:20],
        "api_endpoints": api_endpoints,
        "js_routes": js_routes,
        "websocket_urls": websocket_urls,
        "graphql_hints": list(set(graphql_hints)),
        "ajax_patterns": ajax_patterns[:20],
        "robots_found": robots_found,
        "robots_disallowed": robots_disallowed[:20],
        "sitemap_found": sitemap_found,
        "parameters_found": list(parameters)[:30],
        "pages_visited": list(visited)[:30],
        "errors": errors[:5]
    }
