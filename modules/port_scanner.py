import socket
import ssl
import threading
from urllib.parse import urlparse

PORT_MAP = {
    21: {"service": "FTP", "risky": True, "description": "File Transfer Protocol — credentials often cleartext"},
    22: {"service": "SSH", "risky": False, "description": "Secure Shell"},
    23: {"service": "Telnet", "risky": True, "description": "Telnet — cleartext protocol, high risk"},
    25: {"service": "SMTP", "risky": False, "description": "Email sending"},
    53: {"service": "DNS", "risky": False, "description": "Domain Name System"},
    80: {"service": "HTTP", "risky": False, "description": "Unencrypted web traffic"},
    110: {"service": "POP3", "risky": True, "description": "Email retrieval — often cleartext"},
    143: {"service": "IMAP", "risky": False, "description": "Email retrieval"},
    443: {"service": "HTTPS", "risky": False, "description": "Encrypted web traffic"},
    445: {"service": "SMB", "risky": True, "description": "Windows file sharing — high attack surface"},
    465: {"service": "SMTPS", "risky": False, "description": "Secure email sending"},
    587: {"service": "SMTP-TLS", "risky": False, "description": "Email submission"},
    993: {"service": "IMAPS", "risky": False, "description": "Secure IMAP"},
    995: {"service": "POP3S", "risky": False, "description": "Secure POP3"},
    1433: {"service": "MSSQL", "risky": True, "description": "Microsoft SQL Server — DB exposure risk"},
    1521: {"service": "Oracle", "risky": True, "description": "Oracle DB — DB exposure risk"},
    2222: {"service": "SSH-Alt", "risky": False, "description": "Alternate SSH port"},
    3000: {"service": "HTTP-Dev", "risky": True, "description": "Development server — may expose debug info"},
    3306: {"service": "MySQL", "risky": True, "description": "MySQL database — direct internet exposure is dangerous"},
    3389: {"service": "RDP", "risky": True, "description": "Remote Desktop Protocol — high brute force target"},
    4444: {"service": "Unknown", "risky": True, "description": "Common backdoor/C2 port"},
    5000: {"service": "HTTP-Dev", "risky": True, "description": "Development/Flask server"},
    5432: {"service": "PostgreSQL", "risky": True, "description": "PostgreSQL database"},
    5900: {"service": "VNC", "risky": True, "description": "Virtual Network Computing — GUI remote access"},
    6379: {"service": "Redis", "risky": True, "description": "Redis cache — often no auth by default"},
    7000: {"service": "HTTP-Alt", "risky": False, "description": "Alternate HTTP"},
    8080: {"service": "HTTP-Alt", "risky": False, "description": "Alternate HTTP / proxy"},
    8443: {"service": "HTTPS-Alt", "risky": False, "description": "Alternate HTTPS"},
    8888: {"service": "Jupyter", "risky": True, "description": "Jupyter Notebook — code execution risk"},
    9200: {"service": "Elasticsearch", "risky": True, "description": "Elasticsearch — often no auth"},
    27017: {"service": "MongoDB", "risky": True, "description": "MongoDB — often no auth by default"},
}

TIMEOUT = 2
MAX_THREADS = 30

def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(512).decode(errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else ""
    except Exception:
        return ""

def check_ssl_on_port(host, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.version()
    except Exception:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def scan_single(host, port, results, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            meta = PORT_MAP.get(port, {"service": "Unknown", "risky": False, "description": ""})
            banner = grab_banner(host, port) if port not in (443, 8443) else ""
            ssl_ver = check_ssl_on_port(host, port) if port in (443, 8443, 465, 993, 995, 8443) else None
            entry = {
                "port": port,
                "service": meta["service"],
                "risky": meta["risky"],
                "description": meta["description"],
                "banner": banner[:100] if banner else "",
                "ssl_version": ssl_ver
            }
            with lock:
                results.append(entry)
    except Exception:
        pass

def scan_ports(target):
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://","").replace("http://","").split("/")[0]

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    rdns = reverse_dns(ip)

    open_ports = []
    lock = threading.Lock()
    threads = []

    for port in PORT_MAP:
        t = threading.Thread(target=scan_single, args=(host, port, open_ports, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports.sort(key=lambda x: x["port"])
    risky_count = sum(1 for p in open_ports if p["risky"])
    ssl_ports = [p for p in open_ports if p.get("ssl_version")]

    return {
        "host": host,
        "ip": ip,
        "reverse_dns": rdns,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "risky_count": risky_count,
        "ssl_ports": [p["port"] for p in ssl_ports]
    }
