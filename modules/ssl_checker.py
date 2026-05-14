import ssl
import socket
import datetime
import re

TIMEOUT = 6

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"}

def check_ssl(target):
    host = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
                not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y GMT")
                now = datetime.datetime.utcnow()
                expired = not_after < now
                days_left = max(0, (not_after - now).days)

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                san = cert.get("subjectAltName", [])
                san_list = [v for t, v in san if t == "DNS"]

                # Self-signed check
                self_signed = subject.get("organizationName") == issuer.get("organizationName") and \
                              subject.get("commonName") == issuer.get("commonName")

                # Weak protocol
                weak_protocol = protocol in WEAK_PROTOCOLS

                # Weak cipher
                cipher_name = cipher[0] if cipher else ""
                weak_cipher = any(w in cipher_name.upper() for w in WEAK_CIPHERS)

                # Forward secrecy
                has_forward_secrecy = "DHE" in cipher_name.upper() or "ECDHE" in cipher_name.upper()

                # OCSP stapling (best effort)
                ocsp_stapled = False

                # Cert chain depth
                cert_version = cert.get("version", 0)

                findings = []
                if expired:
                    findings.append({"sev": "critical", "msg": "Certificate has expired"})
                if self_signed:
                    findings.append({"sev": "high", "msg": "Certificate appears self-signed"})
                if weak_protocol:
                    findings.append({"sev": "high", "msg": f"Weak protocol in use: {protocol}"})
                if weak_cipher:
                    findings.append({"sev": "medium", "msg": f"Weak cipher: {cipher_name}"})
                if not has_forward_secrecy:
                    findings.append({"sev": "medium", "msg": "No forward secrecy (use ECDHE/DHE)"})
                if days_left < 30 and not expired:
                    findings.append({"sev": "medium", "msg": f"Certificate expires in {days_left} days"})

                return {
                    "subject": subject.get("commonName", str(cert.get("subject",""))),
                    "org": subject.get("organizationName", ""),
                    "issuer": issuer.get("organizationName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"],
                    "expired": expired,
                    "days_left": days_left,
                    "self_signed": self_signed,
                    "protocol": protocol,
                    "cipher": cipher_name,
                    "key_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                    "weak_protocol": weak_protocol,
                    "weak_cipher": weak_cipher,
                    "forward_secrecy": has_forward_secrecy,
                    "san": san_list[:10],
                    "findings": findings,
                    "error": None
                }

    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificate verification failed: {e}", "findings": [
            {"sev": "high", "msg": "SSL certificate verification failed"}
        ]}
    except socket.gaierror:
        return {"error": "DNS resolution failed", "findings": []}
    except socket.timeout:
        return {"error": "Connection timed out", "findings": []}
    except ConnectionRefusedError:
        return {"error": "Port 443 not open — HTTPS not available", "findings": [
            {"sev": "high", "msg": "HTTPS not available on port 443"}
        ]}
    except Exception as e:
        return {"error": str(e), "findings": []}
