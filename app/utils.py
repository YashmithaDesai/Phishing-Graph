import ssl, socket
import whois
from datetime import datetime

def fetch_ssl_info(domain):
    ssl_info = {"issuer": None, "expires": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info["issuer"] = cert.get("issuer", [])[0][-1] if cert.get("issuer") else "Unknown"
                ssl_info["expires"] = cert.get("notAfter")
    except Exception:
        pass
    return ssl_info

def fetch_whois_info(domain):
    whois_info = {"registrar": None, "creation_date": None}
    try:
        w = whois.whois(domain)
        whois_info["registrar"] = w.registrar
        whois_info["creation_date"] = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
    except Exception:
        pass
    return whois_info

def score_domain_risk(ssl_info, whois_info):
    score = 0
    reasons = []

    # SSL Checks
    if not ssl_info.get("issuer") or "self" in str(ssl_info["issuer"]).lower():
        score += 1
        reasons.append("Self-signed or missing SSL issuer")
    if ssl_info.get("expires"):
        try:
            exp_date = datetime.strptime(ssl_info["expires"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left <= 90:
                score += 1
                reasons.append("SSL expires in ≤ 3 months")
        except Exception:
            pass

    # WHOIS Checks
    creation = whois_info.get("creation_date")
    if creation:
        try:
            creation_date = datetime.strptime(creation[:10], "%Y-%m-%d")
            age_days = (datetime.utcnow() - creation_date).days
            if age_days < 90:
                score += 1
                reasons.append("Domain registered < 3 months ago")
        except Exception:
            pass
    if not whois_info.get("registrar"):
        score += 1
        reasons.append("Missing registrar in WHOIS")

    return score, reasons
