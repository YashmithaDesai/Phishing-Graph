import ssl, socket
import whois
from datetime import datetime
import dns.resolver

def fetch_dns_info(domain):
    dns_info = {"has_a_record": False, "has_mx_record": False, "has_ns_record": False}
    try:
        # Check for A record
        a_records = dns.resolver.resolve(domain, 'A')
        if a_records:
            dns_info["has_a_record"] = True
    except Exception:
        pass

    try:
        # Check for MX record
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            dns_info["has_mx_record"] = True
    except Exception:
        pass

    try:
        # Check for NS record
        ns_records = dns.resolver.resolve(domain, 'NS')
        if ns_records:
            dns_info["has_ns_record"] = True
    except Exception:
        pass

    return dns_info

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

def score_domain_risk(ssl_info, whois_info, dns_info=None):
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

    # DNS Checks
    if dns_info:
        if not dns_info.get("has_a_record"):
            score += 1
            reasons.append("Missing A record")
        if not dns_info.get("has_mx_record"):
            score += 1
            reasons.append("Missing MX record")
        if not dns_info.get("has_ns_record"):
            score += 1
            reasons.append("Missing NS record")

    return score, reasons
