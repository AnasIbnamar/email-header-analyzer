import re
import email
from email import policy
from email.header import decode_header as _decode_header
import dns.resolver
import requests as http_requests
from ml_model import predict_risk
import os
from dotenv import load_dotenv
load_dotenv()

def parse_headers(raw_headers):
    """
    Parse raw email headers and extract all useful fields.
    Returns a structured dictionary with everything we need.
    """
    result = {
        "from": None,
        "reply_to": None,
        "to": None,
        "subject": None,
        "date": None,
        "message_id": None,
        "return_path": None,
        "received_chain": [],
        "all_ips": [],
        "x_headers": {},
        "raw": raw_headers
    }

    try:
        # Parse using Python's built-in email library
        msg = email.message_from_string(raw_headers, policy=policy.compat32)

        # Extract basic fields
        result["from"]        = msg.get("From", "")
        result["reply_to"]    = msg.get("Reply-To", "")
        result["to"]          = msg.get("To", "")
        
        # Decode subject (handles encoded subjects like =?UTF-8?B?...)
        raw_subject = msg.get("Subject", "")
        try:
            decoded_parts = _decode_header(raw_subject)
            subject_str = ""
            for part, enc in decoded_parts:
                if isinstance(part, bytes):
                    subject_str += part.decode(enc or "utf-8", errors="replace")
                else:
                    subject_str += part
            result["subject"] = subject_str
        except Exception:
            result["subject"] = raw_subject
            
        result["date"]        = msg.get("Date", "")
        result["message_id"]  = msg.get("Message-ID", "")
        result["return_path"] = msg.get("Return-Path", "")

        # Extract all Received headers (delivery chain) — they come in reverse order
        received_list = msg.get_all("Received") or []
        for hop in received_list:
            hop_data = parse_received_hop(hop)
            result["received_chain"].append(hop_data)

        # Extract all IPs found across all headers
        all_text = raw_headers
        result["all_ips"] = extract_ips(all_text)

        # Extract any X- custom headers (these can reveal mail clients, servers, spam scores)
        for key in msg.keys():
            if key.lower().startswith("x-"):
                result["x_headers"][key] = msg.get(key)

    except Exception as e:
        result["parse_error"] = str(e)

    return result


def parse_received_hop(received_text):
    """
    Parse a single Received header into its components.
    Example: 'from mail.evil.com (1.2.3.4) by mx.google.com; Mon, 25 Apr 2026'
    """
    hop = {
        "raw": received_text,
        "from_host": None,
        "by_host": None,
        "timestamp": None,
        "ips": []
    }

    # Extract 'from' hostname
    from_match = re.search(r'from\s+(\S+)', received_text, re.IGNORECASE)
    if from_match:
        hop["from_host"] = from_match.group(1)

    # Extract 'by' hostname
    by_match = re.search(r'\bby\s+(\S+)', received_text, re.IGNORECASE)
    if by_match:
        hop["by_host"] = by_match.group(1)

    # Extract timestamp (after the semicolon)
    time_match = re.search(r';\s*(.+)$', received_text.strip(), re.IGNORECASE)
    if time_match:
        hop["timestamp"] = time_match.group(1).strip()

    # Extract IPs from this hop
    hop["ips"] = extract_ips(received_text)

    return hop


def extract_ips(text):
    """
    Extract all unique IPv4 addresses from a block of text.
    Filters out private/loopback IPs to focus on external hops.
    """
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    found = re.findall(ip_pattern, text)

    unique_ips = []
    seen = set()
    for ip in found:
        if ip not in seen and is_valid_ip(ip):
            seen.add(ip)
            unique_ips.append(ip)

    return unique_ips


def is_valid_ip(ip):
    """Check it's a real routable IP, not private, loopback, or malformed."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # Reject leading zeros (e.g. 04.25.13.42 is a date, not an IP)
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            return False

    # Filter out loopback
    if octets[0] == 127:
        return False
    # Filter out private ranges
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    # Filter out obviously invalid first octet
    if octets[0] == 0:
        return False

    return all(0 <= o <= 255 for o in octets)


def detect_spoofing_indicators(parsed):
    """
    Basic spoofing checks on the parsed header data.
    Returns a list of warning strings.
    """
    warnings = []

    from_addr   = parsed.get("from", "") or ""
    reply_to    = parsed.get("reply_to", "") or ""
    return_path = parsed.get("return_path", "") or ""

    # Check if Reply-To differs from From domain
    from_domain    = extract_domain(from_addr)
    replyto_domain = extract_domain(reply_to)

    if reply_to and from_domain and replyto_domain:
        if from_domain.lower() != replyto_domain.lower():
            warnings.append(
                f"Reply-To domain ({replyto_domain}) differs from From domain ({from_domain})"
            )

    # Check if Return-Path differs from From domain
    returnpath_domain = extract_domain(return_path)
    if return_path and from_domain and returnpath_domain:
        if from_domain.lower() != returnpath_domain.lower():
            warnings.append(
                f"Return-Path domain ({returnpath_domain}) differs from From domain ({from_domain})"
            )

    # Check for empty or missing Message-ID
    if not parsed.get("message_id"):
        warnings.append("Missing Message-ID — unusual for legitimate email")

    # Check for no Received hops at all
    if not parsed.get("received_chain"):
        warnings.append("No Received headers found — header may be forged or stripped")

    return warnings


def extract_domain(email_str):
    """Pull the domain out of an email address or angle-bracket address."""
    if not email_str:
        return None
    match = re.search(r'@([\w\.\-]+)', email_str)
    return match.group(1) if match else None


def check_spf(domain):
    """
    Look up the SPF record for a domain via DNS TXT records.
    SPF tells us which servers are allowed to send email for that domain.
    """
    result = {
        "domain": domain,
        "record": None,
        "status": "not_found",
        "verdict": "neutral"
    }

    if not domain:
        result["status"] = "no_domain"
        return result

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["record"] = txt
                result["status"] = "found"

                # Basic verdict from the SPF record's ending mechanism
                if "-all" in txt:
                    result["verdict"] = "strict"       # Hard fail — domain enforces SPF
                elif "~all" in txt:
                    result["verdict"] = "soft_fail"    # Soft fail — likely phishing risk
                elif "?all" in txt:
                    result["verdict"] = "neutral"
                elif "+all" in txt:
                    result["verdict"] = "dangerous"    # Anyone can send — big red flag
                break

    except dns.resolver.NXDOMAIN:
        result["status"] = "domain_not_found"
    except dns.resolver.NoAnswer:
        result["status"] = "no_spf_record"
    except Exception as e:
        result["status"] = f"error: {str(e)}"

    return result


def check_dmarc(domain):
    """
    Look up the DMARC record for a domain.
    DMARC builds on SPF and DKIM — it tells receivers what to do with failing mail.
    """
    result = {
        "domain": domain,
        "record": None,
        "status": "not_found",
        "policy": None,
        "verdict": "none"
    }

    if not domain:
        result["status"] = "no_domain"
        return result

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                result["record"] = txt
                result["status"] = "found"

                # Extract the policy (p=none / p=quarantine / p=reject)
                policy_match = re.search(r'p=(\w+)', txt)
                if policy_match:
                    policy = policy_match.group(1).lower()
                    result["policy"] = policy

                    if policy == "reject":
                        result["verdict"] = "strict"       # Strongest protection
                    elif policy == "quarantine":
                        result["verdict"] = "moderate"     # Goes to spam
                    elif policy == "none":
                        result["verdict"] = "weak"         # Monitoring only — not enforced
                break

    except dns.resolver.NXDOMAIN:
        result["status"] = "domain_not_found"
    except dns.resolver.NoAnswer:
        result["status"] = "no_dmarc_record"
    except Exception as e:
        result["status"] = f"error: {str(e)}"

    return result


def check_dkim(parsed_headers):
    """
    Check for DKIM-Signature header presence.
    Full cryptographic verification requires the private key — we check existence
    and extract the signing domain (d= tag) for display.
    """
    result = {
        "present": False,
        "domain": None,
        "selector": None,
        "verdict": "missing"
    }

    raw = parsed_headers.get("raw", "")
    dkim_match = re.search(r'DKIM-Signature:.*?(?=\n\S|\Z)', raw,
                           re.IGNORECASE | re.DOTALL)

    if dkim_match:
        result["present"] = True
        result["verdict"] = "present"
        dkim_text = dkim_match.group(0)

        # Extract signing domain
        d_match = re.search(r'\bd=([^\s;]+)', dkim_text)
        if d_match:
            result["domain"] = d_match.group(1)

        # Extract selector
        s_match = re.search(r'\bs=([^\s;]+)', dkim_text)
        if s_match:
            result["selector"] = s_match.group(1)

    return result


def geolocate_ip(ip):
    """
    Use the free ip-api.com service to geolocate an IP address.
    No API key required. Returns country, city, ISP, and org.
    """
    result = {
        "ip": ip,
        "country": None,
        "city": None,
        "isp": None,
        "org": None,
        "status": "unknown"
    }

    try:
        response = http_requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()

        if data.get("status") == "success":
            result["country"] = data.get("country")
            result["city"]    = data.get("city")
            result["isp"]     = data.get("isp")
            result["org"]     = data.get("org")
            result["status"]  = "success"
        else:
            result["status"] = data.get("message", "failed")

    except Exception as e:
        result["status"] = "unavailable"

    return result


def calculate_risk_score(parsed, spf, dmarc, dkim, spoofing_warnings):
    """
    Calculate an overall risk score from 0 (safe) to 100 (dangerous).
    This is what makes the tool impressive — a single clear number.
    """
    score = 0

    # SPF scoring
    if spf["status"] in ("not_found", "no_spf_record", "domain_not_found"):
        score += 25
    elif spf["verdict"] == "dangerous":   # +all
        score += 35
    elif spf["verdict"] == "soft_fail":
        score += 15

    # DMARC scoring
    if dmarc["status"] in ("not_found", "no_dmarc_record", "domain_not_found"):
        score += 25
    elif dmarc["verdict"] == "weak":      # p=none
        score += 15
    elif dmarc["verdict"] == "moderate":  # p=quarantine
        score += 5

    # DKIM scoring
    if not dkim["present"]:
        score += 20

    # Spoofing indicators
    score += len(spoofing_warnings) * 10

    return min(score, 100)   # Cap at 100

def check_abuseipdb(ip):
    """
    Check an IP against AbuseIPDB's database of reported malicious IPs.
    Free tier: 1000 checks/day.
    """
    result = {
        "ip": ip,
        "abuse_score": 0,
        "total_reports": 0,
        "country": None,
        "isp": None,
        "domain": None,
        "is_tor": False,
        "last_reported": None,
        "verdict": "clean",
        "status": "unchecked"
    }

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        result["status"] = "no_api_key"
        return result

    try:
        response = http_requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=8
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            result["abuse_score"]   = score
            result["total_reports"] = data.get("totalReports", 0)
            result["country"]       = data.get("countryCode")
            result["isp"]           = data.get("isp")
            result["domain"]        = data.get("domain")
            result["is_tor"]        = data.get("isTor", False)
            result["last_reported"] = data.get("lastReportedAt")
            result["status"]        = "success"

            if score >= 80:
                result["verdict"] = "malicious"
            elif score >= 40:
                result["verdict"] = "suspicious"
            elif score >= 10:
                result["verdict"] = "low_risk"
            else:
                result["verdict"] = "clean"

        elif response.status_code == 429:
            result["status"] = "rate_limited"
        else:
            result["status"] = f"api_error_{response.status_code}"

    except Exception as e:
        result["status"] = "unavailable"

    return result

def detect_email_provider(parsed):
    """
    Identify the email service or tool used to send the email.
    Returns provider name, type, and a risk flag.
    """
    result = {
        "name": "Unknown",
        "type": "unknown",
        "risk": "neutral",
        "detail": ""
    }

    raw        = parsed.get("raw", "").lower()
    x_mailer   = parsed.get("x_headers", {}).get("X-Mailer", "") or ""
    received   = " ".join([h.get("raw", "") for h in parsed.get("received_chain", [])]).lower()
    dkim_domain = None

    # Check DKIM signing domain
    dkim_match = re.search(r'd=([\w\.\-]+)', raw, re.IGNORECASE)
    if dkim_match:
        dkim_domain = dkim_match.group(1).lower()

    x_mailer_lower = x_mailer.lower()

    # --- Malicious / High Risk Tools ---
    if "phpmailer" in x_mailer_lower:
        result.update({
            "name": "PHPMailer",
            "type": "script",
            "risk": "high",
            "detail": "Open-source PHP library — heavily abused in phishing and spam campaigns"
        })
    elif "the bat" in x_mailer_lower:
        result.update({
            "name": "The Bat!",
            "type": "client",
            "risk": "medium",
            "detail": "Desktop email client popular in Eastern Europe — uncommon for legitimate bulk mail"
        })
    elif "swiftmailer" in x_mailer_lower:
        result.update({
            "name": "SwiftMailer",
            "type": "script",
            "risk": "high",
            "detail": "PHP mailing library — frequently used in spam infrastructure"
        })
    elif "sendgrid" in received or (dkim_domain and "sendgrid" in dkim_domain):
        result.update({
            "name": "SendGrid",
            "type": "esp",
            "risk": "low",
            "detail": "Legitimate email delivery platform used by businesses"
        })
    elif "mailchimp" in received or (dkim_domain and "mailchimp" in dkim_domain):
        result.update({
            "name": "Mailchimp",
            "type": "esp",
            "risk": "low",
            "detail": "Legitimate email marketing platform"
        })
    elif "amazonses" in received or (dkim_domain and "amazonses" in dkim_domain):
        result.update({
            "name": "Amazon SES",
            "type": "esp",
            "risk": "low",
            "detail": "Amazon's email sending service — used by legitimate businesses"
        })
    elif "google" in received or (dkim_domain and "google" in dkim_domain) or "gmail" in received:
        result.update({
            "name": "Gmail / Google",
            "type": "provider",
            "risk": "low",
            "detail": "Sent via Google's mail infrastructure"
        })
    elif "outlook" in received or "hotmail" in received or "microsoft" in received:
        result.update({
            "name": "Microsoft Outlook / Hotmail",
            "type": "provider",
            "risk": "low",
            "detail": "Sent via Microsoft's mail infrastructure"
        })
    elif "yahoo" in received or (dkim_domain and "yahoo" in dkim_domain):
        result.update({
            "name": "Yahoo Mail",
            "type": "provider",
            "risk": "low",
            "detail": "Sent via Yahoo's mail infrastructure"
        })
    elif "mailgun" in received or (dkim_domain and "mailgun" in dkim_domain):
        result.update({
            "name": "Mailgun",
            "type": "esp",
            "risk": "low",
            "detail": "Transactional email API service"
        })
    elif "postfix" in received:
        result.update({
            "name": "Postfix",
            "type": "mta",
            "risk": "medium",
            "detail": "Self-hosted mail server — could be legitimate or part of spam infrastructure"
        })
    elif "exim" in received:
        result.update({
            "name": "Exim",
            "type": "mta",
            "risk": "medium",
            "detail": "Self-hosted mail server — common in web hosting environments"
        })
    elif x_mailer:
        result.update({
            "name": x_mailer,
            "type": "client",
            "risk": "neutral",
            "detail": "Custom or uncommon mail client"
        })

    return result

def run_full_analysis(raw_headers):
    """
    Master function — runs everything and returns one complete report dict.
    This is the only function Flask needs to call.
    """
    parsed   = parse_headers(raw_headers)
    warnings = detect_spoofing_indicators(parsed)

    from_domain = extract_domain(parsed.get("from", "") or "")

    spf   = check_spf(from_domain)
    dmarc = check_dmarc(from_domain)
    dkim  = check_dkim(parsed)
    provider = detect_email_provider(parsed)

    # Geolocate AND threat-check all external IPs
    geo_results = []
    for ip in parsed["all_ips"][:5]:
        geo = geolocate_ip(ip)
        geo["abuse"] = check_abuseipdb(ip)
        geo_results.append(geo)

    risk_score = calculate_risk_score(parsed, spf, dmarc, dkim, warnings)

    ml = predict_risk({
        "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "spoofing_warnings": warnings,
        "geo": geo_results,
        "provider": provider,
        "parsed": parsed,
        "risk_score": risk_score
    })

    return {
        "parsed":            parsed,
        "spf":               spf,
        "dmarc":             dmarc,
        "dkim":              dkim,
        "geo":               geo_results,
        "spoofing_warnings": warnings,
        "risk_score":        risk_score,
        "provider":          provider,
        "ml":                ml
    }