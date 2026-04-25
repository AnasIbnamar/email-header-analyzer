import re
import email
from email import policy


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
        result["subject"]     = msg.get("Subject", "")
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
    """Check it's a real routable IP, not private or loopback."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # Filter out loopback
    if octets[0] == 127:
        return False
    # Filter out private ranges (10.x, 172.16-31.x, 192.168.x)
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
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