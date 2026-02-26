import re

def check_headers_for_anomalies(headers: dict):
    """
    Checks basic email header semantics for common phishing anomalies.
    Expects a dictionary of headers like:
    {
        "From": "support@paypal.com.scam.net <scam@test.com>",
        "Reply-To": "hacker@test.com",
        "Received-SPF": "fail",
        "Authentication-Results": "dkim=fail"
    }
    """
    anomalies = []
    risk_points = 0.0
    
    # 1. SPF / DKIM Checks (assuming headers extracted by client)
    spf = headers.get("Received-SPF", "").lower()
    if "fail" in spf or "softfail" in spf:
        anomalies.append("SPF validation failed, sender IP is not authorized.")
        risk_points += 0.4
        
    auth = headers.get("Authentication-Results", "").lower()
    if "dkim=fail" in auth:
        anomalies.append("DKIM signature validation failed. Email may be spoofed.")
        risk_points += 0.4
        
    # 2. From vs Reply-To mismatch
    from_header = headers.get("From", "").lower()
    reply_to = headers.get("Reply-To", "").lower()
    
    # Basic email extraction `<email@box.com>`
    from_email = re.search(r'<([^>]+)>', from_header)
    from_email = from_email.group(1) if from_email else from_header
    
    reply_to_email = re.search(r'<([^>]+)>', reply_to)
    reply_to_email = reply_to_email.group(1) if reply_to_email else reply_to
    
    if reply_to_email and from_email and from_email not in reply_to_email and reply_to_email not in from_email:
        anomalies.append(f"Reply-To address ({reply_to_email}) does not match From address ({from_email}).")
        risk_points += 0.3
        
    # 3. Suspicious words in From display name
    suspicious_keywords = ["support", "billing", "admin", "security", "alert", "account", "update"]
    display_name = from_header.split('<')[0].strip() if '<' in from_header else from_header
    if any(kw in display_name for kw in suspicious_keywords):
        # Only risky if the actual domain doesn't clearly match the keyword intention, 
        # but as a basic heuristic:
        anomalies.append("Sender display name contains typical urgency/authority keywords.")
        risk_points += 0.1

    final_risk = min(1.0, risk_points)
    
    return {
        "header_risk_score": round(final_risk, 2),
        "anomalies_detected": anomalies
    }
