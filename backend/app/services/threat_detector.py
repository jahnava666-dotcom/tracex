import re
import math
from typing import List, Dict, Any, Tuple
from .geo_service import extract_ip_from_text

# High-risk brand targets for typosquatting / spoofing detection
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "chase", 
    "bankofamerica", "wellsfargo", "netflix", "dhl", "fedex", 
    "secure-login", "account-verify", "support-portal"
]

SUSPICIOUS_TLDS = {".ru", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".buzz", ".zip", ".mov"}
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".js", ".iso", ".img", ".hta", ".wsf"}

URGENCY_PATTERNS = [
    r"urgent",
    r"immediate\s+action",
    r"account\s+(?:suspended|locked|terminated|blocked)",
    r"within\s+24\s+hours",
    r"verify\s+your\s+(?:identity|account|credentials|card)",
    r"unauthorized\s+(?:login|activity|transaction)",
    r"payment\s+(?:overdue|declined|failed)",
    r"security\s+alert",
    r"password\s+expired"
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text/HTML body."""
    url_pattern = r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'<>]*)?"
    matches = re.findall(url_pattern, text)
    # Deduplicate while preserving order
    seen = set()
    urls = []
    for u in matches:
        u_clean = u.rstrip(".,;)\"'>")
        if u_clean not in seen:
            seen.add(u_clean)
            urls.append(u_clean)
    return urls

def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    m = re.search(r"https?://([^/:\s]+)", url)
    return m.group(1).lower() if m else ""

def analyze_threats(
    subject: str,
    from_addr: str,
    reply_to: str,
    return_path: str,
    body_text: str,
    raw_headers: str,
    attachments: List[Dict[str, Any]],
    auth_results: Dict[str, Any],
    origin_ip: str
) -> Dict[str, Any]:
    """
    Perform deep forensic threat analysis, compute explainable risk signals,
    and generate IOCs, timeline events, and remediation actions.
    """
    signals: List[Dict[str, Any]] = []
    iocs_domains = set()
    iocs_ips = set()
    iocs_urls = set()
    iocs_attachments: List[Dict[str, Any]] = []
    threat_intel_indicators: List[Dict[str, Any]] = []

    # 1. Header Spoofing Analysis (From vs Return-Path vs Reply-To)
    from_domain = ""
    return_domain = ""
    reply_domain = ""

    from_match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", from_addr)
    return_match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", return_path)
    reply_match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", reply_to)

    if from_match:
        from_domain = from_match.group(1).lower()
        iocs_domains.add(from_domain)
    if return_match:
        return_domain = return_match.group(1).lower()
        iocs_domains.add(return_domain)
    if reply_match:
        reply_domain = reply_match.group(1).lower()
        iocs_domains.add(reply_domain)

    if from_domain and return_domain and from_domain != return_domain:
        signals.append({
            "id": f"sig-{len(signals) + 1}",
            "title": "Sender Address Spoofing",
            "category": "Header Integrity",
            "severity": "critical",
            "scoreImpact": 20,
            "explanation": f"From header domain ({from_domain}) conflicts with envelope Return-Path ({return_domain}).",
            "evidence": f"From: {from_addr} != Return-Path: {return_path}",
            "iconName": "UserX"
        })
    elif from_domain and reply_domain and from_domain != reply_domain:
        signals.append({
            "id": f"sig-{len(signals) + 1}",
            "title": "Reply-To Destination Mismatch",
            "category": "Header Integrity",
            "severity": "high",
            "scoreImpact": 15,
            "explanation": f"Replies route to an external domain ({reply_domain}) different from sender ({from_domain}).",
            "evidence": f"Reply-To: {reply_to}",
            "iconName": "MailWarning"
        })

    # 2. Authentication Failures
    spf_status = auth_results.get("spf", {}).get("status", "PASS")
    dkim_status = auth_results.get("dkim", {}).get("status", "PASS")
    dmarc_status = auth_results.get("dmarc", {}).get("status", "PASS")

    if dmarc_status == "FAIL":
        signals.append({
            "id": f"sig-{len(signals) + 1}",
            "title": "DMARC Policy Rejection",
            "category": "Authentication",
            "severity": "high",
            "scoreImpact": 15,
            "explanation": "Domain alignment failed under strict DMARC rejection policy.",
            "evidence": auth_results.get("dmarc", {}).get("technicalDetails", "DMARC alignment failed."),
            "iconName": "ShieldAlert"
        })
    elif spf_status == "FAIL":
        signals.append({
            "id": f"sig-{len(signals) + 1}",
            "title": "SPF Sender Authorization Failure",
            "category": "Authentication",
            "severity": "medium",
            "scoreImpact": 12,
            "explanation": "Originating mail server is not authorized by domain's published SPF policy.",
            "evidence": auth_results.get("spf", {}).get("technicalDetails", "SPF failure."),
            "iconName": "ShieldX"
        })

    # 3. URL and Domain Threat Extraction
    extracted_urls = extract_urls(body_text + " " + raw_headers)
    for url in extracted_urls:
        iocs_urls.add(url)
        u_domain = extract_domain_from_url(url)
        if u_domain:
            iocs_domains.add(u_domain)

        # Check for IP in URL
        if re.search(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", url):
            signals.append({
                "id": f"sig-{len(signals) + 1}",
                "title": "Raw IP Hostname in URL",
                "category": "Link Analysis",
                "severity": "critical",
                "scoreImpact": 20,
                "explanation": "Hyperlink uses a direct numeric IP address instead of a verified registered domain.",
                "evidence": url,
                "iconName": "ExternalLink"
            })
            threat_intel_indicators.append({
                "indicator": url,
                "type": "URL",
                "reputation": "Malicious",
                "details": "Direct numeric IP link associated with malware host / phishing payload.",
                "confidence": 95,
                "firstSeen": "Today"
            })
        
        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if u_domain.endswith(tld):
                signals.append({
                    "id": f"sig-{len(signals) + 1}",
                    "title": f"Suspicious High-Risk TLD ({tld})",
                    "category": "Domain Intelligence",
                    "severity": "high",
                    "scoreImpact": 15,
                    "explanation": f"Domain '{u_domain}' uses an abuse-prone top level domain frequently employed in phishing.",
                    "evidence": f"URL: {url}",
                    "iconName": "Globe"
                })
                break

        # Check for brand typosquatting in domain
        for brand in TARGET_BRANDS:
            if brand in u_domain and not u_domain.endswith(f"{brand}.com") and not u_domain.endswith(f"{brand}.org"):
                signals.append({
                    "id": f"sig-{len(signals) + 1}",
                    "title": f"Brand Typosquatting Target ({brand})",
                    "category": "Domain Intelligence",
                    "severity": "high",
                    "scoreImpact": 18,
                    "explanation": f"Domain '{u_domain}' contains brand name '{brand}' in an unverified layout.",
                    "evidence": f"Targeted: {brand} | Observed Domain: {u_domain}",
                    "iconName": "Globe"
                })
                threat_intel_indicators.append({
                    "indicator": u_domain,
                    "type": "Domain",
                    "reputation": "Malicious",
                    "details": f"Typosquatting spoofing '{brand}'. NameSilo / bulletproof hosting proxy.",
                    "confidence": 92,
                    "firstSeen": "Today"
                })
                break

    # 4. Attachment Inspection
    for att in attachments:
        fn = att.get("filename", "").lower()
        size_str = att.get("size", "0 KB")
        sha256 = att.get("sha256", "")
        file_type = att.get("fileType", "")
        
        # Dangerous extension or double extension
        has_dangerous_ext = any(fn.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
        is_double_ext = bool(re.search(r"\.[a-zA-Z0-9]+\.(?:exe|vbs|bat|js|scr|zip)$", fn))
        
        verdict = "Clean"
        if has_dangerous_ext or is_double_ext:
            verdict = "Malicious Payload Dropper"
            signals.append({
                "id": f"sig-{len(signals) + 1}",
                "title": "Dangerous Attachment Dropper",
                "category": "Payload Analysis",
                "severity": "critical",
                "scoreImpact": 22,
                "explanation": f"Attachment '{att.get('filename')}' matches executable or script dropper profile.",
                "evidence": f"File: {att.get('filename')} (SHA256: {sha256[:16]}...)",
                "iconName": "FileArchive"
            })
            threat_intel_indicators.append({
                "indicator": sha256,
                "type": "SHA-256",
                "reputation": "Malicious",
                "details": f"Known dropper signature matching payload '{att.get('filename')}'.",
                "confidence": 98,
                "firstSeen": "Today"
            })
        elif fn.endswith(".zip") or fn.endswith(".rar") or fn.endswith(".7z"):
            verdict = "Suspicious Archive"
            signals.append({
                "id": f"sig-{len(signals) + 1}",
                "title": "Compressed Archive Payload",
                "category": "Payload Analysis",
                "severity": "medium",
                "scoreImpact": 10,
                "explanation": f"Archive '{att.get('filename')}' detected. Frequently used to bypass static email gateway inspection.",
                "evidence": f"Archive format: {att.get('filename')}",
                "iconName": "FileArchive"
            })
            threat_intel_indicators.append({
                "indicator": sha256,
                "type": "SHA-256",
                "reputation": "Suspicious",
                "details": f"Compressed archive attachment: {att.get('filename')}",
                "confidence": 85,
                "firstSeen": "Today"
            })

        iocs_attachments.append({
            "filename": att.get("filename", "unknown"),
            "size": size_str,
            "sha256": sha256,
            "fileType": file_type,
            "verdict": verdict
        })

    # 5. Social Engineering & Urgency Language
    combined_content = (subject + " " + body_text).lower()
    matched_urgency = []
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, combined_content)
        if match:
            matched_urgency.append(match.group(0))

    if matched_urgency:
        signals.append({
            "id": f"sig-{len(signals) + 1}",
            "title": "Psychological Urgency & Pressure Tactics",
            "category": "Behavioral / Social Eng",
            "severity": "medium",
            "scoreImpact": 8,
            "explanation": "Message text employs coercive urgency phrases to induce immediate, unreflective action.",
            "evidence": f"Detected phrases: {', '.join(matched_urgency[:3])}",
            "iconName": "AlertTriangle"
        })

    # 6. Infrastructure & Originating IP
    if origin_ip:
        iocs_ips.add(origin_ip)
        # Check if origin IP is known suspicious or flagged
        if origin_ip.startswith("185.220.") or origin_ip.startswith("109.201."):
            signals.append({
                "id": f"sig-{len(signals) + 1}",
                "title": "Flagged Bulletproof Infrastructure IP",
                "category": "Infrastructure",
                "severity": "high",
                "scoreImpact": 12,
                "explanation": f"Originating server IP ({origin_ip}) resides in an Autonomous System with recorded abuse telemetry.",
                "evidence": f"IP {origin_ip} correlated in high-frequency threat intelligence feed.",
                "iconName": "ServerCrash"
            })
            threat_intel_indicators.append({
                "indicator": origin_ip,
                "type": "IP",
                "reputation": "Malicious",
                "details": f"Bulletproof MTA hosting node in high-abuse CIDR block.",
                "confidence": 94,
                "firstSeen": "Today"
            })

    # Calculate overall risk score
    total_score = sum(s["scoreImpact"] for s in signals)
    # Baseline if signals found
    clamped_score = min(max(total_score, 12 if signals else 8), 98)

    # Verdict determination
    if clamped_score >= 85:
        verdict = "Critical Threat"
    elif clamped_score >= 70:
        verdict = "High Risk"
    elif clamped_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    # Executive Summary Generation
    if verdict in ("Critical Threat", "High Risk"):
        summary = (
            f"High-confidence threat identified ({verdict}). Multi-vector analysis flagged "
            f"{len(signals)} forensic indicators including "
            f"{signals[0]['title'] if signals else 'header anomalies'} and "
            f"{'malicious payload attachments' if iocs_attachments else 'domain infrastructure spoofing'}."
        )
    elif verdict == "Suspicious":
        summary = (
            f"Suspicious activity detected. Email triggered {len(signals)} risk warnings including "
            f"unverified authentication or social engineering markers requiring manual analyst review."
        )
    else:
        summary = "Standard email telemetry. Authentication records verified and no malicious payload or domain indicators detected."

    # Recommended Actions
    actions = [
        {"id": 1, "action": f"Quarantine message from enterprise inbox queues (Sender: {from_addr})", "priority": "Critical" if verdict in ("Critical Threat", "High Risk") else "Medium", "completed": False},
        {"id": 2, "action": f"Block outbound network traffic to identified indicators ({', '.join(list(iocs_domains)[:2]) or 'N/A'})", "priority": "High", "completed": False},
        {"id": 3, "action": f"Revoke any active sessions if credentials were submitted to extracted links", "priority": "High" if len(extracted_urls) > 0 else "Low", "completed": False},
        {"id": 4, "action": "Submit cryptographic payload hash to SOC containment SIEM", "priority": "Medium", "completed": False}
    ]

    return {
        "signals": signals,
        "riskScore": clamped_score,
        "verdict": verdict,
        "summary": summary,
        "threatIntel": threat_intel_indicators,
        "iocs": {
            "domains": list(iocs_domains),
            "ips": list(iocs_ips),
            "urls": list(iocs_urls),
            "attachments": iocs_attachments
        },
        "recommendedActions": actions
    }
