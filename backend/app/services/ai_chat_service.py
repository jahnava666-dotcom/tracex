import re
import os
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
import httpx

from ..core.config import settings
from ..core.security import GEOLOCATION_DISCLAIMER, FORENSIC_INTEGRITY_DISCLAIMER

logger = logging.getLogger("tracex.chat")

# Conversation storage in-memory for active sessions
SESSION_HISTORIES: Dict[str, List[Dict[str, str]]] = {}

INTENT_CATEGORIES = {
    "threat_detection": "Email Threat Detection",
    "header_analysis": "Email Header Analysis",
    "infrastructure_intelligence": "IP & Domain Intelligence",
    "forensics_evidence": "Forensic Investigation & Evidence",
    "app_usage": "TRACE-X Platform Guidance",
    "general_cybersecurity": "Cybersecurity & Incident Response"
}

def normalize_text(text: str) -> str:
    """Normalize user query for resilient intent classification including typos and slang."""
    t = text.lower().strip()
    # Handle common typo variants
    typo_map = {
        r"\bphish\b": "phishing",
        r"\bphissing\b": "phishing",
        r"\bfishing\b": "phishing",
        r"\bspoof\b": "spoofing",
        r"\bspofing\b": "spoofing",
        r"\bspoffing\b": "spoofing",
        r"\bdmrc\b": "dmarc",
        r"\bdmark\b": "dmarc",
        r"\bspff\b": "spf",
        r"\bdkim\b": "dkim",
        r"\bgeoloc\b": "geolocation",
        r"\bgeolocashun\b": "geolocation",
        r"\bgeolocat\b": "geolocation",
        r"\battachement\b": "attachment",
        r"\battachmnt\b": "attachment",
        r"\bmalware\b": "malware",
        r"\bsha256\b": "sha-256",
        r"\bsha 256\b": "sha-256",
        r"\brfc822\b": "rfc-822",
        r"\bwhois\b": "whois"
    }
    for pattern, repl in typo_map.items():
        t = re.sub(pattern, repl, t)
    return t

def classify_intent(normalized: str, raw: str) -> Tuple[str, str, float]:
    """
    Classify user message into (intent_category, sub_topic, confidence).
    """
    # 1. App Usage
    if any(k in normalized for k in ["how to analyze", "how do i analyze", "upload email", "analyze an email", "start analysis", "where to analyze"]):
        return "app_usage", "analyze_email_workflow", 0.95
    if any(k in normalized for k in ["how to use", "using trace-x", "how does trace-x work", "what can trace-x do", "help me use"]):
        return "app_usage", "platform_overview", 0.95
    if any(k in normalized for k in ["where are my cases", "view cases", "find cases", "investigation cases", "list of cases", "open case"]):
        return "app_usage", "cases_navigation", 0.95
    if any(k in normalized for k in ["evidence vault", "where is evidence", "download evidence", "view evidence"]):
        return "app_usage", "evidence_vault_navigation", 0.95
    if any(k in normalized for k in ["generate report", "make report", "download report", "export report", "create report", "pdf report", "dossier"]):
        return "app_usage", "reports_navigation", 0.95
    if any(k in normalized for k in ["explain my risk score", "what is my risk score", "interpret risk score", "why is the score", "score 92", "score 100"]):
        return "app_usage", "risk_score_interpretation", 0.95

    # 2. Email Threat Detection
    if any(k in normalized for k in ["is this mail fake", "is this email fake", "check this email", "could this message be a scam", "is this email suspicious", "is this a scam", "am i being scammed", "fake mail", "fake email"]):
        return "threat_detection", "suspicious_email_assessment", 0.95
    if any(k in normalized for k in ["what is phishing", "phishing email", "how does phishing work", "spear phishing", "credential harvesting"]):
        return "threat_detection", "phishing_explanation", 0.95
    if any(k in normalized for k in ["email spoofing", "how does spoofing work", "spoofed email", "display name spoof"]):
        return "threat_detection", "spoofing_explanation", 0.95
    if any(k in normalized for k in ["bec", "business email compromise", "ceo fraud", "vendor compromise", "wire fraud"]):
        return "threat_detection", "business_email_compromise", 0.95
    if any(k in normalized for k in ["attachment", "zip file", "malicious attachment", "executable in email", "vbs", "dropper", "iso file", "macro"]):
        return "threat_detection", "malicious_attachments", 0.95
    if any(k in normalized for k in ["dmarc", "spf", "dkim", "email authentication", "alignment"]):
        return "threat_detection", "email_authentication_protocols", 0.95

    # 3. Header Analysis
    if any(k in normalized for k in ["explain email headers", "what are headers", "how to read headers", "header analysis", "rfc-822"]):
        return "header_analysis", "headers_explanation", 0.95
    if any(k in normalized for k in ["reply-to", "reply to"]):
        return "header_analysis", "reply_to_field", 0.95
    if any(k in normalized for k in ["return-path", "return path", "envelope sender", "bounce address"]):
        return "header_analysis", "return_path_field", 0.95
    if any(k in normalized for k in ["received header", "received headers", "routing trace", "trace hops", "transit hop", "mta hop"]):
        return "header_analysis", "received_headers_tracing", 0.95
    if any(k in normalized for k in ["inconsistenc", "header anomaly", "header mismatch", "time discrepancy"]):
        return "header_analysis", "header_anomalies", 0.95

    # 4. IP and Domain Intelligence
    if any(k in normalized for k in ["geolocation reliability", "ip reliability", "reliable is ip", "how accurate is ip", "geolocation accuracy", "ip accuracy", "can ip prove identity", "ip limitations", "reliability of ip", "accuracy of geolocation"]):
        return "infrastructure_intelligence", "geolocation_reliability", 0.95
    if any(k in normalized for k in ["ip geolocation", "what is geolocation", "locate ip", "ip location", "geolocate", "geolocation"]):
        return "infrastructure_intelligence", "ip_geolocation_concept", 0.95
    if any(k in normalized for k in ["vpn", "proxy", "tor", "exit node", "open relay", "bulletproof", "anonymizer"]):
        return "infrastructure_intelligence", "anonymization_infrastructure", 0.95
    if any(k in normalized for k in ["whois", "dns", "mx record", "domain age", "domain reputation", "typosquat"]):
        return "infrastructure_intelligence", "dns_whois_intelligence", 0.95

    # 5. Forensic Investigation
    if any(k in normalized for k in ["preserve digital evidence", "preserve evidence", "evidence preservation", "chain of custody", "custody"]):
        return "forensics_evidence", "evidence_preservation", 0.95
    if any(k in normalized for k in ["sha-256", "sha256", "hash", "cryptographic hash", "checksum"]):
        return "forensics_evidence", "sha256_hash_explanation", 0.95
    if any(k in normalized for k in ["verify evidence", "verify integrity", "tamper", "hash verification"]):
        return "forensics_evidence", "evidence_verification", 0.95
    if any(k in normalized for k in ["how do i investigate", "investigate email", "investigation steps", "incident response", "soc triage"]):
        return "forensics_evidence", "investigation_workflow", 0.95

    # 6. General Cybersecurity
    if any(k in normalized for k in ["zero trust", "mfa", "2fa", "firewall", "quarantine", "defensive", "protect", "security recommendations"]):
        return "general_cybersecurity", "defensive_posture", 0.85

    # Default fallback intent
    return "general_cybersecurity", "general_triage", 0.60

def generate_expert_response(
    intent: str,
    topic: str,
    query: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate rich, authoritative, domain-expert cyber-forensic responses when no external LLM is configured.
    """
    case_data = context.get("case_data") if context else None
    active_case_id = context.get("case_id") if context else (case_data.get("caseId") if case_data else None)

    # 1. APP USAGE
    if topic == "analyze_email_workflow":
        return {
            "response": (
                "### How to Analyze an Email in TRACE-X\n\n"
                "TRACE-X provides a secure pipeline for analyzing untrusted email messages without executing active content:\n\n"
                "1. **Navigate to the Analyze Tab**: Click **Analyze Email** in the sidebar or use the button below.\n"
                "2. **Provide the Input Artifact**:\n"
                "   - **Upload File**: Drag and drop a standard `.eml`, `.msg`, or `.txt` file (max 25 MB).\n"
                "   - **Paste RFC-822 Headers**: Paste raw header lines directly into the text tab.\n"
                "   - **Sample Incident Demo**: Click *Load Sample Phishing Email* to test the full analysis pipeline.\n"
                "3. **Automatic Engine Triage**:\n"
                "   - Extracts and verifies SPF, DKIM, and DMARC alignment.\n"
                "   - Parses chronological `Received:` transit hops and maps BGP infrastructure.\n"
                "   - Scans URLs, domains, and calculates cryptographic SHA-256 digests for all payloads.\n"
                "4. **Review Investigation Dossier**: View the composite 0–100 risk score, indicators of compromise (IOCs), and recommended containment actions."
            ),
            "suggested_questions": [
                "How do I interpret a risk score?",
                "What do SPF, DKIM, and DMARC mean?",
                "Where can I find my investigation cases?"
            ],
            "actions": [
                {"label": "Analyze an Email Now", "action": "navigate_analyze"},
                {"label": "Open Dashboard", "action": "navigate_dashboard"}
            ]
        }

    if topic == "cases_navigation":
        return {
            "response": (
                "### Accessing Your Investigation Cases\n\n"
                "All analyzed emails and incident dossiers are preserved in the **Investigations** directory:\n\n"
                "1. Click **Investigations** in the left navigation sidebar.\n"
                "2. View historical cases sorted chronologically, showing Case ID, Subject, Risk Score, Verdict, and Assigned Analyst.\n"
                "3. **Filter & Search**: Quickly search by Case ID (e.g., `CASE-1024`), sender domain, IP address, or status (`Open`, `Under Review`, `Mitigated`, `Closed`).\n"
                "4. Click **View Case** to inspect the full interactive evidence dossier including BGP hop maps, IOC tables, and audit logs."
            ),
            "suggested_questions": [
                "How do I interpret a risk score?",
                "How do I generate a forensic report?",
                "How do I verify evidence integrity?"
            ],
            "actions": [
                {"label": "View Recent Cases", "action": "navigate_cases"},
                {"label": "Open Dashboard", "action": "navigate_dashboard"}
            ]
        }

    if topic == "reports_navigation":
        return {
            "response": (
                "### Generating Forensic Incident Reports\n\n"
                "TRACE-X generates audit-ready forensic documentation formatted for SOC incident response and compliance:\n\n"
                "1. **From Any Active Case**: Click the **Generate Report** button in the header of the investigation dossier.\n"
                "2. **Supported Export Formats**:\n"
                "   - **Forensic PDF/Text Dossier**: Complete technical report including header telemetry, SPF/DKIM/DMARC verdicts, BGP transit hops, and playbooks.\n"
                "   - **STIX 2.1 CTI Bundle**: Structured Cyber Threat Intelligence bundle for ingestion into SIEMs and TIPs.\n"
                "   - **JSON Telemetry**: Machine-readable raw investigation records.\n"
                "3. **Reports Archive**: Access previously generated reports anytime under the **Reports** tab in the sidebar."
            ),
            "suggested_questions": [
                "What is chain of custody?",
                "How do I verify evidence integrity?",
                "What is a SHA-256 hash?"
            ],
            "actions": [
                {"label": "Open Reports Archive", "action": "navigate_reports"},
                {"label": "View Recent Cases", "action": "navigate_cases"}
            ]
        }

    if topic == "risk_score_interpretation":
        score_info = f"For **{active_case_id or 'CASE-1024'}**, the composite threat score is **{case_data.get('riskScore', 92) if case_data else 92}/100** ({case_data.get('verdict', 'Critical Threat') if case_data else 'Critical Threat'}).\n\n" if case_data else ""
        return {
            "response": (
                f"### Interpreting TRACE-X Risk Scores\n\n"
                f"{score_info}"
                "The TRACE-X Risk Score evaluates composite forensic signals on a 0–100 scale:\n\n"
                "- **0 – 29: Likely Safe** (Low Risk). Standard transactional email passing strict SPF, DKIM, and DMARC alignment with reputable infrastructure.\n"
                "- **30 – 59: Suspicious** (Medium Risk). Minor header inconsistencies, newly observed sending MTA, or neutral authentication policy requiring analyst triage.\n"
                "- **60 – 84: High Risk**. Corroborated anomalies such as DMARC failure, lookalike sender domain, deceptive redirects, or sender envelope spoofing.\n"
                "- **85 – 100: Critical Threat**. Multiple high-severity indicators: strict authentication failure, malicious binary attachment dropper, verified credential harvesting links, or known bulletproof VPS transit."
            ),
            "suggested_questions": [
                "What do SPF, DKIM, and DMARC mean?",
                "What is email spoofing?",
                "What should I investigate next?"
            ],
            "actions": [
                {"label": "View Active Case", "action": "navigate_results"},
                {"label": "Open Dashboard", "action": "navigate_dashboard"}
            ]
        }

    # 2. THREAT DETECTION
    if topic in ("suspicious_email_assessment", "phishing_explanation"):
        return {
            "response": (
                "### Evaluating Suspicious & Phishing Emails\n\n"
                "To determine if an email is a phishing attempt, conduct a systematic forensic triage across four layers:\n\n"
                "1. **Header & Sender Alignment**:\n"
                "   - Compare the visible `From:` header with the envelope `Return-Path:`. Discrepancies often indicate spoofing.\n"
                "   - Check **SPF, DKIM, and DMARC** authentication results. A DMARC failure (`p=reject` or `p=quarantine`) signifies an unauthorized sender.\n"
                "2. **Domain & Infrastructure Inspection**:\n"
                "   - Look for typosquatting (e.g., `sec-login.com` instead of `login.com`).\n"
                "   - Check domain registration age; newly registered domains (<30 days old) are disproportionately utilized in credential harvesting.\n"
                "3. **Hyperlink Inspection**:\n"
                "   - Never click links directly. Inspect the target URI for multi-stage HTTP 302 redirects leading to suspicious top-level domains.\n"
                "4. **Payload Analysis**:\n"
                "   - Watch for double extensions (e.g., `Invoice.pdf.vbs` or `.zip` containing scripts).\n\n"
                "**Actionable Next Step**: Upload or paste the raw RFC-822 header into the TRACE-X parser for automated cryptographic and routing analysis."
            ),
            "suggested_questions": [
                "How does email spoofing work?",
                "What do SPF, DKIM, and DMARC mean?",
                "How do I analyze an email?"
            ],
            "actions": [
                {"label": "Analyze this Email", "action": "navigate_analyze"},
                {"label": "View Recent Cases", "action": "navigate_cases"}
            ]
        }

    if topic == "email_authentication_protocols":
        return {
            "response": (
                "### Demystifying SPF, DKIM, and DMARC\n\n"
                "These three foundational standards work together to authenticate email origin and prevent spoofing:\n\n"
                "1. **SPF (Sender Policy Framework)**:\n"
                "   - Published as a DNS TXT record by the domain owner specifying which mail servers (IPs/subnets) are authorized to send email on behalf of their domain.\n"
                "   - Evaluates the envelope sender (`Return-Path`).\n\n"
                "2. **DKIM (DomainKeys Identified Mail)**:\n"
                "   - Provides cryptographic non-repudiation using public-key cryptography.\n"
                "   - The sending server signs header fields and body content with a private key; the receiving MTA fetches the public key from DNS to verify the signature (`d=` tag).\n\n"
                "3. **DMARC (Domain-based Message Authentication, Reporting & Conformance)**:\n"
                "   - Enforces **domain alignment** between the visible RFC 5322 `From:` header and the SPF/DKIM authenticated domains.\n"
                "   - Defines enforcement policies: `p=none` (monitoring only), `p=quarantine` (deliver to spam/quarantine), or `p=reject` (drop at perimeter)."
            ),
            "suggested_questions": [
                "What does Return-Path indicate?",
                "What is business email compromise?",
                "How does email spoofing work?"
            ],
            "actions": [
                {"label": "Analyze an Email", "action": "navigate_analyze"}
            ]
        }

    if topic == "spoofing_explanation":
        return {
            "response": (
                "### Understanding Email Spoofing\n\n"
                "Email spoofing exploits the lack of built-in sender verification in the original SMTP (Simple Mail Transfer Protocol):\n\n"
                "1. **Display Name Spoofing**: The attacker changes their display name to an executive or brand (e.g., `\"CEO Name\" <attacker129@external-mail.com>`). The email address is clearly external, but mobile mail clients often display only the name.\n"
                "2. **Envelope / Header Spoofing**: The attacker crafts forged `From:` headers (e.g., `From: security@yourbank.com`) using open relays or unauthenticated MTAs. Without strict DMARC enforcement, mail systems may accept the forged address.\n"
                "3. **Lookalike / Cousin Domains**: Registering domains with subtle character substitutions (homoglyph attacks, e.g., using `rn` instead of `m`, or alternative TLDs).\n\n"
                "**Defense**: Enforce DMARC `p=reject`, implement external sender email banners, and train staff on verifying sender addresses."
            ),
            "suggested_questions": [
                "What is business email compromise?",
                "What do SPF, DKIM, and DMARC mean?",
                "How can malicious attachments be investigated?"
            ],
            "actions": [
                {"label": "Analyze an Email", "action": "navigate_analyze"}
            ]
        }

    if topic == "business_email_compromise":
        return {
            "response": (
                "### Business Email Compromise (BEC)\n\n"
                "BEC is a sophisticated social engineering scheme that rarely relies on malicious malware payloads, making traditional antivirus blind to it:\n\n"
                "1. **Common Scenarios**:\n"
                "   - **Vendor Email Compromise (VEC)**: Intercepting invoice threads and requesting emergency modifications to wire routing details.\n"
                "   - **Executive Impersonation**: Urgently directing finance personnel to acquire gift cards or initiate wire transfers under strict confidentiality.\n"
                "   - **Account Takeover (ATO)**: Compromising valid employee credentials to send internal spear-phishing messages from legitimate mailboxes.\n"
                "2. **Forensic Indicators**:\n"
                "   - Discrepancies between `From:` and `Reply-To:` headers.\n"
                "   - Urgent language demanding deviation from normal verification procedures.\n"
                "   - Anomalous BGP routing hops or logins from uncharacteristic ASNs/countries.\n\n"
                "**Mitigation**: Mandate secondary out-of-band voice confirmation for all wire instructions and enforce FIDO2 hardware MFA."
            ),
            "suggested_questions": [
                "What is the Reply-To field?",
                "How do Received headers help trace email routing?",
                "What is IP geolocation?"
            ],
            "actions": [
                {"label": "Review Recent Cases", "action": "navigate_cases"}
            ]
        }

    if topic == "malicious_attachments":
        return {
            "response": (
                "### Investigating Malicious Email Attachments\n\n"
                "When analyzing suspicious file payloads, observe strict safety protocols:\n\n"
                "1. **Zero-Execution Rule**: Never double-click, unpack, or execute attachments on an analyst workstation. TRACE-X inspects files safely without executing code.\n"
                "2. **Double Extensions & Deceptive MIME Types**: Common techniques include naming files `Report_2026.pdf.vbs` or nesting executables within password-protected archives (`.zip`, `.7z`, `.iso`, `.img`) to bypass static perimeter filters.\n"
                "3. **Cryptographic Hashing**: Calculate authentic SHA-256 digests directly from the raw byte stream to query threat intelligence databases without disclosing proprietary content.\n"
                "4. **High File Entropy**: Files with entropy scores above 7.2 typically indicate encrypted or heavily packed droppers.\n"
                "5. **Isolated Sandboxing**: Detonate payloads exclusively within air-gapped, instrumented sandbox environments."
            ),
            "suggested_questions": [
                "What is a SHA-256 hash?",
                "How do I preserve digital evidence?",
                "How do I verify evidence integrity?"
            ],
            "actions": [
                {"label": "Open Evidence Vault", "action": "navigate_evidence"},
                {"label": "Analyze an Email", "action": "navigate_analyze"}
            ]
        }

    # 3. HEADER ANALYSIS
    if topic in ("headers_explanation", "reply_to_field", "return_path_field", "received_headers_tracing", "header_anomalies"):
        return {
            "response": (
                "### Email Header Forensics & Route Tracing\n\n"
                "RFC 5322 email headers document the entire transit history of a message across the internet:\n\n"
                "1. **`Received:` Headers (Chronological Route)**:\n"
                "   - Read from **bottom to top**. The bottom-most `Received:` header represents the originating client or first hop MTA.\n"
                "   - Each intermediate mail transfer agent (MTA) appends its own IP address, timestamp, and TLS cipher details.\n"
                "   - **Transit Latency**: Time differences greater than 5 seconds between hops often indicate intermediate queuing or malicious proxy hops.\n"
                "2. **`From:` vs `Reply-To:`**:\n"
                "   - `From:` specifies the author displayed to the recipient.\n"
                "   - `Reply-To:` directs where client replies are routed. Discrepancies are a hallmark of phishing and BEC campaigns.\n"
                "3. **`Return-Path:` (Envelope Sender)**:\n"
                "   - Set during the SMTP `MAIL FROM` command where non-delivery reports (bounces) are sent. Used by SPF for validation.\n"
                "4. **`Message-ID` & Timestamp Anomalies**:\n"
                "   - Legitimate systems use standardized, domain-correlated syntax. Missing or generic IDs point to automated spam tools."
            ),
            "suggested_questions": [
                "What is IP geolocation?",
                "What do SPF, DKIM, and DMARC mean?",
                "How do I analyze an email?"
            ],
            "actions": [
                {"label": "Analyze an Email Now", "action": "navigate_analyze"}
            ]
        }

    # 4. INFRASTRUCTURE & IP INTELLIGENCE
    if topic in ("ip_geolocation_concept", "geolocation_reliability", "anonymization_infrastructure", "dns_whois_intelligence"):
        return {
            "response": (
                "### IP Geolocation, BGP Routing & Attribution Realities\n\n"
                "Network intelligence allows analysts to trace infrastructure, but requires understanding its forensic boundaries:\n\n"
                "1. **How IP Geolocation Works**:\n"
                "   - Maps IP addresses to Autonomous System Numbers (ASNs), Internet Service Providers (ISPs), and estimated regional coordinates based on BGP routing announcements and registry allocations (RIPE, ARIN, APNIC).\n"
                "2. **Important Attribution Caveat & Legal Disclaimer**:\n"
                f"   > *{GEOLOCATION_DISCLAIMER}*\n"
                "   - An IP address identifies network transit infrastructure—it does **NOT** establish the personal identity or physical home address of an individual.\n"
                "3. **Anonymization Tactics**:\n"
                "   - Adversaries route traffic through bulletproof VPS hosting, residential proxies, commercial VPNs, or Tor exit nodes to obscure their origin.\n"
                "4. **WHOIS & Domain Intelligence**:\n"
                "   - Examine domain registration dates, name server consistency, and registrar privacy shields to evaluate infrastructure trustworthiness."
            ),
            "suggested_questions": [
                "How do Received headers help trace email routing?",
                "What is a SHA-256 hash?",
                "How do I preserve digital evidence?"
            ],
            "actions": [
                {"label": "View Threat Intelligence", "action": "navigate_threat_intel"},
                {"label": "Open Dashboard", "action": "navigate_dashboard"}
            ]
        }

    # 5. FORENSIC INVESTIGATION & EVIDENCE
    if topic in ("evidence_preservation", "sha256_hash_explanation", "evidence_verification", "investigation_workflow"):
        return {
            "response": (
                "### Digital Forensics, Evidence Preservation & Hash Verification\n\n"
                "Digital evidence must satisfy admissibility standards through strict chain-of-custody protocols:\n\n"
                "1. **Evidence Acquisition**:\n"
                "   - Capture the complete, uncompressed RFC-822 `.eml` file including all headers and MIME boundaries.\n"
                "   - Do not open files in desktop mail clients that modify read status or attachment timestamps.\n"
                "2. **Cryptographic SHA-256 Digesting**:\n"
                "   - A SHA-256 algorithm calculates a 256-bit mathematical fingerprint directly from raw bytes. Even a single modified bit alters the hash completely (the avalanche effect).\n"
                f"   > *{FORENSIC_INTEGRITY_DISCLAIMER}*\n"
                "3. **Chain of Custody & Audit Trails**:\n"
                "   - Every action in TRACE-X is recorded to an append-only audit log with timestamp, analyst identity, and hash confirmation.\n"
                "4. **Integrity Verification in TRACE-X**:\n"
                "   - Open the **Evidence Vault** and use the **Verify Hash** tool to cryptographically confirm that stored evidence matches expected hashes."
            ),
            "suggested_questions": [
                "How do I verify evidence integrity?",
                "How do I generate a forensic report?",
                "How do I analyze an email?"
            ],
            "actions": [
                {"label": "Open Evidence Vault", "action": "navigate_evidence"},
                {"label": "View Case Reports", "action": "navigate_reports"}
            ]
        }

    # 6. GENERAL CYBERSECURITY / DEFAULT
    return {
        "response": (
            "### TRACE-X Forensic Intelligence Guidance\n\n"
            "I can assist your security operations across multiple investigation disciplines:\n\n"
            "1. **Email Threat Detection**: Identifying phishing campaigns, email spoofing, and malicious payloads.\n"
            "2. **Authentication Triage**: Evaluating SPF mechanisms, DKIM key validation, and strict DMARC alignment.\n"
            "3. **Routing & Geolocation**: Mapping chronological MTA transit hops and autonomous system network (ASN) intelligence.\n"
            "4. **Forensic Evidence**: Managing the SHA-256 Evidence Vault, generating incident dossiers, and verifying digital chain of custody.\n\n"
            "What specific email, indicator, or case would you like to examine?"
        ),
        "suggested_questions": [
            "How do I analyze an email?",
            "What is phishing?",
            "What do SPF, DKIM, and DMARC mean?",
            "How does IP geolocation work?"
        ],
        "actions": [
            {"label": "Analyze an Email", "action": "navigate_analyze"},
            {"label": "Open Dashboard", "action": "navigate_dashboard"},
            {"label": "View Recent Cases", "action": "navigate_cases"}
        ]
    }

async def call_external_llm(
    prompt: str,
    system_prompt: str,
    conversation_history: List[Dict[str, str]]
) -> Optional[str]:
    """
    Modular integration with external AI LLMs (OpenAI, Gemini, Anthropic, Ollama, Groq).
    Returns the string response or None if not configured or failed.
    """
    # 1. Check OpenAI
    if settings.OPENAI_API_KEY:
        try:
            headers = {
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }
            messages = [{"role": "system", "content": system_prompt}]
            for msg in conversation_history[-6:]:
                messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            messages.append({"role": "user", "content": prompt})

            async with httpx.AsyncClient(timeout=25.0) as client:
                res = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": messages,
                        "temperature": 0.2
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"[TRACE-X LLM] OpenAI call failed: {e}")

    # 2. Check Gemini
    if settings.GEMINI_API_KEY:
        try:
            model = settings.GEMINI_MODEL or "gemini-1.5-flash"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.GEMINI_API_KEY}"
            contents = []
            for msg in conversation_history[-6:]:
                role = "user" if msg.get("role") == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
            contents.append({"role": "user", "parts": [{"text": f"{system_prompt}\n\nUser Question: {prompt}"}]})

            async with httpx.AsyncClient(timeout=25.0) as client:
                res = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={"contents": contents}
                )
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        return candidates[0]["content"]["parts"][0]["text"]
        except Exception as e:
            logger.warning(f"[TRACE-X LLM] Gemini call failed: {e}")

    # 3. Check Groq
    if settings.GROQ_API_KEY:
        try:
            headers = {
                "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            messages = [{"role": "system", "content": system_prompt}]
            for msg in conversation_history[-6:]:
                messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            messages.append({"role": "user", "content": prompt})

            async with httpx.AsyncClient(timeout=25.0) as client:
                res = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": messages,
                        "temperature": 0.2
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"[TRACE-X LLM] Groq call failed: {e}")

    # 4. Check Ollama local instance
    if settings.OLLAMA_BASE_URL:
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                res = await client.post(
                    f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat",
                    headers={"Content-Type": "application/json"},
                    json={
                        "model": settings.OLLAMA_MODEL or "llama3",
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        "stream": False
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    return data.get("message", {}).get("content")
        except Exception as e:
            logger.warning(f"[TRACE-X LLM] Ollama call failed: {e}")

    return None

async def process_chat_message(
    message: str,
    conversation_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main orchestrator for the TRACE-X Assistant chatbot.
    Handles intent classification, context enrichment, LLM routing, and expert rule fallback.
    """
    normalized = normalize_text(message)
    intent_cat, sub_topic, confidence = classify_intent(normalized, message)
    conv_id = conversation_id or "default-session"

    # Maintain in-memory session history
    if conv_id not in SESSION_HISTORIES:
        SESSION_HISTORIES[conv_id] = []

    history = SESSION_HISTORIES[conv_id]

    # Context enrichment
    case_context_str = ""
    if context and context.get("case_data"):
        c = context["case_data"]
        case_context_str = (
            f"Active Case: {c.get('caseId')} | Subject: {c.get('subject')} | "
            f"Verdict: {c.get('verdict')} | Score: {c.get('riskScore')}/100 | "
            f"Sender: {c.get('from')} | Primary IP: {c.get('primaryInfrastructure', {}).get('ip')}"
        )

    system_prompt = (
        "You are TRACE-X Assistant, an expert digital forensics and email threat intelligence copilot "
        "designed for SOC Tier 2/3 security analysts. "
        "Product: TRACE-X (AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform). "
        "Tagline: Detect. Trace. Investigate. "
        "Guidelines:\n"
        "1. Give direct, authoritative, professional answers first.\n"
        "2. Explain technical concepts (SPF, DKIM, DMARC, BGP hops, SHA-256) clearly.\n"
        "3. Provide numbered steps when giving operational or triage guidance.\n"
        "4. Always distinguish observed evidence from inferred findings.\n"
        "5. Remember that IP geolocation represents network infrastructure routing and does not prove an attacker's personal physical identity.\n"
        "6. Do not fabricate threat intelligence or claims of external verification.\n"
        f"{case_context_str}"
    )

    # 1. Try configured external LLM
    llm_response = await call_external_llm(
        prompt=message,
        system_prompt=system_prompt,
        conversation_history=history
    )

    if llm_response:
        # Append to history
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": llm_response})
        if len(history) > 20:
            history = history[-20:]
            SESSION_HISTORIES[conv_id] = history

        # Determine contextual action buttons
        actions = []
        if intent_cat == "app_usage" or "analyze" in normalized:
            actions.append({"label": "Analyze an Email", "action": "navigate_analyze"})
        if "case" in normalized or "investigation" in normalized:
            actions.append({"label": "View Recent Cases", "action": "navigate_cases"})
        if "evidence" in normalized or "vault" in normalized or "hash" in normalized:
            actions.append({"label": "Review Evidence Vault", "action": "navigate_evidence"})
        if "report" in normalized:
            actions.append({"label": "Generate Report", "action": "navigate_reports"})

        return {
            "response": llm_response,
            "conversation_id": conv_id,
            "intent": intent_cat,
            "topic": sub_topic,
            "confidence": confidence,
            "mode": "ai_llm",
            "provider": "Configured LLM",
            "suggested_questions": [
                "Explain SPF, DKIM, and DMARC",
                "What is the reliability of IP geolocation?",
                "How do I preserve digital evidence?"
            ],
            "actions": actions or [{"label": "Open Dashboard", "action": "navigate_dashboard"}],
            "disclaimer": "Defensive forensic guidance powered by TRACE-X."
        }

    # 2. Rule-Based Forensic Expert Engine Fallback
    expert_result = generate_expert_response(
        intent=intent_cat,
        topic=sub_topic,
        query=message,
        context=context
    )

    # Append to history
    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": expert_result["response"]})
    if len(history) > 20:
        history = history[-20:]
        SESSION_HISTORIES[conv_id] = history

    return {
        "response": expert_result["response"],
        "conversation_id": conv_id,
        "intent": intent_cat,
        "topic": sub_topic,
        "confidence": confidence,
        "mode": "rule_based_expert",
        "provider": "TRACE-X Cyber-Forensic Knowledge Engine",
        "suggested_questions": expert_result.get("suggested_questions", [
            "How do I analyze an email?",
            "What is phishing?",
            "How do I verify evidence integrity?"
        ]),
        "actions": expert_result.get("actions", [{"label": "Open Dashboard", "action": "navigate_dashboard"}]),
        "disclaimer": "Operating in TRACE-X Rule-Based Forensic Expert Mode. (Full AI LLM requires configuring an API key in backend/.env)"
    }
