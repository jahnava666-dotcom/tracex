from datetime import datetime
from sqlalchemy.orm import Session
from .session import engine, SessionLocal, Base
from ..models.case import CaseModel
from ..models.evidence import EvidenceModel
from ..models.threat_intel import ThreatIndicatorModel
from ..models.audit import AuditLogModel
from ..models.report import ReportModel
from ..core.security import FORENSIC_INTEGRITY_DISCLAIMER

# Seed data based on CASE-1024 and initial mock data
CASE_1024_SEED = {
    "case_id": "CASE-1024",
    "email": "security@secure-login-example.com",
    "date": "Today, 10:32:04 AM",
    "received_time": "10:32:04 UTC",
    "subject": "Urgent Account Verification Required",
    "from_address": "security@secure-login-example.com",
    "reply_to": "support@secure-login-example.net",
    "return_path": "<bounces-srv992@bullet-vps-net.org>",
    "message_id": "<20260910103204.77491.qmail@mta-nl-relay.net>",
    "risk_score": 92,
    "verdict": "Critical Threat",
    "summary": "High-confidence credential phishing and malicious ZIP dropper campaign leveraging typosquatted banking domain and header spoofing.",
    "status": "Open",
    "assigned_analyst": "Alex Carter (SOC Tier 2)",
    "auth": {
        "spf": {
            "status": "FAIL",
            "label": "SPF: FAIL",
            "summary": "The sending server is not authorized by the domain's SPF policy.",
            "technicalDetails": "v=spf1 include:_spf.google.com ~all - IP 185.220.101.42 not listed in designated SPF mechanism.",
            "recordFound": "v=spf1 -all",
            "verificationSource": "live_dns"
        },
        "dkim": {
            "status": "SUSPICIOUS",
            "label": "DKIM: SUSPICIOUS",
            "summary": "The email signature could not be fully validated.",
            "technicalDetails": "Signature d=secure-login-example.com failed cryptographic hash verification (bodyhash_mismatch). Key length: RSA-1024.",
            "recordFound": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...",
            "verificationSource": "header_telemetry"
        },
        "dmarc": {
            "status": "FAIL",
            "label": "DMARC: FAIL",
            "summary": "Domain alignment failed.",
            "technicalDetails": "Header From domain (secure-login-example.com) does not align with SPF sender envelope or DKIM d= value under strict policy (p=reject).",
            "recordFound": "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@secure-login-example.com",
            "verificationSource": "live_dns"
        }
    },
    "signals": [
        {
            "id": "sig-1",
            "title": "Sender Spoofing",
            "category": "Header Integrity",
            "severity": "critical",
            "scoreImpact": 20,
            "explanation": "From address claims secure-login-example.com while Return-Path routes to an unverified third-party VPS relay.",
            "evidence": "From: security@secure-login-example.com != Return-Path: bounces-srv992@bullet-vps-net.org",
            "iconName": "UserX"
        },
        {
            "id": "sig-2",
            "title": "DMARC Failure",
            "category": "Authentication",
            "severity": "high",
            "scoreImpact": 15,
            "explanation": "Domain alignment failed with strict reject enforcement triggered on originating MTA.",
            "evidence": "DKIM and SPF alignment checks both failed against RFC 7489 specification.",
            "iconName": "ShieldAlert"
        },
        {
            "id": "sig-3",
            "title": "Suspicious Domain",
            "category": "Domain Intelligence",
            "severity": "high",
            "scoreImpact": 15,
            "explanation": "Domain resembles a legitimate banking portal with typosquatting keywords and was registered only 12 days ago.",
            "evidence": "Domain age: 12 days | Registrar: NameSilo LLC | Whois privacy enabled",
            "iconName": "Globe"
        },
        {
            "id": "sig-4",
            "title": "Malicious URL",
            "category": "Link Analysis",
            "severity": "critical",
            "scoreImpact": 20,
            "explanation": "URL redirects to an unexpected credential harvesting landing page matching known phishing telemetry.",
            "evidence": "https://secure-login-example.com/login -> 302 Redirect to https://auth-verify-portal9.ru/session",
            "iconName": "ExternalLink"
        },
        {
            "id": "sig-5",
            "title": "Suspicious Attachment",
            "category": "Payload Analysis",
            "severity": "medium",
            "scoreImpact": 10,
            "explanation": "Double-extension ZIP archive containing obfuscated VBScript/dropper payload designed to bypass static mail filters.",
            "evidence": "Invoice_2026.zip contains Invoice_2026_PDF.vbs (Entropy: 7.84, SHA256 match in C2 db)",
            "iconName": "FileArchive"
        },
        {
            "id": "sig-6",
            "title": "Urgency Language",
            "category": "Behavioral / Social Eng",
            "severity": "medium",
            "scoreImpact": 7,
            "explanation": "Message text employs severe pressure tactics threatening 24-hour account suspension if action is not taken immediately.",
            "evidence": "\"Immediate action required within 24 hours to prevent permanent account suspension.\"",
            "iconName": "AlertTriangle"
        },
        {
            "id": "sig-7",
            "title": "Reputation",
            "category": "Infrastructure",
            "severity": "high",
            "scoreImpact": 5,
            "explanation": "Originating IP resides within an ASN frequently flagged for hosting bulletproof VPS relays and malware delivery.",
            "evidence": "IP 185.220.101.42 has 38 abuse reports in past 14 days (Confidence: 94%).",
            "iconName": "ServerCrash"
        }
    ],
    "infrastructure_hops": [
        {
            "id": 1,
            "step": "Hop 1: Origin",
            "label": "Email Sender",
            "ip": "109.201.133.15",
            "country": "Romania",
            "region": "Bucharest",
            "asn": "AS208598 (Host Sailor Ltd)",
            "isp": "HostSailor Romania Dedicated",
            "hostingType": "MTA",
            "status": "suspicious",
            "timestamp": "10:32:04 UTC",
            "latency": "+0ms",
            "coordinates": [44.4268, 26.1025]
        },
        {
            "id": 2,
            "step": "Hop 2: Outbound MTA",
            "label": "Mail Server",
            "ip": "194.26.29.112",
            "country": "Germany",
            "region": "Frankfurt",
            "asn": "AS51167 (Contabo GmbH)",
            "isp": "Contabo Cloud VPS",
            "hostingType": "VPS",
            "status": "suspicious",
            "timestamp": "10:32:07 UTC",
            "latency": "+3.1s",
            "coordinates": [50.1109, 8.6821]
        },
        {
            "id": 3,
            "step": "Hop 3: Anonymizing Relay",
            "label": "Relay Server",
            "ip": "185.220.101.42",
            "country": "Netherlands",
            "region": "North Holland",
            "asn": "AS208294 (Relay B.V.)",
            "isp": "Bulletproof VPS Transit",
            "hostingType": "VPS",
            "status": "malicious",
            "timestamp": "10:32:10 UTC",
            "latency": "+2.8s",
            "coordinates": [52.3676, 4.9041]
        },
        {
            "id": 4,
            "step": "Hop 4: Cloud Proxy",
            "label": "Border Gateway",
            "ip": "198.51.100.5",
            "country": "United States",
            "region": "California",
            "asn": "AS13335 (Cloudflare Inc.)",
            "isp": "Cloudflare Global Edge",
            "hostingType": "Cloud",
            "status": "clean",
            "timestamp": "10:32:12 UTC",
            "latency": "+1.9s",
            "coordinates": [37.7749, -122.4194]
        },
        {
            "id": 5,
            "step": "Hop 5: Destination Ingestion",
            "label": "Corporate Gateway",
            "ip": "142.250.80.36",
            "country": "United States",
            "region": "California",
            "asn": "AS15169 (Google LLC)",
            "isp": "Enterprise Email Security MTA",
            "hostingType": "Enterprise Mail Gateway",
            "status": "clean",
            "timestamp": "10:32:14 UTC",
            "latency": "+1.2s",
            "coordinates": [37.3861, -122.0839]
        }
    ],
    "primary_infrastructure": {
        "ip": "185.220.101.42",
        "country": "Netherlands",
        "region": "North Holland",
        "city": "Amsterdam",
        "asn": "AS208294 (Relay B.V.)",
        "isp": "Bulletproof VPS Transit",
        "hosting": "Bulletproof VPS",
        "reverseDns": "mta-nl-relay.net",
        "coordinates": [52.3676, 4.9041]
    },
    "timeline": [
        {
            "id": "ev-1",
            "timestamp": "10:32:04 UTC",
            "event": "Outbound Relay Dispatched",
            "node": "HostSailor Bucharest",
            "ip": "109.201.133.15",
            "status": "normal",
            "details": "Outbound MTA handshake completed via port 587 without client certificate."
        },
        {
            "id": "ev-2",
            "timestamp": "10:32:07 UTC",
            "event": "Transit Hop Latency Spike",
            "node": "Contabo Frankfurt VPS",
            "ip": "194.26.29.112",
            "status": "flagged",
            "details": "Header delay +3.1s anomalous for standard transactional automated outbound pipeline."
        },
        {
            "id": "ev-3",
            "timestamp": "10:32:10 UTC",
            "event": "Anonymizing Relay Relay Intercept",
            "node": "Amsterdam Bulletproof VPS",
            "ip": "185.220.101.42",
            "status": "alert",
            "details": "Header From spoofed. Return-Path altered to bounces-srv992@bullet-vps-net.org."
        },
        {
            "id": "ev-4",
            "timestamp": "10:32:14 UTC",
            "event": "Destination MTA Ingestion",
            "node": "Corporate Border Gateway",
            "ip": "142.250.80.36",
            "status": "alert",
            "details": "DMARC policy strict reject triggered. Message quarantined for Tier 2 SOC forensic inspection."
        }
    ],
    "threat_intel": [
        {
            "indicator": "secure-login-example.com",
            "type": "Domain",
            "reputation": "Malicious",
            "details": "Registered 12 days ago via NameSilo. Typo-squatting campaign target.",
            "confidence": 92,
            "firstSeen": "2026-09-08"
        },
        {
            "indicator": "185.220.101.42",
            "type": "IP",
            "reputation": "Malicious",
            "details": "Bulletproof VPS node in Amsterdam ASN208294. 38 abuse reports in 14 days.",
            "confidence": 94,
            "firstSeen": "2026-08-14"
        },
        {
            "indicator": "https://secure-login-example.com/login",
            "type": "URL",
            "reputation": "Malicious",
            "details": "Redirects to credential harvesting kit mimicking internal SSO portal.",
            "confidence": 96,
            "firstSeen": "2026-09-10"
        },
        {
            "indicator": "Invoice_2026.zip",
            "type": "Attachment",
            "reputation": "Suspicious",
            "details": "Password-protected archive containing hidden VBScript loader dropper.",
            "confidence": 88,
            "firstSeen": "2026-09-10"
        },
        {
            "indicator": "9a84f3e120938402948201948201938401928340192834019283401928340192",
            "type": "SHA-256",
            "reputation": "Malicious",
            "details": "SHA256 signature matching known RedLine stealer dropper variant.",
            "confidence": 98,
            "firstSeen": "2026-09-09"
        }
    ],
    "iocs": {
        "domains": ["secure-login-example.com", "bullet-vps-net.org", "auth-verify-portal9.ru"],
        "ips": ["185.220.101.42", "194.26.29.112", "109.201.133.15"],
        "urls": ["https://secure-login-example.com/login", "https://auth-verify-portal9.ru/session"],
        "attachments": [
            {
                "filename": "Invoice_2026.zip",
                "size": "124.5 KB",
                "sha256": "9a84f3e120938402948201948201938401928340192834019283401928340192",
                "fileType": "application/zip",
                "verdict": "Malicious ZIP Dropper"
            }
        ]
    },
    "recommended_actions": [
        {"id": 1, "action": "Block sender IP 185.220.101.42 on border firewall and inbound mail relays.", "priority": "Critical", "completed": False},
        {"id": 2, "action": "Add domain secure-login-example.com to global enterprise DNS sinkhole.", "priority": "Critical", "completed": False},
        {"id": 3, "action": "Purge all received emails with Message-ID containing 'bullet-vps-net.org'.", "priority": "High", "completed": False},
        {"id": 4, "action": "Force password reset & invalidate active sessions for 3 recipients who clicked login URL.", "priority": "High", "completed": False},
        {"id": 5, "action": "Submit ZIP payload SHA-256 to endpoint detection (EDR) blocklist.", "priority": "Medium", "completed": False}
    ],
    "raw_headers": (
        "Received: from mta-nl-relay.net (185.220.101.42) by mx.google.com with ESMTPS id q194...\n"
        "From: \"Security Team\" <security@secure-login-example.com>\n"
        "Reply-To: support@secure-login-example.net\n"
        "Return-Path: <bounces-srv992@bullet-vps-net.org>\n"
        "Subject: Urgent Account Verification Required\n"
        "Date: Today, 10:32:04 AM\n"
        "Message-ID: <20260910103204.77491.qmail@mta-nl-relay.net>\n"
        "Authentication-Results: mx.google.com; dkim=fail (body hash mismatch); spf=fail (IP 185.220.101.42); dmarc=fail (p=reject)\n"
    ),
    "is_simulated_demo": False,
    "geo_metadata": {
        "provider": "TRACE-X BGP Forensic Gateway",
        "lookupTimestamp": datetime.utcnow().isoformat(),
        "confidence": 92,
        "isSimulated": False,
        "disclaimer": "IP geolocation represents network infrastructure routing and Autonomous System (ASN) intelligence. It does not prove or establish the physical location, identity, or personal device of an attacker."
    }
}

SECONDARY_CASES = [
    {
        "case_id": "CASE-1023",
        "email": "invoices@vendor-update-billing.org",
        "date": "Yesterday, 4:18 PM",
        "received_time": "16:18:22 UTC",
        "subject": "Overdue Invoice Notice #INV-88219 - Wire Transfer Instructions",
        "from_address": "invoices@vendor-update-billing.org",
        "reply_to": "finance-dept@external-payment-hop.net",
        "return_path": "<mailer@billing-relay-vps.de>",
        "message_id": "<20260909161822.4491@vendor-update-billing.org>",
        "risk_score": 78,
        "verdict": "High Risk",
        "summary": "Vendor email compromise attempt requesting sudden payment routing modifications.",
        "status": "Under Review",
        "assigned_analyst": "Sarah Chen (Forensics Lead)",
        "auth": CASE_1024_SEED["auth"],
        "signals": CASE_1024_SEED["signals"][:4],
        "infrastructure_hops": CASE_1024_SEED["infrastructure_hops"],
        "primary_infrastructure": CASE_1024_SEED["primary_infrastructure"],
        "timeline": CASE_1024_SEED["timeline"][:3],
        "threat_intel": CASE_1024_SEED["threat_intel"][:3],
        "iocs": {"domains": ["vendor-update-billing.org"], "ips": ["194.26.29.112"], "urls": [], "attachments": []},
        "recommended_actions": CASE_1024_SEED["recommended_actions"][:3],
        "raw_headers": "Subject: Overdue Invoice Notice #INV-88219\nFrom: invoices@vendor-update-billing.org",
        "is_simulated_demo": False,
        "geo_metadata": CASE_1024_SEED["geo_metadata"]
    },
    {
        "case_id": "CASE-1022",
        "email": "notifications@gitlab-updates.io",
        "date": "Sep 8, 2:11 PM",
        "received_time": "14:11:05 UTC",
        "subject": "[GitLab] Pipeline #49102 Succeeded for branch main",
        "from_address": "notifications@gitlab-updates.io",
        "reply_to": "noreply@gitlab-updates.io",
        "return_path": "<bounces@gitlab-updates.io>",
        "message_id": "<20260908141105.88219@gitlab-updates.io>",
        "risk_score": 12,
        "verdict": "Likely Safe",
        "summary": "Legitimate CI/CD notification email from authenticated enterprise runner.",
        "status": "Closed",
        "assigned_analyst": "Automated Policy Engine",
        "auth": {
            "spf": {"status": "PASS", "label": "SPF: PASS", "summary": "Authorized sender.", "technicalDetails": "v=spf1 include:_spf.gitlab.com ~all", "recordFound": "v=spf1 -all", "verificationSource": "live_dns"},
            "dkim": {"status": "PASS", "label": "DKIM: PASS", "summary": "Signature valid.", "technicalDetails": "d=gitlab-updates.io RSA-2048 verified.", "recordFound": "v=DKIM1;", "verificationSource": "live_dns"},
            "dmarc": {"status": "PASS", "label": "DMARC: PASS", "summary": "Aligned policy.", "technicalDetails": "Strict alignment passed.", "recordFound": "v=DMARC1; p=reject", "verificationSource": "live_dns"}
        },
        "signals": [],
        "infrastructure_hops": CASE_1024_SEED["infrastructure_hops"][3:],
        "primary_infrastructure": CASE_1024_SEED["primary_infrastructure"],
        "timeline": CASE_1024_SEED["timeline"][:2],
        "threat_intel": [],
        "iocs": {"domains": ["gitlab-updates.io"], "ips": [], "urls": [], "attachments": []},
        "recommended_actions": [],
        "raw_headers": "Subject: [GitLab] Pipeline Succeeded\nFrom: notifications@gitlab-updates.io",
        "is_simulated_demo": False,
        "geo_metadata": CASE_1024_SEED["geo_metadata"]
    }
]

def init_db():
    """Create all database tables and seed initial data if empty."""
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # Check if cases already exist
        existing_cases = db.query(CaseModel).count()
        if existing_cases == 0:
            print("[TRACE-X DB] Initializing tables with seed investigation cases...")
            
            # Add CASE-1024
            c1 = CaseModel(**CASE_1024_SEED)
            db.add(c1)
            
            # Add secondary cases
            for sc in SECONDARY_CASES:
                db.add(CaseModel(**sc))
                
            # Seed Evidence items
            ev1 = EvidenceModel(
                id="ev-1024-01",
                investigation_id="CASE-1024",
                user_id="analyst-tier2",
                evidence_type="EML RFC-822 Raw Headers",
                description="Original inbound email stream captured at border MTA relay",
                source="border-mta-amsterdam.org",
                sha256_hash="c83f5e929b9a67812984920409823901b0b30d32104928402930219483019384",
                integrity_status="verified",
                metadata_json={
                    "fileName": "phish_incident_case1024.eml",
                    "fileSize": 48920,
                    "mimeType": "message/rfc822",
                    "collectedAt": "2026-09-10T10:32:04Z",
                    "verifiedAt": datetime.utcnow().isoformat(),
                    "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
                }
            )
            ev2 = EvidenceModel(
                id="ev-1024-02",
                investigation_id="CASE-1024",
                user_id="analyst-tier2",
                evidence_type="Malicious Attachment Dropper",
                description="Extracted password-protected ZIP archive containing VBScript payload",
                source="Invoice_2026.zip",
                sha256_hash="9a84f3e120938402948201948201938401928340192834019283401928340192",
                integrity_status="verified",
                metadata_json={
                    "fileName": "Invoice_2026.zip",
                    "fileSize": 124500,
                    "mimeType": "application/zip",
                    "collectedAt": "2026-09-10T10:33:15Z",
                    "verifiedAt": datetime.utcnow().isoformat(),
                    "forensicDisclaimer": FORENSIC_INTEGRITY_DISCLAIMER
                }
            )
            db.add(ev1)
            db.add(ev2)
            
            # Seed Threat Indicators
            for ind in CASE_1024_SEED["threat_intel"]:
                db.add(ThreatIndicatorModel(
                    case_id="CASE-1024",
                    indicator=ind["indicator"],
                    indicator_type=ind["type"],
                    reputation=ind["reputation"],
                    details=ind["details"],
                    confidence=ind["confidence"],
                    first_seen=ind["firstSeen"],
                    metadata_json={"source": "Automated Seed"}
                ))
                
            # Seed Audit Trail
            db.add(AuditLogModel(
                action="CASE_CREATED",
                resource_type="INVESTIGATION",
                resource_id="CASE-1024",
                metadata_json={"title": CASE_1024_SEED["subject"], "verdict": CASE_1024_SEED["verdict"]}
            ))
            
            # Seed Initial Report
            db.add(ReportModel(
                report_id="REP-2026-1024",
                case_id="CASE-1024",
                title="Forensic Dossier: CASE-1024",
                threat_level="Critical Threat",
                risk_score=92,
                format="PDF",
                summary="Automated forensic export containing header anomalies, IOCs, SPF/DKIM/DMARC breakdown, and remediation plan for CASE-1024."
            ))
            
            db.commit()
            print("[TRACE-X DB] Database seeded successfully.")
    except Exception as e:
        db.rollback()
        print(f"[TRACE-X DB] Database init error: {e}")
    finally:
        db.close()
