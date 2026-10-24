from typing import Optional, Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["AI Forensic Assistant"])

class AiQueryRequest(BaseModel):
    query: str
    caseData: Optional[Dict[str, Any]] = None

@router.post("/ai-assistant")
def ai_assistant_query(payload: AiQueryRequest):
    """
    Forensic AI Analyst triage assistant.
    Provides explainable answers regarding email authentication, payload signatures, and SOC next steps.
    """
    q = payload.query.lower()
    case = payload.caseData or {}
    case_id = case.get("caseId", "the active investigation")
    verdict = case.get("verdict", "Critical Threat")
    signals = case.get("signals", [])
    
    # 1. Why / Classification logic
    if any(k in q for k in ("why", "malicious", "classified", "reason", "verdict")):
        reasons = []
        for s in signals:
            reasons.append(f"• {s.get('title')}: {s.get('explanation')}")
        signal_bullets = "\n".join(reasons) if reasons else "• High severity header and domain spoofing anomalies detected."
        return {
            "response": (
                f"Investigation {case_id} is evaluated as **{verdict}** based on the following corroborated evidence:\n\n"
                f"{signal_bullets}\n\n"
                f"The composite threat score is **{case.get('riskScore', 92)}/100**."
            )
        }

    # 2. Next steps / Investigation
    if any(k in q for k in ("next", "investigate", "step", "recommend", "action")):
        actions = case.get("recommendedActions", [])
        if actions:
            action_lines = "\n".join([f"{idx+1}. **[{a.get('priority')}]** {a.get('action')}" for idx, a in enumerate(actions)])
            return {
                "response": (
                    f"Recommended SOC Tier 2 playbooks for {case_id}:\n\n"
                    f"{action_lines}\n\n"
                    f"Ensure you preserve cryptographic evidence in the Evidence Vault before executing mail purging."
                )
            }
        return {
            "response": (
                "Next immediate actions:\n"
                "1. Quarantine inbound email from exchange perimeter.\n"
                "2. Add originating IP to border firewall drop rules.\n"
                "3. Invalidate credentials for recipients who opened the message."
            )
        }

    # 3. Authentication (DMARC, SPF, DKIM)
    if any(k in q for k in ("dmarc", "spf", "dkim", "auth", "alignment")):
        auth = case.get("auth", {})
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})
        return {
            "response": (
                f"Authentication breakdown for {case_id}:\n\n"
                f"• **SPF**: {spf.get('label', 'FAIL')} — {spf.get('technicalDetails', 'SPF policy mismatch.')}\n"
                f"• **DKIM**: {dkim.get('label', 'SUSPICIOUS')} — {dkim.get('technicalDetails', 'Signature verification failed.')}\n"
                f"• **DMARC**: {dmarc.get('label', 'FAIL')} — {dmarc.get('technicalDetails', 'Domain alignment failed under strict reject policy.')}\n\n"
                f"These failures indicate the message did not originate from an authorized sender."
            )
        }

    # 4. Attachments
    if any(k in q for k in ("attachment", "zip", "file", "payload", "dropper")):
        iocs = case.get("iocs", {})
        atts = iocs.get("attachments", [])
        if atts:
            att_info = "\n".join([f"• `{a.get('filename')}` ({a.get('size')}) — SHA-256: `{a.get('sha256')}` [Verdict: {a.get('verdict')}]" for a in atts])
            return {
                "response": f"Attachment forensic inspection:\n\n{att_info}\n\nDo not execute or unpack this payload outside an isolated sandbox."
            }
        return {
            "response": "No suspicious binary attachments were extracted from this email stream."
        }

    # 5. Mitigation / Fix / Block
    if any(k in q for k in ("mitigate", "block", "fix", "rule", "firewall")):
        primary = case.get("primaryInfrastructure", {})
        ip = primary.get("ip", "185.220.101.42")
        return {
            "response": (
                f"Immediate mitigation controls for {case_id}:\n\n"
                f"• **Firewall/WAF**: `iptables -A INPUT -s {ip} -j DROP`\n"
                f"• **Mail Transport**: Configure MTA rejection rule for envelope bounce domains.\n"
                f"• **DNS Filter**: Sinkhole extracted domains to prevent C2 communication."
            )
        }

    # Default
    return {
        "response": (
            f"TRACE-X AI Forensic Assistant online for {case_id}. "
            "You can ask me to explain why this email was classified as malicious, review SPF/DKIM/DMARC alignment, "
            "inspect attachments, or propose SOC mitigation playbooks."
        )
    }
