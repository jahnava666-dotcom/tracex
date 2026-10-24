import json
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from ..models.report import ReportModel
from ..models.audit import AuditLogModel
from ..core.security import FORENSIC_INTEGRITY_DISCLAIMER

def generate_case_report(
    db: Session,
    case_data: Dict[str, Any],
    report_format: str = "PDF",
    author: str = "TRACE-X Forensic Engine (Automated SOC Tier 2)"
) -> Dict[str, Any]:
    """
    Generate structured forensic dossier for an investigation case.
    Supports PDF/Text dossier, JSON, and STIX 2.1 threat intelligence bundles.
    """
    case_id = case_data.get("caseId", "CASE-UNKNOWN")
    verdict = case_data.get("verdict", "Suspicious")
    risk_score = case_data.get("riskScore", 50)
    report_id = f"REP-{datetime.utcnow().year}-{int(datetime.utcnow().timestamp()) % 9000 + 1000}"
    title = f"Forensic Dossier: {case_id}"

    # Build Content based on format
    if report_format == "STIX 2.1":
        # Cyber Threat Intelligence STIX 2.1 Bundle
        iocs = case_data.get("iocs", {})
        indicators = []
        for d in iocs.get("domains", []):
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{abs(hash(d))}",
                "name": f"Malicious Domain: {d}",
                "pattern": f"[domain-name:value = '{d}']",
                "pattern_type": "stix"
            })
        for ip in iocs.get("ips", []):
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{abs(hash(ip))}",
                "name": f"Observed Infrastructure IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix"
            })
            
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{report_id.lower()}",
            "objects": [
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": f"report--{report_id.lower()}",
                    "name": title,
                    "description": case_data.get("summary", ""),
                    "published": datetime.utcnow().isoformat() + "Z",
                    "report_types": ["threat-report", "forensic-dossier"]
                },
                *indicators
            ]
        }
        content = json.dumps(stix_bundle, indent=2)
        summary = f"STIX 2.1 CTI bundle containing {len(indicators)} indicators extracted from {case_id}."

    elif report_format == "JSON":
        content = json.dumps(case_data, indent=2)
        summary = f"Complete structured forensic JSON export for {case_id}."

    else:
        # PDF / Formatted Text Dossier
        lines = [
            "=" * 72,
            f"TRACE-X DIGITAL FORENSIC INCIDENT DOSSIER - {report_id}",
            "=" * 72,
            f"Case Reference:        {case_id}",
            f"Threat Verdict:        {verdict} (Risk Score: {risk_score}/100)",
            f"Subject:               {case_data.get('subject', 'N/A')}",
            f"From Header:           {case_data.get('from', 'N/A')}",
            f"Return-Path:           {case_data.get('returnPath', 'N/A')}",
            f"Generated:             {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Forensic Investigator: {author}",
            "-" * 72,
            "\nEXECUTIVE SUMMARY:",
            case_data.get("summary", "No summary recorded."),
            "\nAUTHENTICATION TELEMETRY (RFC 7208 / RFC 6376 / RFC 7489):",
            f"  • SPF:   {case_data.get('auth', {}).get('spf', {}).get('label', 'N/A')} - {case_data.get('auth', {}).get('spf', {}).get('summary', '')}",
            f"  • DKIM:  {case_data.get('auth', {}).get('dkim', {}).get('label', 'N/A')} - {case_data.get('auth', {}).get('dkim', {}).get('summary', '')}",
            f"  • DMARC: {case_data.get('auth', {}).get('dmarc', {}).get('label', 'N/A')} - {case_data.get('auth', {}).get('dmarc', {}).get('summary', '')}",
            "\nPRIMARY INFRASTRUCTURE NODE:",
            f"  • IP Address:   {case_data.get('primaryInfrastructure', {}).get('ip', 'N/A')}",
            f"  • Location:     {case_data.get('primaryInfrastructure', {}).get('city', '')}, {case_data.get('primaryInfrastructure', {}).get('country', '')}",
            f"  • ASN / ISP:    {case_data.get('primaryInfrastructure', {}).get('asn', '')} ({case_data.get('primaryInfrastructure', {}).get('isp', '')})",
            "\nDETECTED RISK SIGNALS:"
        ]
        for sig in case_data.get("signals", []):
            lines.append(f"  [{sig.get('severity', '').upper()}] {sig.get('title')}: {sig.get('explanation')}")

        lines.append("\nRECOMMENDED REMEDIATION ACTIONS:")
        for act in case_data.get("recommendedActions", []):
            lines.append(f"  [{act.get('priority', '').upper()}] {act.get('action')}")

        lines.append("\n" + "-" * 72)
        lines.append("FORENSIC LEGAL & CHAIN OF CUSTODY NOTICE:")
        lines.append(FORENSIC_INTEGRITY_DISCLAIMER)
        lines.append("=" * 72)
        
        content = "\n".join(lines)
        summary = f"Automated forensic export containing header anomalies, IOCs, SPF/DKIM/DMARC breakdown, and remediation plan for {case_id}."

    # Persist Report to DB
    report_model = ReportModel(
        report_id=report_id,
        case_id=case_id,
        title=title,
        threat_level=verdict,
        risk_score=risk_score,
        format=report_format,
        summary=summary,
        content=content,
        author=author
    )
    db.add(report_model)
    
    # Audit log
    audit = AuditLogModel(
        action="REPORT_GENERATED",
        resource_type="FORENSIC_REPORT",
        resource_id=report_id,
        metadata_json={
            "caseId": case_id,
            "format": report_format,
            "threatLevel": verdict,
            "riskScore": risk_score
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(report_model)

    return report_model.to_dict()
