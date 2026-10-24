import { EmailInvestigationCase, GeneratedReport } from '../types/forensics';

export const CASE_1024: EmailInvestigationCase = {
  caseId: 'CASE-1024',
  email: 'security@secure-login-example.com',
  date: 'Today, 10:32:04 AM',
  receivedTime: '10:32:04 UTC',
  subject: 'Urgent Account Verification Required',
  from: 'security@secure-login-example.com',
  replyTo: 'support@secure-login-example.net',
  returnPath: '<bounces-srv992@bullet-vps-net.org>',
  messageId: '<20260910103204.77491.qmail@mta-nl-relay.net>',
  riskScore: 92,
  verdict: 'Critical Threat',
  summary: 'High-confidence credential phishing and malicious ZIP dropper campaign leveraging typosquatted banking domain and header spoofing.',
  status: 'Open',
  assignedAnalyst: 'Alex Carter (SOC Tier 2)',
  auth: {
    spf: {
      status: 'FAIL',
      label: 'SPF: FAIL',
      summary: "The sending server is not authorized by the domain's SPF policy.",
      technicalDetails: 'v=spf1 include:_spf.google.com ~all - IP 185.220.101.42 not listed in designated SPF mechanism.',
      recordFound: 'v=spf1 -all'
    },
    dkim: {
      status: 'SUSPICIOUS',
      label: 'DKIM: SUSPICIOUS',
      summary: 'The email signature could not be fully validated.',
      technicalDetails: 'Signature d=secure-login-example.com failed cryptographic hash verification (bodyhash_mismatch). Key length: RSA-1024.',
      recordFound: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...'
    },
    dmarc: {
      status: 'FAIL',
      label: 'DMARC: FAIL',
      summary: 'Domain alignment failed.',
      technicalDetails: 'Header From domain (secure-login-example.com) does not align with SPF sender envelope or DKIM d= value under strict policy (p=reject).',
      recordFound: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@secure-login-example.com'
    }
  },
  signals: [
    {
      id: 'sig-1',
      title: 'Sender Spoofing',
      category: 'Header Integrity',
      severity: 'critical',
      scoreImpact: 20,
      explanation: 'From address claims secure-login-example.com while Return-Path routes to an unverified third-party VPS relay.',
      evidence: 'From: security@secure-login-example.com != Return-Path: bounces-srv992@bullet-vps-net.org',
      iconName: 'UserX'
    },
    {
      id: 'sig-2',
      title: 'DMARC Failure',
      category: 'Authentication',
      severity: 'high',
      scoreImpact: 15,
      explanation: 'Domain alignment failed with strict reject enforcement triggered on originating MTA.',
      evidence: 'DKIM and SPF alignment checks both failed against RFC 7489 specification.',
      iconName: 'ShieldAlert'
    },
    {
      id: 'sig-3',
      title: 'Suspicious Domain',
      category: 'Domain Intelligence',
      severity: 'high',
      scoreImpact: 15,
      explanation: 'Domain resembles a legitimate banking portal with typosquatting keywords and was registered only 12 days ago.',
      evidence: 'Domain age: 12 days | Registrar: NameSilo LLC | Whois privacy enabled',
      iconName: 'Globe'
    },
    {
      id: 'sig-4',
      title: 'Malicious URL',
      category: 'Link Analysis',
      severity: 'critical',
      scoreImpact: 20,
      explanation: 'URL redirects to an unexpected credential harvesting landing page matching known phishing telemetry.',
      evidence: 'https://secure-login-example.com/login -> 302 Redirect to https://auth-verify-portal9.ru/session',
      iconName: 'ExternalLink'
    },
    {
      id: 'sig-5',
      title: 'Suspicious Attachment',
      category: 'Payload Analysis',
      severity: 'medium',
      scoreImpact: 10,
      explanation: 'Double-extension ZIP archive containing obfuscated VBScript/dropper payload designed to bypass static mail filters.',
      evidence: 'Invoice_2026.zip contains Invoice_2026_PDF.vbs (Entropy: 7.84, SHA256 match in C2 db)',
      iconName: 'FileArchive'
    },
    {
      id: 'sig-6',
      title: 'Urgency Language',
      category: 'Behavioral / Social Eng',
      severity: 'medium',
      scoreImpact: 7,
      explanation: 'Message text employs severe pressure tactics threatening 24-hour account suspension if action is not taken immediately.',
      evidence: '"Immediate action required within 24 hours to prevent permanent account suspension."',
      iconName: 'AlertTriangle'
    },
    {
      id: 'sig-7',
      title: 'Reputation',
      category: 'Infrastructure',
      severity: 'high',
      scoreImpact: 5,
      explanation: 'Originating IP resides within an ASN frequently flagged for hosting bulletproof VPS relays and malware delivery.',
      evidence: 'IP 185.220.101.42 has 38 abuse reports in past 14 days (Confidence: 94%).',
      iconName: 'ServerCrash'
    }
  ],
  infrastructureHops: [
    {
      id: 1,
      step: 'Hop 1: Origin',
      label: 'Email Sender',
      ip: '109.201.133.15',
      country: 'Romania',
      region: 'Bucharest',
      asn: 'AS208598 (Host Sailor Ltd)',
      isp: 'HostSailor Romania Dedicated',
      hostingType: 'MTA',
      status: 'suspicious',
      timestamp: '10:32:04 UTC',
      latency: '+0ms',
      coordinates: [44.4268, 26.1025]
    },
    {
      id: 2,
      step: 'Hop 2: Outbound MTA',
      label: 'Mail Server',
      ip: '194.26.29.112',
      country: 'Germany',
      region: 'Frankfurt',
      asn: 'AS51167 (Contabo GmbH)',
      isp: 'Contabo Cloud VPS',
      hostingType: 'VPS',
      status: 'suspicious',
      timestamp: '10:32:07 UTC',
      latency: '+3.1s',
      coordinates: [50.1109, 8.6821]
    },
    {
      id: 3,
      step: 'Hop 3: Anonymizing Relay',
      label: 'Relay Server',
      ip: '185.220.101.42',
      country: 'Netherlands',
      region: 'North Holland',
      asn: 'AS49453 (Global Host Solutions B.V.)',
      isp: 'Bulletproof VPS Relay Network',
      hostingType: 'Cloud',
      status: 'malicious',
      timestamp: '10:32:08 UTC',
      latency: '+1.4s',
      coordinates: [52.3676, 4.9041]
    },
    {
      id: 4,
      step: 'Hop 4: Proxy / Cloud',
      label: 'Cloud / VPS',
      ip: '104.21.32.189',
      country: 'United States',
      region: 'California',
      asn: 'AS13335 (Cloudflare Inc.)',
      isp: 'Reverse Proxy / Anycast CDN',
      hostingType: 'Cloud',
      status: 'clean',
      timestamp: '10:32:11 UTC',
      latency: '+2.8s',
      coordinates: [37.7749, -122.4194]
    },
    {
      id: 5,
      step: 'Hop 5: Inbound Gateway',
      label: 'Recipient Mailbox',
      ip: '142.250.180.26',
      country: 'United States',
      region: 'Enterprise Exchange',
      asn: 'AS15169 (Google LLC)',
      isp: 'Corporate Secure Email Gateway',
      hostingType: 'Enterprise Mail Gateway',
      status: 'clean',
      timestamp: '10:32:15 UTC',
      latency: '+4.2s',
      coordinates: [38.8951, -77.0364]
    }
  ],
  primaryInfrastructure: {
    ip: '185.220.101.42',
    country: 'Netherlands',
    region: 'North Holland (Amsterdam)',
    city: 'Amsterdam',
    asn: 'AS49453 (Global Host Solutions B.V.)',
    isp: 'Offshore Bulletproof Cloud Services',
    hosting: 'VPS / Cloud Server',
    reverseDns: 'srv-nl-relay992.bullet-vps-net.org',
    coordinates: [52.3676, 4.9041]
  },
  timeline: [
    {
      id: 't-1',
      timestamp: '10:32:04',
      event: 'Email generated',
      node: 'Client Agent (scripted mail injection via python-smtplib)',
      ip: '109.201.133.15',
      status: 'flagged',
      details: 'Forged message headers created with spoofed From display and mismatching envelope sender.'
    },
    {
      id: 't-2',
      timestamp: '10:32:07',
      event: 'Server A (Outbound MTA)',
      node: 'mail.direct-outbound-relay.net',
      ip: '194.26.29.112',
      status: 'flagged',
      details: 'Transferred via ESMTP; body digest calculated with rogue DKIM key.'
    },
    {
      id: 't-3',
      timestamp: '10:32:08',
      event: 'Server B (Intermediate Relay)',
      node: 'mta-nl-relay.net',
      ip: '185.220.101.42',
      status: 'alert',
      details: 'High-risk hop identified. IP has active telemetry flags for credential phishing infrastructure.'
    },
    {
      id: 't-4',
      timestamp: '10:32:11',
      event: 'Cloud Relay / Edge Filter',
      node: 'edge-inbound-protection.net',
      ip: '104.21.32.189',
      status: 'normal',
      details: 'TLS 1.3 encrypted handoff; SPF check evaluated and returned FAIL.'
    },
    {
      id: 't-5',
      timestamp: '10:32:15',
      event: 'Victim Mailbox / Gateway Quarantine',
      node: 'inbound-sec-gateway.corp.internal',
      ip: '142.250.180.26',
      status: 'alert',
      details: 'Delivered to corporate quarantine. TRACE-X triage hooked and forensic snapshot initiated.'
    }
  ],
  threatIntel: [
    {
      indicator: 'secure-login-example.com',
      type: 'Domain',
      reputation: 'Suspicious',
      details: 'Domain age: 12 days | Lookalike brand impersonation | Registrant privacy shielded',
      confidence: 96,
      firstSeen: '2026-08-29'
    },
    {
      indicator: '185.220.101.42',
      type: 'IP',
      reputation: 'Suspicious',
      details: 'VPS hosting provider | Bulletproof infrastructure | 38 abuse reports in 14 days',
      confidence: 92,
      firstSeen: '2026-07-14'
    },
    {
      indicator: 'https://secure-login-example.com/login',
      type: 'URL',
      reputation: 'Malicious',
      details: 'Redirect detected to dynamic credential harvester (/session-auth?id=9928)',
      confidence: 99,
      firstSeen: '2026-09-08'
    },
    {
      indicator: 'invoice_2026.zip',
      type: 'Attachment',
      reputation: 'Suspicious',
      details: 'Archive attachment | Contains obfuscated VBScript dropper masquerading as PDF',
      confidence: 94,
      firstSeen: '2026-09-10'
    },
    {
      indicator: '8f4c2e91a0b365d78e5f1234abcd5678ef901234567890abcdef1234567890ab',
      type: 'SHA-256',
      reputation: 'Malicious',
      details: 'Identified as Trojan.Downloader.Agent.VBS signature in malware corpus',
      confidence: 98,
      firstSeen: '2026-09-09'
    }
  ],
  iocs: {
    domains: [
      'secure-login-example.com',
      'auth-verify-portal9.ru',
      'bullet-vps-net.org',
      'mta-nl-relay.net'
    ],
    ips: [
      '185.220.101.42',
      '109.201.133.15',
      '194.26.29.112',
      '104.21.32.189'
    ],
    urls: [
      'https://secure-login-example.com/login',
      'https://auth-verify-portal9.ru/session?ref=mail_verify_921',
      'http://185.220.101.42/drop/payload.enc'
    ],
    attachments: [
      {
        filename: 'Invoice_2026.zip',
        size: '142.6 KB',
        sha256: '8f4c2e91a0b365d78e5f1234abcd5678ef901234567890abcdef1234567890ab',
        fileType: 'application/zip (Encrypted headers)',
        verdict: 'Malicious Script Carrier'
      }
    ]
  },
  recommendedActions: [
    {
      id: 1,
      action: 'Do not click the suspicious URL or forward to internal recipients.',
      priority: 'Critical',
      completed: false
    },
    {
      id: 2,
      action: 'Investigate the destination domain (auth-verify-portal9.ru) and block on perimeter DNS/web gateway.',
      priority: 'Critical',
      completed: false
    },
    {
      id: 3,
      action: 'Search security and firewall logs for the extracted IP (185.220.101.42) for lateral movement.',
      priority: 'High',
      completed: false
    },
    {
      id: 4,
      action: 'Compare the sender with known legitimate communications and blacklist unauthorized reply-to domain.',
      priority: 'High',
      completed: false
    },
    {
      id: 5,
      action: 'Preserve the original email as evidence (RFC 822 EML artifact with SHA-256 custody chain).',
      priority: 'Medium',
      completed: true
    },
    {
      id: 6,
      action: 'Review and execute the attachment in an isolated sandbox environment (Cuckoo/Any.Run).',
      priority: 'High',
      completed: false
    }
  ],
  rawHeaders: `Delivered-To: victim-analyst@corporate.net
Received: by 2002:a05:6830:1989:b0:6e1:f88:2210 with SMTP id e10csp829141fbe;
        Thu, 10 Sep 2026 10:32:15 -0000 (UTC)
X-Google-Smtp-Source: AGHT+IFnK8o3pA/1u92K1f0V
Received: from srv-nl-relay992.bullet-vps-net.org (srv-nl-relay992.bullet-vps-net.org. [185.220.101.42])
        by mx.google.com with ESMTPS id o18si829112pll.142.2026.09.10.10.32.11
        for <victim-analyst@corporate.net>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Sep 2026 10:32:11 -0000 (UTC)
Received-SPF: fail (google.com: domain of bounces-srv992@bullet-vps-net.org does not designate 185.220.101.42 as permitted sender) client-ip=185.220.101.42;
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of bounces-srv992@bullet-vps-net.org does not designate 185.220.101.42 as permitted sender) smtp.mailfrom=bounces-srv992@bullet-vps-net.org;
       dkim=fail header.i=@secure-login-example.com header.s=s1024 header.b=X92bM1;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=secure-login-example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=secure-login-example.com; s=s1024;
        h=from:to:subject:date:message-id:reply-to:mime-version;
        bh=w+89mQp78yZzL+e3...;
        b=X92bM1004...
Received: from [194.26.29.112] (helo=direct-outbound-relay.net)
        by srv-nl-relay992.bullet-vps-net.org with esmtp (Exim 4.94)
        id 1qJ83L-0004p-2M; Thu, 10 Sep 2026 10:32:08 -0000
Received: from [109.201.133.15] by direct-outbound-relay.net with HTTP;
        Thu, 10 Sep 2026 10:32:04 -0000
From: "Security Notification Service" <security@secure-login-example.com>
Reply-To: support@secure-login-example.net
To: victim-analyst@corporate.net
Subject: Urgent Account Verification Required
Date: Thu, 10 Sep 2026 10:32:04 +0000
Message-ID: <20260910103204.77491.qmail@mta-nl-relay.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_99182_1829104"
X-Priority: 1 (Highest)
X-Mailer: Custom SMTPLib Injection Daemon v3.2`
};

export const RECENT_INVESTIGATIONS: EmailInvestigationCase[] = [
  CASE_1024,
  {
    caseId: 'CASE-1023',
    email: 'support@example.com',
    date: 'Yesterday, 14:15:22 PM',
    receivedTime: '14:15:22 UTC',
    subject: 'Action Required: Updated Terms of Service & Billing Portal',
    from: 'support@example.com',
    replyTo: 'support-agent@thirdparty-ticket.io',
    returnPath: '<bounce@thirdparty-ticket.io>',
    messageId: '<20260909141522.1284.msg@ticket.io>',
    riskScore: 67,
    verdict: 'High Risk',
    summary: 'Suspicious third-party ticket redirection with mismatched Return-Path and unaligned SPF record.',
    status: 'Under Review',
    assignedAnalyst: 'Sarah Lin (SOC Tier 1)',
    auth: {
      spf: {
        status: 'FAIL',
        label: 'SPF: FAIL',
        summary: 'Sending IP 198.51.100.89 is not listed in example.com SPF record.',
        technicalDetails: 'v=spf1 include:_spf.example.com ~all'
      },
      dkim: {
        status: 'PASS',
        label: 'DKIM: PASS',
        summary: 'Valid cryptographic signature from thirdparty-ticket.io.',
        technicalDetails: 'd=thirdparty-ticket.io s=k1 rsa-2048 valid'
      },
      dmarc: {
        status: 'FAIL',
        label: 'DMARC: FAIL',
        summary: 'From header domain does not match DKIM or SPF sender.',
        technicalDetails: 'Alignment failure under strict policy.'
      }
    },
    signals: [
      {
        id: 'sig-21',
        title: 'Domain Mismatch',
        category: 'Header Integrity',
        severity: 'high',
        scoreImpact: 18,
        explanation: 'Header From claims example.com while ticketing backend belongs to an external provider.',
        evidence: 'example.com vs thirdparty-ticket.io',
        iconName: 'UserX'
      },
      {
        id: 'sig-22',
        title: 'Suspicious External Link',
        category: 'Link Analysis',
        severity: 'high',
        scoreImpact: 16,
        explanation: 'Payment link redirects to unauthenticated staging subdomain.',
        evidence: 'https://billing-update.staging-portal-verify.net',
        iconName: 'ExternalLink'
      }
    ],
    infrastructureHops: [
      {
        id: 1,
        step: 'Hop 1',
        label: 'Ticketing Agent',
        ip: '198.51.100.89',
        country: 'United States',
        region: 'Ohio',
        asn: 'AS16509 (Amazon.com)',
        isp: 'AWS EC2',
        hostingType: 'Cloud',
        status: 'suspicious',
        timestamp: '14:15:20 UTC',
        latency: '+0ms',
        coordinates: [40.4173, -82.9071]
      },
      {
        id: 2,
        step: 'Hop 2',
        label: 'Recipient Gateway',
        ip: '142.250.180.26',
        country: 'United States',
        region: 'Internal',
        asn: 'AS15169 (Google LLC)',
        isp: 'Inbound Gateway',
        hostingType: 'Enterprise Mail Gateway',
        status: 'clean',
        timestamp: '14:15:22 UTC',
        latency: '+2.0s',
        coordinates: [38.8951, -77.0364]
      }
    ],
    primaryInfrastructure: {
      ip: '198.51.100.89',
      country: 'United States',
      region: 'Ohio',
      city: 'Columbus',
      asn: 'AS16509 (Amazon.com)',
      isp: 'Amazon Data Services',
      hosting: 'AWS Cloud EC2',
      reverseDns: 'ec2-198-51-100-89.compute-1.amazonaws.com',
      coordinates: [40.4173, -82.9071]
    },
    timeline: [
      {
        id: 't-21',
        timestamp: '14:15:20',
        event: 'Generated by third-party helpdesk script',
        node: 'ticket-worker-04',
        ip: '198.51.100.89',
        status: 'flagged',
        details: 'Outbound trigger initiated without enterprise sender validation.'
      },
      {
        id: 't-22',
        timestamp: '14:15:22',
        event: 'Received by Gateway',
        node: 'gateway-inbound-01',
        ip: '142.250.180.26',
        status: 'normal',
        details: 'Quarantined pending DMARC override inspection.'
      }
    ],
    threatIntel: [
      {
        indicator: 'staging-portal-verify.net',
        type: 'Domain',
        reputation: 'Suspicious',
        details: 'Newly registered hosting zone with no brand affiliation',
        confidence: 84,
        firstSeen: '2026-09-01'
      }
    ],
    iocs: {
      domains: ['staging-portal-verify.net'],
      ips: ['198.51.100.89'],
      urls: ['https://billing-update.staging-portal-verify.net'],
      attachments: []
    },
    recommendedActions: [
      { id: 1, action: 'Block domain staging-portal-verify.net in proxy filters.', priority: 'High', completed: false },
      { id: 2, action: 'Notify helpdesk administrator of unauthorized notification relay.', priority: 'Medium', completed: false }
    ],
    rawHeaders: `From: support@example.com\nSubject: Action Required\nReceived-SPF: fail`
  },
  {
    caseId: 'CASE-1022',
    email: 'billing@example.com',
    date: 'Yesterday, 09:04:18 AM',
    receivedTime: '09:04:18 UTC',
    subject: 'Monthly Cloud Infrastructure Invoice #INV-88192',
    from: 'billing@example.com',
    replyTo: 'billing@example.com',
    returnPath: '<bounces@mailer.example.com>',
    messageId: '<inv-88192-20260909090418@mailer.example.com>',
    riskScore: 21,
    verdict: 'Likely Safe',
    summary: 'Standard automated billing notification with valid SPF, 2048-bit DKIM signature, and strict DMARC alignment.',
    status: 'Closed',
    assignedAnalyst: 'Alex Carter (SOC Tier 2)',
    auth: {
      spf: {
        status: 'PASS',
        label: 'SPF: PASS',
        summary: 'Designated sender IP matches SPF policy record.',
        technicalDetails: 'v=spf1 include:_spf.example.com ~all - IP 149.72.10.18 permitted.'
      },
      dkim: {
        status: 'PASS',
        label: 'DKIM: PASS',
        summary: 'Valid signature verified with 2048-bit public RSA key.',
        technicalDetails: 'd=example.com s=s2026 rsa-2048 hash valid.'
      },
      dmarc: {
        status: 'PASS',
        label: 'DMARC: PASS',
        summary: 'Full alignment verified across RFC 7489 specifications.',
        technicalDetails: 'Header From aligns with d=example.com.'
      }
    },
    signals: [],
    infrastructureHops: [
      {
        id: 1,
        step: 'Hop 1',
        label: 'Sendgrid Mailer',
        ip: '149.72.10.18',
        country: 'United States',
        region: 'Texas',
        asn: 'AS11377 (Twilio SendGrid)',
        isp: 'Twilio SendGrid',
        hostingType: 'Cloud',
        status: 'clean',
        timestamp: '09:04:16 UTC',
        latency: '+0ms',
        coordinates: [30.2672, -97.7431]
      },
      {
        id: 2,
        step: 'Hop 2',
        label: 'Corporate Gateway',
        ip: '142.250.180.26',
        country: 'United States',
        region: 'Internal',
        asn: 'AS15169 (Google LLC)',
        isp: 'Corporate Gateway',
        hostingType: 'Enterprise Mail Gateway',
        status: 'clean',
        timestamp: '09:04:18 UTC',
        latency: '+2.1s',
        coordinates: [38.8951, -77.0364]
      }
    ],
    primaryInfrastructure: {
      ip: '149.72.10.18',
      country: 'United States',
      region: 'Texas',
      city: 'Austin',
      asn: 'AS11377 (Twilio SendGrid)',
      isp: 'Twilio Inc.',
      hosting: 'Authorized SaaS Gateway',
      reverseDns: 'o1.sendgrid.net',
      coordinates: [30.2672, -97.7431]
    },
    timeline: [
      {
        id: 't-31',
        timestamp: '09:04:16',
        event: 'Invoiced dispatched via SendGrid',
        node: 'o1.sendgrid.net',
        ip: '149.72.10.18',
        status: 'normal',
        details: 'Clean automated delivery.'
      }
    ],
    threatIntel: [],
    iocs: {
      domains: ['example.com'],
      ips: ['149.72.10.18'],
      urls: ['https://billing.example.com/invoices/88192'],
      attachments: [
        {
          filename: 'Invoice_88192.pdf',
          size: '64.2 KB',
          sha256: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
          fileType: 'application/pdf',
          verdict: 'Benign PDF'
        }
      ]
    },
    recommendedActions: [
      { id: 1, action: 'No action required. Email conforms to all security policies.', priority: 'Low', completed: true }
    ],
    rawHeaders: `From: billing@example.com\nSubject: Invoice #88192\nReceived-SPF: pass`
  },
  {
    caseId: 'CASE-1025',
    email: 'hr-portal@corp-update-notice.com',
    date: 'Sep 08, 2026',
    receivedTime: '18:44:10 UTC',
    subject: 'Urgent: Mandatory Employee Benefits Enrollment Form',
    from: 'hr-portal@corp-update-notice.com',
    replyTo: 'benefits-desk@mail-forward-relay.com',
    returnPath: '<bounces@corp-update-notice.com>',
    messageId: '<hr-form-991204@corp-update-notice.com>',
    riskScore: 78,
    verdict: 'High Risk',
    summary: 'Phishing campaign targeting internal employee credentials via fake HR open-enrollment portal.',
    status: 'Mitigated',
    assignedAnalyst: 'Marcus Vance (SOC Tier 3)',
    auth: {
      spf: { status: 'PASS', label: 'SPF: PASS', summary: 'Originating IP authorized for rogue domain.', technicalDetails: 'v=spf1 a mx ip4:195.133.40.12 ~all' },
      dkim: { status: 'PASS', label: 'DKIM: PASS', summary: 'Valid signature signed with adversary domain key.', technicalDetails: 'd=corp-update-notice.com valid' },
      dmarc: { status: 'SUSPICIOUS', label: 'DMARC: SUSPICIOUS', summary: 'Passes domain alignment for fake lookalike domain.', technicalDetails: 'Adversary registered domain specifically for spoofing.' }
    },
    signals: [
      {
        id: 'sig-41',
        title: 'Lookalike HR Domain',
        category: 'Domain Impersonation',
        severity: 'high',
        scoreImpact: 19,
        explanation: 'Domain registered 3 days ago mimicking internal corporate intranet portal.',
        evidence: 'corp-update-notice.com created 2026-09-05',
        iconName: 'Globe'
      },
      {
        id: 'sig-42',
        title: 'Credential Harvester URL',
        category: 'Phishing',
        severity: 'critical',
        scoreImpact: 20,
        explanation: 'URL contains fake Okta single-sign-on login clone.',
        evidence: 'https://corp-update-notice.com/auth/sso?client_id=hr_app',
        iconName: 'ExternalLink'
      }
    ],
    infrastructureHops: [],
    primaryInfrastructure: {
      ip: '195.133.40.12',
      country: 'Russia',
      region: 'Moscow',
      city: 'Moscow',
      asn: 'AS48287 (Vscale Cloud)',
      isp: 'Selectel VPS Network',
      hosting: 'Offshore VPS',
      reverseDns: 'vps-relay-ru.corp-update-notice.com',
      coordinates: [55.7558, 37.6173]
    },
    timeline: [],
    threatIntel: [
      {
        indicator: 'corp-update-notice.com',
        type: 'Domain',
        reputation: 'Malicious',
        details: 'Active phishing portal detected by security crawlers',
        confidence: 95,
        firstSeen: '2026-09-05'
      }
    ],
    iocs: {
      domains: ['corp-update-notice.com'],
      ips: ['195.133.40.12'],
      urls: ['https://corp-update-notice.com/auth/sso'],
      attachments: []
    },
    recommendedActions: [
      { id: 1, action: 'Add corp-update-notice.com to global DNS sinkhole.', priority: 'Critical', completed: true },
      { id: 2, action: 'Reset credentials for any employees who opened the link.', priority: 'High', completed: true }
    ],
    rawHeaders: `From: hr-portal@corp-update-notice.com\nSubject: Mandatory Benefits`
  }
];

export const MOCK_REPORTS: GeneratedReport[] = [
  {
    reportId: 'REP-2026-1024',
    caseId: 'CASE-1024',
    title: 'Forensic Investigation Dossier: Credential Phishing & Dropper (CASE-1024)',
    threatLevel: 'Critical Threat',
    riskScore: 92,
    createdAt: 'Today, 10:35:12 AM',
    author: 'TRACE-X Forensic Engine / Alex Carter',
    format: 'PDF',
    summary: 'Exhaustive forensic analysis of spoofed banking notification with DMARC failure, malicious ZIP payload, and Amsterdam VPS relay.'
  },
  {
    reportId: 'REP-2026-1023',
    caseId: 'CASE-1023',
    title: 'Triage Summary: External Ticket Spoofing (CASE-1023)',
    threatLevel: 'High Risk',
    riskScore: 67,
    createdAt: 'Yesterday, 15:00:00 PM',
    author: 'TRACE-X Forensic Engine / Sarah Lin',
    format: 'PDF',
    summary: 'Analysis of unaligned ticket relay diverting users to staging credential capture site.'
  },
  {
    reportId: 'REP-2026-1022',
    caseId: 'CASE-1022',
    title: 'Audit Record: Benign Billing Delivery (CASE-1022)',
    threatLevel: 'Likely Safe',
    riskScore: 21,
    createdAt: 'Yesterday, 09:30:10 AM',
    author: 'TRACE-X Forensic Engine / Automated Rule',
    format: 'PDF',
    summary: 'Routine verification confirming full SPF, DKIM, and DMARC alignment on outbound billing.'
  }
];

export const AI_PRESET_RESPONSES: Record<string, string> = {
  default: "I have reviewed all forensic telemetry for this case. The email exhibits critical anomalies: sender impersonation, DMARC alignment failure, a freshly registered lookalike domain, a deceptive URL redirect, and a suspicious ZIP archive payload.",
  why: "The email was classified as a **Critical Threat (92/100)** because of multiple compounding forensic indicators:\n\n1. **DMARC Failure:** The message failed domain alignment under a strict policy.\n2. **Lookalike Domain:** `secure-login-example.com` was registered only 12 days ago with masked Whois data.\n3. **Deceptive Redirect:** The login link routes through a 302 redirect to an offshore credential harvesting server.\n4. **Malicious Dropper:** `Invoice_2026.zip` contains an obfuscated VBScript executable payload matching known malware signatures.\n5. **Bulletproof VPS Relay:** Originating infrastructure routes through a known malicious Dutch VPS.",
  investigate: "Based on SOC standard operating procedures, I recommend following this investigative path:\n\n1. **Query EDR & Firewall Logs:** Search your environment for outbound connections to `185.220.101.42` or `auth-verify-portal9.ru`.\n2. **Sinkhole Extracted Domains:** Block `secure-login-example.com` and redirect endpoints across DNS/proxy filters.\n3. **Mailbox Sweep:** Search Exchange/M365/Google Workspace logs for identical Message-IDs or subject lines.\n4. **Sandbox Detonation:** Run `Invoice_2026.zip` in an isolated detonation chamber to analyze dropped process trees.",
  dmarc: "**DMARC (Domain-based Message Authentication, Reporting, and Conformance)** evaluated to **FAIL**.\n\nEven though the `From:` header claims to be `security@secure-login-example.com`, the actual envelope sender (`Return-Path:`) points to `bullet-vps-net.org`. Neither the SPF check nor the DKIM signature aligned with the visible header identity, which triggers strict rejection under RFC 7489.",
  attachment: "The attachment **`Invoice_2026.zip`** is extremely suspicious (Risk impact: +10):\n\n- File entropy is measured at **7.84**, indicating high obfuscation or compression.\n- Archive unpacking reveals `Invoice_2026_PDF.vbs`, a disguised script designed to drop secondary payloads via Windows Script Host.\n- The calculated SHA-256 hash has known correlations in threat intelligence feeds.",
  mitigation: "To immediately neutralize this threat:\n\n1. **Quarantine or Purge:** Remove the message from all recipient mailboxes immediately.\n2. **Block IOCs at Gateway:** Blacklist IPs `185.220.101.42`, `109.201.133.15`, and the suspicious domains.\n3. **Credential Invalidation:** If any user clicked the link or entered credentials, trigger immediate password resets and revoke active OAuth tokens.\n4. **Preserve EML:** Keep the raw EML header export for legal/compliance forensics."
};
