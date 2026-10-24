# TRACE-X: AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

> **Detect. Trace. Investigate.**

TRACE-X is an enterprise-grade digital forensics platform designed for Security Operations Center (SOC) Tier 2/3 analysts, incident response teams, and forensic investigators. It ingests suspicious emails (RFC-822 / EML payloads), conducts header and protocol authentication (SPF, DKIM, DMARC), maps network transit hops with BGP geolocation, verifies cryptographic evidence integrity (SHA-256), correlates threat intelligence, and provides an intelligent interactive cybersecurity assistant (**TRACE-X Assistant**).

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │    TRACE-X React 19 / Vite Frontend   │
                      │         (http://127.0.0.1:5173)       │
                      └──────────────────┬────────────────────┘
                                         │ /api proxy or CORS
                                         ▼
                      ┌───────────────────────────────────────┐
                      │        FastAPI Forensic Backend       │
                      │         (http://127.0.0.1:8000)       │
                      └────┬──────────────┬───────────────┬───┘
                           │              │               │
        ┌──────────────────┴──┐    ┌──────┴──────┐   ┌────┴────────────────┐
        │  SQLite / Postgres  │    │  Evidence   │   │  Forensic Engines   │
        │  SQLAlchemy DB      │    │  Vault      │   │  - Auth Verifier    │
        │  (data/tracex.db)   │    │  (SHA-256)  │   │  - Geo / BGP Route  │
        └─────────────────────┘    └─────────────┘   │  - Threat Signals   │
                                                     │  - TRACE-X Assistant│
                                                     │  - STIX 2.1 Reports │
                                                     └─────────────────────┘
```

---

## Backend API Specification

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Health status, database connectivity, and feature flags |
| `/api/analyze-email` | `POST` | Ingests `.eml` files or raw header text, extracts IOCs, calculates risk score |
| `/api/cases` | `GET` | Lists all recorded forensic investigation cases |
| `/api/cases` | `POST` | Ingests or persists an investigation case record |
| `/api/cases/{case_id}` | `GET` | Retrieves full forensic dossier for a specific case |
| `/api/cases/{case_id}/status` | `PATCH` | Updates case status (`Open`, `Under Review`, `Mitigated`, `Closed`) |
| `/api/cases/{case_id}` | `DELETE` | Deletes an investigation case and associated records |
| `/api/threat-intelligence` | `GET` | Queries cataloged threat indicators (IPs, domains, URLs, hashes) |
| `/api/threat-intelligence` | `POST` | Submits a new IOC indicator to the threat catalog |
| `/api/geolocation` | `GET` / `POST` | Resolves IP addresses to coordinates, ASN, ISP, and hosting type |
| `/api/evidence` | `GET` | Retrieves digital evidence records for a case |
| `/api/evidence` | `POST` | Uploads an evidence file, computes SHA-256, and stores in private vault |
| `/api/evidence/verify` | `POST` | Cryptographically verifies SHA-256 integrity against stored bytes |
| `/api/evidence/{id}/download`| `GET` | Downloads raw evidence payload from the private vault |
| `/api/reports` | `GET` | Lists all generated forensic incident reports |
| `/api/reports/generate` | `POST` | Generates a report in PDF Dossier, STIX 2.1 CTI bundle, or JSON format |
| `/api/chat` | `POST` | TRACE-X Assistant intelligent AI chat & intent classification endpoint |
| `/api/chat/clear` | `POST` | Clears conversation context history for a session |
| `/api/ai-assistant` | `POST` | Case triage, explanation, and mitigation queries |
| `/api/audit-logs` | `GET` | Immutable append-only chain-of-custody audit trail |

Interactive API documentation is accessible at `http://127.0.0.1:8000/docs` (Swagger UI) and `http://127.0.0.1:8000/redoc`.

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ and npm

### 2. Backend Setup
1. Open a terminal in the project directory:
   ```powershell
   cd C:\sih-2
   ```
2. Activate the virtual environment (or create one):
   ```powershell
   # If not already created:
   python -m venv backend/venv

   # Activate virtualenv:
   .\backend\venv\Scripts\Activate.ps1

   # Install dependencies:
   pip install -r backend/requirements.txt
   ```
3. Initialize the database:
   ```powershell
   python -c "from backend.app.db.init_db import init_db; init_db()"
   ```
4. Start the FastAPI backend:
   ```powershell
   uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Backend will be running on `http://127.0.0.1:8000`.

### 3. Frontend Setup
1. In another terminal window:
   ```powershell
   cd C:\sih-2
   npm install
   ```
2. Start the Vite development server:
   ```powershell
   npm run dev
   ```
   Frontend will be running on `http://127.0.0.1:5173`.
   Vite is preconfigured to forward all `/api/*` requests to the FastAPI backend at `http://127.0.0.1:8000`.

---

## Configuration & Environment Variables

### Backend Configuration (`backend/.env`):
```ini
HOST=0.0.0.0
PORT=8000
DEBUG=True
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000
DATABASE_URL=sqlite:///./data/tracex.db
EVIDENCE_VAULT_DIR=./data/evidence_vault

# Optional live intelligence API keys
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=

# Optional AI LLM Provider Configuration for TRACE-X Assistant
# When empty, TRACE-X runs in built-in Rule-Based Cyber-Forensic Expert Mode automatically.
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-flash
ANTHROPIC_API_KEY=
OLLAMA_BASE_URL=
OLLAMA_MODEL=llama3
GROQ_API_KEY=
```

### Frontend Configuration (`.env.local`):
```ini
VITE_API_URL=http://localhost:8000
```

---

## TRACE-X Assistant Chatbot

The **TRACE-X Assistant** is an intelligent cybersecurity copilot available via a floating launcher in the lower right of the platform:
- **Natural Language Intent Recognition**: Understands questions regarding phishing, email spoofing, SPF/DKIM/DMARC alignment, Return-Path, Received headers, IP geolocation limitations, SHA-256 evidence verification, and TRACE-X navigation.
- **Robust Typo & Slang Handling**: Resilient against misspellings (e.g., *phissing*, *spoffing*, *dmrc*, *geolocashun*, *is this mail fake*).
- **Interactive Action Buttons**: Directly invokes platform workflows (`Analyze an Email`, `View Recent Cases`, `Open Dashboard`, `Review Evidence Vault`, `Generate Report`).
- **Context Awareness**: Inherits the active case telemetry (e.g., `CASE-1024`) when navigating investigation dossiers.
- **Dual Operating Modes**:
  1. **AI Mode**: Integrates with OpenAI, Google Gemini, Anthropic Claude, Ollama, or Groq using server-side keys without exposing secrets to the client.
  2. **Forensic Expert Mode**: Built-in deterministic rule engine delivering accurate, domain-expert responses when external API keys are unavailable. Never hallucinates external connections.

---

## Security & Forensic Standards

1. **Digital Evidence Integrity**:
   - SHA-256 digests are computed directly from raw binary byte streams upon upload.
   - The `/api/evidence/verify` endpoint verifies integrity against stored payload bytes.
   - *Forensic notice*: Cryptographic hash verifies data integrity from the moment of capture, confirming that the payload has not been modified. It does not independently prove the provenance or identity of an attacker.

2. **Network Attribution & Geolocation**:
   - Intermediate relay hops are extracted chronologically from RFC-822 `Received:` headers.
   - Geolocation maps BGP routing, ASNs, and hosting classifications.
   - *Attribution caveat*: IP geolocation reflects infrastructure transit and does not establish an attacker's exact physical device or location.

3. **Safe Payload Handling**:
   - Uploaded attachments and evidence files are stored in a private vault directory (`backend/data/evidence_vault`) with sanitized filenames and restricted permissions.
   - Attachments are never executed or parsed into executable memory.
