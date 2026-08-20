# 🛡️ Intent-Aware Deception System for Real-Time Attacker Profiling

<div align="center">

[![Release](https://img.shields.io/badge/Release-v1.0--RC-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](#)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg?logo=react&logoColor=black)](#)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0+-47A248.svg?logo=mongodb&logoColor=white)](#)
[![Gemini AI](https://img.shields.io/badge/Gemini-2.5--Flash-4285F4.svg?logo=google&logoColor=white)](#)
[![Tests](https://img.shields.io/badge/Tests-67%2F67%20Passed-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#)

**An end-to-end cybersecurity deception platform that captures, classifies, and profiles attacker behavior in real time using AI-powered intent analysis.**

[Architecture](#️-core-architecture--pipeline) • [Getting Started](#-getting-started) • [API Reference](#-api-reference) • [Tech Stack](#-tech-stack) • [Tests](#-running-automated-tests)

</div>

---

## 📌 Project Overview

The **Intent-Aware Deception System** is a full-stack, production-grade honeypot platform that goes beyond simple intrusion detection. It actively profiles attacker intent, maps tactics to MITRE ATT&CK, and surfaces actionable threat intelligence through an interactive analyst dashboard.

### Key Capabilities

| Capability | Description |
|---|---|
| 🪤 **Honeypot Integration** | Cowrie SSH/Telnet honeypot captures real attacker interactions |
| 🧠 **Hybrid Intent Classification** | Deterministic rule engine + Google Gemini 2.5 Flash LLM |
| 📊 **Real-Time Risk Scoring** | Deterministic 0–100 risk engine with severity mapping |
| 🗺️ **MITRE ATT&CK Mapping** | Automatic tactic/technique attribution per session |
| 👤 **Attacker Profiling** | Persistent multi-session attacker profiles with behavioral history |
| ⚡ **Live WebSocket Streaming** | Real-time event & alert broadcasting to dashboard |
| 📈 **Analytics & Heatmaps** | Timeline, intent distribution, risk heatmaps, stage progression |
| 🔒 **Privacy-First Design** | Zero plaintext passwords; all credentials redacted before persistence |

---

## 🏗️ Core Architecture & Pipeline

```
Controlled Attacker / Test Client (SSH/Telnet)
                   ↓
      Cowrie Honeypot (127.0.0.1:2222)
                   ↓
        cowrie.json Real-Time Event Stream
                   ↓
   AsyncLogCollector (services/log_collector.py)
                   ↓
  Event Normalizer & Behavioral Feature Extractor
                   ↓
      Incremental Session Aggregator
                   ↓
  ┌─────────────────────────────────────────┐
  │  Hybrid Intent Classification Engine    │
  │  ├── Rule Classifier (Deterministic)    │
  │  └── Gemini AI Classifier (LLM)         │
  └─────────────────────────────────────────┘
                   ↓
  Deterministic Threat Risk Engine (0–100 Score)
                   ↓
  Session Intelligence & Attacker Profiler
                   ↓
     Persistence Service → MongoDB
     ├── events    (telemetry, per-command)
     ├── sessions  (aggregated session data)
     ├── attackers (persistent host profiles)
     └── alerts    (critical threat notifications)
                   ↓
  ┌──────────────────────────────────────┐
  │    WebSocket Real-Time Dispatcher    │
  │  ├── /ws/events  (live telemetry)    │
  │  └── /ws/alerts  (critical alerts)  │
  └──────────────────────────────────────┘
                   ↓
     FastAPI REST API (http://127.0.0.1:8000)
                   ↓
     React Dashboard (http://127.0.0.1:5173)
```

---

## 🧩 Tech Stack

### Backend
| Component | Technology |
|---|---|
| API Framework | FastAPI 0.115+ with async/await |
| AI / LLM | Google Gemini 2.5 Flash (via `google-genai` SDK) |
| Database | MongoDB 7.0+ via Motor (async driver) |
| Honeypot | Cowrie SSH/Telnet Honeypot |
| Real-Time | WebSockets (native FastAPI) |
| Runtime | Python 3.12+ |

### Frontend
| Component | Technology |
|---|---|
| Framework | React 19 (Vite) |
| Styling | Tailwind CSS |
| Charts | Recharts |
| HTTP Client | Axios |
| Icons | Lucide React |

---

## 📁 Project Structure

```
intent-aware-deception-system/
├── backend/
│   └── app/
│       ├── api/routers/          # FastAPI route handlers
│       │   ├── analytics.py      # Analytics & heatmap endpoints
│       │   ├── attackers.py      # Attacker profile endpoints
│       │   ├── alerts.py         # Alert management endpoints
│       │   ├── events.py         # Event telemetry endpoints
│       │   └── sessions.py       # Session management endpoints
│       ├── models/               # Pydantic data models
│       │   ├── event.py
│       │   ├── session.py
│       │   ├── attacker.py
│       │   ├── alert.py
│       │   ├── intent.py
│       │   └── session_intelligence.py
│       ├── services/             # Core business logic
│       │   ├── log_collector.py         # Async Cowrie log ingestion
│       │   ├── event_normalizer.py      # Raw event → normalized model
│       │   ├── feature_extractor.py     # Behavioral feature extraction
│       │   ├── session_aggregator.py    # Incremental session state
│       │   ├── rule_classifier.py       # Deterministic intent rules
│       │   ├── gemini_classifier.py     # Google Gemini LLM classifier
│       │   ├── hybrid_classifier.py     # Orchestrates rule + LLM
│       │   ├── risk_engine.py           # Deterministic risk scorer
│       │   ├── session_intelligence.py  # Multi-session profiler
│       │   ├── mitre_mapper.py          # MITRE ATT&CK mapper
│       │   ├── gemini_session_analyst.py # AI session analysis
│       │   ├── persistence_service.py   # MongoDB CRUD operations
│       │   └── websocket_manager.py     # Real-time broadcast manager
│       ├── database/             # MongoDB connection & indexing
│       ├── config.py             # Environment-based configuration
│       ├── main.py               # FastAPI application entry point
│       └── pipeline.py           # Main deception pipeline orchestrator
├── frontend/
│   └── src/
│       ├── pages/                # React page components
│       │   ├── DashboardPage.jsx        # Executive overview
│       │   ├── SessionsPage.jsx         # Session list & filters
│       │   ├── SessionDetailPage.jsx    # Deep dive + AI analyst
│       │   ├── AttackersPage.jsx        # Attacker host profiles
│       │   ├── AttackerDetailPage.jsx   # Per-IP intelligence
│       │   ├── AlertsPage.jsx           # Critical alert management
│       │   └── AnalyticsPage.jsx        # Charts, heatmaps & timelines
│       ├── components/           # Reusable UI components
│       ├── hooks/                # Custom React hooks
│       └── services/             # API client abstraction
├── honeypot/                     # Cowrie honeypot instance
├── scripts/
│   ├── run_backend.py            # Backend startup script
│   ├── run_cowrie.py             # Cowrie startup script
│   ├── test_client.py            # Controlled SSH test attacker
│   └── verify_phase8_full.py     # End-to-end system audit
├── tests/                        # 67-test pytest suite
├── data/                         # Seed/reference data
├── docs/                         # Additional documentation
├── .env.example                  # Environment variable template
└── requirements.txt              # Python dependencies
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+**
- **Node.js 18+** & **npm**
- **MongoDB 7.0+** running locally on port `27017`
- **Google Gemini API Key** *(optional — system gracefully falls back to deterministic rule analysis if absent)*

---

### Step 1: Clone & Environment Setup

```bash
# Clone the repository
git clone https://github.com/Rakshita-Shetty7/intent-aware-deception-system.git
cd intent-aware-deception-system

# Create and activate Python virtual environment
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and fill in your GEMINI_API_KEY and MongoDB URI
```

---

### Step 2: Configure Environment

Edit your `.env` file:

```env
# MongoDB
MONGODB_URI=mongodb://localhost:27017
DATABASE_NAME=intent_deception_db

# Google Gemini AI (optional but recommended)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
GEMINI_ENABLED=true

# Cowrie honeypot log path
COWRIE_LOG_PATH=./honeypot/var/log/cowrie/cowrie.json

# API server
API_HOST=0.0.0.0
API_PORT=8000
```

---

### Step 3: Start All Services

#### 1. Start Cowrie Honeypot (Port 2222)
```powershell
.\.venv\Scripts\python.exe scripts/run_cowrie.py
```

#### 2. Start FastAPI Backend + Deception Pipeline (Port 8000)
```powershell
.\.venv\Scripts\python.exe scripts/run_backend.py --host 127.0.0.1 --port 8000 --with-pipeline
```

#### 3. Start React Dashboard (Port 5173)
```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open your browser to: **`http://127.0.0.1:5173/`**

---

### Step 4: Generate Test Traffic

Run a controlled SSH attack session against the honeypot:
```powershell
.\.venv\Scripts\python.exe scripts/test_client.py 127.0.0.1 2222 root root
```

Watch the dashboard populate in real time with classified events, risk scores, and attacker profiles.

---

## 📡 API Reference

Base URL: `http://127.0.0.1:8000`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health check |
| `GET` | `/api/dashboard/stats` | Executive KPI summary |
| `GET` | `/api/events` | Paginated event telemetry (filterable) |
| `GET` | `/api/events/recent` | Most recent N events |
| `GET` | `/api/events/{id}` | Single event detail |
| `GET` | `/api/sessions` | Paginated sessions (filterable) |
| `GET` | `/api/sessions/{id}` | Session detail |
| `GET` | `/api/sessions/{id}/analyze` | AI session analysis via Gemini |
| `GET` | `/api/sessions/{id}/mitre` | MITRE ATT&CK mapping |
| `GET` | `/api/attackers` | Paginated attacker profiles |
| `GET` | `/api/attackers/{source_ip}` | Attacker host intelligence |
| `GET` | `/api/alerts` | Paginated critical alerts |
| `GET` | `/api/analytics/intents` | Intent distribution |
| `GET` | `/api/analytics/severity` | Severity breakdown |
| `GET` | `/api/analytics/timeline` | Event timeline |
| `GET` | `/api/analytics/stages` | Attack stage progression |
| `GET` | `/api/analytics/risk-distribution` | Risk score histogram |
| `GET` | `/api/analytics/heatmap` | Source IP × time heatmap |
| `WS` | `/ws/events` | Live event stream (WebSocket) |
| `WS` | `/ws/alerts` | Live critical alerts (WebSocket) |

Interactive API docs: **`http://127.0.0.1:8000/docs`**

---

## 🧪 Running Automated Tests

Run the full 67-test suite:
```powershell
.\.venv\Scripts\pytest.exe tests -v
```

Run individual test modules:
```powershell
.\.venv\Scripts\pytest.exe tests/test_hybrid_classifier.py -v
.\.venv\Scripts\pytest.exe tests/test_risk_engine.py -v
.\.venv\Scripts\pytest.exe tests/test_api_endpoints.py -v
.\.venv\Scripts\pytest.exe tests/test_e2e_pipeline.py -v
```

Run the Phase 8 End-to-End System Audit:
```powershell
.\.venv\Scripts\python.exe scripts/verify_phase8_full.py
```

### Test Coverage

| Module | Test File |
|---|---|
| Rule Classifier | `test_rule_classifier.py` |
| Gemini Classifier | `test_gemini_classifier.py` |
| Hybrid Classifier | `test_hybrid_classifier.py` |
| Risk Engine | `test_risk_engine.py` |
| Event Normalizer | `test_event_normalizer.py` |
| Feature Extractor | `test_feature_extractor.py` |
| Session Aggregator | `test_session_aggregator.py` |
| Session Intelligence | `test_session_intelligence.py` |
| Log Collector | `test_log_collector.py` |
| Persistence Service | `test_persistence_service.py` |
| REST API Endpoints | `test_api_endpoints.py` |
| Analytics Endpoints | `test_analytics_endpoints.py` |
| WebSocket Streaming | `test_websocket_streaming.py` |
| Attacker Intelligence | `test_phase7_attacker_intelligence.py` |
| E2E Pipeline | `test_e2e_pipeline.py` |
| Sanitization | `test_sanitization.py` |
| MongoDB Connection | `test_mongodb_connection.py` |

---

## 🔍 Intent Classification

The hybrid classifier identifies the following attacker intents:

| Intent | Description |
|---|---|
| `RECONNAISSANCE` | Host/network enumeration, system discovery |
| `CREDENTIAL_BRUTE_FORCE` | Password spraying, authentication attacks |
| `PRIVILEGE_ESCALATION` | sudo abuse, SUID exploitation |
| `LATERAL_MOVEMENT` | Pivoting, SSH key manipulation |
| `DATA_EXFILTRATION` | File copying, network transfers |
| `PERSISTENCE` | Cron jobs, backdoors, startup modification |
| `DEFENSE_EVASION` | Log clearing, history manipulation |
| `MALWARE_DEPLOYMENT` | Downloading & executing payloads |
| `COMMAND_EXECUTION` | Generic shell command execution |
| `UNKNOWN` | Unclassified / low-signal activity |

---

## 🗺️ MITRE ATT&CK Integration

Sessions are automatically mapped to MITRE ATT&CK tactics and techniques via `/api/sessions/{id}/mitre`, returning:
- Matched **Tactics** (e.g., TA0001 Initial Access)
- Matched **Techniques** (e.g., T1110 Brute Force)
- Confidence scores per mapping
- Evidence command references

---

## 🧠 AI Integration Details

The system integrates **Google Gemini 2.5 Flash** via the official `google-genai` Python SDK for two purposes:

1. **Intent Classification** — LLM-based behavioral analysis to supplement deterministic rules, especially for ambiguous or novel command patterns.
2. **Session Analysis** — On-demand AI analyst report: threat narrative, attacker sophistication assessment, and recommended countermeasures.

> **Graceful Degradation**: If `GEMINI_API_KEY` is absent or the API is unavailable, the system automatically falls back to the deterministic rule classifier with zero downtime.

---

## 📊 Dashboard Pages

| Page | Description |
|---|---|
| **Executive Dashboard** | KPI cards: total events, active sessions, critical alerts, top intents |
| **Sessions** | Filterable, paginated session table with risk scores and severity badges |
| **Session Detail** | Full event timeline, AI analyst report, MITRE mapping, stage trajectory |
| **Attackers** | Host intelligence profiles with multi-session behavioral history |
| **Attacker Detail** | Per-IP deep dive: all sessions, cumulative risk, intent distribution |
| **Alerts** | Critical threshold alerts with status management |
| **Analytics** | Intent pie charts, severity bars, risk histograms, source heatmaps, timelines |

---

## 🛡️ Security & Privacy

| Control | Implementation |
|---|---|
| **Zero Plaintext Passwords** | All auth attempts redact passwords to `[REDACTED]` before persistence |
| **Environment Secrets** | API keys/URIs live only in `.env` (git-ignored) |
| **Sanitized WebSocket Streams** | Credentials are never broadcast to clients |
| **AI Boundary Enforcement** | Gemini is used for descriptive intelligence only; all risk scores are computed deterministically |
| **Deterministic Risk Authority** | Risk scores (0–100) are always math-based; LLM output never overrides them |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'feat: add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">

Built with ❤️ by [Rakshita Shetty](https://github.com/Rakshita-Shetty7)

⭐ Star this repo if you find it useful!

</div>
