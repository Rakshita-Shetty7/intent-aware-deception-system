# Intent-Aware Deception System for Real-Time Attacker Profiling

[![Release](https://img.shields.io/badge/Release-v1.0--RC-emerald.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](#)
[![React](https://img.shields.io/badge/React-19-61dafb.svg)](#)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0+-47A248.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-67%2F67%20Passed-brightgreen.svg)](#)

---

## 🎯 Project Objective

The **Intent-Aware Deception System for Real-Time Attacker Profiling** is an end-to-end, controlled honeypot cybersecurity platform designed to:
- Capture live and simulated attacker interactions in an isolated deception environment using **Cowrie**.
- Stream and ingest honeypot event telemetry asynchronously in real time.
- Extract behavioral patterns, command signatures, and tactic indicators.
- Classify attacker intent and attack stage using a **Hybrid Classifier** (combining deterministic heuristic rules and large language model intelligence via the official Google Gemini SDK).
- Evaluate threat severity and compute deterministic session risk scores ($0 \le \text{risk} \le 100$).
- Maintain persistent, indexed attacker profiles, sessions, alerts, and telemetry records in **MongoDB**.
- Expose threat intelligence via high-performance **FastAPI REST APIs** and push live updates to web clients over **WebSockets**.
- Provide an interactive, dark cybersecurity analyst dashboard built in **React 19**, **Tailwind CSS**, and **Recharts**.

---

## 🏗️ Core Architecture & Pipeline

```text
Controlled Attacker Test Client (SSH/Telnet)
                   ↓
Cowrie Honeypot (127.0.0.1:2222)
                   ↓
cowrie.json Real-Time Event Stream
                   ↓
AsyncLogCollector (backend/app/services/log_collector.py)
                   ↓
Event Normalizer & Behavioral Feature Extractor
                   ↓
Incremental Session Aggregator
                   ↓
Hybrid Intent Classification Engine (Deterministic Rules + Google Gemini AI)
                   ↓
Deterministic Threat Risk Engine (0-100 Score & Severity Mapping)
                   ↓
Session Intelligence Attacker Profiler (Multi-stage progression tracking)
                   ↓
Persistence Service (backend/app/services/persistence_service.py)
                   ↓
MongoDB Database (deception_db)
├── events       (Indexed by session_id, timestamp, source_ip, intent, severity, risk_score)
├── sessions     (Indexed by session_id, source_ip, last_seen, severity, risk_score)
├── attackers    (Indexed by source_ip, last_seen, maximum_risk, severity)
└── alerts       (Indexed by alert_id, session_id, timestamp, severity, status)
                   ↓
WebSocket Real-Time Dispatcher (backend/app/services/websocket_manager.py)
├── /ws/events   (Live sanitized telemetry streaming)
└── /ws/alerts   (Critical threshold threat notifications)
                   ↓
FastAPI REST API Server (http://127.0.0.1:8000)
├── /api/health
├── /api/dashboard/stats
├── /api/events (filtering, pagination, /recent, /{id})
├── /api/sessions (filtering, pagination, /{id}, /{id}/analyze, /{id}/mitre)
├── /api/attackers (filtering, pagination, /{source_ip})
├── /api/alerts (filtering, pagination)
└── /api/analytics (intents, severity, timeline, stages, risk-distribution, heatmap)
                   ↓
React Dashboard (http://127.0.0.1:5173)
├── Executive Overview Dashboard
├── Live & Historical Sessions
├── Session Deep Dive & Attack Trajectory
├── Google Gemini AI Session Analyst
├── Attacker Host Intelligence Profiles
├── Critical Security Alerts
└── Threat Intelligence Analytics & Risk Heatmap
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.12+**
- **Node.js 18+** & **npm**
- **MongoDB 7.0+** running locally on port 27017
- Optional: **Google Gemini API Key** (for LLM intent classification and AI session analysis; system gracefully falls back to deterministic rule analysis if absent).

---

### Step 1: Environment Setup

```powershell
# Clone or open repository
cd intent-aware-deception-system

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

---

### Step 2: Start All Services

#### 1. Start Cowrie Honeypot (Port 2222)
```powershell
.\.venv\Scripts\python.exe scripts/run_cowrie.py
```

#### 2. Start FastAPI Backend with Deception Pipeline (Port 8000)
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

### Step 3: Run Controlled Honeypot Interactions

Execute a controlled SSH session against the honeypot to generate telemetry:
```powershell
.\.venv\Scripts\python.exe scripts/test_client.py 127.0.0.1 2222 root root
```

---

## 🧪 Running Automated Tests

Run the full test suite (67 unit and integration tests):
```powershell
.\.venv\Scripts\pytest.exe tests -v
```

Run the Phase 8 End-to-End System Audit:
```powershell
.\.venv\Scripts\python.exe scripts/verify_phase8_full.py
```

---

## 🛡️ Security & Privacy Assurance

- **Zero Plaintext Passwords**: All authentication attempts have password fields redacted (`[REDACTED]`) before persistence and broadcasting.
- **Environment Separation**: API keys and secrets exist only in `.env` (ignored by git).
- **Sanitized Telemetry**: Sensitive credentials are never broadcast over WebSockets or transmitted to the Gemini API.
- **Deterministic Risk Authority**: All risk scores ($0 \le \text{risk} \le 100$) are calculated by the deterministic mathematical Risk Engine; AI is used strictly for descriptive threat intelligence and reasoning.
