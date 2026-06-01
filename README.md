# 🛡️ VIGIL — Real-Time Behavioral Immune System for AI Agent Pipelines
> Visual Intelligence & Governance for Intelligent Layers  
> **Team CS · GM University · ArmorIQ Track 2 · HackBriven**

🔗 **GitHub Repository**: [https://github.com/shankarsai000/VIGIL](https://github.com/shankarsai000/VIGIL)

VIGIL is an advanced, real-time security monitoring and containment system designed for distributed AI agent pipelines. It protects active agent pipelines from behavioral threats, privilege escalations, unauthorized agent-to-agent delegations, and massive exfiltration vectors. 

Every single security threat is gated through the **ArmorIQ Policy Engine** for authorization before containment is executed, audited in immutable logs, and dynamically translated into plain English narrative by a dedicated **Claude AI incident explainer**.

### 📦 What's Included
- **Backend Services**: Python FastAPI server with async WebSocket support for real-time telemetry
- **Frontend Dashboard**: React 18 + TypeScript + Tailwind CSS with real-time state management
- **Detection Engine**: 3-layer hybrid anomaly detection (Heuristics, EWMA Baselines, Isolation Forest)
- **Policy Gateway**: ArmorIQ integration for threat authorization and audit trails
- **Containerized Deployment**: Docker & Docker Compose for seamless multi-container orchestration

---

## 🏗️ System Architecture

```
                       [AI Agent Telemetry Feed]
                                   │
                                   ▼
                       [Behavioral Monitor Interceptor]
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
      [Sliding Window Metrics]              [3-Layer Hybrid Detector]
      (Rate, Payload, Delegations)           ├── Layer 1: Heuristic Rules
                │                            ├── Layer 2: EWMA Baselines
                ▼                            └── Layer 3: Isolation Forest (ML)
      [EWMA Profiles Calibration]                     │
                │                                     ▼
                └──────────────────────────────► [Aggregated Threat Score]
                                                      │
                                                      ▼
                                           [ArmorIQ Policy Gate]
                                            (POST /intent/verify)
                                                      │
                                   ┌──────────────────┴──────────────────┐
                                   ▼                                     ▼
                              [APPROVED]                              [DENIED]
                                   │                                     │
                                   ▼                                     ▼
                       [Remediation Executor]                     [Audit Event Log]
                       ├── QUARANTINE (Confinement)                      │
                       ├── ALERT (Operators warn)                        ▼
                       └── LOG (Audited SQLite)                     (Log Only)
                                   │
                                   ▼
                       [Claude AI Incident Explainer]
                       (Translate metrics to plain English)
                                   │
                                   ▼
                       [FastAPI WebSocket Hub]
                                   │
                                   ▼
                      [VIGIL Real-Time Dashboard]
```

---

## 🛠️ Technology Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.11+, FastAPI | Async web core, websockets server hub |
| **Database** | SQLite via aiosqlite | Asynchronous local telemetry store and fallback audit logs |
| **Detection Engine** | Scikit-Learn Isolation Forest, EWMA | Behavioral baseline calculation and anomaly classification |
| **Policy Brain** | ArmorIQ SDK Gateway | Action validation and immutable remote auditing |
| **LLM Narrator** | Anthropic Claude API (`claude-3-5-sonnet`) | Dynamic 3-sentence plain English narration of incidents |
| **Frontend** | React 18, TypeScript, Zustand | Real-time state management and sleek dashboard |
| **Styling** | Tailwind CSS | Glassmorphism UI panel design with custom alerts |
| **Deployment** | Docker, Docker-compose, Nginx | Multi-container builds with reverse proxied endpoints |

---

## 🚀 Quick Setup (Docker - Recommended)

The fastest way to get VIGIL running is using Docker Compose:

### Prerequisites
- **Docker** and **Docker Compose** installed on your system
- **Git** for cloning the repository

### Steps

1. **Clone the repository**:
```bash
git clone https://github.com/shankarsai000/VIGIL.git
cd VIGIL
```

2. **Configure Environment** (optional):
```bash
cp .env.example .env
```
*Note: The project comes with `ARMORIQ_API_KEY=mock` by default for local testing without external API credentials.*

3. **Spin Up the Application**:
```bash
docker-compose up --build -d
```

4. **Verify Services**:
```bash
docker-compose ps
```

5. **Access the Dashboard**:
👉 **[http://localhost:5173](http://localhost:5173)**
- Backend API: [http://localhost:8000](http://localhost:8000)
- API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🧪 Live Demo Scenarios

The VIGIL dashboard includes interactive demonstrations of real-time threat detection and response:

### 🎬 Dashboard Overview
1. Open the VIGIL Dashboard at [http://localhost:5173](http://localhost:5173)
2. Confirm the top-right indicator shows **● CONNECTED** (WebSocket telemetry stream active)
3. View **Active AI Agents**: CustomerBot, AnalyticsAgent, and BillingAgent in NORMAL status with 20 seeded telemetry events

---

### 🔥 Scenario 1: Prompt Injection on CustomerBot
* **The Attack**: Malicious instructions are injected into the chatbot, instructing it to export financial databases to an external host.
* **Execution**: Click the **Prompt Injection** button in the bottom panel.
* **What to Show the Judges**:
  * An incident flashes instantly in the **Threat Feed** with a threat score of **88%** (Critical).
  * The **ArmorIQ Policy Gate** evaluates the payload, authorizing immediate containment.
  * **CustomerBot** status transitions instantly to **QUARANTINED** (red pulsing card border).
  * Within 2 seconds, the **VIGIL Narrator** renders a plain-English explanation: *"A user attempted to hijack CustomerBot by injecting a prompt instructing it to bypass safety boundaries and export data..."*
  * Click the incident card in the feed to slide open the detail overlay, showing the detailed **Rule Engine (60%)** score contribution.

---

### 🔥 Scenario 2: Privilege Escalation on CustomerBot
* **The Attack**: An attacker tries to force the chatbot to invoke the unauthorized tool `billing_database`.
* **Execution**: Click the **Privilege Escalation** button.
* **What to Show the Judges**:
  * An incident is registered in the feed with a threat score of **90%** (Scope Violation).
  * The **ArmorIQ Policy Gate** denies access to the tool.
  * An immutable entry is written to the **ArmorIQ Audit Trail** on the right column showing a **✓ APPROVED** policy decision to execute the **QUARANTINE** remediation.
  * The chatbot remains contained and quarantined, preventing database exposure.

---

### 🔥 Scenario 3: Unauthorized Delegation
* **The Attack**: The chatbot attempts to delegate processing actions directly to the restricted **BillingAgent** (violating authorization boundaries).
* **Execution**: Click the **Unauthorized Delegation** button.
* **What to Show the Judges**:
  * VIGIL intercepts the delegation event, scoring it at **95%** severity.
  * Highlight the **ArmorIQ Audit Trail** logging the exact violation, proving boundary compliance.

---

### 🔥 Scenario 4: Data Exfiltration Anomaly on AnalyticsAgent
* **The Attack**: AnalyticsAgent is compromised and suddenly attempts a massive **500KB** data exfiltration request (100x normal baseline).
* **Execution**: Click the **Data Exfiltration** button.
* **What to Show the Judges**:
  * VIGIL's **EWMA Behavior Profiler** layer triggers a **Volume Anomaly** flag (score contribution).
  * The aggregated threat score crosses the critical threshold.
  * **AnalyticsAgent** is immediately quarantined, preventing major data leakage.

---

## 🚀 Local Development Setup

For local development without Docker, follow these instructions:

### Prerequisites
- **Python 3.11+** with venv support
- **Node.js 18+** with npm
- **Git**

### Backend Server

1. **Activate Virtual Environment**:
```powershell
# PowerShell
.\venv\Scripts\Activate.ps1

# Command Prompt
.\venv\Scripts\activate.bat

# Linux/macOS
source venv/bin/activate
```

2. **Install Dependencies** (if not already installed):
```bash
pip install -r backend/requirements.txt
```

3. **Run the Backend Server**:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend API**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Frontend Dashboard

1. **Navigate to Frontend Directory**:
```bash
cd frontend
```

2. **Install Dependencies**:
```bash
npm install
```

3. **Start Development Server**:
```bash
npm run dev
```
- **Dashboard**: [http://localhost:5173](http://localhost:5173)

---

## 📚 API & Component Structure

- **Backend**: `/backend/` - FastAPI server with detection engine, WebSocket hub, and ArmorIQ gateway
- **Frontend**: `/frontend/` - React + TypeScript with real-time state management
- **Services**: `/backend/services/` - Modular threat detection, remediation, and incident management services
- **Models**: `/backend/models/` - Pre-trained ARMORCLAW detection model
- **Storage**: `/backend/storage/` - Audit logs, replay logs, and telemetry storage

---

## 🤝 Contributing

VIGIL is an open-source project. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature/your-feature`
5. Submit a pull request

---

## 📝 License

This project is part of the ArmorIQ Track 2 at HackBriven. See LICENSE for details.

---

## 🌐 URLs Summary

| Component | URL |
| :--- | :--- |
| **Frontend Dashboard** | [http://localhost:5173](http://localhost:5173) |
| **Backend API** | [http://127.0.0.1:8000](http://127.0.0.1:8000) |
| **API Documentation** | [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) |
| **GitHub Repository** | [https://github.com/shankarsai000/VIGIL](https://github.com/shankarsai000/VIGIL) |

