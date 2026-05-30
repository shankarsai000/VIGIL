# 🛡️ VIGIL — Real-Time Behavioral Immune System for AI Agent Pipelines
> Visual Intelligence & Governance for Intelligent Layers  
> **Team CS · GM University · ArmorIQ Track 2 · HackBriven May 30 2026**

VIGIL is an advanced, real-time security monitoring and containment system designed for distributed AI agent pipelines. It protects active agent pipelines from behavioral threats, privilege escalations, unauthorized agent-to-agent delegations, and massive exfiltration vectors. 

Every single security threat is gated through the **ArmorIQ Policy Engine** for authorization before containment is executed, audited in immutable logs, and dynamically translated into plain English narrative by a dedicated **Claude AI incident explainer**.

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

## 🚀 Setup Instructions (5 Steps)

Follow these simple steps to spin up VIGIL locally on your workstation:

### 1. Clone & Navigate
Ensure you are in the project root directory:
```bash
cd VIGIL
```

### 2. Configure Environment Variables
Copy `.env.example` to create your local `.env` configuration file:
```bash
cp .env.example .env
```
*Note: By default, `ARMORIQ_API_KEY=mock` is configured. This enables local mock verification policies so the dashboard runs perfectly out of the box without active remote API keys.*

### 3. Spin Up Docker Containers
Build and boot both backend and frontend applications concurrently using docker-compose:
```bash
docker-compose up --build -d
```

### 4. Verify Services Status
Check container status:
```bash
docker-compose ps
```
* Backend will be running at [http://localhost:8000](http://localhost:8000)
* Frontend Dashboard will be accessible at [http://localhost:5173](http://localhost:5173)

### 5. Launch the Dashboard
Open your web browser and navigate to:
👉 **[http://localhost:5173](http://localhost:5173)**

---

## 🧪 Judge Live Demo Guide

To demonstrate VIGIL's capabilities to hackathon judges, follow this exact step-by-step click sequence:

### 🎬 Setup Verification
1. Open the VIGIL Dashboard.
2. Confirm the top-right indicator shows **● CONNECTED** (indicating active WebSocket telemetry stream).
3. Observe the **Active AI Agents** column showing **CustomerBot**, **AnalyticsAgent**, and **BillingAgent** operating securely in `NORMAL` status with 20 seeded historical telemetry events (warming up the EWMA baselines).

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

## 🚀 How to Run the Project (Local Development)

Follow these steps to spin up the entire VIGIL Autonomous Security Governance pipeline on your Windows system:

### 1. Backend Server Setup

The backend serves the 3-layer hybrid detection engine, WebSocket telemetry streams, and ArmorIQ mock gateways.

#### Activate Python Virtual Environment (`venv`):
Open your terminal (Command Prompt or PowerShell) in the root of the project directory and run:
```powershell
# In PowerShell:
.\venv\Scripts\Activate.ps1

# In Command Prompt:
.\venv\Scripts\activate.bat
```

#### Run the Uvicorn Server:
Once the virtual environment is active, run the Uvicorn development server:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
* **URL**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### 2. Frontend Observability Console Setup

The frontend is a next-generation Vite + React + Tailwind dashboard.

#### Navigate to the Frontend Directory:
Open a separate terminal window and navigate to the frontend folder:
```bash
cd frontend
```

#### Install Node Dependencies (if running for the first time):
```bash
npm install
```

#### Run the Frontend Development Server:
```bash
npm run dev
```
* **Local Web Interface**: [http://localhost:5173](http://localhost:5173)

---

### 🌐 System URLs Summary
* **Frontend Console**: [http://localhost:5173](http://localhost:5173)
* **Backend API Host**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive OpenAPI Specs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

