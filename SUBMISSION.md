# VIGIL 2.0 — Policy Immune System for AI Agent Pipelines

> **Hackathon Submission**: Flow State Hackathon by ArmorIQ (October 10 – October 17, 2026)  
> **Team**: Team CS · GM University  
> **Repository**: [https://github.com/shankarsai000/VIGIL](https://github.com/shankarsai000/VIGIL)  
> **Submission Branch**: `submission-package`  

---

## 1. Short Description

VIGIL is an autonomous policy immune system for AI agent pipelines. It detects behavioral attacks and tool misuse across active agents, transforms confirmed incidents into candidate ArmorIQ policies, mathematically proves safety via counterfactual replay over historical traffic with Clopper-Pearson binomial confidence bounds, enforces approved rules through the ArmorIQ Policy Platform, and preserves tamper-evident evidence in hash-chained audit ledgers and signed offline vaults.

---

## 2. How the Agent Works

VIGIL operates as a closed-loop security control plane for multi-agent workflows:

1. **Telemetry & Dual-Engine Detection**:
   - The runtime intercepts agent tool calls, delegations, and payloads.
   - Dual-engine analysis combines Isolation Forest anomaly detection and EWMA call-rate analysis with heuristic threat signatures (data exfiltration, prompt injections, capability violations, behavioral spoofing).
   - Records all traffic as action records with structural argument redaction (argument shapes only, zero raw queries or secrets).
2. **Incident Containment & Human-in-the-Loop Governance**:
   - High-severity incidents trigger fail-closed containment holds.
   - Requests are routed to an authenticated Slack approval channel using Block Kit with HMAC-SHA256 signature verification, verified corporate email domain validation, single-use server-issued nonces, and a strict 2-approver rule for high-impact actions.
3. **Automated Policy Synthesis**:
   - Confirmed incidents are grouped into candidate deny rules targeting the exact malicious tool and argument pattern.
4. **Counterfactual Replay & Statistical Bound**:
   - Before any policy can activate or block an agent, it is replayed against the complete historical traffic baseline.
   - The candidate rule must achieve zero false blocks ($k = 0$) on benign traffic, and compute the exact Clopper-Pearson upper confidence bound $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ at 95% confidence ($\delta = 0.05$).
5. **Signed Receipts & Evidence Vault**:
   - Every state transition is written to an append-only SHA-256 hash-chained audit ledger.
   - Evidence bundles with Ed25519-signed manifests can be exported and verified offline on air-gapped systems.

---

## 3. How ArmorIQ is Used

ArmorIQ is the platform security boundary and policy evaluation engine:

1. **Intent Token Minting**:
   - When an agent or containment action is initiated, VIGIL captures the execution plan (`capture_plan`) and requests a signed intent token from the ArmorIQ API (`get_intent_token`).
2. **Policy Enforcement at Proxy**:
   - Invocations pass through the ArmorIQ Customer Proxy (`https://customer-proxy.armoriq.ai`), where Open Policy Agent (OPA) evaluates identity policies and tool restrictions against the token.
3. **Fail-Closed Boundary**:
   - If an agent reaches past its boundary, ArmorIQ raises a `PolicyBlockedException` at the platform level. VIGIL ensures that policy denials are strictly platform blocks, never simulated by client-side pre-checks.
4. **FastMCP Integration**:
   - Both the containment server (`vigil-containment`, port 8790) and the tools server (`vigil-tools`, port 8791) run as FastMCP servers registered with ArmorIQ identity configurations (`config/*.armoriq.yaml`).

---

## 4. Other Tools

- **FastMCP**: Python-based Model Context Protocol servers providing tools (`quarantine_agent`, `billing_database`, `order_status`).
- **Slack Bolt SDK**: Enterprise governance adapter delivering interactive Block Kit approval cards.
- **Scikit-learn**: Isolation Forest models for tool-call anomaly detection.
- **Cryptography (PyCA)**: Ed25519 signing and verification for evidence bundles and receipts.
- **FastAPI & Uvicorn**: High-performance asynchronous backend and REST API.
- **React, Vite & Tailwind/Vanilla CSS**: Real-time operations dashboard with live WebSocket feeds.

---

## 5. Proof of ArmorIQ

Empirical evidence proving the ArmorIQ security boundary holds under live and offline evaluation:

1. **Live Platform Verification Receipt**:
   - Live intent token minting (`https://api.armoriq.ai`) and live proxy blocking (`https://customer-proxy.armoriq.ai`) verified against real ArmorIQ cloud infrastructure.
   - 3/3 simulated attack calls blocked with `PolicyBlockedException` from OPA: [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json)
2. **Preflight Introspection**:
   - Empirically documented SDK exceptions and layer attribution: [`evidence/M5/preflight.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json)
3. **Live Scenario Matrix (ALLOW, DENY, HOLD, BENIGN)**:
   - Full live test suite run recorded in [`evidence/live/matrix.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/matrix.json)
4. **Platform Registration Audit**:
   - Identity `vigil-containment-v2` and MCP configs documented in [`evidence/platform_changes.md`](file:///d:/vigil-v2/vigil-v2/evidence/platform_changes.md)
5. **Signed Evidence Vault**:
   - Air-gapped verification proving tamper detection: [`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt)

---

## 6. Setup

### Prerequisites
- Python 3.11+ (managed via `uv`)
- Node.js 18+ (for frontend dashboard)
- ArmorIQ Account with `ARMORIQ_API_KEY` and `ARMORIQ_USER_EMAIL`

### Environment Configuration (`.env`)
```bash
ARMORIQ_MODE=live
ARMORIQ_API_KEY=[REDACTED]
ARMORIQ_USER_EMAIL=[REDACTED]
ARMORIQ_AGENT_ID=vigil-containment-v2
ARMORIQ_CONTAINMENT_MCP_ID=vigil-containment-v2
OPERATOR_API_KEY=[REDACTED]
SUBMISSION_MODE=1
SLACK_MODE=socket
SLACK_BOT_TOKEN=[REDACTED]
SLACK_SIGNING_SECRET=[REDACTED]
SLACK_APPROVAL_CHANNEL=[REDACTED]
SLACK_APP_TOKEN=[REDACTED]
SLACK_ALLOWED_EMAIL_DOMAINS=gmail.com
```

### Installation & Launch
```powershell
# 1. Install dependencies
uv pip install -r requirements.txt
cd frontend && npm install && cd ..

# 2. Run offline tests
uv run pytest

# 3. Start services
uv run uvicorn backend.main:app --host 0.0.0.0 --port 8000
cd frontend && npm run dev
```

---

## 7. Brief Compliance Table

Mapping each requirement from [`docs/brief/BRIEF_RAW.md`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md) to its verifiable evidence path:

| ID | Brief Requirement Quote | Source Line | Evidence Path | Status |
|---|---|---|---|---|
| **BR-01** | *"Build an autonomous agent that takes real actions (writing code, calling tools, triggering workflows)."* | [`BRIEF_RAW.md:3`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L3) | [`backend/main.py`](file:///d:/vigil-v2/vigil-v2/backend/main.py), [`demo/tools_mcp/server.py`](file:///d:/vigil-v2/vigil-v2/demo/tools_mcp/server.py) | **PASS** |
| **BR-02** | *"The unique requirement is to demonstrate your agent reaching past its boundary and proving that the ArmorIQ security boundary successfully holds."* | [`BRIEF_RAW.md:3`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L3) | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json), [`evidence/live/deny.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/deny.json) | **PASS** |
| **BR-03** | *"Build Week: October 10 – October 17"* | [`BRIEF_RAW.md:9`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L9) | [`CHANGELOG.md`](file:///d:/vigil-v2/vigil-v2/CHANGELOG.md), [`docs/DISCLOSURE.md`](file:///d:/vigil-v2/vigil-v2/docs/DISCLOSURE.md) | **PASS** |
| **BR-04** | *"Submissions Close: Today, October 17"* | [`BRIEF_RAW.md:11`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L11) | Release tag `v2.0.0-submission` on branch `submission-package` | **IN PROGRESS** |
| **BR-05** | *"You must submit a working project"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | [`evidence/SLACK-1/offline.txt`](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/offline.txt), [`scripts/check_requirements.py`](file:///d:/vigil-v2/vigil-v2/scripts/check_requirements.py) | **PASS** |
| **BR-06** | *"a short demo"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | `docs/demo.mp4` (Human recorded walkthrough, <= 90 seconds) | **NOT STARTED** |
| **BR-07** | *"clear documentation showing what your agent does"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | [`README.md`](file:///d:/vigil-v2/vigil-v2/README.md), [`docs/ARCHITECTURE.md`](file:///d:/vigil-v2/vigil-v2/docs/ARCHITECTURE.md), [`docs/RUNBOOK.md`](file:///d:/vigil-v2/vigil-v2/docs/RUNBOOK.md) | **PASS** |
| **BR-08** | *"how you integrated ArmorIQ (or an MCP server)"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | [`backend/app/policies/containment_mcp.py`](file:///d:/vigil-v2/vigil-v2/backend/app/policies/containment_mcp.py), [`config/vigil-containment.armoriq.yaml`](file:///d:/vigil-v2/vigil-v2/config/vigil-containment.armoriq.yaml) | **PASS** |
| **BR-09** | *"and how the security boundary was tested."* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json), [`evidence/SLACK-1/live_containment_approve.json`](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/live_containment_approve.json) | **PASS** |
| **BR-10** | *"Event: Flow State, an online, Discord-first AI agent and MCP hackathon organized by ArmorIQ."* | [`BRIEF_RAW.md:1`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L1) | [`config/vigil-containment.armoriq.yaml`](file:///d:/vigil-v2/vigil-v2/config/vigil-containment.armoriq.yaml), [`config/vigil-tools.armoriq.yaml`](file:///d:/vigil-v2/vigil-v2/config/vigil-tools.armoriq.yaml) | **PASS** |

---

## 8. Known Limitations

1. **Replay is Counterfactual, Not Dynamic**:
   - Historical replay verifies that a candidate rule would not have blocked legitimate historical traffic. It does not simulate adaptive multi-turn adversarial tactics where an agent circumvents a block by discovering alternate tool combinations.
2. **Conditional Exchangeability Assumption**:
   - The statistical upper bound $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ assumes that future agent traffic follows the distribution of the recorded baseline. If tools or prompts shift, bounds must be recalibrated.
3. **Unlabelled Traffic Baseline**:
   - Historical records are labelled as "assumed benign". If undetected attacks contaminated the historical baseline, the measured false-block rate reflects that baseline.
