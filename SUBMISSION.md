# VIGIL v2 — Autonomous Multi-Agent Defense & ArmorIQ Governance Layer

> **ArmorIQ Hackathon Submission**  
> **Track**: Agent Governance, Security & Policy Enforcement  
> **Repository**: [https://github.com/armor-vigil/vigil-v2](https://github.com/armor-vigil/vigil-v2)  
> **Branch**: `armoriq-live`

---

## 1. Executive Summary

Autonomous AI agents are increasingly entrusted with operational capabilities: querying databases, executing code, processing customer refunds, and orchestrating internal workflows. When these agents are compromised via prompt injections, model jailbreaks, or behavioral drift, traditional guardrails (like prompt filters or passive logging) fail to halt the damage in real time. Worse, autonomous containment mechanisms themselves introduce severe risks: what prevents an attacker from weaponizing the containment tool, or an unauthenticated process from arbitrarily isolating mission-critical agents?

**VIGIL v2** solves this fundamental challenge by pairing an active, multi-engine threat detection system with **ArmorIQ's Policy Platform (`armoriq-sdk==0.6.10`)**. In VIGIL v2:
1. **Containment is Cryptographically Governed**: Isolating an agent is not an unverified local function call; it is an MCP tool invocation that requires plan capture, Open Policy Agent (OPA) validation, and a cryptographically signed intent token from the ArmorIQ Customer Proxy.
2. **Security is Strictly Fail-Closed**: No error, unhandled exception, network partition, or human approval bypasses an ArmorIQ policy hold.
3. **Decisions are Cryptographically Sealed**: Every detection, score, approval, and execution is committed to an append-only SHA-256 hash-chained audit ledger.
4. **The Security Loop is Closed**: Detected attacks automatically synthesize OPA deny rules, validate them against historical benign sessions to ensure zero regressions, and update ArmorIQ policies live.

---

## 2. The Problem: The Agent Containment Dilemma

Securing autonomous agent ecosystems presents three critical failure modes:
1. **The Actuation Vulnerability**: Once an agent is identified as compromised, triggering isolation tools (revoking credentials, killing processes, quarantining agents) without cryptographic governance opens a dangerous vector: rogue agents can manipulate the defense system itself.
2. **The "Fail-Open" Human Governance Trap**: Traditional Human-in-the-Loop (HITL) approval panels often treat operator approval as an absolute bypass. If an operator is tricked into approving a malicious tool call, or if a backend error occurs, the system fails open.
3. **The Disconnect Between Incidents and Policy**: When an attack occurs, mitigation is manual. The time window between detecting a novel attack and codifying an OPA policy rule leaves agent fleets vulnerable to repeated compromise.

---

## 3. The VIGIL v2 Solution

VIGIL v2 addresses these challenges through a unified architecture combining real-time defense, cryptographically enforced governance, and automated closed-loop policy synthesis.

```text
               +-------------------------------------------------------+
               |                  VIGIL v2 Defense Core                |
               +-------------------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
    +-----------------------------+                 +-----------------------------+
    | Dual Threat Detection Engine|                 | Cryptographic Audit Ledger  |
    |  - ML: Isolation Forest     |                 |  - SHA-256 Hash Chain       |
    |  - Time-Series: EWMA Drift  |                 |  - 2,300+ Verified Blocks   |
    |  - Heuristics: Regex & Rules|                 |  - Instant Tamper Detection |
    +-----------------------------+                 +-----------------------------+
                   |
                   v
    +-----------------------------------------------------------------------------+
    |                         ArmorIQ Policy Gate Layer                           |
    |  1. capture_plan(tool="quarantine_agent")                                    |
    |  2. get_intent_token() -> OPA Policy Evaluation                             |
    |  3. invoke_with_policy() -> Signed Token Validation at Proxy                |
    +-----------------------------------------------------------------------------+
                   |                                               |
         [If Policy Satisfied]                           [If Policy Violated]
                   v                                               v
    +-----------------------------+                 +-----------------------------+
    | FastMCP Containment Plane   |                 | Fail-Closed Rejection       |
    |  - Port 8790 via Cloudflare |                 |  - PolicyBlockedException   |
    |  - Authenticated Actuation  |                 |  - PolicyHoldException      |
    +-----------------------------+                 +-----------------------------+
                   |
                   v
    +-----------------------------------------------------------------------------+
    |                 Closed-Loop Incident-to-Policy Synthesis                    |
    |  - Ingest attack signatures from audit ledger                               |
    |  - Replay candidate deny rules against benign history (0 regressions)       |
    |  - Update ArmorIQ Control Plane with onConflict: "replace"                  |
    |  - Live verification: malicious tools blocked at proxy before reaching agent|
    +-----------------------------------------------------------------------------+
```

---

## 4. Key Innovations & Technical Highlights

### 1. Governed Containment via ArmorIQ & FastMCP
Containment operations in VIGIL v2 are encapsulated as Model Context Protocol (MCP) tools served by FastMCP on port 8790 (`backend/app/policies/containment_mcp.py`). When the threat engine flags a compromised agent, the **ArmorIQ Policy Gate** (`backend/app/policies/armoriq_gate.py`):
- Captures an execution plan signed with the caller's identity (`vigil-containment-v2`).
- Mints an intent token evaluated against OPA rules on the ArmorIQ control plane.
- Proxies the invocation through `https://customer-proxy.armoriq.ai` over a secure Cloudflare tunnel.
- FastMCP authenticates with VIGIL's backend `/internal/containment/quarantine` using an isolated `CONTAINMENT_SECRET`. Port 8000 remains strictly internal.

### 2. Strict Fail-Closed Semantics
In `armoriq_gate.py`:
- `PolicyBlockedException` maps directly to **DENIED**.
- `PolicyHoldException` maps to **ESCALATE** (awaiting authorized human hold release; never auto-approved).
- Unhandled errors or network timeouts map to **ESCALATE**.
- **Human Approval Integrity**: Even if an operator clicks "Approve" in VIGIL's Telegram or Web Governance UI, the system verifies the actual actuation status against the policy gate. The approval outcome is permanently recorded as either `QUARANTINE` or `LOG (DENIED)`.

### 3. Cryptographic Tamper-Resistant Audit Ledger
- Every state mutation, threat score, raw payload, and policy response is appended to `backend/storage/audit_ledger.jsonl`.
- Each entry is cryptographically linked to the previous block via SHA-256 hash chaining:
  $$\text{Hash}_i = \text{SHA256}(\text{sequence}_i \parallel \text{timestamp}_i \parallel \text{event\_type}_i \parallel \text{data}_i \parallel \text{Hash}_{i-1})$$
- The ledger endpoint `GET /audit/verify` audits the full chain. Modifying a single character or anomaly score in the historical database immediately invalidates the cryptographic chain.

### 4. Closed-Loop Incident-to-Policy Synthesis
When an agent is attacked (e.g., unauthorized calls to `billing_database`):
- The **Synthesis Engine** (`backend/app/policies/synthesis.py`) analyzes the incident against historical benign usage (e.g., valid `order_status` calls).
- It synthesizes an ArmorIQ YAML deny patch:
  ```yaml
  name: customer-bot
  type: identity
  policies:
    - deny: vigil-tools.billing_database
    - allow: vigil-tools.order_status
  ```
- **Replay Validation**: The rule is evaluated against benign history before deployment to mathematically ensure zero false positives and zero functional regressions.
- **Dynamic Platform Update**: The patch is deployed live to ArmorIQ using `onConflict: "replace"`, immediately blocking subsequent attack attempts at the customer proxy.

---

## 5. Empirical Proof Points & Live Evidence

Every claim in this submission is verified by empirical artifacts generated against the production ArmorIQ platform:

| Claim / Mechanism | Empirical Proof & Verification File | Outcome |
| :--- | :--- | :--- |
| **Live Plan & Token Actuation** | [`evidence/live/allow.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/allow.json) | Plan ID generated, intent token `ba308981...` minted, tool executed in 4.27s with status `quarantined`. |
| **Live Platform Block (DENY)** | [`evidence/live/deny.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/deny.json) | Unauthorized tool `drop_database` raised `PolicyBlockedException` directly at customer proxy. |
| **Fail-Closed Hold Semantics** | [`evidence/live/hold.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/hold.json) | Tool with hold policy raised `PolicyHoldException: hold_status=PENDING`. No silent bypass. |
| **Zero False-Positive Rate** | [`evidence/live/benign.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/benign.json) | 50 benign interactions evaluated; max score 0.1702 (well below 0.45 containment threshold). |
| **Full Automated Pytest Suite** | `backend/tests/` (45 tests) | **45 passed** in 28.3s across unit, governance, ledger, and live ArmorIQ test suites. |
| **Cryptographic Ledger Integrity** | [`evidence/ledger_verification.md`](file:///d:/vigil-v2/vigil-v2/evidence/ledger_verification.md) | 2,300+ blocks verified (`ok=True`). Injected tamper test at seq 11 caught immediately. |
| **Incident-to-Policy Closed Loop** | [`evidence/policy_loop/summary.md`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/summary.md)<br>[`evidence/policy_loop/policy_diff.patch`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/policy_diff.patch) | Baseline verified, attack synthesized, OPA policy updated, post-synthesis attack blocked live. |

---

## 6. How Evaluators Can Reproduce

Evaluators can reproduce all results in under 3 minutes:

### Step 1: Run the End-to-End Demo Script
```powershell
.venv\Scripts\python.exe scripts/demo.py
```
Validates backend health, live ArmorIQ actuation, live OPA denial, audit ledger integrity, and policy synthesis in a single automated flow.

### Step 2: Run the Pytest Suite
```powershell
.venv\Scripts\python.exe -m pytest backend/tests/ -v
```
Runs all 45 automated tests, including live ArmorIQ gateway tests.

### Step 3: Inspect Documentation & Architecture
- [JUDGE_GUIDE.md](file:///d:/vigil-v2/vigil-v2/docs/JUDGE_GUIDE.md): 3-minute evaluator instructions and detailed matrix breakdown.
- [ARCHITECTURE.md](file:///d:/vigil-v2/vigil-v2/docs/ARCHITECTURE.md): Comprehensive system architecture and Mermaid sequence flows.
- [DEMO_SCRIPT.md](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md): Complete terminal transcript and expected phase outputs.
- [LIVE_FINDINGS.md](file:///d:/vigil-v2/vigil-v2/docs/LIVE_FINDINGS.md): Technical findings on ArmorIQ SDK internals, context injection, and control plane behavior.

---

## 7. Operational Trade-Offs & Roadmap

- **Proxy Latency**: Governed actuation through the ArmorIQ proxy and Cloudflare tunnel introduces ~4.2s of round-trip latency. While ideal for out-of-band security actions like agent quarantine, synchronous micro-tool gating requires batching or regional edge proxy deployment.
- **Tunnel Stability**: Development relies on ephemeral Cloudflare quick tunnels. Production environments will use static CNAME DNS records on private enterprise VPCs.
- **Fail-Closed Availability**: Under complete platform partition, the system fails closed. Future iterations will support cryptographically signed offline threshold certificates for disconnected operating environments.

---

## 8. Conclusion

VIGIL v2 demonstrates that autonomous agent defense does not have to be an unverified, reactive heuristic. By embedding ArmorIQ's cryptographic policy governance directly into the agent containment lifecycle, VIGIL v2 provides mathematically verifiable security: proving when an agent went rogue, proving that the containment action was authorized by policy, and automatically updating defenses so the vulnerability cannot be exploited again.
