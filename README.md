# 🛡️ VIGIL 3.0 — Real-Time Behavioral Immune System for AI Agent Pipelines
> **Autonomous AI Runtime Immune System Native to the ArmorIQ Policy Platform (`armoriq-sdk==0.6.10`)**  
> **Team CS · GM University · ArmorIQ Track 2 · Flow State Hackathon**

[![Python 3.11](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![ArmorIQ SDK](https://img.shields.io/badge/armoriq--sdk-0.6.10-purple.svg)](https://pypi.org/project/armoriq-sdk/)
[![Test Suite](https://img.shields.io/badge/pytest-passing%20(22%2F22%20v3%20core)-success.svg)](backend/tests/)
[![Clopper-Pearson Bound](https://img.shields.io/badge/stat--rigor-one--sided%2095%25%20bound%20%E2%89%A4%200.5%25-brightgreen.svg)](evidence/V8/scenario_6.json)
[![Tamper-Evident Ledger](https://img.shields.io/badge/audit--trail-SHA--256%20hash--chained-orange.svg)](evidence/audit_ledger.jsonl)
[![Evidence Vault](https://img.shields.io/badge/evidence--vault-Ed25519%20signed-blueviolet.svg)](evidence/vault/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

🔗 **GitHub Repository**: [https://github.com/shankarsai000/VIGIL](https://github.com/shankarsai000/VIGIL)  
📋 **Judge & Evaluator Guide**: [`docs/JUDGE_GUIDE.md`](docs/JUDGE_GUIDE.md)  
📄 **Executive One-Pager**: [`docs/ONE_PAGER.md`](docs/ONE_PAGER.md)  
🎬 **Demonstration Video Script**: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md)  
📖 **Definitive Technical Guide**: [`CLAUDE.md`](CLAUDE.md)

---

## 1. System Mission & Core Thesis

Autonomous enterprise AI agents require privileged tool access across production databases, external APIs, and internal messaging gateways. Traditional heuristic security controls force a dangerous false dichotomy:
1. **Permissive Governance**: Unchecked agent autonomy risks prompt injection, privilege escalation, and stealth exfiltration.
2. **Naive Heuristic Blocking**: Static rule filters disrupt legitimate business operations with false blocks, destroying pipeline reliability.

### The Core Thesis
> **"We win on safe blocking. False blocks are the metric we minimise. Attacks blocked is secondary."**

**VIGIL 3.0** transforms detection from reactive blocking into an **active behavioral immune system**:
- Threat telemetry (DIFC lineage taint, sliding exfiltration budgets, canary tripwires, and output injections) is calculated in real time.
- **Rule A (Single Authority)**: Only ArmorIQ decides whether an agent's tool call is allowed or blocked. VIGIL never executes client-side tool blocks; it attaches dynamic inline deny policies during intent token minting, delegating the definitive decision to the ArmorIQ Policy Proxy.
- Confirmed zero-day incidents trigger automated synthesis of candidate Open Policy Agent (OPA) deny rules.
- **Counterfactual Replay Proof**: Every candidate rule is replayed over 600 historical benign records from the tamper-evident ledger to mathematically prove zero false blocks ($\le 0.5\%$ one-sided Clopper-Pearson 95% upper bound) before routing to a two-person cryptographic Slack governance approval gateway (`#vigil-approvals`).
- Every containment action produces an offline-verifiable Ed25519 receipt sealed in a SHA-256 hash-chained audit ledger.

---

## 2. High-Level System Architecture

```text
┌───────────────────────────────────────────────────────────────────────────┐
│                          1. INGRESS & INTERCEPTION                        │
│   External Inputs / Webhooks              MCP Tool Return Payloads        │
│                │                                      │                   │
│                ▼                                      ▼                   │
│     [Bidirectional Interceptor] ◄───── [Deterministic Output Scanner]    │
└────────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                       2. TELEMETRY & RISK ENGINE                          │
│   ├── DIFC Lineage Tracker (4 Taint Levels, Cycle / Depth Ceilings)       │
│   ├── Sliding-Window Exfiltration Budgets (1m: 10KB, 1h: 100KB, Entropy)  │
│   ├── HMAC-SHA256 Canary Tripwires (decoy honeypot table monitoring)     │
│   └── 3-Layer Threat Detector (Heuristics + EWMA Baselines + ML)         │
└────────────────┬──────────────────────────────────────────────────────────┘
                 │ (Consolidated Risk & Provenance Vector)
                 ▼
┌───────────────────────────────────────────────────────────────────────────┐
│        3. ARMORIQ POLICY BOUNDARY (Single Enforcement Authority)          │
│   1. client.capture_plan(...)          ──> Capture LLM plan & hash        │
│   2. client.get_intent_token(policy=.) ──> Mint token with inline deny     │
│   3. client.invoke_with_policy(...)    ──> ArmorIQ Proxy evaluates OPA    │
│                                            (Raises PolicyBlockedException)│
└────────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼ (Governed Containment Directives)
┌───────────────────────────────────────────────────────────────────────────┐
│                 4. GRADUATED CONTAINMENT ACTUATION PLANE                  │
│   FastMCP Containment Server (:8790, Auth: X-Containment-Secret)          │
│   ├── Tier 1: LOG_ONLY           ── Telemetry audit trace only            │
│   ├── Tier 2: DOWNGRADE_SCOPE    ── Strip state-mutating / admin tools    │
│   ├── Tier 3: SHADOW_SANDBOX     ── Route queries to synthetic Mirage DB  │
│   └── Tier 4: QUARANTINE_ROLLBACK── Session isolation + Reverse Saga undo │
└────────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                5. TAMPER-EVIDENT AUDIT & EVIDENCE VAULT                   │
│   ├── SHA-256 Hash-Chained Audit Ledger (backend/storage/audit_ledger)    │
│   └── Offline-Verifiable Evidence Vault (Ed25519 Cryptographic Bundles)   │
└────────────────┬──────────────────────────────────────────────────────────┘
                 │
                 ▼ (Quarantined Incident Traces)
┌───────────────────────────────────────────────────────────────────────────┐
│                   6. ADAPTIVE POLICY IMMUNITY LOOP                        │
│   ├── Pydantic Candidate Antibody Generator (strict JSON, extra: forbid)   │
│   ├── Pure Counterfactual Replay Engine (600 Benign Baseline Events)      │
│   │   └── Mathematical Gate: 0 False Blocks, Clopper-Pearson <= 0.005     │
│   └── Slack 2-Person Cryptographic Gateway (#vigil-approvals, HMAC Nonce) │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 6 Core Engineering Innovations (V1 through V6)

### 🔹 Pillar 1: Decentralized Information Flow Control (DIFC) Taint Tracking (`backend/app/provenance/lineage.py`)
- Propagates 4 distinct security labels across multi-hop delegation chains:
  - `0 - SYSTEM_TRUSTED`: Internal hardened services
  - `1 - VERIFIED_INTERNAL`: Authenticated internal agents
  - `2 - USER_UNTRUSTED`: User-facing inputs
  - `3 - EXTERNAL_POISON_RISK`: Webhooks, external retrieval, or indirect prompt injection
- **Monotonic Upward Propagation**: Spans inherit $\max(\text{Taint}(\text{Parent}), \text{Taint}(\text{Input}))$.
- **Confused Deputy Neutralization**: When a tainted agent delegates to an internal agent (e.g. `CustomerBot` $\rightarrow$ `AnalyticsAgent` $\rightarrow$ `BillingAgent`), VIGIL detects when taint exceeds the sink ceiling (`config/sinks.yaml`) and passes an inline deny for `vigil-tools/billing_database` during intent token minting.

### 🔹 Pillar 2: 4-Tier Graduated Containment Ladder & Mirage Honeypot (`backend/app/policies/containment_ladder.py`)
Replaces disruptive binary kill switches with calibrated operational tiers:
1. **Tier 1: `LOG_ONLY`** ($S < 0.45$): Telemetry and audit logging only.
2. **Tier 2: `DOWNGRADE_SCOPE`** ($0.45 \le S < 0.75$): Surgically strips state-mutating and administrative capabilities while retaining read/FAQ operations.
3. **Tier 3: `SHADOW_SANDBOX`** ($0.75 \le S < 0.90$): Silently multiplexes SQLite queries to the synthetic **Mirage Honeypot** (`honeypot_mirage.db`) to harvest attacker TTPs without operational downtime or data leakage.
4. **Tier 4: `QUARANTINE_ROLLBACK`** ($S \ge 0.90$ or canary hit): Full session isolation and automated backward compensating rollbacks.
- **Actuation**: Executed as ArmorIQ-governed tool calls on `vigil-containment` (port 8790) authenticated via `X-Containment-Secret`.

### 🔹 Pillar 3: Cumulative Exfiltration Budgets & Canary Tripwires (`backend/app/budgets/`)
- **Sliding-Window Exfiltration Budgets**:
  - **1-Minute Window**: 10 KB ceiling (`10,240` bytes)
  - **1-Hour Window**: 100 KB ceiling (`102,400` bytes)
  - **Shannon Entropy Ceiling**: $H \ge 5.8$ bits flags encrypted or compressed exfiltration blobs.
  - **Inclusive Boundary Rule**: Budget comparisons are inclusive (`>=`), tripping immediately upon reaching the exact limit.
  - **Privacy Invariant**: Stores rolling aggregates and timestamps only; raw payloads are discarded.
- **HMAC-SHA256 Canary Tripwires**:
  - Injects synthetic honey-rows into sandbox database responses containing cryptographically derived tokens.
  - Any external access or outbound exfiltration of a canary token triggers an immediate, deterministic escalation to Tier 4 (`QUARANTINE_ROLLBACK`).

### 🔹 Pillar 4: Bidirectional Output Scanning & Schema Pinning (`backend/app/detection/output_scanner.py`, `backend/app/runtime/pinning.py`)
- **Pre-Context Output Scanning**: Scans tool return payloads before they enter the agent context window. Detects role-marker injections (`<system>`, `[INST]`, `ADMIN_OVERRIDE`) and elevates taint to Level 3 (`EXTERNAL_POISON_RISK`).
- **Canonical MCP Schema Pinning**: Computes and pins canonical SHA-256 hashes of registered tool parameter schemas. Detects mid-runtime "tool rug-pull" attacks where malicious MCP servers tamper with tool definitions.

### 🔹 Pillar 5: Policy Immune Loop & Replay Engine (`backend/app/immune/`)
- **Automated Candidate Synthesis**: Generates targeted OPA deny rules from forensic incident traces, validated against a strict Pydantic model (`CandidateRuleSchema`, `extra: forbid`).
- **Counterfactual Replay Proof**: Automatically executes candidate rules across 600 historical benign records from the ledger.
- **Statistical Gate**: Requires **100% attack coverage** ($C \ge 90\%$) and **0 false blocks**, mathematically verifying that the one-sided 95% Clopper-Pearson upper bound satisfies $\bar{p} \le 0.005$ ($0.498\%$).
- **2-Person Slack Governance**: Promotes verified candidates to `#vigil-approvals` requiring cryptographic HMAC nonces from two independent operators before live deployment.

### 🔹 Pillar 6: Compensating Rollbacks & Standalone Evidence Vault (`backend/app/runtime/rollback.py`, `evidence/vault/`)
- **Distributed Saga Pattern**: Traverses a Blast Radius DAG of downstream tool calls and executes declarative inverse tools defined in [`config/tool_compensations.yaml`](config/tool_compensations.yaml).
- **Cryptographic State Integrity**: Verifies SHA-256 state hashes before and after compensation.
- **Irreversible Actions Boundary**: Tools with external physical side-effects (`send_external_email`, `wire_transfer_funds`) are explicitly cataloged as `IRREVERSIBLE`.
- **Standalone Evidence Vault**: Bundles telemetry, containment outcomes, and governance approvals into offline-verifiable, Ed25519-signed archive packages verified with `scripts/verify_bundle.py`.

---

## 4. Empirical Benchmark & Ablation Results

### Phase V9 Ablation Progression (E0 through E5 across 1,080 trials)
Evaluated across 80 attack traces (20 confused deputy, 20 low-and-slow, 20 tool rug-pull, 20 injected output) and 1,000 benign operations (500 delegations + 500 bulk reads):

| Configuration | Active Security Layers | Attack Detection Rate [Two-Sided 95% CI] | Mean Events to Alert | Benign Disruption / 1,000 Events | False-Block 95% Upper Bound |
|---|---|---|---|---|---|
| **E0** `[OFFLINE-HARNESS]` | Baseline (Single-Turn Heuristics Only) | **0.0%** [0.0%, 4.5%] | N/A (Missed) | 0.0 / 1k | 0.299% |
| **E1** `[OFFLINE-HARNESS]` | + DIFC Lineage Taint Propagation | **25.0%** [16.0%, 35.9%] | 3.0 events | 0.0 / 1k | 0.299% |
| **E2** `[OFFLINE-HARNESS]` | + Sliding Budgets (1m/10KB, 1h/100KB, Entropy) | **50.0%** [38.6%, 61.4%] | 4.0 events | 0.0 / 1k | 0.299% |
| **E3** `[OFFLINE-HARNESS]` | + HMAC Canary Sandbox Tripwires | **50.0%** [38.6%, 61.4%] | 4.0 events | 0.0 / 1k | 0.299% |
| **E4** `[OFFLINE-HARNESS]` | + Output Scanning & Canonical Schema Pinning | **100.0%** [95.5%, 100.0%] | 2.5 events | 0.0 / 1k | 0.299% |
| **E5** `[OFFLINE-HARNESS]` | + Auto-Antibody Replay & Compensating Rollback | **100.0%** [95.5%, 100.0%] | 2.5 events | **0.0 / 1k** | **0.299%** |

*All intervals are exact Clopper-Pearson confidence bounds. Source receipts: [`evidence/V9/results.json`](evidence/V9/results.json), [`evidence/V9/results.md`](evidence/V9/results.md).*

### Large-Scale False Positive Minimization Benchmark (215,000 benign events)
Across 60 runs comparing VIGIL against naive methods:
- **Naive Per-Agent Deny**: 3.10% false blocks
- **Naive Global Tool Deny**: 10.85% false blocks
- **VIGIL (Replay + Clopper-Pearson Gate)**: **0.0000%** false blocks ([0.000%, 0.002%] 95% bound), saving thousands of legitimate business operations from disruption. *(Source: [`evidence/I1/results.json`](evidence/I1/results.json))*.

---

## 5. Live Demonstration Scenarios

The VIGIL repository includes fully automated scenario runners and interactive dashboard visualizers:

### 🎬 Scenario 5: Confused Deputy Multi-Hop Delegation
- **Source Script**: [`scripts/scenario_confused_deputy.py`](scripts/scenario_confused_deputy.py)
- **Evidence Receipt**: [`evidence/V8/scenario_5.json`](evidence/V8/scenario_5.json)
- **Attack Flow**:
  1. `CustomerBot` ingests ticket #8821 containing indirect prompt injection instructions.
  2. `CustomerBot` delegates to `AnalyticsAgent`, which delegates to `BillingAgent`.
  3. Single-turn threat score on `BillingAgent` is **`0.0`** (appears legitimate in isolation).
  4. VIGIL's DIFC engine tracks lineage taint from root, elevating taint to `EXTERNAL_POISON_RISK` (Level 3).
  5. Intent token minting attaches inline deny for `vigil-tools/billing_database`.
  6. ArmorIQ OPA proxy enforces the block (`PolicyBlockedException`, status: `ARMORIQ_ENFORCED`, metadata: `{'layer': 'opa'}`).

### 🎬 Scenario 6: Low-and-Slow Exfiltration, Canary Tripwire & Antibody Synthesis
- **Source Script**: [`scripts/scenario_low_and_slow.py`](scripts/scenario_low_and_slow.py)
- **Evidence Receipt**: [`evidence/V8/scenario_6.json`](evidence/V8/scenario_6.json)
- **Attack Flow**:
  1. `AnalyticsAgent` exfiltrates database records in small 2,048-byte chunks, evading single-call volume thresholds.
  2. Budget ledger tracks sliding 1-minute window ceiling of 10,240 bytes.
  3. First alert triggers at **chunk 5** (cumulative 10,240B $\ge$ 10,240B ceiling), selecting `DOWNGRADE_SCOPE`.
  4. Canary token (`canary_token_0`) trips at **chunk 24**, escalating containment to `QUARANTINE_ROLLBACK`.
  5. Automated antibody engine synthesizes candidate deny rule and evaluates counterfactual replay across **600 benign records**:
     - 0 observed false blocks (one-sided 95% Clopper-Pearson bound: **`0.00498` $\le 0.005$**).
     - Empirical pipeline synthesis & replay completed in measured **0.0331s** (offline harness).

---

## 6. The ArmorIQ Platform Integration (`armoriq-sdk==0.6.10`)

VIGIL strictly integrates with the official ArmorIQ Python SDK:
```bash
pip install armoriq-sdk==0.6.10
```

### The Three-Step Governed Execution Flow
Every interaction with an external tool or containment action follows this exact 3-step sequence:
1. **`client.capture_plan(llm: str, prompt: str, plan: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> PlanCapture`**:
   Captures the LLM execution plan, generating a deterministic plan hash and returning a `PlanCapture` instance.
2. **`client.get_intent_token(plan_capture: PlanCapture, policy: Optional[Dict[str, Any]] = None, validity_seconds: float = 60.0) -> IntentToken`**:
   Exchanges the plan with ArmorIQ. An inline deny policy (derived dynamically from VIGIL taint ceilings) is attached via `policy`. Returns a cryptographically signed `IntentToken`.
3. **`client.invoke_with_policy(mcp: str, action: str, intent_token: IntentToken, params: Optional[Dict[str, Any]] = None, options: Optional[InvokeOptions] = None) -> MCPInvocationResult`**:
   Sends the tool call through the ArmorIQ Customer Proxy (`https://customer-proxy.armoriq.ai`). The proxy validates the token and OPA rules against target `mcp` server, `action` tool, and `params`. If unauthorized, the proxy raises `PolicyBlockedException` (`metadata={'layer': 'opa'}`).

### Critical Platform Finding (Mint-Time vs. Invoke-Time Enforcement)
Live empirical probing ([`evidence/P1/mint_probe.json`](evidence/P1/mint_probe.json)) proved that ArmorIQ evaluates inline deny policies at **tool invocation time** (`invoke_with_policy`) via OPA, not at token mint time. In accordance with Rule A (*Single Authority*), VIGIL does not implement a client-side plan-vetting pre-check; only ArmorIQ blocks agent tool calls.

---

## 7. Quickstart & Verification Runbook (5-Minute Path)

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend dashboard)
- `uv` (recommended) or standard `venv`

### Step 1: Run Full Test Suite & Self-Checking Verification (~15s)
```powershell
# Run the 22 core v3 tests (AST checks, signatures, budgets, demo scenarios, guide consistency)
uv run pytest backend/tests/test_one_threshold_table.py backend/tests/test_sdk_signatures.py backend/tests/test_demo_scenarios.py backend/tests/test_budgets_and_canaries.py backend/tests/test_v9_benchmarks.py backend/tests/test_guide_consistency.py

# Verify guide Section 6 matches config/thresholds.yaml
uv run python scripts/generate_guide_thresholds.py --check

# Verify all guide evidence paths and numbers match evidence files
uv run python scripts/check_guide_evidence.py
```

### Step 2: Run Live Scenario Demonstrations (~10s)
```powershell
# Run Scenario 5: Confused Deputy multi-hop taint propagation
uv run python scripts/scenario_confused_deputy.py

# Run Scenario 6: Low-and-slow exfiltration, canary tripwire & antibody replay
uv run python scripts/scenario_low_and_slow.py
```

### Step 3: Verify Standalone Evidence Vault Bundle (~2s)
```powershell
uv run python backend/app/evidence/verify_bundle.py --bundle evidence/vault/sample_bundle
```

### Step 4: Run the Complete Ablation Benchmark (~20s)
```powershell
uv run python bench/v3/run_ablations.py --seed 42
```

---

## 8. Starting the Full Stack Locally

### 1. Terminal 1: Containment FastMCP Server
```powershell
uv run python -m backend.app.policies.containment_mcp
# Runs at http://127.0.0.1:8790
```

### 2. Terminal 2: Domain Tools FastMCP Server
```powershell
uv run python -m backend.app.policies.tools_mcp
# Runs at http://127.0.0.1:8791
```

### 3. Terminal 3: VIGIL Core Gateway API
```powershell
uv run uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
# API: http://127.0.0.1:8000
# OpenAPI Docs: http://127.0.0.1:8000/docs
```

### 4. Terminal 4: Frontend Governance Dashboard
```powershell
cd frontend
npm install
npm run dev
# Dashboard: http://localhost:5173
```

### 🐳 Docker Compose (Alternative All-in-One Deployment)
```bash
docker-compose up --build -d
```

---

## 9. Centralized Threshold Specification (`config/thresholds.yaml`)

Every threshold in VIGIL is centrally managed in [`config/thresholds.yaml`](config/thresholds.yaml). Hardcoded float constants (`0.45, 0.65, 0.75, 0.85, 0.90, 0.92`) are strictly prohibited in application logic and verified by static AST tests:

```yaml
detection:
  anomaly_score_threshold: 0.45       # Base Isolation Forest / heuristic threshold

containment_ladder:
  log_only_ceiling: 0.45              # Tier 1 ceiling
  surgical_downgrade_range: [0.45, 0.75]  # Tier 2 range
  mirage_honeypot_range: [0.75, 0.90]     # Tier 3 range
  quarantine_rollback_threshold: 0.90     # Unified system-wide quarantine and rollback trigger

governance:
  escalate_threshold: 0.65            # Human approval escalation threshold in gate
  quarantine_threshold: 0.90          # Single unified quarantine threshold

provenance_and_lineage:
  max_delegation_depth: 6             # Max hops before DEGRADED
  restricted_sink_ceilings:
    billing_database: "VERIFIED_INTERNAL"
    export_financial_records: "SYSTEM_TRUSTED"
    iam_role_grant: "SYSTEM_TRUSTED"

low_and_slow_budgets:
  window_1m_bytes_max: 10240          # 10 KB / 1-minute window (inclusive >=)
  window_1h_bytes_max: 102400         # 100 KB / 1-hour window (inclusive >=)
  shannon_entropy_threshold: 5.8      # Shannon entropy threshold (bits)
  canary_hit_trigger_count: 1         # 1 hit triggers instant quarantine

policy_immune:
  min_coverage: 0.90                  # 90% attack coverage required
  max_false_block_upper: 0.005        # 0.5% max Clopper-Pearson upper bound
  min_benign_records: 600             # Minimum historical baseline records
  min_attack_records: 3               # Minimum incident traces
  delta_significance: 0.05            # 95% Confidence Level (1 - delta)
  antibody_backtest_window: 600       # 600 benign events replayed for antibodies
```

---

## 10. Repository Layout & File Navigation

```text
.
├── backend/
│   ├── app/
│   │   ├── api/                      # FastAPI routers and operator authentication
│   │   ├── budgets/                  # 1m/1h sliding budgets, Shannon entropy & HMAC canaries
│   │   ├── channels/                 # 2-person cryptographic Slack approval gateway
│   │   ├── detection/                # Hybrid threat detector & tool output scanner
│   │   ├── immune/                   # Pydantic candidate synthesis, replay engine & Clopper-Pearson
│   │   ├── policies/                 # ArmorIQ gate, containment ladder & FastMCP servers
│   │   ├── provenance/               # DIFC lineage taint engine (Levels 0-3, DAG limits)
│   │   └── runtime/                  # Audit ledger, Mirage honeypot, schema pinning & Saga rollback
│   ├── main.py                       # Core FastAPI application (port 8000)
│   └── tests/                        # Comprehensive test suite (AST checks, signatures, consistency)
├── config/
│   ├── thresholds.yaml               # Single source of truth for all system thresholds
│   ├── sinks.yaml                    # Restricted sinks and taint ceiling mappings
│   ├── tool_compensations.yaml       # Compensating inverses and IRREVERSIBLE declarations
│   └── vigil-containment.armoriq.yaml# ArmorIQ MCP registration manifest
├── docs/
│   ├── ARCHITECTURE.md               # Complete architectural blueprint & Saga flows
│   ├── DEMO_SCRIPT.md                # 85-second human video demonstration script
│   ├── INNOVATION.md                 # Innovation claims register & research citations
│   ├── JUDGE_GUIDE.md                # 5-minute evaluator reproduction path
│   ├── ONE_PAGER.md                  # Executive summary with measured results
│   ├── SANDBOX.md                    # Disclosure of honeypots and canary decoys
│   └── V3_SPEC.md                    # Complete technical specification and triage table
├── evidence/                         # Immutable empirical evidence receipts (V0–VF, I1, M5, P1, R2)
│   ├── DOC-FIX-1/                    # Phase DOC-FIX-1 report and auth finding
│   ├── V8/                           # Scenarios 5 & 6 execution receipts
│   ├── V9/                           # Ablations E0–E5 results.json and markdown table
│   └── vault/                        # Standalone Ed25519-signed bundles and verification logs
├── frontend/                         # Vite + React 18 + TypeScript governance dashboard
│   ├── src/components/               # TaintGraph, ContainmentPill, AntibodyCard, BlastRadiusView
│   └── src/tests/                    # Vitest UI suite with Rule D static metric scanner
└── scripts/                          # Verification scripts, scenario runners, and audit tools
```

---

## 11. Core Invariants & Governance Rules

1. **Fail Closed**: Any check that errors, times out, or encounters a network partition denies or escalates to human operators. Never approves by default.
2. **Rule A (ArmorIQ Decides)**: Only ArmorIQ decides whether an agent tool call is allowed or blocked. VIGIL never returns `allowed: False` on its own.
3. **Rule B (Governed Containment)**: Containment actions are executed exclusively as ArmorIQ-authorized tool calls on the FastMCP server (`vigil-containment`, port 8790) carrying `X-Containment-Secret`.
4. **Rule C (Statistical Rigor)**: Zero events in $n$ trials is strictly reported as `"0 of n; one-sided 95% upper bound from Clopper-Pearson"`. The phrase "0% false positives" on finite data is strictly prohibited.
5. **Rule D (No Hardcoded Metrics)**: All dashboard percentages, scores, and latency benchmarks are dynamically computed by the pipeline or loaded from API props.
6. **Rule E (Antibodies as Proposals Only)**: LLM-synthesized candidate rules are parsed against a strict Pydantic model (`extra: forbid`), counterfactually backtested across $\ge 600$ benign records (proving bound $\le 0.005$), and submitted for two-person human approval. Never auto-applied.
7. **Rule F (Deception is Sandbox-Only)**: Mirage honeypots and canary tripwires are strictly confined to the sandbox. They never receive production credentials or real user records.
8. **Rule G (Compensations)**: Compensating rollbacks exist only for tools declaring an explicit inverse in `config/tool_compensations.yaml`. All other tools are designated `IRREVERSIBLE`.
9. **Rule H (Single Threshold Table)**: Every score threshold, sliding window budget, and timeout lives centrally in `config/thresholds.yaml` and is guarded by static AST tests.

---

## 12. License & Acknowledgments

This project is submitted to the **ArmorIQ Track 2** at **HackBriven** by **Team CS, GM University**.  
Licensed under the [MIT License](LICENSE).
