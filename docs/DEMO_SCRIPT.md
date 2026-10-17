# VIGIL Policy Immune System — Live Demonstration Script

A step-by-step walkthrough of the VIGIL autonomous policy immune lifecycle, demonstrating how confirmed security incidents are transformed into mathematically proven, cryptographically signed, and platform-enforced ArmorIQ policies in under two minutes.

---

## Prerequisites & Launch

### 1. Launch the End-to-End Scripted Demonstration
To run the automated governance lifecycle end-to-end:
```bash
python scripts/demo_policy_loop.py --offline
```
*(For live platform enforcement with ArmorIQ credentials, run without `--offline`: `python scripts/demo_policy_loop.py --live`).*

### 2. Optional: Launch the Interactive Web Dashboard
```bash
# Terminal 1: Backend API
uvicorn backend.main:app --port 8000

# Terminal 2: Governance UI
cd frontend && npm run dev
```
Open your browser to: [http://localhost:5173/?tab=proposals](http://localhost:5173/?tab=proposals)

---

## On-Screen Steps in Order

### Step 1: Incident Ingestion & Labelled Telemetry
- **On-Screen Action**: Script ingests recorded agent traffic for `customer-bot`.
- **What to Observe**:
  - 620 historical records are loaded as `BENIGN_ASSUMED` baseline.
  - An exfiltration attempt triggers incident `inc-2026-10-m6-exfil` with 12 confirmed `ATTACK` records on `vigil-tools.billing_database`.
  - Action records strictly enforce structural redaction (argument shapes only, zero raw queries or plaintext secrets stored).
- **Evidence Reference**: [`evidence/M1/action_traces_sample.jsonl`](file:///d:/vigil-v2/vigil-v2/evidence/M1/action_traces_sample.jsonl)

---

### Step 2: Candidate Rule Grouping
- **On-Screen Action**: VIGIL's candidate extractor groups attack records by `(agent_id, tool)` family.
- **What to Observe**:
  - Extracts candidate deny rule: `CandidateRule(agent_id='customer-bot', mcp_id='vigil-tools', tool='billing_database')`.
  - Families that only separate by argument value are classified as `NOT_ENFORCEABLE` (ArmorIQ enforces tool-level globs, not arbitrary regex arguments).
- **Evidence Reference**: [`evidence/M3/customer-bot.manifest.json`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.manifest.json)

---

### Step 3: Counterfactual Replay & Clopper-Pearson Statistical Bound
- **On-Screen Action**: The pure replay engine evaluates the candidate against the historical record.
- **What to Observe**:
  - The replay table displays:
    ```text
    +-----------------------------------------------------------------------+
    | Metric                      | Observed Value | Mathematical Criterion |
    +-----------------------------------------------------------------------+
    | Attacks Observed            | 12             | Total incident vectors |
    | Attacks Blocked             | 12             | Target tool matches    |
    | Attack Coverage             |         100.0% | >= 90.0% required      |
    | Benign Baseline             | 620            | >= 600 required        |
    | Benign False Blocks         | 0              | Metric to MINIMISE     |
    | False-Block Rate (Point)    |          0.00% | Empirical rate         |
    | 95% Clopper-Pearson Bound   |         0.482% | <= 0.500% required     |
    | REPLAY VERDICT              | ACCEPT         | SAFE TO PROPOSE        |
    +-----------------------------------------------------------------------+
    ```
  - Exact one-sided statistical bound $\bar{p}_{0.95} = 0.482\% \le 0.500\%$.
  - Rule is classified as `ACCEPT` (proven safe: zero autoimmune disruption).
- **Evidence Reference**: [`evidence/M2/replay_report_accept.json`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_accept.json)

---

### Step 4: Governance Approval via Slack Channel
- **On-Screen Action**: Review and authorize governance actions from Slack (or the Approval Channel UI panel).
- **What to Observe**:
  - Proposal is delivered to `#vigil-approvals` Slack channel via Block Kit interactive card.
  - Card displays title, kind, tier, summary fields, replay numbers (Coverage: 100.0%, 95% Clopper-Pearson bound: 0.482%), expiration countdown, dashboard deep-link, and single-use `Approve` / `Reject` buttons.
  - Interactive buttons carry server-issued nonces (zero raw arguments, zero secrets, zero decision state in payload).
  - High-impact tier proposal strictly enforces a two-person approval policy on the server:
    1. First Approver (`sec-lead@corp.internal` in Slack): Clicks Approve. Status remains `PROPOSED` (1 of 2).
    2. Second Approver (`compliance-officer@corp.internal` in Slack): Clicks Approve. Status transitions to `APPROVED` (2 of 2).
  - Separation of duties: proposal creator cannot approve their own proposal.
  - Duplicate approvals are ignored idempotently without secondary execution.
  - Slack message is dynamically updated via `chat.update` with outcome, approver identities, and timestamp.
  - Every callback accepted/rejected and decision is committed to the hash-chained audit ledger.
- **Evidence Reference**: [`evidence/SLACK-1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/report.md), [`evidence/SLACK-1/offline.txt`](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/offline.txt)

---

### Step 5: ArmorIQ Verification in Sandbox
- **On-Screen Action**: Sandbox agent executes verification calls under the signed intent envelope.
- **What to Observe**:
  - 3 attack calls against `billing_database`: All 3 are **DENIED** with `PolicyBlockedException` at the OPA platform layer (`layer: "opa"`).
  - 3 benign calls on `order_status`: All 3 are **ALLOWED** and execute successfully.
  - Platform denial is proven directly in code before production promotion.
- **Evidence Reference**: [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json)

---

### Step 6: Ed25519 Signed Receipt & Hash-Chained Audit Ledger
- **On-Screen Action**: Receipt generation and ledger verification.
- **What to Observe**:
  - Verifier issues receipt signed with Ed25519 (private key lives outside repository at `~/.vigil/receipt_ed25519.key`).
  - Cryptographic signature validates with public key; tampered receipts fail.
  - Receipt digest is appended to the tamper-evident ledger at [`backend/storage/audit_ledger.jsonl`](file:///d:/vigil-v2/vigil-v2/backend/storage/audit_ledger.jsonl).
- **Evidence Reference**: [`evidence/M5/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_receipt.json)

---

### Step 7: Cross-Tenant Shared Signatures
- **On-Screen Action**: Export & import of abstract security motifs.
- **What to Observe**:
  - Export: Emits signed motif bundle `CATEGORY:secret_read -> CATEGORY:external_send` with bucketed support (`"medium"`).
  - Privacy: Zero tool names, agent IDs, tenant IDs, argument values, or timestamps are exposed.
  - Import: Evaluates imported motif against local traffic; local benign contradictions are rejected immediately without writing config.
- **Evidence Reference**: [`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt)
