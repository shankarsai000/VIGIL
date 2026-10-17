# VIGIL Innovation Register

This document tracks all candidate innovations evaluated on the ArmorIQ platform, their measured empirical outcomes, evidence artifacts, and status.

## Innovation Claims Register

| Feature | Claim (One Sentence) | Metric | Status | Evidence Path |
|---|---|---|---|---|
| **Feature A: Pre-Execution Plan Vetting** | ArmorIQ rejects a toxic agent execution plan at intent token mint time before any step runs. | Mint-time refusal vs invoke-time enforcement | **NEGATIVE** | [`evidence/P1/mint_probe.json`](file:///d:/vigil-v2/vigil-v2/evidence/P1/mint_probe.json) |
| **Feature B: Explainable Denials** | Every ArmorIQ denial maps deterministically to its approving proposal, replay coverage, and statistical false-block bound with zero invented provenance. | Provenance attribution accuracy (100% on approved, 0% on unlinked/planted) | **MEASURED-OFFLINE** | [`backend/tests/test_explainable_denials.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_explainable_denials.py) |
| **Feature C: Policy Immune System Replay Validation** | Replaying candidate security rules over historical agent traffic with Clopper-Pearson false-block bounds prevents benign workflow disruption. | False-block upper bound $\le 1\%$, attack coverage $\ge 90\%$ | **MEASURED-OFFLINE** | [`evidence/I1/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.json) |
| **Feature D: Live Dual-MCP Autonomous Containment** | ArmorIQ customer proxy gates sensitive tool execution across distributed MCP servers with Ed25519 tamper-evident receipts. | Real live proxy latency and decision fidelity across ALLOW, DENY, HOLD, and BENIGN | **MEASURED-LIVE** | [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json) |

---

## Detailed Innovation Findings

### Feature A: Pre-Execution Plan Vetting (Negative Finding)
- **Hypothesis**: The ArmorIQ SDK method `client.get_intent_token(plan_capture, policy=policy)` evaluates inline deny rules and raises `PolicyBlockedException` at mint time, preventing token issuance for known malicious plan templates.
- **Empirical Probe**: Executed `scripts/probe_mint_live.py` against the production ArmorIQ proxy `https://customer-proxy.armoriq.ai` using SDK v0.6.10.
- **Observed Behavior**:
  - `get_intent_token` successfully issued a signed intent token (`token_id: 7ea57cebab814e5ab738434378d67746`, `plan_hash: 2c23c10d894052614fe53baeca81822d756c9930f4f29df91fa8c9edc1bb15c9`).
  - The block occurred downstream at `client.invoke_with_policy(...)`, raising `PolicyBlockedException` (`layer: "opa"`, `reason: "policy_constraints_not_satisfied"`).
- **Rule Adherence**: Per the P1 specification (*"If the deny raises only at invoke: do not build plan vetting. Record a negative finding in docs/INNOVATION.md and continue to Feature B"*), no client-side plan pre-check was constructed. Only ArmorIQ may block agent tool calls.
- **Artifact**: [`evidence/P1/mint_probe.json`](file:///d:/vigil-v2/vigil-v2/evidence/P1/mint_probe.json).

---

### Feature B: Explainable Denials
- **Objective**: Ensure operators inspecting an ArmorIQ tool denial understand exactly why the call was blocked, which policy proposal generated the rule, what replay coverage was validated, and the upper bound on false blocks.
- **Design & Invariants**:
  1. On denial, VIGIL queries stored approved policy proposals in `AgentRegistry`.
  2. If matched, returns:
     - `rule_id`: synthetic rule identifier (`rule-<agent>-<tool>`)
     - `proposal_id`: UUID of the human/operator approved proposal
     - `coverage`: empirical replay block rate on attack traces
     - `false_block_bound`: Clopper-Pearson 95% upper bound on benign traffic
     - `replay_window`: counts of benign and attack traces evaluated
     - `source`: `"policy_immune"`
     - `policy_driven`: `true`
  3. If unapproved or planted with no matching proposal:
     - Returns `source: "unknown"` and `policy_driven: false`.
     - Strictly forbids inventing or hallucinating policy provenance.
- **Endpoints & UI**:
  - `GET /denials/{trace_id}` exposed on backend API.
  - Interactive provenance display integrated into the frontend Incident Panel (`IncidentPanel.tsx`).
- **Verification**: Verified via `backend/tests/test_explainable_denials.py` (4 tests passing).

---

## Architectural Constraint Check

### Non-ArmorIQ Tool Denial Scan
A repository-wide check and git diff inspection verifies that **zero** tool-call blocks occur outside ArmorIQ's policy boundary.
- Client-side tool pre-check denials: **0 hits**
- Agent-call interception blocks outside ArmorIQ proxy: **0 hits**
- Gateway containment actions (containment MCP isolation) are tracked as external platform actions and do not block agent tool calls directly.
