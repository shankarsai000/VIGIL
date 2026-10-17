# VIGIL: Policy-Immune AI Agent Governance Architecture

## 1. The Problem
Enterprise autonomous AI agents operate with high privileges, invoking internal APIs, executing database queries, and delegating sub-tasks across complex multi-agent graphs. Traditional security architectures fall short:
- **Perimeter Defenses are Blind**: Perimeter firewalls cannot inspect the semantic context or intent of internal agent tool invocations.
- **Naive Autonomous Blocking Breaks Operations**: Heuristic detectors that aggressively block agent execution incur high false-positive rates, disrupting mission-critical business workflows.
- **The Metric Hierarchy**: In enterprise agent security, the true objective is **safe blocking**. Minimising the false-block rate is the primary metric; blocking attacks is secondary. An immune system must never cause autoimmune destruction of normal business operations.

---

## 2. Product Principles

### 2.1 Safe Blocking
- Candidate security policies generated from incident post-mortems must be verified against recorded historical traffic before live enforcement.
- A proposed rule is rejected if it collides with legitimate historical behavior of that agent.
- Policies are dry-run by default until proven safe.

### 2.2 Fail Closed
- Every decision path, gate invocation, credential lookup, and authorization check must fail closed.
- If a check times out, encounters a network error, receives an unexpected HTTP status, or fails authorization, the outcome must be `DENIED` or `ESCALATE`.
- Default-allow or fail-open fallbacks are strictly prohibited.

### 2.3 One Enforcement Path
- Containment actions (such as agent quarantine) and policy alterations must traverse a single, unified enforcement gate (`ArmorIQGate`) and approval workflow.
- Direct status modifications (e.g., setting `status = QUARANTINED` directly on agent profiles or database records) are forbidden across the codebase and enforced by AST scanning tests.

---

## 3. Metric Definitions

### 3.1 Coverage
Coverage measures the fraction of observed attack vectors or tools targeted during an incident that have candidate deny rules synthesized:
$$\text{Coverage} = \frac{|\mathcal{T}_{\text{attacked}} \cap \mathcal{T}_{\text{policy_denied}}|}{|\mathcal{T}_{\text{attacked}}|}$$
Where $\mathcal{T}_{\text{attacked}}$ is the set of tool names identified in confirmed attack telemetry.

### 3.2 False-Block Rate (Empirical)
The empirical rate at which a synthesized candidate policy would block legitimate, non-malicious operations across recorded baseline traffic:
$$\text{False-Block Rate} = \frac{|\{e \in \mathcal{D}_{\text{benign}} : \text{Policy}(\text{agent}(e), \text{tool}(e)) = \text{DENY}\}|}{|\mathcal{D}_{\text{benign}}|}$$
A candidate policy proposal is valid if and only if empirical false-block rate equals $0$ across the verification corpus.

### 3.3 Statistical Upper Bound
Given $n$ recorded benign events where $k = 0$ false blocks are observed, the one-sided upper confidence bound on the true out-of-sample false-block probability $p$ at confidence level $1 - \delta$ is calculated via the Clopper-Pearson / Beta distribution quantile:
$$\bar{p}_{1-\delta} = 1 - \delta^{1/n}$$
For example, across $n = 300$ benign samples with $0$ violations, the $95\%$ confidence upper bound on false blocks is:
$$\bar{p}_{0.95} = 1 - (0.05)^{1/300} \approx 0.00994 \text{ (0.99%)}$$

---

## 4. Foundational Assumptions

### 4.1 Exchangeability
- Historical recorded interactions and future agent interactions are assumed to be conditionally exchangeable given the agent's profile, role, and operational context.
- If an agent's operational scope, underlying model, or prompt template changes (covariate shift), the empirical safety bounds must be re-calibrated on fresh traffic.

### 4.2 Assumed Benign Labels
- Unlabelled historical agent traffic is **assumed benign** rather than confirmed benign.
- Ground truth malicious labels derive exclusively from simulator scenario ground truth or human-confirmed incident triage.
- All evaluation reports and safety metrics must explicitly acknowledge the "assumed benign" baseline.

---

## 5. The Policy Immune Lifecycle & Evidence Links

The complete governance lifecycle is implemented and empirically verified across seven milestones:

1. **M0 — Baseline Truth Check & Specification**:
   - Confirmed architectural AST containment invariants, gate-routed isolation, and expiration conflicts.
   - Evidence: [`evidence/M0/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M0/report.md), [`evidence/M0/backend_tests.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M0/backend_tests.txt).

2. **M1 — Labelled Action Records & Structural Redaction**:
   - Implemented schema v1 `ActionRecord` with argument shape redaction (types, lengths, keys only).
   - Ingested 20,000 records in 0.53s (< 30s budget).
   - Evidence: [`evidence/M1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M1/report.md), [`evidence/M1/action_traces_sample.jsonl`](file:///d:/vigil-v2/vigil-v2/evidence/M1/action_traces_sample.jsonl).

3. **M2 — Pure Counterfactual Replay Engine & Exact Bound**:
   - Pure statistical engine computing coverage and exact one-sided Clopper-Pearson bounds $\bar{p}_{1-\delta}$.
   - Verified zero database/network dependencies and strict mathematical monotonicity.
   - Evidence: [`evidence/M2/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M2/report.md), [`evidence/M2/replay_report_accept.json`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_accept.json).

4. **M3 — Candidate Rules & Dry-Run Compiler**:
   - Synthesizes candidate rules from incident families. Generates `armoriq.yaml` patches and SDK inline policies.
   - Refuses write-back unless status is `APPROVED`.
   - Evidence: [`evidence/M3/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M3/report.md), [`evidence/M3/customer-bot.manifest.json`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.manifest.json).

5. **M4 — Proposal Workflow & UI**:
   - Two-person approval governance for High Impact tier (`>= 2` distinct approvers required).
   - 72-hour hard server-side expiration with HTTP 409 conflict handling.
   - Evidence: [`evidence/M4/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M4/report.md), [`evidence/M4/backend_tests.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M4/backend_tests.txt).

6. **M5 — ArmorIQ Platform Verification & Ed25519 Receipts**:
   - Sandbox agent runs attack calls against live ArmorIQ platform; verified authentic `PolicyBlockedException` at OPA layer (`layer: "opa"`).
   - Benign calls succeed. Receipts signed with Ed25519; private key outside repo; hash chained into audit ledger.
   - Evidence: [`evidence/M5/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M5/report.md), [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json), [`evidence/M5/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_receipt.json).

7. **M6 — Shared Signatures & Demo Pack**:
   - Cross-tenant motif bundle export/import over tool categories with support buckets (`small`, `medium`, `large`). Zero sensitive identifiers leaked.
   - Scripted end-to-end demo running in 0.31s (< 120s limit).
   - Evidence: [`evidence/M6/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M6/report.md), [`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt).

8. **Evidence Vault — Signed Offline-Verifiable Evidence Bundles**:
   - Exports complete incident and time-window bundles: contiguous ledger segment with boundary chain proofs, redacted action records (shapes only), proposals, approvals, platform receipts, containment outcomes, and sanitized configuration snapshots.
   - Cryptographically signed with Ed25519; verified offline on air-gapped systems using standalone `verify_bundle.py`.
   - Evidence: [`evidence/vault/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/vault/report.md), [`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt), [`docs/EVIDENCE_VAULT.md`](file:///d:/vigil-v2/vigil-v2/docs/EVIDENCE_VAULT.md).

---

## 6. Verification Status Matrix

| Verification Tier | Components & Tests Verified | Evidence Paths |
|---|---|---|
| **Verified Offline (Fakes)** | - All 45 immune and vault unit tests (`test_action_records.py`, `test_immune_replay.py`, `test_immune_compiler.py`, `test_immune_workflow.py`, `test_immune_verify.py`, `test_immune_signatures.py`, `test_evidence_vault.py`).<br>- Gate fail-closed behavior on SDK exception fakes.<br>- Exact mathematical Clopper-Pearson bound calculation.<br>- Privacy assertion against planted identifiers in signature bundles and evidence vaults.<br>- 1-byte tamper detection across all 5 bundle files.<br>- Ledger line deletion detection and sequence gap rejection.<br>- Offline verification with zero network access. | [`evidence/M2/replay_report_accept.json`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_accept.json)<br>[`evidence/M5/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M5/report.md)<br>[`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt)<br>[`evidence/vault/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/vault/report.md)<br>[`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt) |
| **Verified Live (ArmorIQ Platform)** | - Token minting (`client.get_intent_token`) against `https://api.armoriq.ai`.<br>- Live OPA platform policy block (`PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied`) at `https://customer-proxy.armoriq.ai`.<br>- FastMCP tool reachability (`order_status`, `billing_database`) via Cloudflare tunnel.<br>- Hash-chained ledger update (seq 10763) with real Ed25519 signature. | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json)<br>[`evidence/M5/preflight.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json)<br>[`evidence/platform_changes.md`](file:///d:/vigil-v2/vigil-v2/evidence/platform_changes.md) |
| **Unverified / Platform Limits** | - Remote control plane agent registration endpoint `https://api.armoriq.ai/iap/sdk/register` returned HTTP 500 without org-admin permissions (handled via `--dry-run` and live intent token policy snapshot).<br>- ArmorIQ Dashboard row generation for pre-execution OPA blocks (requests terminated at OPA evaluation prior to upstream invocation execution). | [`evidence/M5/report.md:43-51`](file:///d:/vigil-v2/vigil-v2/evidence/M5/report.md#L43-L51) |

---

## 7. Mathematical & Behavioral Limitations

1. **Counterfactual Replay is Not Adaptive Simulation**:
   - Replay demonstrates what a proposed security policy *would have blocked* across the historical recorded trace.
   - It **does not simulate how an autonomous agent or adversary would have adapted** if blocked (e.g., trying alternative tools, invoking bash sub-shells, or hallucinating new workflows).
   - Dynamic adversary adaptation requires sandboxed live evaluation or multi-turn red-teaming.

2. **Bound Validity Under Exchangeability & Label Assumptions**:
   - The one-sided Clopper-Pearson false-block bound $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ is valid **if and only if** the exchangeability assumption holds.
   - If the agent's base prompt, system instructions, or underlying model weights change (covariate shift), previous historical traces no longer represent future tool usage distributions.
   - The bound treats unlabelled records as **assumed benign**. If covert malicious operations are present in the historical baseline, the true false-block probability on purely benign actions may deviate.

