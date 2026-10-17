# VIGIL 2.0 — Live Demonstration Script (90-Second Walkthrough)

A timed 85-second script for the official demonstration video of the VIGIL 2.0 Policy Immune System and ArmorIQ platform governance.

---

## Video Specifications
- **Target Duration**: 85 seconds (Limit: $\le$ 90 seconds)
- **Resolution**: 1080p (1920x1080) at 30/60 fps
- **Audio**: Crisp narration with clear terminal & UI focus
- **Artifact Path**: `docs/demo.mp4` (Human recorded)

---

## Timed Scene Breakdown (Total: 85 Seconds)

### Scene 1: The Problem & ArmorIQ Architecture (00:00 – 00:15 | 15s)
- **Visual**: Title slide / Architecture diagram from `docs/ARCHITECTURE.md`.
- **Narration**: *"Autonomous AI agents require privileged tool access, but naive blocking causes catastrophic business disruption. VIGIL 2.0 solves this with a Policy Immune System native to ArmorIQ. Candidate security rules are replayed over historical agent telemetry to mathematically guarantee zero false-positive disruption before deployment."*
- **On-Screen Focus**: The dual FastMCP architecture (`vigil-tools` on 8791, `vigil-containment` on 8790) and the single enforcement gate.

---

### Scene 2: Incident Telemetry & Structural Redaction (00:15 – 00:30 | 15s)
- **Visual**: Terminal running `uv run python scripts/demo_policy_loop.py`.
- **Narration**: *"When customer-bot experiences an exfiltration attack targeting our billing database, VIGIL ingests the telemetry with strict structural redaction: only argument shapes and keys are stored, with zero secrets or plaintext ever recorded."*
- **On-Screen Focus**: Terminal showing 620 benign baseline records and 12 attack records ingested.

---

### Scene 3: Counterfactual Replay & Clopper-Pearson Bound (00:30 – 00:45 | 15s)
- **Visual**: The Replay Evaluation table in the terminal or Web UI.
- **Narration**: *"VIGIL's pure replay engine tests the candidate rule against historical operations. Across 620 benign events, it proves 0 false blocks and calculates an exact Clopper-Pearson 95% upper bound of 0.48%—meeting our strict 0.5% safety threshold. The rule is accepted as proven safe."*
- **On-Screen Focus**: Replay verdict: `ACCEPT` (Coverage: 100%, 95% Clopper-Pearson bound: 0.482% $\le$ 0.500%).

---

### Scene 4: Slack Two-Person Governance Gateway (00:45 – 00:60 | 15s)
- **Visual**: Slack channel `#vigil-approvals` interactive card.
- **Narration**: *"For high-impact policy changes, VIGIL enforces server-side two-person approval. Approvers inspect the mathematical replay bounds in Slack and authenticate decisions with single-use cryptographic nonces."*
- **On-Screen Focus**: First approver clicks `Approve` (state: 1 of 2); second approver clicks `Approve` (state transitions to `APPROVED`).

---

### Scene 5: Live Platform Enforcement & Explainable Denials (00:60 – 00:75 | 15s)
- **Visual**: Web dashboard Incident Detail Panel & Terminal.
- **Narration**: *"Under live ArmorIQ proxy enforcement, attack calls on billing_database are blocked by OPA with PolicyBlockedException, while legitimate order_status calls pass through. In the VIGIL dashboard, our Explainable Denials endpoint shows full provenance linking the block to the approved proposal and replay bound."*
- **On-Screen Focus**: Web UI Policy Denial Provenance card showing Rule ID, Proposal ID, and Replay Coverage.

---

### Scene 6: Ed25519 Receipts & Tamper-Proof Ledger (00:75 – 00:85 | 10s)
- **Visual**: Audit Ledger export & standalone verification tool.
- **Narration**: *"Every platform decision produces an offline-verifiable Ed25519 receipt sealed in a SHA-256 hash-chained ledger. VIGIL 2.0: safe, mathematically verified, ArmorIQ-native agent governance."*
- **On-Screen Focus**: Standalone verification script verifying 2,300+ entries: `[PASS] Chain Valid, 0 Tampering`.
