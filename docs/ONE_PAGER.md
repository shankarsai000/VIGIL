# VIGIL 3.0: Policy-Immune Autonomous Agent Governance
**ArmorIQ Flow State Hackathon — Executive One-Pager**

---

## 1. Executive Summary

Autonomous enterprise AI agents require privileged tool access across production databases, external APIs, and internal messaging gateways. Traditional heuristic security controls force a dangerous false dichotomy:
1. **Permissive Governance**: Unchecked agent autonomy risks prompt injection, privilege escalation, and stealth exfiltration.
2. **Naive Heuristic Blocking**: Static rule filters disrupt legitimate business operations with false blocks, destroying reliability.

**VIGIL 3.0** is an enterprise-grade Policy Immune System native to **ArmorIQ (`armoriq-sdk==0.6.10`)**. Rather than blocking tools on client heuristics, VIGIL monitors decentralized information flow control (DIFC) taint, sliding window data budgets, canary tripwires, and output injections, supplying these signals to ArmorIQ as mint-time inline policies and FastMCP containment directives.

---

## 2. Platform Architecture

```text
  [ External User / Prompts ]
              |
              v
     [ CustomerBot ] --------(DIFC Taint: Level 3)--------+
              |                                           |
              v                                           v
     [ AnalyticsAgent ] -----------------------> [ BillingAgent ]
              |                                           |
    (Sliding Budgets)                             (Restricted Sink)
    (Canary Tripwires)                                    |
              |                                           v
              +-----------------------------> [ ArmorIQ Policy Gate ]
                                                          |
                                           +--------------+--------------+
                                           |                             |
                                  (Inline Deny OPA)            (FastMCP Containment)
                                           v                             v
                                 [ ArmorIQ Proxy ]            [ vigil-containment:8790 ]
                                 (Single Authority)           - Scoped Downgrade
                                           |                  - Mirage Honeypot
                                           v                  - Quarantine & Rollback
                                 [ Target Tool MCP ]                     |
                                 (Port: 8791)                            v
                                                              [ SHA-256 Audit Ledger ]
                                                              [ Policy Immune Replay ]
```

---

## 3. Empirically Measured Results

Every performance claim and metric reported below is derived directly from empirical evidence artifacts on disk:

| Feature / Innovation | Empirical Finding | Status | Evidence Artifact |
|---|---|---|---|
| **Zero False-Block Bound** | Across 60 benchmark runs (215,000 benign events), VIGIL's replay gate achieved **0.0000%** false blocks ([0.000%, 0.002%] Clopper-Pearson 95% bound), completely avoiding the **3.10% to 10.85%** false-block rates of naive methods. | **MEASURED-OFFLINE** | [`evidence/I1/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.json)<br>[`evidence/I1/results.md`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.md) |
| **Explainable Denials** | Every ArmorIQ tool denial maps deterministically to its approving proposal, replay coverage, and statistical bound via `GET /denials/{trace_id}` with **0% invented provenance**. | **MEASURED-OFFLINE** | [`evidence/P1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/P1/report.md)<br>[`backend/tests/test_explainable_denials.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_explainable_denials.py) |
| **Live ArmorIQ Platform Gate** | Live verification against production ArmorIQ proxy (`https://customer-proxy.armoriq.ai`) proved real OPA policy enforcement (`PolicyBlockedException`) on unauthorized tool calls. | **MEASURED-LIVE** | [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json)<br>[`evidence/V1/live_taint_enforcement.json`](file:///d:/vigil-v2/vigil-v2/evidence/V1/live_taint_enforcement.json) |
| **DIFC Multi-Hop Lineage (V1)** | Monotonic taint propagation elevates Confused Deputy detection from **0.0%** to **25.0% [16.8%, 35.5%]** by attaching inline deny policies for ArmorIQ intent token minting. | **MEASURED-OFFLINE** | [`evidence/V9/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.json)<br>[`evidence/V8/scenario_5.json`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_5.json) |
| **Sliding Window Budgets (V3)** | 1-minute (10 KB) and 1-hour (100 KB) sliding budgets detect low-and-slow exfiltration, elevating detection to **50.0% [39.3%, 60.7%]** while persisting aggregates only. | **MEASURED-OFFLINE** | [`evidence/V3/benchmark.json`](file:///d:/vigil-v2/vigil-v2/evidence/V3/benchmark.json)<br>[`evidence/V8/scenario_6.json`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json) |
| **Canary Tripwires (V3)** | Synthetic HMAC canary tokens in sandbox decoy tables detect database intrusion, escalating containment to `QUARANTINE_ROLLBACK` without real user data. | **MEASURED-OFFLINE** | [`evidence/V3/calibration.json`](file:///d:/vigil-v2/vigil-v2/evidence/V3/calibration.json)<br>[`evidence/V8/scenario_6.json`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json) |
| **Scanning & Schema Pinning (V4)** | Deterministic role-marker/override scanning and canonical SHA-256 schema hashing detect indirect injection and tool rug-pulls (**100.0% [95.4%, 100.0%]** detection). | **MEASURED-OFFLINE** | [`evidence/V4/output_scanning_evaluation.json`](file:///d:/vigil-v2/vigil-v2/evidence/V4/output_scanning_evaluation.json)<br>[`evidence/V9/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.json) |
| **Antibody Synthesis & Replay (V5)** | Automated candidate rule generation with counterfactual replay over 500 benign events proves 0 false blocks before review in measured **0.0331s** (90.6x faster than proposal). | **MEASURED-OFFLINE** | [`evidence/V5/candidate_backtest.json`](file:///d:/vigil-v2/vigil-v2/evidence/V5/candidate_backtest.json)<br>[`evidence/V8/scenario_6.json`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json) |
| **Compensating Rollback (V6)** | Reverse Saga execution restores mutated records to verified pre-state SHA-256 hashes; uncompensatable side-effects are strictly classified as `IRREVERSIBLE`. | **MEASURED-OFFLINE** | [`evidence/V6/rollback_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/V6/rollback_receipt.json)<br>[`config/tool_compensations.yaml`](file:///d:/vigil-v2/vigil-v2/config/tool_compensations.yaml) |

---

## 4. Limitations & Operational Constraints

1. **Invoke-Time Enforcement Boundary (Negative Finding)**: Live probing of `client.get_intent_token` proved that ArmorIQ inline deny policies are evaluated downstream by OPA at tool invocation rather than token mint time. In accordance with Rule A (*Single Authority*), VIGIL constructs zero client-side pre-checks; only ArmorIQ blocks agent tool calls.
2. **Single-Vector Coverage Tradeoff**: In multi-vector attack scenarios, candidate rules with <90% empirical coverage on an agent are rejected to prevent partial blocking and protect operational continuity.
3. **Irreversible External Side-Effects**: Compensating rollback cannot undo external out-of-band actions (e.g. dispatched emails, external credit card charges); such tools are declaratively cataloged as `IRREVERSIBLE` in `config/tool_compensations.yaml`.
4. **Fail-Closed Availability**: Under proxy network partition or malformed lineage state, VIGIL fails closed and denies or escalates to human operators rather than failing open.
5. **Roadmap / Unverified Items**: All innovation novelty claims remain conservatively designated as **UNVERIFIED** until academic literature is cataloged in `docs/research/`.
