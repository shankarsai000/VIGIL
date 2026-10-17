# VIGIL 2.0: Policy-Immune Autonomous Agent Governance
**ArmorIQ Flow State Hackathon — Executive Overview**

---

## The Vision: Safe Blocking for Autonomous AI Agents

Enterprise agents operate with expanding tool access across databases, internal APIs, and messaging systems. Traditional security controls force a dangerous false choice:
1. **Permissive Governance**: Agents operate unchecked, risking prompt injection, data exfiltration, and privilege escalation.
2. **Aggressive Heuristic Blocking**: Naive policy rules block legitimate business operations (false-positive disruptions), destroying trust and business continuity.

**VIGIL 2.0** introduces the **Policy Immune System**, an active defense architecture native to **ArmorIQ (`armoriq-sdk==0.6.10`)**. Rather than blocking based on static heuristics, VIGIL synthesizes candidate OPA policies from security incidents, replays them counterfactually against historical agent telemetry, and deploys them to ArmorIQ **if and only if** they satisfy exact **one-sided Clopper-Pearson statistical bounds** ensuring near-zero false-positive risk.

---

## Architecture

```text
  [ Agent Tools ] <---- (Proxy: 8791) <----+
                                           |
  [ LLM Agent ] ----> [ ArmorIQ Gate ] ----+---> [ ArmorIQ Proxy / OPA ]
                             |                           |
                  (Fail-Closed Escalation)       (Policy Enforcement)
                             v                           v
                  [ Slack Approval Gate ]       [ FastMCP Containment ]
                             |                      (Port: 8790)
                             +---------------------------+
                                                         |
                                             [ SHA-256 Audit Ledger ]
                                             [ Policy Immune Replay ]
```

---

## Measured Results (Empirically Verified)

Only claims backed by empirical evidence on disk are reported as results:

| Measured Result | Finding | Evidence Path |
|---|---|---|
| **Zero False-Block Safe Blocking** | Across 60 benchmark runs (215,000 benign events), VIGIL's replay gate achieved **0.0000%** false blocks ([0.000%, 0.002%] Clopper-Pearson 95% bound), completely avoiding the **3.10% to 10.85%** false-block rates of naive methods. | [`evidence/I1/results.md`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.md)<br>[`evidence/I1/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.json) |
| **Statistical Bound Protects Sparse Traffic** | When benign traffic is constrained (<600 samples), point estimates mislead naive systems into premature rule deployment; VIGIL's Clopper-Pearson bound correctly rejected unproven candidates as `INSUFFICIENT_EVIDENCE`. | [`evidence/I1/results.md#finding-2`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.md#finding-2) |
| **Explainable Denials (Zero Invention)** | Every ArmorIQ tool denial maps deterministically via `GET /denials/{trace_id}` to its approving proposal, rule ID, and statistical bound. Planted/unlinked denials strictly return `source: "unknown"` with 0% invented provenance. | [`evidence/P1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/P1/report.md)<br>[`backend/tests/test_explainable_denials.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_explainable_denials.py) |
| **Live ArmorIQ Platform Boundary Proof** | Verified live OPA policy denial (`PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied`) against `https://customer-proxy.armoriq.ai` with dual FastMCP servers and Ed25519 signed receipts. | [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json)<br>[`evidence/R2/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/R2/report.md) |
| **Negative Finding: Invoke-Time Enforcement** | Empirical probe of `client.get_intent_token` proved that inline deny policies are enforced by OPA downstream at `invoke`, not at mint time. In accordance with platform rules, no client-side pre-checks were built. | [`evidence/P1/mint_probe.json`](file:///d:/vigil-v2/vigil-v2/evidence/P1/mint_probe.json)<br>[`docs/INNOVATION.md`](file:///d:/vigil-v2/vigil-v2/docs/INNOVATION.md) |

---

## Known Limitations & Trade-Offs

In adherence to scientific transparency, we document the real-world operational constraints:

1. **Multi-Vector Attack Coverage Tradeoff**: When an agent experiences attacks across multiple tools simultaneously, single-tool rules cover only a fraction of total attacks (50%). VIGIL's replay gate rejects rules with <90% coverage to prevent partial blocking, prioritizing zero false blocks over aggressive coverage (42.1% overall coverage vs 100% naive).
2. **Proxy Roundtrip Latency**: Governed out-of-band containment through the ArmorIQ proxy introduces 3.5s–4.5s latency. This is optimal for containment escalation but unsuited for synchronous high-frequency micro-queries.
3. **Fail-Closed Availability Risk**: If proxy connectivity is interrupted, the ArmorIQ Gate halts automated tool calls and escalates to operators rather than failing open.
4. **Prior-Art Literature**: Because no external references were placed in `docs/research/`, novelty claims remain conservatively designated as **UNVERIFIED**.
