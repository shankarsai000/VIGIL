# VIGIL 2.0 Demonstration Guide

This guide details how to reproduce and observe the VIGIL Policy Immune System in action, demonstrating that autonomous agents cannot bypass the ArmorIQ security boundary.

---

## 1. Demo Video (90-Second Walkthrough)

- **Video File**: `docs/demo.mp4` (Human recorded, <= 90 seconds)
- **Live Interactive Dashboard**: Available at `http://localhost:5173`
- **Demo Script**: Step-by-step narration script in [`docs/DEMO_SCRIPT.md`](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md)

---

## 2. Running the 2-Minute End-to-End Demo

You can execute the entire Policy Immune lifecycle automatically via a single script:

```powershell
uv run python scripts/demo_policy_loop.py --offline
```

*(For live evaluation against the real ArmorIQ cloud platform, run `uv run python scripts/demo_policy_loop.py --live`).*

### What the Demo Proves:

1. **Incident Ingestion**:
   - The detector ingests 620 baseline records (assumed benign) and catches a data exfiltration attempt on `vigil-tools.billing_database`.
   - Structural argument redaction strips plaintext secrets and raw SQL.

2. **Counterfactual Replay & Clopper-Pearson Bound**:
   - The replay engine validates the candidate rule against all historical calls.
   - Proves zero false blocks ($k = 0$) on legitimate traffic with an exact statistical upper bound ($p < 0.48\%$).

3. **Two-Person Governance & Proposal Lifecycle**:
   - High-impact rule proposal dispatched to the `#vigil-approvals` Slack channel.
   - Evaluated under the 2-approver rule and separation of duties.

4. **ArmorIQ Security Boundary Enforcement**:
   - The agent is simulated attacking the forbidden tool 3 times.
   - The signed execution plan is verified at the gate.
   - The call is rejected by the ArmorIQ Policy Engine with `PolicyBlockedException` from OPA.
   - A cryptographic receipt is signed and committed to the tamper-evident ledger.

5. **Tamper-Evident Evidence Vault**:
   - An immutable evidence bundle is exported and verified offline via `verify_bundle.py`.
