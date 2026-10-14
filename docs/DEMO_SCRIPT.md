# VIGIL v2 — End-to-End Demo Script & Expected Outputs

This document records the exact expected walkthrough and terminal outputs when running `scripts/demo.py` for evaluators and hackathon judges.

---

## Prerequisites
1. **Virtual Environment**: Active Python virtualenv with `armoriq-sdk==0.6.10` (`.venv\Scripts\python.exe`).
2. **Environment Variables**: `.env` populated with valid `ARMORIQ_API_KEY`, `ARMORIQ_USER_EMAIL`, `OPERATOR_API_KEY`, and `CONTAINMENT_SECRET`.
3. **Background Daemons**:
   - VIGIL Core Backend: `http://127.0.0.1:8000`
   - Containment FastMCP Server: `http://127.0.0.1:8790`
   - Active Cloudflare Tunnel forwarding port 8790 to trycloudflare.com

---

## Running the Demo
```powershell
.venv\Scripts\python.exe scripts/demo.py
```

---

## Expected Terminal Output Walkthrough

```text
=============================================================================
  🛡️  VIGIL v2 — Autonomous Multi-Agent Defense & ArmorIQ Governance Layer
=============================================================================

[*] Environment: ArmorIQ LIVE Mode
[*] Principal:   user...@[domain]
[*] Identity:    vigil-containment-v2
[*] Proxy:       https://customer-proxy.armoriq.ai

===========================================================================
  1. PREFLIGHT CONNECTIVITY & HEALTH CHECKS
===========================================================================
  [✓] VIGIL Backend Core: HTTP 200 OK (http://127.0.0.1:8000)
  [✓] Containment FastMCP Server: HTTP 200 OK (http://127.0.0.1:8790)

===========================================================================
  2. LIVE GOVERNED CONTAINMENT ACTUATION
===========================================================================
  Triggering live policy-gated quarantine against ArmorIQ Customer Proxy...
  [✓] Plan Captured & Signed:  ID=71405651-1479-4a4c-963f-22b79fe4beb8
  [✓] Intent Token Minted:     Token=ba30898177874d2b... (OPA Validated)
  [✓] Actuation Status:        success in 4442.09ms
  [✓] Response Trace:          {'content': [{'type': 'text', 'text': '{\n  "status": "quarantined",\n  "agent_id": "customer_bot"\n}'}], 'isError': False}

===========================================================================
  3. LIVE FAIL-CLOSED POLICY ENFORCEMENT (DENY)
===========================================================================
  Attempting unauthorized execution of 'drop_database' on production proxy...
  [✓] Policy Block Verified:   Tool 'drop_database' denied by OPA: policy_constraints_not_satisfied
  [✓] Exception Class:         armoriq_sdk.exceptions.PolicyBlockedException
  [✓] Enforcement Action:      block

===========================================================================
  4. CRYPTOGRAPHIC AUDIT LEDGER INTEGRITY
===========================================================================
  [✓] Ledger File:             backend\storage\audit_ledger.jsonl
  [✓] Verified Chain Length:   2308 blocks
  [✓] Head Digest:             d4c353959bcbd9ac2290af043ac3685ade4d0535fd9eaa23adcdbd9e297a2210
  [✓] Integrity Status:        ok=True (Zero gaps, zero reordering, zero edits)

===========================================================================
  5. CLOSED-LOOP INCIDENT-TO-POLICY SYNTHESIS
===========================================================================
  Simulating attack on customer-bot: 2 attack calls on billing_database, 3 benign calls on order_status...
  [✓] Synthesized Rule:        DENY vigil-tools.billing_database
  [✓] Protection Verification: Blocks 2 attack calls, 0 benign regressions
  [✓] Protected Tools:         order_status preserved without regression

===========================================================================
  🏆 DEMO COMPLETE: ALL PLATFORM ENFORCEMENTS & INTEGRITY CHECKS PASSED
===========================================================================
```

---

## Verifying Each Assertion
- **Step 2 (Quarantine Actuation)**: Traces through ArmorIQ customer proxy -> Cloudflare Tunnel -> FastMCP server -> VIGIL internal quarantine endpoint. Confirms `customer_bot` is quarantined in memory and state.
- **Step 3 (Platform Denial)**: Demonstrates fail-closed semantics where an unauthorized tool call triggers `PolicyBlockedException` directly at the policy proxy.
- **Step 4 (Cryptographic Ledger)**: Demonstrates SHA-256 hash-chain verification with zero gaps or mutations.
- **Step 5 (Synthesis)**: Replay validation prevents false positives while blocking zero benign operations.
