# VIGIL v2 — Judge & Evaluator Reproduction Guide

## 30-Second Summary

**VIGIL v2** is an active defense platform for autonomous AI agent ecosystems. When an agent experiences prompt injection, privilege escalation, or behavior drift, VIGIL v2 intercepts the threat and executes cryptographically governed containment via the **ArmorIQ Policy Platform (`armoriq-sdk==0.6.10`)**. 

Crucially, VIGIL v2 closes the loop:
1. **Governed Containment**: Quarantine actions require a cryptographically signed intent token and OPA policy evaluation via ArmorIQ.
2. **Fail-Closed Guarantees**: Human approvals, errors, or network partitions cannot bypass security holds.
3. **Cryptographic Ledger**: 2,300+ events sealed in a SHA-256 hash chain with instant tamper detection.
4. **Closed-Loop Policy Synthesis**: Real attacks automatically synthesize OPA deny rules, replayed against benign history to guarantee zero false positives, and deployed live to block subsequent attacks.

---

## Architecture at a Glance

```text
+-------------------+       +-----------------------+       +-------------------------+
| Compromised Agent | ----> | Threat Engine (ML)    | ----> | ArmorIQ Policy Gate     |
+-------------------+       | (Score: [0.0 - 1.0])  |       | (Capture Plan + Tokens) |
                            +-----------------------+       +-------------------------+
                                        |                                |
                                        v                                v
                            +-----------------------+       +-------------------------+
                            | SHA-256 Audit Ledger  |       | ArmorIQ Proxy (OPA)     |
                            | (Cryptographic Proof) |       +-------------------------+
                            +-----------------------+                    |
                                        ^                                v
                                        |                   +-------------------------+
                            +-----------------------+       | FastMCP Quarantine      |
                            | Closed-Loop Synthesis | <---- | (Port 8790 via Tunnel)  |
                            +-----------------------+       +-------------------------+
```

---

## 3-Minute Reproduction Instructions

All commands must be executed using the project virtual environment (`.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on POSIX).

### 1. Run the Automated End-to-End Demo (All 5 Phases)
This single script validates connectivity, live governed actuation, fail-closed denial, ledger verification, and policy synthesis in ~25 seconds:
```powershell
.venv\Scripts\python.exe scripts/demo.py
```
*Expected Result*: All 5 phases output `[✓]`, concluding with `🏆 DEMO COMPLETE: ALL PLATFORM ENFORCEMENTS & INTEGRITY CHECKS PASSED`. (Full trace details in [DEMO_SCRIPT.md](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md)).

---

### 2. Run the Full Test Suite
Executes all 45 automated unit and live integration tests:
```powershell
.venv\Scripts\python.exe -m pytest backend/tests/ -v
```
*Expected Result*: `45 passed` in ~28 seconds. Tests cover detection models, cryptographic ledger integrity, Telegram governance, approval state transitions, and live ArmorIQ platform gating.

---

### 3. Reproduce the Live Scenario Matrix
Executes the live scenario matrix against `https://customer-proxy.armoriq.ai`:
```powershell
.venv\Scripts\python.exe scripts/run_live_matrix.py
```
*Evaluates 4 scenarios against the live platform*:
- **ALLOW**: Minted intent token actuates `quarantine_agent` in ~4.3s.
- **DENY**: Unauthorized tool `drop_database` blocked by OPA (`PolicyBlockedException`).
- **HOLD**: Tool requiring human approval raises `PolicyHoldException` (proves fail-closed).
- **BENIGN**: 50 benign agent tool calls evaluated with 0 false positives.

---

### 4. Verify Cryptographic Ledger & Tamper Resistance
Verifies the live hash chain (2,300+ entries) and demonstrates mathematical tamper detection:
```powershell
.venv\Scripts\python.exe scripts/verify_ledger_tamper.py
```
*Evaluates*:
- Live ledger integrity: `ok: True`.
- Injected mutation test: Alters a single anomaly score at sequence 11 on a duplicate ledger. Proves the chain breaks at block 11 with `'entry content does not match its hash'`.

---

### 5. Reproduce the Closed-Loop Incident-to-Policy Synthesis
Demonstrates the full attack-to-mitigation cycle:
```powershell
.venv\Scripts\python.exe scripts/run_policy_loop.py
```
*Flow*:
1. Baseline test: Both `order_status` and `billing_database` tools succeed.
2. Injects simulated exploit on `billing_database`.
3. Synthesizes OPA rule: `DENY vigil-tools.billing_database`.
4. Replay validation proves 2 attacks blocked, 0 benign regressions.
5. Pushes patch to ArmorIQ platform with `onConflict: "replace"`.
6. Live re-test: `order_status` succeeds; `billing_database` is blocked by OPA.

---

## Empirical Evidence Catalog

Every claim made in VIGIL v2 traces to empirical evidence generated against the live ArmorIQ platform:

| Evaluation Dimension | File / Artifact Path | Description |
| :--- | :--- | :--- |
| **Live Actuation (ALLOW)** | [`evidence/live/allow.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/allow.json) | Plan ID, signed intent token (`ba308981...`), 4.27s roundtrip trace, quarantined status. |
| **Platform Block (DENY)** | [`evidence/live/deny.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/deny.json) | OPA `PolicyBlockedException` output and policy constraint rejection. |
| **Human Hold (HOLD)** | [`evidence/live/hold.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/hold.json) | `PolicyHoldException` confirming fail-closed hold semantics. |
| **False-Positive Matrix** | [`evidence/live/benign.json`](file:///d:/vigil-v2/vigil-v2/evidence/live/benign.json) | 50 benign tool interactions evaluated (max score 0.1702 < threshold 0.45). |
| **Scenario Summary** | [`evidence/live/matrix.md`](file:///d:/vigil-v2/vigil-v2/evidence/live/matrix.md) | Formatted scenario matrix comparing inputs, latency, and enforcement outcomes. |
| **Policy Diff (Before/After)**| [`evidence/policy_loop/policy_diff.patch`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/policy_diff.patch) | Git-style diff showing synthesized `deny` rule for `vigil-tools.billing_database`. |
| **Baseline vs Post-Policy** | [`evidence/policy_loop/step1_baseline.json`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/step1_baseline.json)<br>[`evidence/policy_loop/step3_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/step3_verification.json) | Empirical JSON traces proving `billing_database` allowed prior to synthesis and denied after. |
| **Synthesis Summary** | [`evidence/policy_loop/summary.md`](file:///d:/vigil-v2/vigil-v2/evidence/policy_loop/summary.md) | Full audit of incident-to-policy closed loop with zero regressions. |
| **Audit Ledger Export** | [`evidence/ledger_export.jsonl`](file:///d:/vigil-v2/vigil-v2/evidence/ledger_export.jsonl) | 2,023+ block JSONL export of real SHA-256 hash-chained event records. |
| **Tamper Proof Report** | [`evidence/ledger_verification.md`](file:///d:/vigil-v2/vigil-v2/evidence/ledger_verification.md) | Cryptographic verification report proving genesis-to-head consistency and tamper failure. |

---

## Honest Account of Limits & Trade-Offs

In keeping with hackathon guidelines, we document the operational realities and technical trade-offs of this architecture:

### 1. Governed Proxy Latency Overhead
- **Observation**: Direct local MCP tool execution requires ~10–25ms. Governed actuation through the ArmorIQ platform (`capture_plan` $\rightarrow$ `get_intent_token` $\rightarrow$ `invoke_with_policy` through proxy and Cloudflare tunnel) requires **4.2 to 4.4 seconds**.
- **Trade-Off**: This latency is acceptable for critical out-of-band security actions (e.g., isolating an agent, killing API access), but would introduce noticeable overhead if applied synchronously to high-throughput, low-latency micro-tool calls.

### 2. Cloudflare Quick Tunnel Ephemerality
- **Observation**: Free Cloudflare quick tunnels (`trycloudflare.com`) assign dynamic subdomains that cycle if the daemon process terminates.
- **Mitigation & Production Path**: In production, organizations bind named, authenticated Cloudflare Tunnels (or AWS API Gateways) with static CNAME DNS records, eliminating the need to update MCP endpoint URLs in ArmorIQ configurations.

### 3. Fail-Closed Platform Dependency
- **Observation**: When `ARMORIQ_MODE=live` is enabled, if the ArmorIQ control proxy is unreachable (e.g., network timeout, DNS failure, 502 Bad Gateway), the ArmorIQ Gate raises an exception and treats the action as `ESCALATE`.
- **Security Implication**: The system will **never** fail-open or allow an unverified action. However, automated actuation halts until network connectivity is restored or an operator intervenes out-of-band.

### 4. Stateless MCP Servers vs. Stateful Agent Runtimes
- **Observation**: Model Context Protocol (FastMCP) servers are stateless protocol adapters. When the ArmorIQ proxy executes `quarantine_agent` on port 8790, FastMCP forwards the command to VIGIL's backend `/internal/containment/quarantine` endpoint using an internal `CONTAINMENT_SECRET`.
- **Design Decision**: VIGIL Core (:8000) maintains the authoritative agent lifecycle state machine in SQLite/Postgres. Port 8000 remains strictly internal and is never tunneled publicly.
