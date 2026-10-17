# Flow State Hackathon — Requirements Baseline (REQUIREMENTS.md)

This requirements file is generated directly from the official hackathon brief in [`docs/brief/BRIEF_RAW.md`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md) per Phase R0. Every later phase is evaluated and tested against these IDs.

---

## 1. Hackathon Window & Rules

- **Event**: Flow State (online, Discord-first AI agent and MCP hackathon organized by ArmorIQ)
- **Build Week**: October 10, 2026 – October 17, 2026
- **Submissions Close**: October 17, 2026 (Today)
- **Results Announced**: October 22, 2026
- **Time Zone**: UTC ("All times are UTC")
- **In-Window Work Rule**: All submission commits and evaluation artifacts must be generated within the October 10 – October 17 window.
- **Pre-Existing Code Rule**: Not specified in brief text. VIGIL discloses baseline commits in [`docs/DISCLOSURE.md`](file:///d:/vigil-v2/vigil-v2/docs/DISCLOSURE.md) with exact git diff tracking of in-window work.

---

## 2. BR-xx Rules Table

| ID | Short Verbatim Quote | Source Line | Evidence Required | Status |
|---|---|---|---|---|
| **BR-01** | *"Build an autonomous agent that takes real actions (writing code, calling tools, triggering workflows)."* | [`BRIEF_RAW.md:3`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L3) | Functional agent runtime with real tools and event stream. | **PASS** |
| **BR-02** | *"The unique requirement is to demonstrate your agent reaching past its boundary and proving that the ArmorIQ security boundary successfully holds."* | [`BRIEF_RAW.md:3`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L3) | Live verification receipt proving ArmorIQ policy block on unauthorized tool call without client bypass. | **PASS** |
| **BR-03** | *"Build Week: October 10 – October 17"* | [`BRIEF_RAW.md:9`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L9) | Git commit history confirming all new features developed within window. | **PASS** |
| **BR-04** | *"Submissions Close: Today, October 17"* | [`BRIEF_RAW.md:11`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L11) | Complete submission freeze, tagged release, and verified checklist before deadline. | **IN PROGRESS** |
| **BR-05** | *"You must submit a working project"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | Passing automated test suite, runnable backend, functioning frontend, and passing health check. | **PASS** |
| **BR-06** | *"a short demo"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | Recorded walkthrough video (`docs/demo.mp4`) adhering to short duration (<= 90 seconds). | **NOT STARTED** |
| **BR-07** | *"clear documentation showing what your agent does"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | Comprehensive documentation covering architecture, threat models, runbook, and APIs. | **PASS** |
| **BR-08** | *"how you integrated ArmorIQ (or an MCP server)"* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | Containment MCP server (`backend/app/policies/containment_mcp.py`), tools MCP server (`demo/tools_mcp/server.py`), and SDK integration. | **PASS** |
| **BR-09** | *"and how the security boundary was tested."* | [`BRIEF_RAW.md:15`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L15) | Empirical verification matrix, adversarial scenarios (ALLOW, DENY, HOLD, BENIGN), and signed receipts. | **PASS** |
| **BR-10** | *"Event: Flow State, an online, Discord-first AI agent and MCP hackathon organized by ArmorIQ."* | [`BRIEF_RAW.md:1`](file:///d:/vigil-v2/vigil-v2/docs/brief/BRIEF_RAW.md#L1) | Platform registration and MCP server configurations (`config/vigil-containment.armoriq.yaml`, `config/vigil-tools.armoriq.yaml`). | **PASS** |

---

## 3. PK-xx Package Items Table

| ID | Package Item / Deliverable | Source / Requirement | Evidence Path | Status |
|---|---|---|---|---|
| **PK-01** | Working Project Source Code | Brief Line 15 | [`backend/`](file:///d:/vigil-v2/vigil-v2/backend/), [`frontend/`](file:///d:/vigil-v2/vigil-v2/frontend/) | **PASS** |
| **PK-02** | Short Demo Video (<= 90 seconds) | Brief Line 15 ("short demo") | `docs/demo.mp4` (Human recorded) | **NOT STARTED** |
| **PK-03** | System Architecture Documentation | Brief Line 15 ("clear documentation") | [`docs/ARCHITECTURE.md`](file:///d:/vigil-v2/vigil-v2/docs/ARCHITECTURE.md) | **PASS** |
| **PK-04** | ArmorIQ Policy Configurations | Brief Line 15 ("integrated ArmorIQ") | `config/vigil-containment.armoriq.yaml`, `config/vigil-tools.armoriq.yaml` | **IN PROGRESS** |
| **PK-05** | Security Boundary Test Evidence | Brief Line 15 ("boundary was tested") | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json), [`evidence/SLACK-1/`](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/) | **PASS** |
| **PK-06** | Secret-Handling Compliance | CLAUDE.md Non-Negotiable 5 | Zero secrets in git history; all tokens redacted in reports | **PASS** |
| **PK-07** | Open Source License File | R1 Specification | `LICENSE` | **NOT STARTED** |
| **PK-08** | Security Reporting Policy | R1 Specification | `SECURITY.md` | **NOT STARTED** |
| **PK-09** | Baseline Disclosure & In-Window Commits | R1 Specification | `docs/DISCLOSURE.md`, `CHANGELOG.md` | **NOT STARTED** |
| **PK-10** | Continuous Integration Workflow | R1 Specification | `.github/workflows/ci.yml` | **NOT STARTED** |

---

## 4. IN-xx Innovation Criteria Table

*Note: The brief does not publish itemized judging weights ("not specified"). The criteria below represent internal technical innovations evaluated in benchmarks.*

| ID | Innovation Criterion | Type | Metric / Proof | Status |
|---|---|---|---|---|
| **IN-01** | Policy Synthesis from Confirmed Incidents | Internal | Automated OPA/ArmorIQ rule generation from AST and motifs | **PASS** |
| **IN-02** | Counterfactual Traffic Replay Validation | Internal | Zero false blocks on recorded benign baseline prior to activation | **PASS** |
| **IN-03** | Clopper-Pearson Exact Binomial Bound | Internal | Upper bound on false-block probability at 95% confidence | **PASS** |
| **IN-04** | Cryptographic Evidence Vault | Internal | Ed25519 signed manifest with standalone offline verification script | **PASS** |
| **IN-05** | Multi-Provider Slack Approval Governance | Internal | Real-time HMAC-SHA256, verified corporate identity, 2-approver rule | **PASS** |
