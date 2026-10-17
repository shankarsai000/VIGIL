# VIGIL v2: what changed, how to run it, what is verified

## What changed

**ArmorIQ integration.** The old gate called custom REST endpoints (`/v1/intent/verify` and others) that are not part of the ArmorIQ SDK. The gate now uses `armoriq-sdk==0.6.10`. In `live` mode, each quarantine is a governed tool call. VIGIL captures a plan for `quarantine_agent`, mints an intent token with an inline allow policy, and invokes the containment MCP server (`backend/app/policies/containment_mcp.py`). That server carries out the quarantine through a secret-protected callback. A hold becomes ESCALATE, an explicit denial becomes DENIED, and any other error becomes ESCALATE.

**Fail closed.** Auth failures no longer fall back to local thresholds. Malformed responses no longer default to approved. Timeouts (20 s) escalate. Live mode refuses to start without a real key and a principal.

**Modes** (`ARMORIQ_MODE`): `live`, `disabled` (default), `local-demo`. See the table below.

**Containment strictly routes through the gate.** Previously, four code paths bypassed the ArmorIQ gate: auto-remediation block 8c triggered containment on raw score alone; `AutoRemediationOrchestrator` called `quarantine_service.isolate_agent` and `registry.update_status(QUARANTINED)` directly; `AttackGraphService` set downstream agent status to `QUARANTINED` directly; and `QuarantineService` maintained in-memory isolations detached from the registry. These are now fixed: all containment requests must route through `RemediationExecutor.request_containment` and `gate.authorize_containment`. Auto-remediation requests containment rather than applying it directly; `AttackGraphService` creates `ApprovalRequest` records rather than setting status; and every containment writes a tamper-evident audit ledger block documenting its source (`gate`, `human`, `auto`, `graph`). An architectural AST allowlist test (`backend/tests/test_containment_allowlist.py`) ensures no unauthorized code can write `AgentStatus.QUARANTINED`.

**Human approval goes through the gate.** Approving a request calls `RemediationExecutor.execute_human_approved`. Approval unlocks containment only in `local-demo`. It cannot override an ArmorIQ hold or denial, and it contains nothing in `disabled`. The recorded outcome is what actually happened: `QUARANTINE`, `NOT_CONTAINED (ESCALATE)`, and so on. Both the dashboard and the Telegram path use this method.

**Authentication.** `POST /observe`, `/agents/register`, `/attack/{type}`, `/telegram/approvals/{id}/resolve`, and the WebSocket require `OPERATOR_API_KEY`, sent as `X-VIGIL-Operator-Key` or as `?key=` on the WebSocket. An unset key returns 503, and a wrong key returns 401. The containment callback requires `CONTAINMENT_SECRET`, sent as `X-Containment-Secret`.

**Tamper-evident audit.** Every containment decision is appended to a hash-chained ledger at `backend/storage/audit_ledger.jsonl`. `GET /audit/verify` recomputes the chain and reports the first broken entry.

**Policy synthesis.** `backend/app/policies/synthesis.py` proposes ArmorIQ deny rules from the tool calls in a confirmed attack. A rule is proposed only when the same agent never uses that tool legitimately in its benign history. Proposals come out as reviewable YAML. Validation checks the recorded call history. It does not re-run agent episodes.

**Bugs fixed.** Each of these was found by running the code:
- The backend could not be imported: `seed.py` used `Any` without importing it.
- The backend could not start on PostgreSQL: the events table used SQLite's `AUTOINCREMENT`. It now uses `BIGSERIAL` on PostgreSQL.
- `requirements.txt` was missing `aiosqlite`, `python-telegram-bot`, and `joblib`.
- Approving a pending request returned HTTP 500, because the incident was inserted a second time. Re-logging an incident is now an upsert on `incident_id`.
- Dashboard approval quarantined regardless of the proposed action. It now acts on the proposed action, as the Telegram path already did.
- A Telegram ALERT approval executed the LOG action. It now executes ALERT.
- The Telegram path recorded a fabricated `ArmorIQ APPROVED`. It now records `NOT_CONSULTED (human approval)`.

**Archived.** The flat duplicate modules at `backend/*.py` (monitor, detector, remediation, explainer, models, seed, simulator, armoriq_gate, config) were not imported by the running app. They are now in `archive/legacy_flat_backend/`. The archived gate still has the old fail-open behaviour. Do not import it.

## Modes

| Mode | Who decides a quarantine | Contains automatically | Contains on human approval | Audit label |
|---|---|---|---|---|
| `live` | ArmorIQ, per call | Only if ArmorIQ allows | Only if ArmorIQ allows. Approval does not override it | `armoriq-live` |
| `disabled` (default) | Nobody. Quarantine escalates | No | No | `disabled (NOT ArmorIQ)` |
| `local-demo` | Fixed thresholds (score ≥ 0.85 approve, ≥ 0.65 escalate) | By threshold | Yes | `local-demo (NOT ArmorIQ)` |

`local-demo` is not valid for a submission.

## How to run

Local, the way it was verified:
1. Start PostgreSQL 16 and Redis 7. Set `DATABASE_URL` and `REDIS_HOST`.
2. `pip install -r backend/requirements.txt -r backend/requirements-dev.txt`
3. `OPERATOR_API_KEY=... CONTAINMENT_SECRET=... ARMORIQ_MODE=local-demo uvicorn backend.main:app --port 8000`
4. Containment actuator: `CONTAINMENT_SECRET=... VIGIL_INTERNAL_URL=http://127.0.0.1:8000 python -m backend.app.policies.containment_mcp` (port 8790, path `/mcp`). For `live` mode, expose it through a tunnel and register that URL with ArmorIQ.
5. Dashboard: set `VITE_VIGIL_OPERATOR_KEY` in `frontend/.env.local`. Vite ships that key inside the browser bundle, so use it only on a machine you control.
6. Tests: `python -m pytest backend/tests` (39 offline tests).

Docker: `docker compose up` starts `vigil-containment` as well. Put the variables in `.env`.

## Policy Immune System Enhancements (M0 — M6)

VIGIL v2 has been extended with the complete Policy Immune System architecture:

1. **Schema v1 Labelled Action Records & Structural Redaction (Phase M1)**:
   - Captures every agent interaction as a redacted `ActionRecord` holding argument shapes, types, lengths, and keys only. Placed secrets and raw SQL/payload text never reach storage.
   - Evidence: [`evidence/M1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M1/report.md), [`evidence/M1/action_traces_sample.jsonl`](file:///d:/vigil-v2/vigil-v2/evidence/M1/action_traces_sample.jsonl).

2. **Counterfactual Replay Engine & Exact Clopper-Pearson Bound (Phase M2)**:
   - Evaluates candidate denial rules over historical recorded traffic with zero network or database calls.
   - Computes attack coverage and the exact one-sided Clopper-Pearson upper bound $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ via the Beta PPF ($k=0, \ \delta=0.05$).
   - Replay verdict requires coverage $\ge 90\%$, $\bar{p}_{0.95} \le 0.5\%$, and $\ge 600$ benign samples.
   - Evidence: [`evidence/M2/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M2/report.md), [`evidence/M2/replay_report_accept.json`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_accept.json).

3. **Candidate Synthesis & Dry-Run Compiler (Phase M3)**:
   - Groups attack events into candidate rule families `(agent_id, tool)`. Generates dot-notation `armoriq.yaml` patches and slash-notation SDK inline policies.
   - Compiler enforces `--dry-run` by default; `--write` is strictly prohibited unless proposal status is `APPROVED`.
   - Evidence: [`evidence/M3/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M3/report.md), [`evidence/M3/customer-bot.manifest.json`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.manifest.json).

4. **Two-Person Proposal Approval Workflow & UI (Phase M4)**:
   - Enforces a 72-hour hard server expiration (returns HTTP 409).
   - High Impact proposals (blast radius spanning multiple agents or historical collisions) demand two distinct human approvers.
   - Evidence: [`evidence/M4/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M4/report.md), [`evidence/M4/backend_tests.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M4/backend_tests.txt).

5. **ArmorIQ Platform Verification & Ed25519 Signed Receipts (Phase M5)**:
   - Sandbox verification agent runs attack calls against live ArmorIQ platform (`armoriq-sdk==0.6.10`, production proxy `https://customer-proxy.armoriq.ai`).
   - Empirically proved authentic platform denial via `PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied` at the OPA evaluation layer (`layer: "opa"`).
   - Benign calls on `order_status` succeed.
   - Issues Ed25519 cryptographic receipts; private key lives outside repository at `~/.vigil/receipt_ed25519.key`. Appends receipt hash to `backend/storage/audit_ledger.jsonl`.
   - Evidence: [`evidence/M5/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M5/report.md), [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json), [`evidence/M5/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_receipt.json), [`evidence/M5/preflight.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json).

6. **Cross-Tenant Shared Signatures & Demo Pack (Phase M6)**:
   - Privacy-preserving export of abstract tool category motifs (`CATEGORY:secret_read -> CATEGORY:external_send`) with discretized support buckets (`small`, `medium`, `large`). Zero sensitive identifiers leaked.
   - Import maps motifs to local tools via `config/tool_categories.yaml`, evaluates them counterfactually against local traffic, and rejects contradicted rules without modifying live configurations.
   - Scripted end-to-end demo completes in 0.31s (< 120s limit).
   - Evidence: [`evidence/M6/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M6/report.md), [`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt), [`docs/DEMO_SCRIPT.md`](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md).

7. **Evidence Vault: Offline-Verifiable Cryptographic Evidence Bundles**:
   - Bundles complete incident and time-window telemetry: contiguous ledger segments with chain proofs, redacted action records (shapes only), proposals, approvals, platform receipts, containment outcomes, and configuration snapshots with zero secret values.
   - Manifest signed with Ed25519; verified offline on air-gapped systems using standalone `verify_bundle.py`.
   - Evidence: [`evidence/vault/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/vault/report.md), [`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt), [`docs/EVIDENCE_VAULT.md`](file:///d:/vigil-v2/vigil-v2/docs/EVIDENCE_VAULT.md).

8. **Approvals via Slack (SLACK-1 Adapter)**:
   - Replaced Telegram with an authenticated, identity-bound Slack approval adapter.
   - Every governance decision (containment holds and Policy Immune proposals) is cryptographically verified via HMAC-SHA256, bound to a verified corporate identity (`users:read.email` matching `SLACK_ALLOWED_EMAIL_DOMAINS`), protected against replay via server-issued single-use nonces, and audited to the hash-chained ledger.
   - Separation of duties (proposer cannot approve) and two-approver rule for HIGH-impact tier proposals enforced on server.
   - Telegram removed from all approval paths with legacy `/telegram/approvals` routes returning HTTP 410 Gone; UI updated with `ApprovalChannelPanel` and live `/health` status badge.
   - **Offline Claims [VERIFIED: PASS]**:
     - Signature verification: valid signatures pass, tampered payload rejected, stale timestamp rejected, missing headers rejected, empty secret fails closed.
     - Identity verification: corporate domains pass, personal domains rejected, missing emails rejected, Slack Connect guests rejected.
     - Nonce validation: mismatched and reused nonces rejected (consumed on first use).
     - Separation of duties and 2-approver rule: requester rejected, HIGH-impact requires 2 distinct approvers, duplicate clicks idempotent.
     - Zero argument leak: Block Kit payloads strip secrets and raw argument data.
     - Telegram removal: legacy routes return 410 Gone, AST check confirms zero Telegram imports in approval paths.
   - **Live Claims [VERIFIED: PASS]**:
     - Live containment card delivered to #vigil-approvals channel (***16RY) in real Slack workspace **VIGIL Governance** via Socket Mode.
     - Approved live by authorized corporate identity slssaishankar@gmail.com (***T0N9); card updated in-place, state transitioned, and committed to hash-chained ledger sequence 10817 ([evidence/SLACK-1/live_containment_approve.json](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/live_containment_approve.json)).
     - Rejection of non-allowlisted email domains verified live without state mutation ([evidence/SLACK-1/live_non_allowlisted_rejection.json](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/live_non_allowlisted_rejection.json)).
     - Stale button click on expired request returns 409 and marks message EXPIRED ([evidence/SLACK-1/live_expired_rejection.json](file:///d:/vigil-v2/vigil-v2/evidence/SLACK-1/live_expired_rejection.json)).

---

## Verification Matrix

| Category | Status & Scope | Evidence Reference |
|---|---|---|
| **Verified Offline (Fakes & Mocks)** | **VERIFIED (PASS)**: 45 backend immune and vault unit tests pass. Covers gate fail-closed handling, AST containment allowlisting, pure mathematical bounds, compiler safety, workflow expiration, receipt verification, privacy leaks, 1-byte tamper detection across all 5 bundle files, deleted ledger line detection, and offline verification with zero network access. | [`evidence/M0/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M0/report.md)<br>[`evidence/M2/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M2/report.md)<br>[`evidence/M4/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/M4/report.md)<br>[`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt)<br>[`evidence/vault/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/vault/report.md)<br>[`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt) |
| **Verified Live (ArmorIQ Platform)** | **VERIFIED (PASS)**: Live platform token minting (`https://api.armoriq.ai`) and live policy blocking (`https://customer-proxy.armoriq.ai`) empirically reproduced with `PolicyBlockedException` from OPA on 3/3 attack calls. FastMCP server running over Cloudflare tunnel. | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json)<br>[`evidence/M5/preflight.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json)<br>[`evidence/platform_changes.md`](file:///d:/vigil-v2/vigil-v2/evidence/platform_changes.md) |
| **What Remains Unverified** | **UNVERIFIED**: Control plane network registration endpoint (`https://api.armoriq.ai/iap/sdk/register`) returned HTTP 500 without org-admin permissions (handled via `--dry-run` and live intent token policy snapshot). Dashboard row generation for pre-execution OPA blocks (calls terminated at OPA evaluation before backend execution). Telegram live bot execution (no live token provided in environment). | [`evidence/M5/report.md:43-51`](file:///d:/vigil-v2/vigil-v2/evidence/M5/report.md#L43-L51) |

---

## Fundamental Limitations

1. **Replay is Counterfactual, Not Dynamic**:
   - The replay engine measures whether a candidate deny rule would have safely neutralized past attacks without breaking legitimate operations.
   - It **does not simulate adaptive adversarial responses**: an autonomous agent whose tool is blocked may retry with alternative tools, hallucinate arguments, or attempt sub-shell escapes.
   - Dynamic adversary adaptation requires sandboxed live evaluation or multi-turn red-teaming.

2. **Bound Validity Conditions**:
   - The statistical upper bound $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ assumes **conditional exchangeability**: future agent operations follow the same distribution as the recorded baseline.
   - If the agent's prompt, fine-tuned weights, or system tools undergo covariate shift, historical replay bounds must be recalibrated.
   - Unlabelled historical records are treated as **assumed benign**. If hidden attack actions contaminate the baseline, the empirical bound reflects that tainted baseline.

