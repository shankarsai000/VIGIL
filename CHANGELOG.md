# Changelog

All notable changes to the VIGIL Policy Immune System during the Flow State Hackathon build window (October 10 – October 17, 2026) are documented in this file, grouped chronologically.

---

## 2026-10-17

### Added
- **Phase R0 Requirements Baseline**:
  - Parsed official Flow State hackathon brief into checkable IDs in `docs/brief/REQUIREMENTS.md`.
  - Built automated compliance validator `scripts/check_requirements.py` enforcing evidence paths on disk.
- **Phase SLACK-1 Live Verification**:
  - Live containment hold approval verified with authorized corporate user (`slssaishankar@gmail.com`) via Slack Socket Mode.
  - Live rejection of unauthorized email domain verified without state mutation.
  - Live stale button expiry verified with HTTP 409 and card update to `EXPIRED`.
  - Captured live evidence in `evidence/SLACK-1/live_containment_approve.json`.
- **Phase SLACK-1 Slack Approval Adapter**:
  - Implemented `backend/app/channels/base.py` approval channel abstractions.
  - Built `backend/app/channels/slack.py` Bolt adapter with HMAC-SHA256 signature checking, `users:read.email` lookup, single-use nonce consumption, and Block Kit delivery.
  - Added separation of duties and two-approver rule for HIGH-impact proposals.
  - Created PostgreSQL migration `backend/migrations/002_remove_telegram_from_approvals.sql`.
  - Built `ApprovalChannelPanel.tsx` and mounted in frontend `GovernanceView.tsx`.
  - Deprecated `/telegram/approvals` routes with HTTP 410 Gone.
  - Comprehensive 17-test offline test suite in `backend/tests/test_slack_approvals.py`.

---

## 2026-10-16

### Added
- **Phase M5 ArmorIQ Verification & Signed Receipts**:
  - Preflight introspection of `armoriq_sdk` token minting and OPA invocation exception classes.
  - Built `backend/app/immune/verify.py` sandbox execution harness with N-attack simulation.
  - Signed execution plan verification ensuring policy blocks originate from ArmorIQ platform OPA rules rather than client sidechecks.
  - Generated Ed25519-signed verification receipts with cryptographic intent tokens.
- **Phase M4 Policy Proposals Workflow & Governance**:
  - Built `backend/app/immune/workflow.py` enforcing lifecycle: `PROPOSED` -> `APPROVED` | `REJECTED` | `EXPIRED`.
  - Two-human approval requirement for HIGH impact tier (family spans > 1 agent, benign samples > 5000, or point estimate > 0).
  - 72-hour hard proposal expiration returning HTTP 409 Conflict.
  - Complete dashboard governance interface and approval audit logging.
- **Evidence Vault**:
  - Built `backend/app/evidence/bundle.py` collecting contiguous hash-chained ledger segments, redacted action records, proposals, receipts, and zero-secret config snapshots.
  - Ed25519 signed manifest with standalone air-gapped `verify_bundle.py`.

---

## 2026-10-15

### Added
- **Phase M3 Candidate Rules & Dry-Run Compiler**:
  - Synthesized minimal OPA Rego and ArmorIQ candidate rules from incident action records.
  - Dry-run validation compiling rules to mock targets without touching live infrastructure.
- **Phase M2 Counterfactual Replay Engine & Statistical Bounds**:
  - Built pure counterfactual replay engine replaying candidate deny rules against historical event streams.
  - Implemented exact Clopper-Pearson binomial upper confidence bound: $\bar{p}_{1-\delta} = 1 - \delta^{1/n}$ at 95% confidence.
  - Enforced zero false blocks on benign traffic prior to candidate graduation.
- **Phase M1 Action Records, Structural Redaction & Labelled Traces**:
  - Implemented structural argument redaction preserving parameter shapes while scrubbing raw payloads.
  - Ground-truth trace labelling ("assumed benign" vs. confirmed attack).
- **Phase M0 Baseline Truth Check & Specification**:
  - Documented baseline platform truth, threat taxonomies, and architectural invariants.

---

## 2026-10-14

### Added
- **Core Platform & Governance Infrastructure**:
  - Route all containment paths through fail-closed ArmorIQ gate (`backend/services/containment_service.py`).
  - Quarantine release restricted exclusively to human operator approval with ledger auditing.
  - Tamper-evident hash-chained audit ledger (`GET /audit/verify`).
  - Derived all executive dashboard metrics honestly from ground-truth storage.
  - Live scenario matrix verified against ArmorIQ platform (ALLOW, DENY, HOLD, BENIGN).
  - FastMCP containment server integration with Cloudflare tunnel exposure.
