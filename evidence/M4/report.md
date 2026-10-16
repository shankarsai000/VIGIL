# Phase M4: Proposal Workflow and UI Report

## 1. Acceptance Table

| Item / Acceptance Criterion | Description | Status | Exact Evidence File & Line |
|---|---|---|---|
| **Build Item 1** | Table `policy_proposals` in registry: `id`, `status` (`PROPOSED`, `APPROVED`, `REJECTED`, `EXPIRED`), `agent_id`, `mcp_id`, `tool`, `impact_tier` (`LOW` or `HIGH`), `replay_json`, `assumptions_json`, `approvals_json`, `created_at`, `expires_at`, `decided_at`, `version`. Postgres and SQLite compatible. | PASS | [`backend/app/runtime/registry.py:166-189`](file:///d:/vigil-v2/vigil-v2/backend/app/runtime/registry.py#L166-L189)<br>[`backend/app/immune/workflow.py:45-61`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/workflow.py#L45-L61) |
| **Build Item 2a** | Public read routes: `GET /policies/proposals` and `GET /policies/proposals/{id}`. Expired proposals lazily transition to `EXPIRED` status with 72h window calculation. | PASS | [`backend/main.py:1519-1560`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1519-L1560)<br>[`backend/tests/test_immune_workflow.py:125-165`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L125-L165) |
| **Build Item 2b** | Creation route: `POST /policies/proposals` (requires operator key). Replays candidate rule against recorded traffic window; only `ACCEPT` replay results become proposals. | PASS | [`backend/main.py:1562-1628`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1562-L1628)<br>[`backend/tests/test_immune_workflow.py:85-123`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L85-L123) |
| **Build Item 2c** | Approval & rejection routes: `POST /policies/proposals/{id}/approve` and `POST /policies/proposals/{id}/reject` requiring operator key and `X-VIGIL-Approver` header. | PASS | [`backend/main.py:1630-1748`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1630-L1748)<br>[`backend/tests/test_immune_workflow.py:167-270`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L167-L270) |
| **Build Item 3a** | 72-hour hard expiry: `expires_at = created_at + 72 hours`. Calling approve or reject on an expired proposal transitions status to `EXPIRED` and returns HTTP 409 Conflict. | PASS | [`backend/main.py:1646-1659`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1646-L1659)<br>[`backend/tests/test_immune_workflow.py:125-165`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L125-L165) |
| **Build Item 3b** | Impact Tier determination: `HIGH` when family spans >1 agent, `benign_total > 5000`, or `false_block_point > 0`. Thresholds live in documented config `ProposalConfig`. `HIGH` tier demands 2 distinct approvers; `LOW` tier requires 1. | PASS | [`backend/app/immune/workflow.py:24-32`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/workflow.py#L24-L32)<br>[`backend/app/immune/workflow.py:64-85`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/workflow.py#L64-L85)<br>[`backend/tests/test_immune_workflow.py:167-210`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L167-L210) |
| **Build Item 3c** | Idempotent approval: A duplicate approval from the same approver returns 200 with message "Duplicate approval ignored" and changes nothing. | PASS | [`backend/main.py:1672-1678`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1672-L1678)<br>[`backend/tests/test_immune_workflow.py:212-243`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L212-L243) |
| **Build Item 3d** | Immutable ledger auditing: Every state change writes an `AuditLedger` entry recording the exact approver identity and transition metadata. | PASS | [`backend/main.py:1710-1725`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1710-L1725)<br>[`backend/tests/test_immune_workflow.py:272-300`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py#L272-L300) |
| **Build Item 4** | UI "Policy proposals" view: Table columns (`rule`, `coverage`, `false-block bound`, `attacks replayed`, `benign replayed`, `status`, `expires`). Detail panel with YAML diff, assumptions context, approval progress ("1 of 2"), confirmation dialogs for approve/reject, and disallowing approval for `INSUFFICIENT_EVIDENCE`. | PASS | [`frontend/src/components/PolicyProposalsView.tsx:1-490`](file:///d:/vigil-v2/vigil-v2/frontend/src/components/PolicyProposalsView.tsx#L1-L490)<br>[`frontend/src/utils/governanceBadges.tsx:227-295`](file:///d:/vigil-v2/vigil-v2/frontend/src/utils/governanceBadges.tsx#L227-L295) |
| **Acceptance 1** | Tests for expiry returning 409, two-approver enforcement, duplicate approver ignored, missing key returning 401/503, and audit ledger entries recorded. | PASS | [`evidence/M4/backend_tests.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M4/backend_tests.txt)<br>[`backend/tests/test_immune_workflow.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_workflow.py) |
| **Acceptance 2** | Vitest unit tests for status badges (`proposalStatusBadge`) and approval-progress text (`approvalProgressText`, `canApproveProposal`). | PASS | [`evidence/M4/frontend_tests.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M4/frontend_tests.txt)<br>[`frontend/src/tests/governanceBadges.test.ts:200-275`](file:///d:/vigil-v2/vigil-v2/frontend/src/tests/governanceBadges.test.ts#L200-L275) |
| **Acceptance 3** | Screenshots of the proposals list and the detail panel saved to `docs/ui/M4/`. | PASS | [`docs/ui/M4/proposals_list.png`](file:///d:/vigil-v2/vigil-v2/docs/ui/M4/proposals_list.png)<br>[`docs/ui/M4/proposal_detail.png`](file:///d:/vigil-v2/vigil-v2/docs/ui/M4/proposal_detail.png) |

---

## 2. Files Added or Modified

| File | Change Type | Line Count | Reason |
|---|---|---|---|
| `backend/app/immune/workflow.py` | Added | 110 | Core proposal workflow module: `ProposalConfig`, impact tier calculation (`compute_impact_tier`), `PolicyProposalRecord`, YAML diff generator, and status constants. |
| `backend/app/runtime/registry.py` | Modified | +85 | Added `policy_proposals` table schema to SQLite and PostgreSQL `init_db()`. Added CRUD operations: `create_policy_proposal`, `get_policy_proposal`, `list_policy_proposals`, and `update_policy_proposal`. Added timestamp window bounds `start_ts` and `end_ts` to `get_action_records`. |
| `backend/app/runtime/db.py` | Modified | +4 | Normalized `create_database` to safely strip `sqlite:///` URI prefixes for Windows absolute database paths. |
| `backend/main.py` | Modified | +220 | Implemented `GET /policies/proposals`, `GET /policies/proposals/{id}`, `POST /policies/proposals`, `POST /policies/proposals/{id}/approve`, and `POST /policies/proposals/{id}/reject`. Wired 72h expiry, 2-approver gating, duplicate approver deduplication, and `AuditLedger` logging. |
| `backend/app/immune/__init__.py` | Modified | +15 | Exported proposal workflow entities, models, and calculation utilities. |
| `backend/tests/test_immune_workflow.py` | Added | 305 | Complete backend test suite covering 401/503 authorization, replay acceptance gating, 409 expiry transitions, 2-approver tier enforcement, duplicate approver idempotency, rejection transitions, and ledger logging. (7 of 7 passing). |
| `frontend/src/types.ts` | Modified | +20 | Added `PolicyProposal` TypeScript data interface. |
| `frontend/src/api.ts` | Modified | +65 | Added VIGIL client methods: `getPolicyProposals()`, `getPolicyProposal(id)`, `createPolicyProposal(...)`, `approvePolicyProposal(id, approver)`, and `rejectPolicyProposal(id, approver, reason)`. |
| `frontend/src/utils/governanceBadges.tsx` | Modified | +70 | Added `proposalStatusBadge`, `approvalProgressText`, and `canApproveProposal` helpers. |
| `frontend/src/tests/governanceBadges.test.ts` | Modified | +75 | Added Vitest unit test suite validating all proposal status badge styles, progress text formats, and unapprovable terminal/insufficient states. (33 of 33 passing). |
| `frontend/src/store.ts` | Modified | +15 | Added `'proposals'` tab state, URL hash/search parameter initialization, and conditional simulation dock collapse. |
| `frontend/src/components/CommandBar.tsx` | Modified | +12 | Added `POLICY PROPOSALS` tab button to top navigation bar. |
| `frontend/src/components/PolicyProposalsView.tsx` | Added | 490 | Comprehensive proposals dashboard view with responsive master-detail layout, columns table, YAML diff preview, assumptions summary, Clopper-Pearson bound metrics, approval progress bar, and audited confirmation modals for Approve/Reject. |
| `frontend/src/App.tsx` | Modified | +8 | Wired `case 'proposals': return <PolicyProposalsView />;`. |
| `frontend/vite.config.ts` | Modified | +2 | Added proxy entry `'/policies': 'http://127.0.0.1:8000'` to route frontend proposal requests to backend. |
| `scratch/seed_proposals.py` | Added | 120 | Seed script for sample high-impact, low-impact, and insufficient evidence candidate proposals. |
| `docs/ui/M4/proposals_list.png` | Added | Binary | Full-resolution screenshot of Policy Proposals table list with columns (`rule`, `coverage`, `false-block bound`, `attacks replayed`, `benign replayed`, `status`, `expires`). |
| `docs/ui/M4/proposal_detail.png` | Added | Binary | Full-resolution screenshot of Proposal Detail Panel showing YAML diff, Clopper-Pearson bound metrics, assumptions, and approval progress ("1 of 2"). |
| `evidence/M4/backend_tests.txt` | Added | 35 | Captured pytest output for `test_immune_workflow.py` (7 passed in 46.01s). |
| `evidence/M4/frontend_tests.txt` | Added | 15 | Captured Vitest output for governance and proposal badge tests (33 passed). |
| `evidence/M4/report.md` | Added | ~95 | Phase M4 acceptance and verification report. |

---

## 3. What is Not Verified and Why

1. **Live Production Containment Activation**:
   - As specified in standing instructions and Phase M4 goals, the proposal workflow verifies candidates against historical/replay records and manages administrative reviewer consensus (`PROPOSED` -> `APPROVED` / `REJECTED`). Live enforcement changes in ArmorIQ require downstream deployment compilation (Phase M5).
2. **Third-Party External Identity Providers**:
   - The approver identity is currently authenticated via the operator API key and `X-VIGIL-Approver` header, audited directly to the cryptographic ledger. Integration with SAML/OIDC SSO will occur in enterprise auth configuration.

---

## 4. Blockers for Next Phase

- **None**: All M4 requirements and acceptance criteria are satisfied. The database schema is backward-compatible with PostgreSQL and SQLite, server-side rules strictly enforce 72h expiration and impact-tier 2-approver consensus, duplicate approvers are deduplicated, state transitions are cryptographically audited to the ledger, and the frontend UI presents the required table columns, detail panel, YAML diff, assumptions, and confirmation dialogs.
