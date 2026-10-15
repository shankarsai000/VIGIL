# Phase M0: Baseline Truth Check and Product Spec Report

## 1. Acceptance Table

| Step / Claim | Description | Status | Verdict | Exact Evidence File & Line |
|---|---|---|---|---|
| **Step 1** | Create branch `policy-immune` & `evidence/M0/` | PASS | CONFIRMED | `evidence/M0/` directory created on branch `policy-immune` |
| **Step 2** | Run backend tests, frontend tests, and frontend build | PASS | CONFIRMED | `evidence/M0/backend_tests_offline.txt:77` (67 passed)<br>`evidence/M0/frontend_tests.txt:8` (25 passed)<br>`evidence/M0/frontend_build.txt:12` (built in 9.80s) |
| **Claim 3a** | Every write of status `QUARANTINED` is allowlisted | PASS | CONFIRMED | `backend/app/remediation/remediation.py:335`<br>`backend/main.py:553`<br>`backend/tests/test_containment_allowlist.py:40-112`<br>`evidence/M0/backend_tests_offline.txt:28` |
| **Claim 3b** | Auto-remediation path requests containment through gate; never isolates directly | PASS | CONFIRMED | `backend/app/remediation/remediation.py:212`<br>`backend/services/auto_remediation_orchestrator.py:74-85`<br>`backend/tests/test_containment_allowlist.py:246-271`<br>`evidence/M0/backend_tests_offline.txt:30` |
| **Claim 3c** | Attack-graph path creates approval requests and never writes status | PASS | CONFIRMED | `backend/services/attack_graph_service.py:133-158`<br>`backend/tests/test_containment_allowlist.py:115-170`<br>`evidence/M0/backend_tests_offline.txt:29` |
| **Claim 3d** | Existing approval requests enforce expiry on server (HTTP 409) | FAIL | FALSE | `backend/main.py:731-733`<br>`evidence/M0/claim_d_evidence.txt:1`<br>*Details*: Server returns HTTP 200 upon approving expired request instead of HTTP 409. |
| **Claim 3e** | Status-mapping tests cover `NOT_CONTAINED (ESCALATE)` and `NOT_CONTAINED (DENIED)` | PASS | CONFIRMED | `frontend/src/tests/governanceBadges.test.ts:53-71`<br>`evidence/M0/frontend_tests.txt:8` |
| **Claim 3f** | `GET /health` reports the gate mode | PASS | CONFIRMED | `backend/main.py:386-411`<br>`backend/tests/test_security_and_routes.py:117-132`<br>`evidence/M0/backend_tests_offline.txt:71` |
| **Claim 3g** | No Google Fonts references remain in `frontend/src` or `frontend/index.html` | PASS | CONFIRMED | `frontend/index.html:1-15`<br>`frontend/src/styles/globals.css:1-50` (Self-hosted @font-face only) |
| **Claim 3h** | Recovery loop never restores gate-sourced or human-sourced quarantines | PASS | CONFIRMED | `backend/app/runtime/simulator.py:453-456`<br>`backend/tests/test_quarantine_release.py:145-195`<br>`evidence/M0/backend_tests_offline.txt:61` |
| **Step 4** | Create `docs/POLICY_IMMUNE.md` with problem, principles, math, assumptions | PASS | CONFIRMED | `docs/POLICY_IMMUNE.md:1-68` |
| **Step 5** | Write `evidence/M0/report.md` | PASS | CONFIRMED | `evidence/M0/report.md` |

---

## 2. Files Added or Modified

| File | Change Type | Line Count | Reason |
|---|---|---|---|
| `docs/POLICY_IMMUNE.md` | Added | 68 | Product specification covering problem definition, safe blocking principles, fail-closed enforcement, mathematical definitions of coverage and false-block rate with statistical upper bounds, and explicit assumptions (exchangeability, assumed benign labels). |
| `CLAUDE.md` | Added | 31 | Project standing instructions, non-negotiable rules, report formats, and git standards. |
| `frontend/vite.config.ts` | Modified | +1 | Configured `pool: 'forks'` under vitest config to avoid Node.js worker thread deadlocks in Windows environments. |
| `evidence/M0/backend_tests.txt` | Added | 175 | Full test output of backend test suite including live tunnel attempt. |
| `evidence/M0/backend_tests_offline.txt` | Added | 78 | Full test output of offline backend test suite (`pytest -m "not live"`: 67 passed). |
| `evidence/M0/frontend_tests.txt` | Added | 16 | Full test output of frontend vitest suite (25 passed). |
| `evidence/M0/frontend_build.txt` | Added | 15 | Full output of frontend production build (`tsc && vite build`). |
| `evidence/M0/claim_d_evidence.txt` | Added | 15 | Test fixture execution output proving server-side expiry behavior on approval requests. |
| `scratch/test_claim_d.py` | Added | 88 | Test fixture exercising resolution of expired approval requests against the FastAPI app. |
| `evidence/M0/report.md` | Added | ~85 | Phase M0 baseline truth check report. |

---

## 3. What is Not Verified and Why

1. **Live ArmorIQ Cloud Gateway Integration**:
   - `backend/tests/test_armoriq_gate.py` contains 3 live tests marked `@pytest.mark.live`.
   - When executing against the live endpoint with ephemeral/test credentials, the public SSE endpoint at `https://armoriq.mywire.org` was unreachable from this local test environment (HTTP connection failed).
   - Offline gate semantics (fail-closed, timeout escalation, policy hold handling, authorization fallback rejection) were fully verified (17/17 gate tests passed in offline mode).
2. **Approval Request Expiry Enforcement (Claim 3d)**:
   - Server route `/telegram/approvals/{request_id}/resolve` does not reject requests with HTTP 409 when expired; it returned HTTP 200 during testing. As instructed by M0 rules ("Build no features in this phase"), this was recorded as FALSE without introducing unauthorized feature code in M0.

---

## 4. Blockers for Next Phase

- **Claim 3d (Server-side Approval Expiry)**:
  - While Stop Rules for M0 only halt if Claim 3a or Claim 3b fail (both confirmed PASS), Claim 3d represents a gap where expired requests are not rejected with HTTP 409. An expiry validation check (`if time.time() - req.requested_at > TTL: raise HTTPException(status_code=409, detail="Approval request expired")`) must be planned and tested in subsequent phase work.
- **Stop Rule Assessment**:
  - Claim 3a (`QUARANTINED` allowlist): **CONFIRMED (PASS)**
  - Claim 3b (Auto-remediation gate containment): **CONFIRMED (PASS)**
  - Neither 3a nor 3b failed. Stop rule was not triggered. M0 is ready to conclude.
