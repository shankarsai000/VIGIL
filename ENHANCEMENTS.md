# VIGIL v2: what changed, how to run it, what is verified

## What changed

**ArmorIQ integration.** The old gate called custom REST endpoints (`/v1/intent/verify` and others) that are not part of the ArmorIQ SDK. The gate now uses `armoriq-sdk==0.6.10`. In `live` mode, each quarantine is a governed tool call. VIGIL captures a plan for `quarantine_agent`, mints an intent token with an inline allow policy, and invokes the containment MCP server (`backend/app/policies/containment_mcp.py`). That server carries out the quarantine through a secret-protected callback. A hold becomes ESCALATE, an explicit denial becomes DENIED, and any other error becomes ESCALATE.

**Fail closed.** Auth failures no longer fall back to local thresholds. Malformed responses no longer default to approved. Timeouts (20 s) escalate. Live mode refuses to start without a real key and a principal.

**Modes** (`ARMORIQ_MODE`): `live`, `disabled` (default), `local-demo`. See the table below.

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

## Verification

**Offline tests (39, all pass).** They cover gate fail-closed behaviour, using fakes that raise the SDK's real exception classes. They also cover ledger tamper detection, synthesis rules, route protection, the containment callback, and the containment MCP tool.

**Live, in this sandbox** (local PostgreSQL 16.15 and Redis 7.0.15, uvicorn, no Docker):
- Startup succeeds and the schema initializes.
- Write endpoints: no key returns 401, a wrong key returns 401, the right key returns 200.
- Containment callback: no secret returns 401. With the secret, the agent becomes QUARANTINED.
- WebSocket: the right key is accepted. A wrong key is refused at the handshake.
- `GET /audit/verify` reports ok across 70 entries from simulator and manual traffic.
- Human approval, `local-demo`: the agent becomes QUARANTINED. The ledger records `APPROVED` with `local-demo (NOT ArmorIQ)`.
- Human approval, `disabled`: a quarantine proposal is approved and the agent stays NORMAL. The ledger records `ESCALATE`, `disabled (NOT ArmorIQ)`, and `NOT_CONTAINED`.
- Containment MCP over streamable HTTP: `quarantine_agent` is callable from an MCP client, and the quarantine is applied. A malformed call is refused.

**Not verified.** Live ArmorIQ. No platform key was available, so `live` mode is covered only by fakes. The SDK surface was checked against the installed version 0.6.10. Holds, approvals, and the containment MCP registration on the ArmorIQ platform are untested. The Telegram path was not exercised live, because no bot is configured here.

## Open items (found, not fixed)

- The ArmorClaw model has no weights in the repo. `backend/models/armorclaw/v4` contains config and tokenizer files only, so the prompt-injection classifier cannot run.
- No trained telemetry model file is in the repo, so the ML layer is probably inactive. Not verified at runtime.
- `/health` lists DistilBERT and Random Forest engines. Neither was shown to be loaded here. Treat that list as unverified.
- Approving a request marks the approval record `APPROVED` even when containment did not happen. The real outcome is recorded in the incident and the ledger, not as a separate approval status.
- Read endpoints (`GET /agents`, `/incidents`, `/audit`, `/api/v2/*`) are still unauthenticated.
- The operator key ships to the browser with the dashboard bundle.
- In `local-demo` the simulator generates attacks, approvals, and quarantines continuously, so the demo state changes without user input.
- Conformal false-quarantine calibration is not built. It needs labelled agent episodes. The repo's labelled data is network flows.
- Some README claims are wrong. The storage is PostgreSQL only, not SQLite. The audit trail is hash-chained now, but it is still local, not immutable. Mock mode was removed. The ArmorClaw weights are missing.

## Next steps

1. Register the containment MCP with ArmorIQ, write the `quarantine_agent` policy, and run one `live` authorization end to end.
2. Store the containment outcome on the approval record.
3. Authenticate the read endpoints. Move the dashboard to a server-side proxy so the key stays off the browser.
4. Build conformal calibration once labelled agent episodes exist.
5. Delete `archive/` after one release.
