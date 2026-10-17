# VIGIL 2.0 — External Systems & Sandbox Environment (SANDBOX.md)

This document provides a complete inventory of all external services, cloud dependencies, and local state systems used by VIGIL 2.0 during development and evaluation, detailing their operating mode (Real, Sandbox, or Mocked), endpoints, and credentials handling.

---

## 1. External Systems Inventory

| System | Role | Mode | Endpoint / Host | Account / Workspace / Identifier | Auth Mechanism | Redacted in Repo? |
|---|---|---|---|---|---|---|
| **ArmorIQ Management API** | Policy & identity management | Real (Production Cloud) | `https://api.armoriq.ai` | Agent: `vigil-containment-v2` | Bearer Token (`ARMORIQ_API_KEY`) | Yes (`***` in all logs & evidence) |
| **ArmorIQ Policy Proxy** | Forward enforcement proxy & signed receipts | Real (Production Cloud) | `https://customer-proxy.armoriq.ai` | Agent: `vigil-containment-v2` | Bearer Token (`ARMORIQ_API_KEY`) | Yes |
| **Slack API & Webhooks** | Human approval governance channel | Real (Production Cloud) | `https://slack.com/api/` | Workspace: `VIGIL Governance`<br>Channel: `***16RY` | Bot Token (`xoxb-***`)<br>Signing Secret (`HMAC-SHA256`) | Yes (`xoxb-***` redacted) |
| **Cloudflare Quick Tunnels** | Ingress for Slack interactive callbacks | Real (Ephemeral) | `https://*.trycloudflare.com` | Ephemeral quick tunnel via `cloudflared` | TLS Ingress | Yes |
| **Anthropic Claude API** | Natural language attack explanations | Real / Fallback Mock | `https://api.anthropic.com` | Model: `claude-3-5-sonnet-20241022` | API Key (`ANTHROPIC_API_KEY`) | Yes |
| **Containment FastMCP** | Action containment execution gate | Real (Local Process) | `http://127.0.0.1:8001/sse` | MCP Server: `vigil-containment` | Bearer Token (`MCP_AUTH_TOKEN`) | Yes |
| **Tools FastMCP** | Demo tool capabilities (DB, terminal, network) | Real (Local Process) | `http://127.0.0.1:8002/sse` | MCP Server: `vigil-tools` | Local IPC / SSE | N/A |
| **Persistence Database** | Incident states, audit ledger, proposals | Real (Local File) | `sqlite:///./vigil.db` | Single-tenant local SQLite (Postgres-compatible) | File permissions | N/A |
| **Redis / Cache** | Pub/Sub message broker | Mocked / In-Memory | `in-memory://` | Fallback event bus (`backend/app/bus.py`) | None | N/A |

---

## 2. Operating Modes

VIGIL supports distinct operating modes configured via environment variables:

### A. Live Production Mode (`ARMORIQ_MODE=live`)
- **Required for Hackathon Evaluation & Submission**: In this mode, VIGIL forwards every containment action proposal through the live ArmorIQ policy proxy (`customer-proxy.armoriq.ai`).
- Returns real cryptographic receipts signed by ArmorIQ cloud infrastructure.
- Rejects non-allowlisted actions at the ArmorIQ security boundary.
- **Fail-Safe Gate**: When `SUBMISSION_MODE=1` is set, VIGIL will refuse to boot unless `ARMORIQ_MODE=live`.

### B. Offline / Test Mode (`ARMORIQ_MODE=mock` or `local-demo`)
- Used for automated unit and offline integration testing (`pytest`).
- Emulates ArmorIQ policy decisions deterministically using local policy evaluation rules.
- Enables zero-network CI/CD test execution (`.github/workflows/ci.yml`).
- Allows offline verification of the tamper-evident cryptographic ledger and evidence vault (`verify_bundle.py`).

---

## 3. Credential & Secret Redaction Guarantee

Per project non-negotiables:
1. **Zero Raw Secrets in Source Control**: No `.env` files, actual API keys, Slack bot tokens, or signing secrets are committed to git.
2. **Template Provided**: All required environment variable names are documented in [`.env.example`](file:///d:/vigil-v2/vigil-v2/.env.example).
3. **Structured Log Masking**: All server logs and JSON receipts automatically mask tokens (e.g. `ARMORIQ_API_KEY` truncated to prefix/suffix or `***`).
4. **Vulnerability Reporting**: Any discovered secrets or boundary bypasses should be reported according to [`SECURITY.md`](file:///d:/vigil-v2/vigil-v2/SECURITY.md).
