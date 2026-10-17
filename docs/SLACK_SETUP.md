# Slack Approval Adapter Setup Guide (SLACK-1)

This guide documents the configuration steps required to connect VIGIL 2.0 to Slack for governance approvals (containment holds and Policy Immune proposals).

---

## 1. Create Slack App in API Dashboard

1. Navigate to [api.slack.com/apps](https://api.slack.com/apps) in your browser.
2. Click **Create New App** > **From an app manifest** (or **From scratch**).
3. Select your corporate development workspace.
4. Name the application: `VIGIL Governance Gateway`.

---

## 2. Configure Bot Scopes (Permissions)

In the left sidebar, click **OAuth & Permissions**. Under **Bot Token Scopes**, add the following required OAuth scopes:

| Scope | Purpose |
|---|---|
| `chat:write` | Post and update Block Kit interactive approval cards |
| `users:read` | Read user profiles to look up account attributes |
| `users:read.email` | Extract and verify corporate email identities |
| `channels:read` | Inspect public approval channels |
| `groups:read` | Inspect private approval channels |
| `commands` | Support optional governance slash commands |

> [!IMPORTANT]
> The Slack bot MUST have `users:read.email` enabled in order to bind Slack clicks to verified corporate identities. Slack Connect guests and unverified users will be rejected fail-closed.

---

## 3. Configure Interactivity & Webhook Endpoints

In the left sidebar, click **Interactivity & Shortcuts**:
1. Toggle the switch to **On**.
2. **Request URL**:
   - For Production (HTTP mode):
     `https://<your-vigil-domain>/integrations/slack/interactions`
   - For Local Development (using ngrok or cloudflare tunnel):
     `https://<your-tunnel-subdomain>.ngrok-free.app/integrations/slack/interactions`
3. Click **Save Changes**.

### Optional: Socket Mode (Local Development)
If developing locally without an external tunnel:
1. In the left sidebar, click **Socket Mode** and toggle **Enable Socket Mode** to **On**.
2. Create an App-level token (`xapp-...`) with `connections:write` scope named `vigil-socket-token`.
3. Set `SLACK_MODE=socket` and configure `SLACK_APP_TOKEN=xapp-...` in `.env`.

---

## 4. Install App to Workspace and Channel

1. Click **Install to Workspace** on the left sidebar under **Install App** and click **Allow**.
2. Copy the **Bot User OAuth Token** (`xoxb-...`).
3. Under **Basic Information** > **App Credentials**, copy the **Signing Secret**.
4. In your Slack client, create or choose a dedicated governance channel (e.g., `#vigil-approvals`).
5. Invite the bot to the channel by typing:
   ```text
   /invite @VIGIL Governance Gateway
   ```
6. Copy the Channel ID (right click channel > **View channel details** > copy Channel ID at the bottom, e.g. `C0123456789`).

---

## 5. Environment Variables Configuration

Add the following variables to `.env` (never commit real tokens):

```bash
# Slack Approval Gateway Configuration (SLACK-1)
SLACK_BOT_TOKEN="xoxb-your-bot-user-oauth-token"
SLACK_SIGNING_SECRET="your-signing-secret-from-app-credentials"
SLACK_APPROVAL_CHANNEL="C0123456789"
SLACK_ALLOWED_EMAIL_DOMAINS="corp.company.com,security.company.com"

# Execution mode: 'http' (recommended for webhooks) or 'socket' (local testing)
SLACK_MODE="http"

# Required only if SLACK_MODE=socket
SLACK_APP_TOKEN="xapp-your-app-level-token"
```

---

## 6. End-to-End Security Architecture

1. **HMAC-SHA256 Signature Verification**: Every callback hitting `/integrations/slack/interactions` is checked against `SLACK_SIGNING_SECRET` with version prefix `v0`. Any request with missing headers, delta $> 300$ seconds, or mismatched signatures is rejected immediately.
2. **Replay Protection via Single-Use Nonces**: Buttons pass server-issued nonces inside their value fields (never the decision). The nonce is stored server-side and invalidated upon first use.
3. **Corporate Identity Binding**: The clicker's Slack user ID is resolved via `users.info`. Their verified email must match one of the domains in `SLACK_ALLOWED_EMAIL_DOMAINS`. Slack Connect guests or unconfirmed emails are rejected.
4. **Separation of Duties & Two-Approver Rule**:
   - The proposer of a Policy Proposal cannot approve their own proposal.
   - High-impact proposals demand approvals from two distinct, verified corporate identities.
5. **Auditing**: Every delivery, callback verification, acceptance, and rejection is recorded into the hash-chained `AuditLedger`.
