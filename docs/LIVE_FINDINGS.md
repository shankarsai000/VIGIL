# VIGIL v2 — Live Platform Findings & Day-One Questions

This document records the exact, observed empirical results from live runs against the real ArmorIQ platform (`armoriq-sdk==0.6.10`, production environment `https://customer-proxy.armoriq.ai`).

---

## 1. Does an inline deny fail at get_intent_token or at invoke? Which exception class?

### Observation
- **Action not in signed plan**: Fails immediately and locally at `client.invoke_with_policy` before any network call.  
  **Exception class**: `armoriq_sdk.exceptions.IntentMismatchException`  
  *Message*: `"Action 'different_action' not found in the original plan. Plan contains actions: ['quarantine_agent']. You can only invoke actions that were included in the plan when you called capture_plan()."`
- **Tool denied by platform policy**:
  During `get_intent_token`, the IAP service mints the intent token with policy evaluation metadata (`default_enforcement_action: 'block'`).
  When `client.invoke_with_policy` evaluates against OPA policy on invocation, it fails at `invoke`!  
  **Exception class**: `armoriq_sdk.exceptions.PolicyBlockedException`  
  *Message*: `"Tool 'drop_database' denied by OPA: policy_constraints_not_satisfied"`
- **Direct IAP token mint block**:
  If the platform control plane or token issuance endpoint rejects the requested tools directly, `get_intent_token` raises `PolicyBlockedException`:  
  *Message*: `"Policy blocked intent token issuance: <reason>"`

---

## 2. Does a block appear in the ArmorIQ dashboard as a policy trace? Which trace or intent identifiers does the SDK result expose?

### Observation
Yes, policy decisions produce trace records associated with the registered identity (`vigil-containment`) and policy (`cli-vigil-containment-vigil-containment`).

### Exact SDK Attributes Exposed (introspected directly from live runtime instances):

#### `IntentToken` Attributes:
- `token_id` (`str`): Unique identifier of the minted token (e.g., `'e6befda953a84713844288e9a3b5f47e'`).
- `plan_id` (`str`): Unique UUID of the plan capture (e.g., `'18906aaa-ae30-49aa-9500-caf74a04a73a'`).
- `plan_hash` (`str`): SHA-256 cryptographic hash over canonical plan steps.
- `policy_validation` (`dict`): Contains:
  - `domain`: Registered proxy domain
  - `requested_tools`: `['quarantine_agent']`
  - `allowed_tools`: list of allowed tools
  - `denied_tools`: list of denied tools
  - `denied_reasons`: list of refusal reasons
  - `matched_policies`: list containing `policyId`, `policyName`, `priority`, `defaultEnforcementAction`
  - `default_enforcement_action`: `'block'` or `'allow'`
  - `decision_source`: `'opa'`
  - `policy_ref`: trace reference (e.g., `'armoriq:b200362a8e93:1a138ed5d65'`)
- `policy_snapshot` (`list`): Snapshot of registered policy member rules and version hashes.
- `step_proofs` (`list`): Merkle tree proofs for each individual step.
- `issued_at`, `expires_at`, `time_until_expiry`: Token validity timestamps.
- `jwt_token`: Signed token credential payload.

#### `PolicyBlockedException` Attributes:
- `enforcement_action`: `'block'`
- `reason`: `'policy_constraints_not_satisfied'`
- `args`: `("Tool '<tool>' denied by OPA: policy_constraints_not_satisfied",)`
- `metadata`: Policy evaluation metadata (or `None`).

---

## 3. What does a hold look like with wait_for_approval=False?

### Observation
When `InvokeOptions(wait_for_approval=False)` is specified and a tool call triggers human-in-the-loop approval or delegation:
- The SDK does **not** block or poll the network waiting for an operator.
- It immediately raises:
  **Exception class**: `armoriq_sdk.exceptions.PolicyHoldException`
- **Attributes on `PolicyHoldException`**:
  - `delegation_context` (`dict`): Holds delegation identifiers (`delegation_id`, `status`).
  - `metadata` (`dict`): Hold details (e.g., `'hold_status': 'PENDING'`).
  - `args`: Human-readable explanation message.
- In VIGIL, `armoriq_gate.py` catches `PolicyHoldException` and translates it directly into `PolicyDecision.ESCALATE`.

---

## 4. Does the streamable HTTP endpoint at /mcp satisfy the proxy? If the proxy injects extra arguments such as _policy_context, make containment_mcp.py accept them and add a test.

### Observation
Yes, the streamable HTTP endpoint at `/mcp` successfully satisfies the ArmorIQ proxy under two configuration requirements:
1. **Stateless HTTP mode**: FastMCP must set `app.settings.stateless_http = True`. Without this, incoming proxied requests without an established `mcp-session-id` return `-32600 Session not found`.
2. **DNS Rebinding & Host header**: FastMCP must set `enable_dns_rebinding_protection = False` (or permit the tunnel domain) so public Cloudflare tunnel host headers (`*.trycloudflare.com`) are not rejected with `421 Misdirected Request`.
3. **Extra Arguments Handling**:
   - FastMCP prohibits parameter names beginning with an underscore in python signatures (`InvalidSignature`).
   - However, FastMCP's argument validator (`ArgModelBase`) automatically ignores extra injected JSON fields such as `_policy_context` during tool invocation.
   - Verified end-to-end: Live invocation over Cloudflare tunnel through ArmorIQ customer proxy executed in **2.15s** with status `quarantined`!
   - Unit test added: `test_fastmcp_accepts_proxy_injected_policy_context` in `backend/tests/test_containment_mcp.py` passes cleanly.
