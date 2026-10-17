# Finding: Containment MCP Authentication Discrepancy (Fix 10)

## Date: 2026-10-17
## Phase: DOC-FIX-1
## Target Component: `backend/app/policies/containment_mcp.py` vs `CLAUDE.md` / `docs/ARCHITECTURE.md`

---

### 1. Discrepancy Overview
- **Claimed in Documentation**:
  - `CLAUDE.md` (§3 Mermaid diagram line 87): `CONTAINMENT_MCP["vigil-containment FastMCP (:8790)<br/>(Bearer Token Auth)"]`
  - `docs/ARCHITECTURE.md` (lines 65, 97, 143): `FastMCP -->|Bearer CONTAINMENT_SECRET| InternalAPI`, `Requires CONTAINMENT_SECRET bearer token authentication... (Auth: Bearer)`.
- **Actual Implementation in Code (`backend/app/policies/containment_mcp.py`)**:
  - The FastMCP server exposes standard tool endpoints (`quarantine_agent`, `downgrade_session`, `route_to_shadow`, `rollback_session`) without an inbound Bearer authentication check on the MCP protocol listener (`http://127.0.0.1:8790`).
  - Downstream communication from the FastMCP server to VIGIL Core (`POST /internal/containment/...`) is authenticated via an HTTP header:
    ```python
    headers = {"X-Containment-Secret": CONTAINMENT_SECRET}
    ```
  - No `Authorization: Bearer <TOKEN>` header is evaluated or checked.

---

### 2. Security & Architecture Analysis
1. **Inbound FastMCP Layer**:
   - The FastMCP tool listener on port 8790 binds to `127.0.0.1`. In production deployments, ingress to this port must either be restricted via network policy / reverse proxy or upgraded to support FastMCP authorization middleware if exposed across networks.
2. **Outbound VIGIL Core Ingress**:
   - VIGIL Core verifies the incoming secret header `X-Containment-Secret` matching the environment's `CONTAINMENT_SECRET`. This prevents unauthorized external requests from calling `/internal/containment/*` without knowledge of the secret.
   - However, calling this "Bearer Token Auth" in architecture documentation is technically inaccurate and misleading to operators auditing cryptographic boundaries.

---

### 3. Corrective Action Taken
1. **Corrected `CLAUDE.md`**:
   - Updated the architecture Mermaid diagram from `(Bearer Token Auth)` to `(Shared Secret: X-Containment-Secret)`.
   - Updated Rule B description to accurately specify `X-Containment-Secret` inter-process authentication.
2. **Logged Finding**:
   - Documented this finding in `evidence/DOC-FIX-1/containment_auth_finding.md` and included in `evidence/DOC-FIX-1/report.md`.
