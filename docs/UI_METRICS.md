# VIGIL UI Metrics & Telemetry Derivation Standards

This document establishes the authoritative definitions, mathematical formulations, and data sources for every operational and executive metric displayed across the VIGIL v2 dashboard. 

No metric displayed in VIGIL is hardcoded or estimated. Every number maps directly to live cryptographic ledger states, PostgreSQL agent registries, or active runtime telemetry events.

---

## 1. Executive Portal Metrics (`ExecutiveView.tsx`)

### Operational Agents
- **Definition**: The count and percentage of registered agents currently operating under normal operational conditions.
- **Formula**: 
  $$\text{Operational Share} = \frac{\text{Active Agents}}{\text{Total Registered Agents}} \times 100$$
  where $\text{Active Agents} = \text{Total Agents} - \text{Quarantined Agents}$.
- **Denominator**: Total agents registered in `AgentRegistry`.
- **Tooltip**: *"Number of registered agents currently operating in NORMAL status vs total agents."*
- **Source**: `useVigilStore().agents` (synced via WebSocket `AGENT_UPDATE` & `/health`).

### Quarantine Isolations
- **Definition**: The exact number of agent pipelines actively confined in `QUARANTINED` status.
- **Invariant**: Quarantined agents can **only** be released by explicit human operator action with a mandatory reason (`POST /agents/{agent_id}/release`). Background simulation routines never restore gate-enforced or operator-enforced quarantines.
- **Tooltip**: *"Number of agents currently isolated under QUARANTINED status (released only by human operator)."*
- **Source**: `agents.values().filter(a => a.status === 'QUARANTINED').length`.

### Threats Contained
- **Definition**: The proportion of security incidents that directly resulted in active containment isolation (`QUARANTINED`). Replaces previously hardcoded figures with true derived counts.
- **Formula**:
  $$\text{Containment Rate} = \frac{\text{Incidents with Quarantine Outcome}}{\text{Total Logged Incidents}} \times 100$$
- **Denominator**: Total security incidents logged in `incidents` list.
- **Tooltip**: *"Security incidents whose containment outcome is QUARANTINED, divided by total recorded incidents."*
- **Source**: `incidents.filter(i => i.action_taken === 'QUARANTINE' || i.containment_outcome === 'QUARANTINED').length`.

### Compliance Rate
- **Definition**: The ratio of policy governance decisions approved and successfully executed relative to all decisions rendered by the governance gate.
- **Formula**:
  $$\text{Compliance Rate} = \frac{\text{Approved Decisions Executed}}{\text{Total Evaluated Decisions}} \times 100$$
- **Denominator**: Total decisions evaluated (`totalDecisions`), clearly presented alongside the rate.
- **Tooltip**: *"Compliance rate = APPROVED governance decisions that were executed, divided by all decisions, showing the full denominator."*
- **Source**: Derived from resolved `ApprovalRequest` statuses and executed remediation actions.

### Threat Profile Breakdown
- **Definition**: Dynamic distribution of detected threat vectors across the active incident stream.
- **Formula**: 
  $$\text{Threat Share}_k = \frac{\text{Count}(\text{ThreatType}_k)}{\sum_j \text{Count}(\text{ThreatType}_j)} \times 100$$
- **Denominator**: Total recorded incidents.
- **Source**: Computed dynamically from `incidents.map(i => i.threat_type)`. Replaces static fixed-width progress bars.

### Cryptographic Audit Ledger Status
- **Definition**: Cryptographic integrity verification of the append-only SHA-256 hash-chained audit ledger.
- **API Endpoint**: `GET /audit/verify`
- **Output**: 
  - `ok`: boolean (true if all previous-hash links and block digests match)
  - `entries`: total number of verified blocks in chain
  - `bad_seq`: first corrupted sequence number if chain is broken
  - `last_hash`: 64-character SHA-256 digest of the chain head
- **Tooltip**: *"Cryptographic verification status of the hash-chained audit ledger (/audit/verify)"*

---

## 2. Global Header & Command Bar (`CommandBar.tsx`)

### Enforcement Mode Badge
- **Definition**: Live enforcement authority reported by the ArmorIQ gate in `GET /health`.
- **Modes**:
  1. `ARMORIQ ENFORCED` (Teal badge): Backend running in live mode with valid ArmorIQ SDK policy evaluation (`armoriq-live`).
  2. `NOT ENFORCED BY ARMORIQ` (Amber badge): Backend running in local demonstration mode (`local-demo`). Local behavioral thresholds apply; ArmorIQ cloud enforcement is not active.
  3. `CONTAINMENT DISABLED` (Grey badge): Automated containment is completely deactivated (`disabled`).
- **Source**: Additive fields `gate_mode` and `armoriq_mode` from `GET /health`.

### Isolated Agents Counter
- **Definition**: Real-time counter of agents currently isolated in `QUARANTINED` state.
- **Source**: `agents.values().filter(a => a.status === 'QUARANTINED').length`.

### Contained Threats Counter
- **Definition**: Real-time counter of security threats that were contained via quarantine. Labelled honestly as `CONTAINED` (replaces previous deceptive `PREVENTED` label).
- **Source**: `incidents.filter(i => i.action_taken === 'QUARANTINE' || i.containment_outcome === 'QUARANTINED').length`.

### Connection State Indicator
- **Connected** (Pulsing Teal): Active WebSocket connection streaming events with timestamp fresher than last error.
- **Disconnected / Reconnecting** (Red / Amber): WebSocket disconnected, attempting backoff reconnection.

---

## 3. Incident Intelligence Stream (`ThreatConsole.tsx` & `IncidentPanel.tsx`)

### Multi-Engine Concurrency Arcs
- **Rule Engine Score**: Deterministic pattern matching confidence (60% baseline weight).
- **EWMA Behavior Score**: Exponentially weighted moving average call-rate anomaly confidence (25% weight).
- **Isolation Forest Score**: Unsupervised machine learning outlier isolation confidence (15% weight).
- **Integrated Threat Score**: Weighted ensemble confidence metric:
  $$\text{Score} = 0.60 \times S_{\text{rule}} + 0.25 \times S_{\text{ewma}} + 0.15 \times S_{\text{iforest}}$$

### Decision vs. Containment Separation
Every incident card distinctly decouples policy decision from actual containment outcome:
- **Policy Decision**: `APPROVED` | `DENIED` | `ESCALATE`
- **Containment Outcome**: `QUARANTINED` | `NOT CONTAINED (Reason)` | `PENDING APPROVAL` | `NO ACTION`
- **Enforcement Authority**: `armoriq-live` | `local-demo (NOT ArmorIQ)` | `disabled`
