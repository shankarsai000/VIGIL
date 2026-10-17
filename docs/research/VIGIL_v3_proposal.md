# VIGIL — Real-Time Behavioral Immune System for Enterprise Multi-Agent Workflows
*(Extracted text from uploaded proposal PDF: `docs/research/VIGIL_v3_proposal.pdf`)*

Transforming VIGIL from a reactive anomaly monitor into a category-defining Autonomous AI Runtime Immune System requires solving the exact operational bottlenecks that currently block enterprises from deploying multi-agent pipelines in production.

While VIGIL v2 effectively catches single-turn volumetric and heuristic spikes (Prompt Injection, Privilege Escalation, 500KB Exfiltration) and enforces binary QUARANTINE, real-world production pipelines fail in subtler ways: indirect cross-agent poisoning, "low-and-slow" chunked exfiltration, tool/MCP server rug-pulls, and self-inflicted downtime from whole-agent quarantines.

---

## 6 Core Product Innovations (Problem → Architecture → Impact)

### 1. Cross-Agent "Confused Deputy" Attacks
- **Real-World Production Problem**: Agent A reads an untrusted email, summarizes it, and asks trusted Agent B to run a privileged tool. Isolated inspection of Agent B sees a clean internal request.
- **New VIGIL Feature**: Cryptographic Taint Tracking & Lineage-Aware Policy Gate (DIFC).
- **How It Works in VIGIL's Stack**: Stamp every telemetry event with a `taint_level` (`UNTRUSTED_EXT`, `USER_INPUT`, `INTERNAL_VERIFIED`) and `lineage_trace_id`. Propagate taint across agent delegations so ArmorIQ blocks high-privilege tools whenever upstream lineage is tainted—even if the final prompt looks benign.

### 2. Binary Quarantine Kills Uptime
- **Real-World Production Problem**: Quarantining an entire agent like CustomerBot on one attack or false positive takes down the service for all legitimate users—creating a self-inflicted DoS.
- **New VIGIL Feature**: Surgical Capability Downgrading & Shadow Honeypot Routing ("Mirage Mode").
- **How It Works in VIGIL's Stack**: Replace binary QUARANTINE with graduated containment:
  - (a) **Session-Scoped Tool Stripping**: Revoke write/admin tools for the offending trace while keeping the agent live.
  - (b) **Shadow Sandbox Routing**: Silently swap real SQLite/API connections to a synthetic honey-twin so the attacker thinks they succeeded while VIGIL records their full kill chain.

### 3. "Low-and-Slow" Salami Exfiltration
- **Real-World Production Problem**: Attackers bypass EWMA and Isolation Forest by extracting 2KB across 250 turns instead of a single 500KB spike, or splitting requests across multiple sub-agents.
- **New VIGIL Feature**: Cumulative Entropy Ledgers & Canary Tripwires.
- **How It Works in VIGIL's Stack**: Maintain a sliding-window Exfiltration Budget Ledger per principal/trace tracking cumulative bytes, Shannon entropy, and sensitive record counts across turns. Inject invisible cryptographic Canary Tokens (synthetic honey-rows) into database responses; if any agent emits a canary hash, trigger an instant 100% deterministic containment.

### 4. MCP & Tool Output Poisoning
- **Real-World Production Problem**: Agents dynamically call external MCP tools that return hidden prompt injections inside JSON responses, or silently mutate their tool schemas after registration.
- **New VIGIL Feature**: Bidirectional MCP Firewall & Schema Hash Pinning.
- **How It Works in VIGIL's Stack**: Pin SHA-256 hashes of all registered tool schemas inside VIGIL's hash-chained SQLite store to block mid-runtime "rug-pulls." Scan tool return payloads (ingress from tools) before they enter the agent's context window, neutralizing indirect prompt injections before the LLM processes them.

### 5. Static Detection Rules Decay Fast
- **Real-World Production Problem**: In v2, Claude explains the incident to humans, but Layer 1 heuristics stay static until an engineer manually writes a new rule.
- **New VIGIL Feature**: Closed-Loop "Adaptive Immunity" (Auto-Antibody Synthesis).
- **How It Works in VIGIL's Stack**: Upgrade the Claude AI Incident Explainer into an Active Antibody Generator. When Layer 3 (Isolation Forest) catches a zero-day behavioral anomaly, Claude synthesizes a deterministic Layer 1 heuristic/ArmorIQ rule, automatically backtests it against `/backend/storage/` replay logs to verify 0% false-positive regression, and stages it for 1-click deployment.

### 6. Lingering Blast Radius Before Containment
- **Real-World Production Problem**: If an agent executes two tool calls and gets quarantined on the third, the first two side effects remain active.
- **New VIGIL Feature**: Transactional Intent Checkpoints & Compensating Rollbacks.
- **How It Works in VIGIL's Stack**: Register a compensating rollback hook (`undo_action`) alongside every state-mutating request at `POST /intent/verify`. When a trace is quarantined, the Remediation Executor walks backward through the hash-chained audit trail to revoke tokens, revert staging writes, and visualize the exact Blast Radius DAG in React.

---

## Upgraded System Architecture (VIGIL v3 Immune Loop)

```text
[External Inputs / MCP Tool Outputs]
       │
       ▼
┌──────────────────────────────────────────────┐
│ Bidirectional Interceptor & Taint Stamper    │
│ (Assigns Provenance Tag + Canary Tripwires)  │
└──────────────────────┬───────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
[Cumulative Ledger] [3-Layer Hybrid]  [Lineage DAG]
(Entropy, Canary,   ├── L1: Antibodies (Cross-Agent Taint
Low-and-Slow Budget)├── L2: EWMA Baselines  Propagation &
                    └── L3: Iso Forest Loop Collusion)
       └───────────────┬───────────────┘
                       │
                       ▼
    [Aggregated Risk & Provenance Vector]
                       │
                       ▼
        [ArmorIQ Policy & Lineage Gate]
       (POST /intent/verify + Taint Rule)
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
[SURGICAL DOWNGRADE] [MIRAGE HONEYPOT] [QUARANTINE + ROLLBACK]
(Strip Write Tools)  (Synthetic DB Twin) (Freeze + Compensating Undo)
       └───────────────┬───────────────┘
                       │
                       ▼
     [Claude AI Explainer + Antibody Synthesizer]
     ├── Plain-English Narrative for Operators
     └── Auto-Backtested Rule Patch (Replay Verified)
```

---

## Concrete Implementation Blueprints from Proposal

### 1. Cross-Agent Taint Propagation & Lineage Gate (`/backend/services/taint_tracker.py`)
```python
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Dict, List, Set

class TaintLevel(IntEnum):
    SYSTEM_TRUSTED = 0        # Internal system prompts & signed configs
    VERIFIED_INTERNAL = 1     # Clean internal agent state
    USER_UNTRUSTED = 2        # Direct external user input
    EXTERNAL_POISON_RISK = 3  # Unverified MCP output, web scrape, external email

@dataclass
class TraceLineage:
    trace_id: str
    current_taint: TaintLevel = TaintLevel.SYSTEM_TRUSTED
    agent_hops: List[str] = field(default_factory=list)
    taint_sources: Set[str] = field(default_factory=set)

class ProvenanceEngine:
    def __init__(self):
        self._traces: Dict[str, TraceLineage] = {}
        self.restricted_sinks = {
            "billing_database": TaintLevel.VERIFIED_INTERNAL,
            "export_financial_records": TaintLevel.SYSTEM_TRUSTED,
            "iam_role_grant": TaintLevel.SYSTEM_TRUSTED,
        }

    def propagate_delegation(
        self, trace_id: str, from_agent: str, to_agent: str, payload_taint: TaintLevel, source_label: str
    ) -> TraceLineage:
        lineage = self._traces.get(trace_id, TraceLineage(trace_id=trace_id))
        if payload_taint >= lineage.current_taint:
            lineage.current_taint = payload_taint
            lineage.taint_sources.add(source_label)
        lineage.agent_hops.append(f"{from_agent}->{to_agent}")
        self._traces[trace_id] = lineage
        return lineage

    def evaluate_sink_policy(self, trace_id: str, tool_name: str) -> dict:
        lineage = self._traces.get(trace_id)
        if not lineage:
            return {"allowed": False, "reason": "Missing cryptographic lineage trace (Fail-Closed)"}
        if len(lineage.agent_hops) > 6:
            return {"allowed": False, "reason": f"Delegation depth exceeded ({len(lineage.agent_hops)} hops)"}
        max_allowed_taint = self.restricted_sinks.get(tool_name, TaintLevel.EXTERNAL_POISON_RISK)
        if lineage.current_taint > max_allowed_taint:
            return {
                "allowed": False,
                "reason": (
                    f"DIFC Taint Violation: Tool '{tool_name}' requires taint <= {max_allowed_taint.name}, "
                    f"but trace carries {lineage.current_taint.name} from {list(lineage.taint_sources)}"
                ),
            }
        return {"allowed": True, "taint_level": lineage.current_taint.name}
```

### 2. Graduated Containment: Surgical Tool Stripping & Mirage Honeypot (`/backend/services/remediation.py`)
```python
from enum import Enum

class ContainmentAction(str, Enum):
    LOG_ONLY = "LOG_ONLY"                     # Score < 40%: Audit only
    SURGICAL_DOWNGRADE = "DOWNGRADE_SCOPE"     # Score 40-74%: Strip write/admin tools for session
    MIRAGE_HONEYPOT = "SHADOW_SANDBOX"         # Score 75-89%: Route attacker to synthetic DB twin
    FULL_QUARANTINE = "QUARANTINE_ROLLBACK"    # Score >= 90% or Canary: Freeze + run rollback hooks

def select_adaptive_remediation(threat_score: float, canary_triggered: bool, is_critical_agent: bool) -> dict:
    if canary_triggered or threat_score >= 0.92:
        return {
            "mode": ContainmentAction.FULL_QUARANTINE,
            "execute_compensating_rollbacks": True,
            "summary": "Deterministic breach or critical severity: quarantining agent and rolling back session side-effects."
        }
    if 0.75 <= threat_score < 0.92:
        return {
            "mode": ContainmentAction.MIRAGE_HONEYPOT,
            "target_datasource": "sqlite+aiosqlite:///./backend/storage/honeypot_mirage.db",
            "summary": "High-confidence attack redirected to Mirage Honeypot to capture attacker objectives without downtime."
        }
    if 0.45 <= threat_score < 0.75 or is_critical_agent:
        return {
            "mode": ContainmentAction.SURGICAL_DOWNGRADE,
            "revoked_capabilities": ["db_write", "external_http_post", "agent_delegate"],
            "retained_capabilities": ["faq_search", "read_public_docs"],
            "summary": "Elevated risk: stripped state-mutating capabilities for session while keeping agent online."
        }
    return {"mode": ContainmentAction.LOG_ONLY, "summary": "Within normal behavioral envelope."}
```

### 3. Closed-Loop "Auto-Vaccination" Engine (`/backend/services/antibody_synthesizer.py`)
1. Capture: Incident triggers via Isolation Forest or Canary.
2. Synthesize: Claude generates structured JSON Candidate Antibody.
3. Replay Backtest: VIGIL runs candidate rule against last 500 normal telemetry events to compute FPR.
4. Hot-Reload: If FPR == 0.0% and detection recall on attack payload is 100%, dashboard displays `"⚡ Deploy Verified Antibody (0% FPR)"` button.

### 4. Demo Scenarios & UI Upgrades
- **Scenario 5 (Indirect Cross-Agent Taint Attack / Confused Deputy)**: CustomerBot reads support ticket with hidden instructions, forwards summary to AnalyticsAgent, which asks BillingAgent to export records. Shows 22% heuristic score on BillingAgent but blocked by Lineage Provenance.
- **Scenario 6 (Low-and-Slow Exfiltration + Mirage Honeypot)**: AnalyticsAgent extracts records in 1.8KB chunks, hits Canary Record on chunk #4. Triggers Mirage Mode synthetic DB switch. Shows 3-second badge and 0.0% false positives.
- **Frontend Dashboard Upgrades**:
  - Live Agent Topology & Taint Graph (CustomerBot ⇄ AnalyticsAgent ⇄ BillingAgent).
  - Containment Spectrum Pill (NORMAL, SCOPED DOWNGRADE, MIRAGE HONEYPOT, QUARANTINED + ROLLED BACK).
  - One-click "Immunize Fleet" Action in Threat Overlay.
  - Interactive Architecture Explorer.
