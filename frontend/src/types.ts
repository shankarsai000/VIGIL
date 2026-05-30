// Agent status enum
export enum AgentStatus {
  NORMAL = 'NORMAL',
  QUARANTINED = 'QUARANTINED',
  ALERT = 'ALERT',
  REVOKED = 'REVOKED',
  WATCHLIST = 'WATCHLIST',
  ANOMALOUS = 'ANOMALOUS',
}

// Threat type enum
export enum ThreatType {
  NONE = 'NONE',
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION',
  UNAUTHORIZED_DELEGATION = 'UNAUTHORIZED_DELEGATION',
  DATA_EXFILTRATION = 'DATA_EXFILTRATION',
  RATE_ANOMALY = 'RATE_ANOMALY',
  VOLUME_ANOMALY = 'VOLUME_ANOMALY',
  MODEL_POISONING = 'MODEL_POISONING',
  PROMPT_MUTATION = 'PROMPT_MUTATION',
  CAPABILITY_VIOLATION = 'CAPABILITY_VIOLATION',
  SUPPLY_CHAIN_COMPROMISE = 'SUPPLY_CHAIN_COMPROMISE',
  BEHAVIORAL_SPOOFING = 'BEHAVIORAL_SPOOFING',
  ATTACK_PROPAGATION = 'ATTACK_PROPAGATION',
}

// Confidence levels
export enum Confidence {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

// Policy decision
export enum PolicyDecision {
  APPROVED = 'APPROVED',
  DENIED = 'DENIED',
  ESCALATE = 'ESCALATE',
}

// Incident state enum
export enum IncidentState {
  NEW = 'NEW',
  WATCHLIST = 'WATCHLIST',
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  UNDER_INVESTIGATION = 'UNDER_INVESTIGATION',
  QUARANTINED = 'QUARANTINED',
  MONITORING = 'MONITORING',
  RESOLVED = 'RESOLVED',
  RECOVERED = 'RECOVERED',
}

// WebSocket event types
export enum WSEventType {
  AGENT_UPDATE = 'AGENT_UPDATE',
  INCIDENT_DETECTED = 'INCIDENT_DETECTED',
  POLICY_DECISION = 'POLICY_DECISION',
  REMEDIATION_EXECUTED = 'REMEDIATION_EXECUTED',
  EXPLANATION_READY = 'EXPLANATION_READY',
  AUDIT_LOG_ENTRY = 'AUDIT_LOG_ENTRY',
  TELEGRAM_STATUS = 'TELEGRAM_STATUS',
  MODEL_INTEGRITY_ALERT = 'MODEL_INTEGRITY_ALERT',
  CAPABILITY_VIOLATION_ALERT = 'CAPABILITY_VIOLATION_ALERT',
  SUPPLY_CHAIN_ALERT = 'SUPPLY_CHAIN_ALERT',
  ATTACK_GRAPH_UPDATE = 'ATTACK_GRAPH_UPDATE',
  REMEDIATION_CHAIN_UPDATE = 'REMEDIATION_CHAIN_UPDATE',
  EVIDENCE_CHAIN_UPDATE = 'EVIDENCE_CHAIN_UPDATE',
  GOVERNANCE_UPDATE = 'GOVERNANCE_UPDATE',
}

export interface TelegramStatus {
  connected: boolean;
  bot_username: string;
  active_sessions: number;
  pending_approvals_count: number;
  sleep_mode: boolean;
}

export interface TelegramUser {
  telegram_id: number;
  username: string;
  display_name: string;
  role: 'ADMIN' | 'SECURITY_ANALYST' | 'OBSERVER' | 'EXECUTIVE';
  is_active: boolean;
  registered_at: number;
  last_seen: number;
}

export interface ApprovalRequest {
  request_id: string;
  incident_id: string;
  agent_id: string;
  threat_type: ThreatType;
  threat_score: number;
  proposed_action: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'INVESTIGATING';
  requested_at: number;
  resolved_at: number | null;
  resolved_by: number | null;
  telegram_message_id: number | null;
  chat_id: number | null;
}

export interface Agent {
  agent_id: string;
  name: string;
  permitted_tools: string[];
  permitted_agents: string[];
  baseline_call_rate: number;
  status: AgentStatus;
  registered_at: string;
  armoriq_id: string | null;
  anomaly_score: number;  // latest score from detection
  event_count: number;
}

export interface DetectionResult {
  score: number;
  threat_type: ThreatType;
  confidence: Confidence;
  rule_score: number;
  ewma_score: number;
  iforest_score: number;
  details: Record<string, any>;
}

export interface AgentEvent {
  agent_id: string;
  event_type: string;
  target: string;
  payload: string;
  payload_size: number;
  timestamp: number;
}

export interface Incident {
  incident_id: string;
  agent_id: string;
  threat_type: ThreatType;
  detection_result: DetectionResult;
  policy_decision: PolicyDecision;
  action_taken: string;
  explanation: string;
  timestamp: number;
  event: AgentEvent;
  state: IncidentState;
}

export interface AuditEntry {
  entry_id: string;
  agent_id: string;
  decision: PolicyDecision;
  action: string;
  score: number;
  threat_type: ThreatType;
  timestamp: number;
  source: string;
}

export interface WSEvent {
  type: WSEventType;
  timestamp: number;
  agent_id: string;
  payload: Record<string, any>;
}

export interface AttackType {
  type: string;
  label: string;
  description: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'agent' | 'tool';
  status: AgentStatus | 'active' | 'inactive';
  score?: number;
  tools?: string[];
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'delegation' | 'tool_call';
  status: 'normal' | 'suspicious' | 'malicious' | 'active';
}

export interface ReplayEvent {
  step: number;
  timestamp: number;
  type: 'inject' | 'detect' | 'verify' | 'quarantine' | 'explain';
  label: string;
  description: string;
  incidentId?: string;
  agentId?: string;
}

export interface ExecutiveMetrics {
  totalThreatsPrevented: number;
  avgResponseTimeMs: number;
  activeAgentsCount: number;
  quarantinedCount: number;
  dataProtectedBytes: number;
  trustIndex: number;
  policyApprovalRate: number;
}

export interface ModelIntegrityBaseline {
  agent_id: string;
  model_name: string;
  model_hash: string;
  embedding_baseline: string;
  updated_at: number;
}

export interface ModelIntegrityEvent {
  event_id: string;
  agent_id: string;
  metric_name: string;
  baseline_value: string;
  current_value: string;
  drift_score: number;
  timestamp: number;
}

export interface CapabilityProfile {
  agent_id: string;
  allowed_tools: string[];
  allowed_destinations: string[];
  learned_at: number;
}

export interface CapabilityViolation {
  violation_id: string;
  agent_id: string;
  action_type: string;
  target: string;
  timestamp: number;
}

export interface SupplyChainDependency {
  dependency_id: string;
  agent_id: string;
  dependency_name: string;
  expected_version: string;
  expected_hash: string;
  certificate_subject: string | null;
  registered_at: number;
}

export interface SupplyChainEvent {
  event_id: string;
  agent_id: string;
  dependency_name: string;
  current_version: string;
  current_hash: string;
  issue_type: string;
  timestamp: number;
}

export interface PromptMutationRecord {
  record_id: string;
  agent_id: string;
  original_prompt: string;
  mutated_prompt: string;
  levenshtein_distance: number;
  similarity_score: number;
  is_anomaly: boolean;
  timestamp: number;
}

export interface AttackGraphNode {
  node_id: string;
  agent_id: string;
  compromise_likelihood: number;
  state: 'NORMAL' | 'SUSPECT' | 'COMPROMISED';
  updated_at: number;
}

export interface AttackGraphEdge {
  edge_id: string;
  source_agent_id: string;
  target_agent_id: string;
  propagation_probability: number;
  delegation_count: number;
  updated_at: number;
}

export interface RemediationScript {
  script_id: string;
  incident_id: string;
  script_type: string;
  code: string;
  generated_at: number;
}

export interface TamperProofIncident {
  incident_id: string;
  signature: string;
  public_key_pem: string;
  merkle_proof: string | null;
  signed_at: number;
}

export interface RemediationChainStep {
  step_index: number;
  name: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  details: string;
}

export interface RemediationChain {
  chain_id: string;
  incident_id: string;
  agent_id: string;
  steps_json: string;
  current_step: number;
  status: 'PLANNING' | 'EXECUTING' | 'COMPLETED' | 'FAILED';
  started_at: number;
  updated_at: number;
}

export interface BehavioralFootprintScore {
  agent_id: string;
  repetition_score: number;
  entropy_score: number;
  timing_regularity: number;
  tool_predictability: number;
  spoofing_likelihood: number;
  updated_at: number;
}

export interface ThreatIntelligenceData {
  integrity_baselines: ModelIntegrityBaseline[];
  integrity_events: ModelIntegrityEvent[];
  capability_profiles: CapabilityProfile[];
  capability_violations: CapabilityViolation[];
  supply_chain_dependencies: SupplyChainDependency[];
  supply_chain_events: SupplyChainEvent[];
  prompt_mutations: PromptMutationRecord[];
  spoofing_scores: BehavioralFootprintScore[];
  attack_graph: {
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };
}
