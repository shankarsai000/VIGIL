import { 
  Agent, 
  AuditEntry, 
  Incident, 
  WSEvent, 
  TelegramStatus, 
  TelegramUser, 
  ApprovalRequest,
  ThreatIntelligenceData,
  ModelIntegrityBaseline,
  ModelIntegrityEvent,
  CapabilityProfile,
  CapabilityViolation,
  SupplyChainDependency,
  SupplyChainEvent,
  AttackGraphNode,
  AttackGraphEdge,
  RemediationChain,
  BehavioralFootprintScore,
  RemediationScript,
  TamperProofIncident,
  PolicyProposal
} from './types';

// Operator key for write endpoints and the WebSocket.
// Automatically reads from window.__VIGIL_OPERATOR_KEY__ (injected dynamically by backend at runtime),
// browser localStorage, or build-time environment variable, with sensible default fallback.
export function getOperatorKey(): string {
  if (typeof window !== 'undefined' && (window as any).__VIGIL_OPERATOR_KEY__) {
    return (window as any).__VIGIL_OPERATOR_KEY__;
  }
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('vigil_operator_key');
    if (stored) return stored;
  }
  return (import.meta as any).env?.VITE_VIGIL_OPERATOR_KEY || 'vigil_op_key_2026';
}

function operatorHeaders(): Record<string, string> {
  return { 'X-VIGIL-Operator-Key': getOperatorKey() };
}

type EventHandler = (event: WSEvent) => void;

const MAX_RECONNECT_ATTEMPTS = 5;
const BASE_RECONNECT_DELAY = 1000; // ms

export class VIGILClient {
  private ws: WebSocket | null = null;
  private eventHandlers: EventHandler[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  private countdownTimer: number | null = null;
  private _connectionStatus: 'connected' | 'reconnecting' | 'offline' = 'offline';
  private _reconnectCountdown = 0;
  private _lastWsEventTime = 0;
  private _lastWsErrorTime = 0;

  private _onConnectionChange: ((connected: boolean) => void) | null = null;
  private _onStateChange: ((status: 'connected' | 'reconnecting' | 'offline', countdown?: number) => void) | null = null;
  private _onWsEvent: (() => void) | null = null;
  private _onWsError: (() => void) | null = null;
  private _onWriteError: ((banner: string) => void) | null = null;

  get connected(): boolean {
    return this._connectionStatus === 'connected' && this._lastWsEventTime > this._lastWsErrorTime;
  }

  get connectionStatus(): 'connected' | 'reconnecting' | 'offline' {
    return this._connectionStatus;
  }

  get reconnectCountdown(): number {
    return this._reconnectCountdown;
  }

  set onConnectionChange(handler: (connected: boolean) => void) {
    this._onConnectionChange = handler;
  }

  set onStateChange(handler: (status: 'connected' | 'reconnecting' | 'offline', countdown?: number) => void) {
    this._onStateChange = handler;
  }

  set onWsEvent(handler: () => void) {
    this._onWsEvent = handler;
  }

  set onWsError(handler: () => void) {
    this._onWsError = handler;
  }

  set onWriteError(handler: (banner: string) => void) {
    this._onWriteError = handler;
  }

  private _notifyState(): void {
    const isConn = this._connectionStatus === 'connected' && this._lastWsEventTime > this._lastWsErrorTime;
    this._onConnectionChange?.(isConn);
    this._onStateChange?.(this._connectionStatus, this._reconnectCountdown);
  }

  private _handleWriteResponse(res: Response, operationName: string): void {
    if (!res.ok) {
      if (res.status === 401) {
        this._onWriteError?.(
          `Write rejected (401 Unauthorized) for ${operationName}: Missing or mismatched OPERATOR_API_KEY / VITE_VIGIL_OPERATOR_KEY setting. Verify environment configuration.`
        );
      } else if (res.status === 503) {
        this._onWriteError?.(
          `Write unavailable (503 Service Unavailable) for ${operationName}: ArmorIQ policy enforcement gateway unreachable. Check ARMORIQ_API_KEY setting.`
        );
      } else {
        this._onWriteError?.(
          `Write failed (${res.status} ${res.statusText}) for ${operationName}.`
        );
      }
    }
  }

  connect(): void {
    // Construct WebSocket URL using browser window location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const key = getOperatorKey();
    const wsUrl = `${protocol}//${window.location.host}/ws?key=${encodeURIComponent(key)}`;
    
    try {
      logger(`Connecting to WebSocket: ${protocol}//${window.location.host}/ws`);
      this.ws = new WebSocket(wsUrl);
      
      this.ws.onopen = () => {
        console.log('[VIGIL] WebSocket connected');
        this.reconnectAttempts = 0;
        this._connectionStatus = 'connected';
        this._lastWsEventTime = Date.now();
        this._notifyState();
      };

      this.ws.onmessage = (event) => {
        this._lastWsEventTime = Date.now();
        this._onWsEvent?.();
        this._notifyState();
        try {
          const data = JSON.parse(event.data) as WSEvent;
          this.eventHandlers.forEach((handler) => handler(data));
        } catch (err) {
          console.warn('[VIGIL] Failed to parse WS message:', err);
        }
      };

      this.ws.onclose = (event) => {
        console.log('[VIGIL] WebSocket disconnected (code:', event.code, ')');
        this._lastWsErrorTime = Date.now();
        this._onWsError?.();
        this._connectionStatus = 'offline';
        this._notifyState();
        this._scheduleReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[VIGIL] WebSocket error:', error);
        this._lastWsErrorTime = Date.now();
        this._onWsError?.();
        this._notifyState();
      };
    } catch (err) {
      console.error('[VIGIL] Failed to create WebSocket:', err);
      this._lastWsErrorTime = Date.now();
      this._onWsError?.();
      this._scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.countdownTimer !== null) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onclose = null; // prevent auto-reconnect
      this.ws.close();
      this.ws = null;
    }
    this._connectionStatus = 'offline';
    this._notifyState();
  }

  onEvent(handler: EventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter((h) => h !== handler);
    };
  }

  private _scheduleReconnect(): void {
    if (this.countdownTimer !== null) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      console.error('[VIGIL] Max reconnect attempts reached');
      this._connectionStatus = 'offline';
      this._notifyState();
      return;
    }

    this._connectionStatus = 'reconnecting';
    const delay = BASE_RECONNECT_DELAY * Math.pow(2, this.reconnectAttempts);
    this._reconnectCountdown = Math.ceil(delay / 1000);
    this._notifyState();

    this.countdownTimer = window.setInterval(() => {
      this._reconnectCountdown = Math.max(0, this._reconnectCountdown - 1);
      this._notifyState();
    }, 1000);

    this.reconnectTimer = window.setTimeout(() => {
      if (this.countdownTimer !== null) {
        clearInterval(this.countdownTimer);
        this.countdownTimer = null;
      }
      this.reconnectAttempts++;
      this.connect();
    }, delay);
  }

  // REST API Methods
  async getAgents(): Promise<Agent[]> {
    const res = await fetch('/agents');
    if (!res.ok) throw new Error(`Failed to fetch agents: ${res.statusText}`);
    return res.json();
  }

  async getIncidents(): Promise<Incident[]> {
    const res = await fetch('/incidents');
    if (!res.ok) throw new Error(`Failed to fetch incidents: ${res.statusText}`);
    return res.json();
  }

  async getAuditLog(): Promise<AuditEntry[]> {
    const res = await fetch('/audit');
    if (!res.ok) throw new Error(`Failed to fetch audit log: ${res.statusText}`);
    return res.json();
  }

  async verifyAuditLedger(): Promise<{ ok: boolean; entries: number; last_hash: string | null; bad_seq: number | null; reason: string | null }> {
    const res = await fetch('/audit/verify');
    if (!res.ok) throw new Error(`Failed to verify audit ledger: ${res.statusText}`);
    return res.json();
  }

  async fireAttack(attackType: string): Promise<{ status: string; attack_type: string }> {
    const res = await fetch(`/attack/${attackType}`, { method: 'POST', headers: operatorHeaders() });
    this._handleWriteResponse(res, `fire attack "${attackType}"`);
    if (!res.ok) throw new Error(`Failed to fire attack: ${res.statusText}`);
    return res.json();
  }

  // Telegram Governed Runtime API Methods
  async getTelegramStatus(): Promise<TelegramStatus> {
    const res = await fetch('/telegram/status');
    if (!res.ok) throw new Error(`Failed to fetch Telegram status: ${res.statusText}`);
    return res.json();
  }

  // Generic Approval Channel API Methods
  async getApprovals(): Promise<ApprovalRequest[]> {
    const res = await fetch('/approvals');
    if (!res.ok) throw new Error(`Failed to fetch approvals: ${res.statusText}`);
    return res.json();
  }

  async getAllApprovals(limit: number = 20): Promise<ApprovalRequest[]> {
    const res = await fetch(`/approvals/all?limit=${limit}`);
    if (!res.ok) throw new Error(`Failed to fetch all approvals: ${res.statusText}`);
    return res.json();
  }

  async getTelegramApprovals(): Promise<ApprovalRequest[]> {
    return this.getApprovals();
  }

  async getAllTelegramApprovals(limit: number = 20): Promise<ApprovalRequest[]> {
    return this.getAllApprovals(limit);
  }

  async getTelegramUsers(): Promise<TelegramUser[]> {
    const res = await fetch('/telegram/users');
    if (!res.ok) throw new Error(`Failed to fetch Telegram users: ${res.statusText}`);
    return res.json();
  }

  async resolveApproval(requestId: string, action: 'approve' | 'deny'): Promise<{ status: string; resolved_to: string }> {
    const res = await fetch(`/approvals/${requestId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...operatorHeaders() },
      body: JSON.stringify({ action }),
    });
    this._handleWriteResponse(res, `resolve approval (${action})`);
    if (!res.ok) throw new Error(`Failed to resolve approval: ${res.statusText}`);
    return res.json();
  }

  async bulkResolveApprovals(requestIds: string[], action: 'approve' | 'deny'): Promise<{ status: string; action: string; results: any[] }> {
    const res = await fetch('/approvals/bulk-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...operatorHeaders() },
      body: JSON.stringify({ action, request_ids: requestIds }),
    });
    this._handleWriteResponse(res, `bulk resolve (${action})`);
    if (!res.ok) throw new Error(`Failed to bulk resolve approvals: ${res.statusText}`);
    return res.json();
  }

  // VIGIL 2.0 API Methods
  async getModelIntegrity(agentId: string): Promise<{ baseline: ModelIntegrityBaseline | null; events: ModelIntegrityEvent[] }> {
    const res = await fetch(`/api/v2/integrity/${agentId}`);
    if (!res.ok) throw new Error(`Failed to fetch model integrity: ${res.statusText}`);
    return res.json();
  }

  async getAttackGraph(incidentId: string): Promise<{ nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; trigger_agent: string | null; blast_radius: number; timestamp: number }> {
    const res = await fetch(`/api/v2/attack-graph/${incidentId}`);
    if (!res.ok) throw new Error(`Failed to fetch attack graph: ${res.statusText}`);
    return res.json();
  }

  async getCapabilities(agentId: string): Promise<{ profile: CapabilityProfile | null; violations: CapabilityViolation[] }> {
    const res = await fetch(`/api/v2/capabilities/${agentId}`);
    if (!res.ok) throw new Error(`Failed to fetch capabilities: ${res.statusText}`);
    return res.json();
  }

  async getSupplyChain(agentId: string): Promise<{ dependencies: SupplyChainDependency[]; events: SupplyChainEvent[] }> {
    const res = await fetch(`/api/v2/supply-chain/${agentId}`);
    if (!res.ok) throw new Error(`Failed to fetch supply chain: ${res.statusText}`);
    return res.json();
  }

  async getEvidence(incidentId: string): Promise<TamperProofIncident | null> {
    const res = await fetch(`/api/v2/evidence/${incidentId}`);
    if (!res.ok) throw new Error(`Failed to fetch evidence chain: ${res.statusText}`);
    return res.json();
  }

  async getRemediationChain(incidentId: string): Promise<RemediationChain | null> {
    const res = await fetch(`/api/v2/remediation-chains/${incidentId}`);
    if (!res.ok) throw new Error(`Failed to fetch remediation chain: ${res.statusText}`);
    return res.json();
  }

  async getSpoofing(agentId: string): Promise<BehavioralFootprintScore | null> {
    const res = await fetch(`/api/v2/spoofing/${agentId}`);
    if (!res.ok) throw new Error(`Failed to fetch spoofing score: ${res.statusText}`);
    return res.json();
  }

  async getRemediationScript(incidentId: string): Promise<RemediationScript | null> {
    const res = await fetch(`/api/v2/remediation-scripts/${incidentId}`);
    if (!res.ok) throw new Error(`Failed to fetch remediation script: ${res.statusText}`);
    return res.json();
  }

  async getThreatIntelligence(): Promise<ThreatIntelligenceData> {
    const res = await fetch('/api/v2/threat-intelligence');
    if (!res.ok) throw new Error(`Failed to fetch threat intelligence: ${res.statusText}`);
    return res.json();
  }

  async releaseAgent(agentId: string, reason: string): Promise<{ status: string; agent_id: string; reason: string }> {
    const res = await fetch(`/agents/${agentId}/release`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...operatorHeaders(),
      },
      body: JSON.stringify({ reason }),
    });
    this._handleWriteResponse(res, `release agent ${agentId}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Failed to release agent: ${res.statusText}`);
    }
    return res.json();
  }

  async getHealth(): Promise<{
    status: string;
    gate_mode?: string;
    armoriq_mode?: string;
    active_agents?: number;
    approval_channel?: {
      channel: string;
      status: string;
      mode: string;
      configured: boolean;
    };
  }> {
    const res = await fetch('/health');
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return res.json();
  }

  async getPolicyProposals(): Promise<PolicyProposal[]> {
    const res = await fetch('/policies/proposals');
    if (!res.ok) throw new Error(`Failed to fetch policy proposals: ${res.statusText}`);
    return res.json();
  }

  async getPolicyProposal(id: string): Promise<PolicyProposal> {
    const res = await fetch(`/policies/proposals/${id}`);
    if (!res.ok) throw new Error(`Failed to fetch policy proposal ${id}: ${res.statusText}`);
    return res.json();
  }

  async createPolicyProposal(data: {
    agent_id: string;
    tool: string;
    window_start: number;
    window_end: number;
  }): Promise<PolicyProposal> {
    const res = await fetch('/policies/proposals', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...operatorHeaders(),
      },
      body: JSON.stringify(data),
    });
    this._handleWriteResponse(res, `create policy proposal for ${data.agent_id}/${data.tool}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Failed to create policy proposal: ${res.statusText}`);
    }
    return res.json();
  }

  async approvePolicyProposal(id: string, approver: string): Promise<PolicyProposal> {
    const res = await fetch(`/policies/proposals/${id}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-VIGIL-Approver': approver,
        ...operatorHeaders(),
      },
    });
    this._handleWriteResponse(res, `approve policy proposal ${id}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Failed to approve policy proposal: ${res.statusText}`);
    }
    return res.json();
  }

  async rejectPolicyProposal(id: string, approver: string, reason?: string): Promise<PolicyProposal> {
    const res = await fetch(`/policies/proposals/${id}/reject`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-VIGIL-Approver': approver,
        ...operatorHeaders(),
      },
      body: JSON.stringify({ reason: reason || 'Rejected by operator' }),
    });
    this._handleWriteResponse(res, `reject policy proposal ${id}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Failed to reject policy proposal: ${res.statusText}`);
    }
    return res.json();
  }

  async getDenialExplanation(traceId: string): Promise<any> {
    const res = await fetch(`/denials/${traceId}`);
    if (!res.ok) throw new Error(`Failed to fetch denial explanation for ${traceId}: ${res.statusText}`);
    return res.json();
  }
}

function logger(msg: string) {
  console.log(`[VIGIL API] ${msg}`);
}

// Singleton client instance
export const vigilClient = new VIGILClient();
