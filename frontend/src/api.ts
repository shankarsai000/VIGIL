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
  TamperProofIncident
} from './types';

type EventHandler = (event: WSEvent) => void;

const MAX_RECONNECT_ATTEMPTS = 5;
const BASE_RECONNECT_DELAY = 1000; // ms

export class VIGILClient {
  private ws: WebSocket | null = null;
  private eventHandlers: EventHandler[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  private _connected = false;
  private _onConnectionChange: ((connected: boolean) => void) | null = null;

  get connected(): boolean {
    return this._connected;
  }

  set onConnectionChange(handler: (connected: boolean) => void) {
    this._onConnectionChange = handler;
  }

  connect(): void {
    // Construct WebSocket URL using browser window location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
      logger(`Connecting to WebSocket: ${wsUrl}`);
      this.ws = new WebSocket(wsUrl);
      
      this.ws.onopen = () => {
        console.log('[VIGIL] WebSocket connected');
        this._connected = true;
        this.reconnectAttempts = 0;
        this._onConnectionChange?.(true);
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WSEvent;
          this.eventHandlers.forEach((handler) => handler(data));
        } catch (err) {
          console.warn('[VIGIL] Failed to parse WS message:', err);
        }
      };

      this.ws.onclose = () => {
        console.log('[VIGIL] WebSocket disconnected');
        this._connected = false;
        this._onConnectionChange?.(false);
        this._scheduleReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[VIGIL] WebSocket error:', error);
      };
    } catch (err) {
      console.error('[VIGIL] Failed to create WebSocket:', err);
      this._scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onclose = null; // prevent auto-reconnect
      this.ws.close();
      this.ws = null;
    }
    this._connected = false;
    this._onConnectionChange?.(false);
  }

  onEvent(handler: EventHandler): () => void {
    this.eventHandlers.push(handler);
    return () => {
      this.eventHandlers = this.eventHandlers.filter((h) => h !== handler);
    };
  }

  private _scheduleReconnect(): void {
    if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      console.error('[VIGIL] Max reconnect attempts reached');
      return;
    }
    const delay = BASE_RECONNECT_DELAY * Math.pow(2, this.reconnectAttempts);
    console.log(`[VIGIL] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);
    this.reconnectTimer = window.setTimeout(() => {
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

  async fireAttack(attackType: string): Promise<{ status: string; attack_type: string }> {
    const res = await fetch(`/attack/${attackType}`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to fire attack: ${res.statusText}`);
    return res.json();
  }

  // Telegram Governed Runtime API Methods
  async getTelegramStatus(): Promise<TelegramStatus> {
    const res = await fetch('/telegram/status');
    if (!res.ok) throw new Error(`Failed to fetch Telegram status: ${res.statusText}`);
    return res.json();
  }

  async getTelegramApprovals(): Promise<ApprovalRequest[]> {
    const res = await fetch('/telegram/approvals');
    if (!res.ok) throw new Error(`Failed to fetch Telegram approvals: ${res.statusText}`);
    return res.json();
  }

  async getTelegramUsers(): Promise<TelegramUser[]> {
    const res = await fetch('/telegram/users');
    if (!res.ok) throw new Error(`Failed to fetch Telegram users: ${res.statusText}`);
    return res.json();
  }

  async resolveApproval(requestId: string, action: 'approve' | 'deny'): Promise<{ status: string; resolved_to: string }> {
    const res = await fetch(`/telegram/approvals/${requestId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) throw new Error(`Failed to resolve approval: ${res.statusText}`);
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
}

function logger(msg: string) {
  console.log(`[VIGIL API] ${msg}`);
}

// Singleton client instance
export const vigilClient = new VIGILClient();
