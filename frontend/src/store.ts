import { create } from 'zustand';
import { Agent, Incident, AuditEntry, TelegramStatus, TelegramUser, ApprovalRequest } from './types';

const MAX_INCIDENTS = 50;
const MAX_AUDIT_ENTRIES = 100;

export interface VigilState {
  // Existing State
  agents: Map<string, Agent>;
  incidents: Incident[];
  auditLog: AuditEntry[];
  connected: boolean;
  lastUpdate: number;
  selectedIncidentId: string | null;

  // New Observability State
  activeTab: 'operations' | 'replay' | 'governance' | 'executive' | 'threat_intel';
  selectedAgentId: string | null;
  simulationDockOpen: boolean;
  replayIncidentId: string | null;
  replayStep: number;
  replayIsPlaying: boolean;
  activeGraphHighlight: string | null;

  // Telegram Governed Runtime State
  telegramStatus: TelegramStatus | null;
  pendingApprovals: ApprovalRequest[];
  telegramUsers: TelegramUser[];

  // Actions
  setAgents: (agents: Agent[]) => void;
  updateAgent: (agent: Agent) => void;
  addIncident: (incident: Incident) => void;
  updateIncidentExplanation: (incidentId: string, explanation: string) => void;
  updateIncidentState: (incidentId: string, state: Incident['state']) => void;
  addAuditEntry: (entry: AuditEntry) => void;
  setAuditLog: (entries: AuditEntry[]) => void;
  setConnected: (connected: boolean) => void;
  setSelectedIncidentId: (id: string | null) => void;

  // New Actions
  setActiveTab: (tab: 'operations' | 'replay' | 'governance' | 'executive' | 'threat_intel') => void;
  setSelectedAgentId: (id: string | null) => void;
  setSimulationDockOpen: (open: boolean) => void;
  setReplayIncidentId: (id: string | null) => void;
  setReplayStep: (step: number) => void;
  setReplayIsPlaying: (isPlaying: boolean) => void;
  setActiveGraphHighlight: (highlight: string | null) => void;

  // Telegram Governed Runtime Actions
  setTelegramStatus: (status: TelegramStatus | null) => void;
  setPendingApprovals: (approvals: ApprovalRequest[]) => void;
  setTelegramUsers: (users: TelegramUser[]) => void;
  addPendingApproval: (approval: ApprovalRequest) => void;
  resolvePendingApproval: (requestId: string, status: 'APPROVED' | 'DENIED' | 'INVESTIGATING', resolvedBy: number) => void;
}

export const useVigilStore = create<VigilState>((set) => ({
  agents: new Map(),
  incidents: [],
  auditLog: [],
  connected: false,
  lastUpdate: Date.now(),
  selectedIncidentId: null,

  // Default values
  activeTab: 'operations',
  selectedAgentId: null,
  simulationDockOpen: true,
  replayIncidentId: null,
  replayStep: 0,
  replayIsPlaying: false,
  activeGraphHighlight: null,

  telegramStatus: null,
  pendingApprovals: [],
  telegramUsers: [],

  setAgents: (agents) =>
    set(() => {
      const map = new Map<string, Agent>();
      agents.forEach((a) => map.set(a.agent_id, a));
      return { agents: map, lastUpdate: Date.now() };
    }),

  updateAgent: (agent) =>
    set((state) => {
      const newAgents = new Map(state.agents);
      newAgents.set(agent.agent_id, agent);
      return { agents: newAgents, lastUpdate: Date.now() };
    }),

  addIncident: (incident) =>
    set((state) => {
      // Avoid duplicates
      const filtered = state.incidents.filter((inc) => inc.incident_id !== incident.incident_id);
      return {
        incidents: [incident, ...filtered].slice(0, MAX_INCIDENTS),
        lastUpdate: Date.now(),
      };
    }),

  updateIncidentExplanation: (incidentId, explanation) =>
    set((state) => ({
      incidents: state.incidents.map((inc) =>
        inc.incident_id === incidentId ? { ...inc, explanation } : inc
      ),
      lastUpdate: Date.now(),
    })),

  updateIncidentState: (incidentId, state) =>
    set((s) => ({
      incidents: s.incidents.map((inc) =>
        inc.incident_id === incidentId ? { ...inc, state } : inc
      ),
      lastUpdate: Date.now(),
    })),

  addAuditEntry: (entry) =>
    set((state) => {
      // Avoid duplicates
      const filtered = state.auditLog.filter((e) => e.entry_id !== entry.entry_id);
      return {
        auditLog: [entry, ...filtered].slice(0, MAX_AUDIT_ENTRIES),
        lastUpdate: Date.now(),
      };
    }),

  setAuditLog: (entries) =>
    set(() => ({
      auditLog: entries.slice(0, MAX_AUDIT_ENTRIES),
      lastUpdate: Date.now(),
    })),

  setConnected: (connected) => set(() => ({ connected })),

  setSelectedIncidentId: (id) => set(() => ({ selectedIncidentId: id })),

  // Reducer implementations
  setActiveTab: (tab) => set(() => ({ activeTab: tab })),
  
  setSelectedAgentId: (id) => set(() => ({ selectedAgentId: id })),
  
  setSimulationDockOpen: (open) => set(() => ({ simulationDockOpen: open })),
  
  setReplayIncidentId: (id) => set(() => ({ replayIncidentId: id, replayStep: 0, replayIsPlaying: false })),
  
  setReplayStep: (step) => set(() => ({ replayStep: step })),
  
  setReplayIsPlaying: (isPlaying) => set(() => ({ replayIsPlaying: isPlaying })),
  
  setActiveGraphHighlight: (highlight) => set(() => ({ activeGraphHighlight: highlight })),

  setTelegramStatus: (status) => set(() => ({ telegramStatus: status })),

  setPendingApprovals: (approvals) => set(() => ({ pendingApprovals: approvals })),

  setTelegramUsers: (users) => set(() => ({ telegramUsers: users })),

  addPendingApproval: (approval) =>
    set((state) => {
      const filtered = state.pendingApprovals.filter((a) => a.request_id !== approval.request_id);
      return {
        pendingApprovals: [approval, ...filtered],
      };
    }),

  resolvePendingApproval: (requestId, status, resolvedBy) =>
    set((state) => ({
      pendingApprovals: state.pendingApprovals.map((a) =>
        a.request_id === requestId
          ? { ...a, status, resolved_at: Date.now() / 1000, resolved_by: resolvedBy }
          : a
      ),
    })),
}));
