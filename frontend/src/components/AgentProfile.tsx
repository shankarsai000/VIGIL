import React from 'react';
import { useVigilStore } from '../store';
import { AgentStatus } from '../types';

export const AgentProfile: React.FC = () => {
  const { selectedAgentId, setSelectedAgentId, agents, incidents, updateAgent, addAuditEntry } = useVigilStore();

  if (!selectedAgentId) return null;

  const agent = agents.get(selectedAgentId);
  if (!agent) return null;

  const trustScore = Math.max(0, Math.min(100, Math.round((1 - agent.anomaly_score) * 100)));
  const isQuarantined = agent.status === AgentStatus.QUARANTINED;
  const isThreatened = agent.status === AgentStatus.ALERT || agent.status === AgentStatus.ANOMALOUS || agent.status === AgentStatus.REVOKED;

  const agentIncidents = incidents.filter((inc) => inc.agent_id === agent.agent_id);

  const toggleQuarantine = () => {
    const nextStatus = isQuarantined ? AgentStatus.NORMAL : AgentStatus.QUARANTINED;
    const updated = {
      ...agent,
      status: nextStatus,
      anomaly_score: nextStatus === AgentStatus.NORMAL ? 0.0 : agent.anomaly_score,
    };
    updateAgent(updated);

    // Write audit log
    const audit: any = {
      entry_id: `audit-${Math.random().toString(36).substring(2, 10)}`,
      agent_id: agent.agent_id,
      decision: nextStatus === AgentStatus.QUARANTINED ? 'DENIED' : 'APPROVED',
      action: nextStatus === AgentStatus.QUARANTINED ? 'OPERATOR_MANUAL_QUARANTINE' : 'OPERATOR_MANUAL_RESTORE',
      score: agent.anomaly_score,
      threat_type: 'NONE',
      timestamp: Date.now(),
      source: 'OPERATOR_INTERFACE',
    };
    addAuditEntry(audit);
  };

  return (
    <div className="absolute right-0 top-0 bottom-0 w-[380px] bg-slate-950/95 border-l border-vigil-border/60 z-40 flex flex-col shadow-2xl animate-slide-in select-none">
      {/* Header */}
      <div className="p-5 border-b border-vigil-border/40 flex items-center justify-between bg-slate-900/40">
        <div>
          <div className="flex items-center space-x-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isQuarantined ? 'bg-vigil-red animate-ping' : isThreatened ? 'bg-vigil-amber animate-pulse' : 'bg-vigil-teal'}`} />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">{agent.name}</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500 font-bold uppercase">{agent.agent_id}</span>
        </div>
        <button
          onClick={() => setSelectedAgentId(null)}
          className="text-slate-400 hover:text-white transition-colors"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* Core Stats Overview */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-slate-900/60 border border-vigil-border/20 rounded-xl p-3 text-center">
            <span className="text-[9px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
              BEHAVIORAL INDEX
            </span>
            <span className={`text-2xl font-black font-sans ${isQuarantined ? 'text-vigil-red' : isThreatened ? 'text-vigil-amber' : 'text-vigil-teal'}`}>
              {trustScore}%
            </span>
            <span className="text-[8px] font-mono text-slate-400 block pt-1 uppercase">
              {trustScore > 75 ? 'TRUSTED WORKER' : trustScore > 40 ? 'SUSPICIOUS RATE' : 'CONTAINMENT REQ'}
            </span>
          </div>

          <div className="bg-slate-900/60 border border-vigil-border/20 rounded-xl p-3 text-center">
            <span className="text-[9px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
              ANOMALY SCORE
            </span>
            <span className={`text-2xl font-black font-mono ${agent.anomaly_score > 0.6 ? 'text-vigil-red' : agent.anomaly_score > 0.2 ? 'text-vigil-amber' : 'text-vigil-teal'}`}>
              {agent.anomaly_score.toFixed(3)}
            </span>
            <span className="text-[8px] font-mono text-slate-400 block pt-1 uppercase">
              LATEST TELEMETRY
            </span>
          </div>
        </div>

        {/* Quarantine Interactive Action */}
        <div className={`p-4 rounded-xl border flex flex-col space-y-3 ${
          isQuarantined 
            ? 'bg-vigil-red/10 border-vigil-red/30' 
            : 'bg-slate-900/30 border-vigil-border/40'
        }`}>
          <div>
            <span className="text-[11px] font-bold font-mono text-white block uppercase">
              Remediation Action Console
            </span>
            <p className="text-[10px] text-slate-400 pt-1 leading-normal font-sans">
              {isQuarantined 
                ? 'Operator Manual Override is active. This agent is isolated from triggering downstream tools.' 
                : 'Instantly isolate this agent and revoke authorization to execution pipelines if suspicious behavior is suspected.'}
            </p>
          </div>
          <button
            onClick={toggleQuarantine}
            className={`w-full py-2 rounded font-mono font-bold tracking-widest text-xs uppercase transition-all duration-300 ${
              isQuarantined
                ? 'bg-vigil-teal text-black shadow-[0_0_15px_rgba(0,242,254,0.3)] hover:opacity-90'
                : 'bg-vigil-red text-white shadow-[0_0_15px_rgba(255,42,95,0.2)] hover:opacity-90'
            }`}
          >
            {isQuarantined ? '✓ AUTHORIZE AGENT pipeline' : '⚠️ ISOLATE & QUARANTINE AGENT'}
          </button>
        </div>

        {/* Allowed Toolchains */}
        <div className="space-y-2">
          <span className="text-[10px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
            AUTHORIZED SYSTEM TOOLCHAIN
          </span>
          <div className="flex flex-wrap gap-1.5">
            {agent.permitted_tools && agent.permitted_tools.length > 0 ? (
              agent.permitted_tools.map((t) => (
                <span
                  key={t}
                  className="bg-slate-900/80 border border-vigil-border/60 text-slate-300 px-2 py-1 rounded text-[10px] font-mono font-semibold"
                >
                  🛠️ {t}
                </span>
              ))
            ) : (
              <span className="text-[10px] text-slate-500 font-mono">NO TOOLS REGISTERED</span>
            )}
          </div>
        </div>

        {/* Delegation Targets */}
        <div className="space-y-2">
          <span className="text-[10px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
            AUTHORIZED DELEGATE TARGETS
          </span>
          <div className="flex flex-wrap gap-1.5">
            {agent.permitted_agents && agent.permitted_agents.length > 0 ? (
              agent.permitted_agents.map((a) => (
                <span
                  key={a}
                  className="bg-slate-900/80 border border-vigil-border/60 text-slate-300 px-2 py-1 rounded text-[10px] font-mono font-semibold"
                >
                  🔗 {a}
                </span>
              ))
            ) : (
              <span className="text-[10px] text-slate-500 font-mono">NO DELEGATIONS AUTHORIZED</span>
            )}
          </div>
        </div>

        {/* Telemetry Constants */}
        <div className="space-y-3 font-mono text-[10px]">
          <span className="text-[10px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
            AGENT REGISTRY INFO
          </span>
          <div className="bg-slate-950/60 p-3 rounded-lg border border-vigil-border/20 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-500">ARMORIQ ID:</span>
              <span className="text-slate-300">{agent.armoriq_id || 'NOT_LINKED'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">BASELINE RATE:</span>
              <span className="text-slate-300">{agent.baseline_call_rate} EPS</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">TOTAL EVENTS:</span>
              <span className="text-slate-300">{agent.event_count}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">REGISTERED AT:</span>
              <span className="text-slate-300 text-[9px]">{new Date(agent.registered_at).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Incident History Timeline */}
        <div className="space-y-3">
          <span className="text-[10px] font-mono font-bold tracking-widest text-slate-500 block uppercase">
            RECENT DETECTED THREATS ({agentIncidents.length})
          </span>
          {agentIncidents.length === 0 ? (
            <div className="p-4 rounded bg-slate-900/20 text-center font-mono text-[10px] text-slate-500 border border-vigil-border/10">
              NO INCIDENTS DETECTED ON THREAD
            </div>
          ) : (
            <div className="space-y-2">
              {agentIncidents.map((inc) => (
                <div
                  key={inc.incident_id}
                  className="bg-slate-900/60 border border-vigil-red/20 rounded-lg p-3 space-y-1 font-mono text-[10px]"
                >
                  <div className="flex justify-between">
                    <span className="text-vigil-red font-bold uppercase">{inc.threat_type}</span>
                    <span className="text-slate-500">{new Date(inc.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-slate-400 text-[9px] leading-tight font-sans">
                    Action: {inc.action_taken}
                  </div>
                  <div className="flex justify-between pt-1">
                    <span className="text-slate-500">DECISION:</span>
                    <span className="text-vigil-red font-bold">{inc.policy_decision}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
