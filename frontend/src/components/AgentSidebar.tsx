import React, { useState } from 'react';
import { useVigilStore } from '../store';
import { AgentStatus } from '../types';

export const AgentSidebar: React.FC = () => {
  const { agents, selectedAgentId, setSelectedAgentId, setActiveGraphHighlight } = useVigilStore();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'QUARANTINED' | 'ALERT'>('ALL');

  const agentList = Array.from(agents.values());

  const filteredAgents = agentList.filter((agent) => {
    const matchesSearch = agent.name.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (statusFilter === 'ALL') return matchesSearch;
    if (statusFilter === 'ACTIVE') return matchesSearch && agent.status === AgentStatus.NORMAL;
    if (statusFilter === 'QUARANTINED') return matchesSearch && agent.status === AgentStatus.QUARANTINED;
    if (statusFilter === 'ALERT') return matchesSearch && (agent.status === AgentStatus.ALERT || agent.status === AgentStatus.ANOMALOUS);
    return matchesSearch;
  });

  return (
    <aside className="w-[280px] border-r border-vigil-border/40 glass-panel flex flex-col h-full select-none shrink-0 overflow-hidden">
      {/* Title */}
      <div className="p-4 border-b border-vigil-border/30 flex items-center justify-between">
        <h2 className="text-xs uppercase font-mono font-bold tracking-widest text-vigil-muted">
          Agent Intelligence
        </h2>
        <span className="bg-vigil-teal/10 border border-vigil-teal/20 text-vigil-teal px-2 py-0.5 rounded text-[10px] font-mono font-bold">
          {agentList.length} LIVE
        </span>
      </div>

      {/* Search Input */}
      <div className="p-3 border-b border-vigil-border/20">
        <div className="relative">
          <input
            type="text"
            placeholder="FILTER BY AGENT ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900/60 border border-vigil-border/40 rounded px-8 py-1.5 text-xs font-mono tracking-wide text-white placeholder-slate-500 focus:outline-none focus:border-vigil-teal/80 transition-colors"
          />
          <svg
            className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-slate-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth="2.5"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="grid grid-cols-4 border-b border-vigil-border/20 text-[9px] font-mono font-bold text-center">
        <button
          onClick={() => setStatusFilter('ALL')}
          className={`py-2 transition-colors ${statusFilter === 'ALL' ? 'text-vigil-teal border-b-2 border-vigil-teal' : 'text-slate-500 hover:text-white'}`}
        >
          ALL
        </button>
        <button
          onClick={() => setStatusFilter('ACTIVE')}
          className={`py-2 transition-colors ${statusFilter === 'ACTIVE' ? 'text-vigil-teal border-b-2 border-vigil-teal' : 'text-slate-500 hover:text-white'}`}
        >
          ACTV
        </button>
        <button
          onClick={() => setStatusFilter('ALERT')}
          className={`py-2 transition-colors ${statusFilter === 'ALERT' ? 'text-vigil-red border-b-2 border-vigil-red' : 'text-slate-500 hover:text-white'}`}
        >
          ALRT
        </button>
        <button
          onClick={() => setStatusFilter('QUARANTINED')}
          className={`py-2 transition-colors ${statusFilter === 'QUARANTINED' ? 'text-vigil-red border-b-2 border-vigil-red' : 'text-slate-500 hover:text-white'}`}
        >
          QRTN
        </button>
      </div>

      {/* Agent List */}
      <div className="flex-1 overflow-y-auto divide-y divide-vigil-border/10">
        {filteredAgents.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            NO AGENTS MATCH FILTER
          </div>
        ) : (
          filteredAgents.map((agent) => {
            const isSelected = selectedAgentId === agent.agent_id;
            const trustScore = Math.max(0, Math.min(100, Math.round((1 - agent.anomaly_score) * 100)));
            const isThreatened = agent.status === AgentStatus.ALERT || agent.status === AgentStatus.ANOMALOUS || agent.status === AgentStatus.REVOKED;
            const isQuarantined = agent.status === AgentStatus.QUARANTINED;

            // Generate a simple dynamic sparkline based on status and anomaly score
            const baselineSeed = agent.anomaly_score > 0.3 ? [15, 35, 10, 45, 60, 30, 80] : [10, 15, 12, 14, 11, 16, 12];
            const sparklinePoints = baselineSeed.map((val, idx) => `${idx * 10},${30 - (val / 100) * 25}`).join(' ');

            return (
              <div
                key={agent.agent_id}
                onClick={() => setSelectedAgentId(isSelected ? null : agent.agent_id)}
                onMouseEnter={() => setActiveGraphHighlight(agent.agent_id)}
                onMouseLeave={() => setActiveGraphHighlight(null)}
                className={`p-3 cursor-pointer flex items-center justify-between transition-all duration-200 hover:bg-slate-900/30 ${
                  isSelected ? 'bg-slate-900/60 border-l-2 border-vigil-teal' : ''
                }`}
              >
                {/* Left: Info */}
                <div className="flex flex-col space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      isQuarantined ? 'bg-vigil-red animate-ping' :
                      isThreatened ? 'bg-vigil-amber animate-pulse' :
                      'bg-vigil-teal'
                    }`} />
                    <span className="text-xs font-bold text-slate-100 tracking-wide">{agent.name}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 tracking-wide uppercase">
                    {agent.agent_id}
                  </span>
                  <div className="pt-1">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono ${
                      isQuarantined ? 'bg-vigil-red/10 text-vigil-red border border-vigil-red/20' :
                      isThreatened ? 'bg-vigil-amber/10 text-vigil-amber border border-vigil-amber/20' :
                      'bg-vigil-teal/10 text-vigil-teal border border-vigil-teal/20'
                    }`}>
                      {agent.status}
                    </span>
                  </div>
                </div>

                {/* Right: Sparkline & Score Ring */}
                <div className="flex items-center space-x-3">
                  {/* Custom Mini SVG Sparkline */}
                  <svg className="w-10 h-6 overflow-visible" strokeWidth="1.5" fill="none">
                    <path
                      d={`M ${sparklinePoints}`}
                      stroke={isQuarantined || isThreatened ? '#ff2a5f' : '#00f2fe'}
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>

                  {/* Tiny Trust Score Indicator */}
                  <div className="relative w-8 h-8 flex items-center justify-center">
                    <svg className="w-8 h-8 transform -rotate-90">
                      <circle
                        cx="16"
                        cy="16"
                        r="12"
                        className="stroke-slate-800"
                        strokeWidth="2.5"
                        fill="transparent"
                      />
                      <circle
                        cx="16"
                        cy="16"
                        r="12"
                        className={`${isQuarantined ? 'stroke-vigil-red' : isThreatened ? 'stroke-vigil-amber' : 'stroke-vigil-teal'}`}
                        strokeWidth="2.5"
                        fill="transparent"
                        strokeDasharray={2 * Math.PI * 12}
                        strokeDashoffset={2 * Math.PI * 12 * (1 - trustScore / 100)}
                        strokeLinecap="round"
                      />
                    </svg>
                    <span className="absolute text-[8px] font-bold font-mono text-white">
                      {trustScore}%
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
};
