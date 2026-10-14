import React, { useState } from 'react';
import { ThreatType, PolicyDecision } from '../types';
import { useVigilStore } from '../store';

export const ThreatConsole: React.FC = () => {
  const { incidents, setSelectedIncidentId } = useVigilStore();
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);

  // Helper to format time relative
  const formatTime = (ts: number) => {
    const elapsed = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (elapsed < 60) return `${elapsed}s ago`;
    const mins = Math.floor(elapsed / 60);
    return `${mins}m ago`;
  };

  const getThreatBadge = (type: ThreatType) => {
    const label = type.replace('_', ' ');
    if (type === ThreatType.PROMPT_INJECTION || type === ThreatType.DATA_EXFILTRATION) {
      return <span className="badge badge-red">{label}</span>;
    }
    return <span className="badge badge-amber">{label}</span>;
  };

  const getPolicyBadge = (decision: PolicyDecision) => {
    switch (decision) {
      case PolicyDecision.APPROVED:
        return <span className="badge badge-teal">PASSED</span>;
      case PolicyDecision.DENIED:
        return <span className="badge badge-red">BLOCKED</span>;
      case PolicyDecision.ESCALATE:
        return <span className="badge badge-amber">ESCALATED</span>;
      default:
        return <span className="badge badge-gray">{decision}</span>;
    }
  };

  return (
    <div className="glass-panel flex-1 flex flex-col h-full overflow-hidden select-none">
      {/* Title */}
      <div className="p-4 border-b border-vigil-border/40 flex justify-between items-center bg-slate-950/20">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-vigil-red animate-pulse" />
          <h2 className="text-xs uppercase font-mono font-bold tracking-widest text-white">
            Security Incident Intelligence Stream
          </h2>
        </div>
        <span className="text-[10px] text-vigil-muted font-mono font-bold uppercase">
          TELEMETRY FEEDS: {incidents.length} SECURED
        </span>
      </div>

      {/* Stream Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {incidents.length === 0 ? (
          <div className="h-full flex flex-col justify-center items-center text-center py-12 space-y-3">
            <div className="w-12 h-12 rounded-full bg-vigil-teal/10 flex justify-center items-center relative animate-pulse">
              <span className="w-3.5 h-3.5 rounded-full bg-vigil-teal shadow-[0_0_12px_#00f2fe]" />
            </div>
            <div>
              <p className="text-xs font-bold text-white uppercase tracking-widest font-mono">ALL SYSTEMS PROTECTED</p>
              <p className="text-[10px] text-vigil-muted max-w-[280px] mt-1 font-sans leading-normal">
                Autonomous rule engines and ArmorIQ pipeline scanners have found no anomalous payloads.
              </p>
            </div>
          </div>
        ) : (
          incidents.map((incident) => {
            const isExpanded = expandedIncidentId === incident.incident_id;
            const scorePercent = (incident.detection_result.score * 100).toFixed(0);
            const detection = incident.detection_result;

            return (
              <div
                key={incident.incident_id}
                onClick={() => {
                  setExpandedIncidentId(isExpanded ? null : incident.incident_id);
                  // Sync with store selected ID if needed
                  setSelectedIncidentId(incident.incident_id);
                }}
                className={`p-4 bg-slate-950/40 rounded-xl border border-vigil-border/30 hover:border-vigil-border/60 transition-all duration-300 cursor-pointer relative overflow-hidden flex flex-col space-y-3 ${
                  isExpanded ? 'border-vigil-border/90 bg-slate-950/80 shadow-lg shadow-black/30' : ''
                }`}
              >
                {/* Background red backing visual representing severity */}
                <div 
                  className="absolute left-0 top-0 bottom-0 bg-vigil-red/5 pointer-events-none transition-all duration-300"
                  style={{ width: `${incident.detection_result.score * 100}%` }}
                />

                {/* Header row */}
                <div className="flex justify-between items-start z-10">
                  <div className="flex flex-col space-y-1">
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <span className="text-xs font-bold text-white uppercase tracking-wide">
                        {incident.agent_id}
                      </span>
                      {getThreatBadge(incident.threat_type)}
                      {getPolicyBadge(incident.policy_decision)}
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 font-bold uppercase">
                      ID: {incident.incident_id.slice(0, 12)} | {formatTime(incident.timestamp)}
                    </span>
                  </div>

                  <div className="flex items-center space-x-3 text-right">
                    <div>
                      <span className={`text-sm font-black font-mono ${incident.detection_result.score > 0.6 ? 'text-vigil-red' : 'text-vigil-amber'}`}>
                        {scorePercent}%
                      </span>
                      <div className="text-[8px] text-slate-500 uppercase tracking-widest font-mono">
                        Threat Index
                      </div>
                    </div>
                    <svg className={`w-4 h-4 text-slate-500 transition-transform duration-300 ${isExpanded ? 'rotate-180 text-white' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </div>

                {/* Narrative explanation */}
                <div className="z-10 pl-3 border-l-2 border-vigil-teal/40">
                  {incident.explanation ? (
                    <p className="text-xs font-sans text-slate-300 leading-normal italic">
                      "{incident.explanation}"
                    </p>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-vigil-teal animate-pulse" />
                      <span className="text-[10px] text-slate-500 font-mono italic">Writing LLM narrative explanation...</span>
                    </div>
                  )}
                </div>

                {/* Expanded forensic visualization block */}
                {isExpanded && (
                  <div className="z-10 mt-3 pt-3 border-t border-vigil-border/30 grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-[10px] animate-fade-in" onClick={(e) => e.stopPropagation()}>
                    
                    {/* 1. Multi-Engine Scans confidence radial arcs */}
                    <div className="bg-slate-950/80 p-3 rounded-lg border border-vigil-border/40 flex flex-col justify-between">
                      <span className="text-[9px] font-bold text-slate-500 tracking-wider uppercase block pb-2">
                        MULTI-ENGINE CONCURRENCY
                      </span>
                      <div className="flex items-center justify-around py-1">
                        <div className="flex flex-col items-center">
                          <svg className="w-12 h-12 transform -rotate-90">
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#1e293b" strokeWidth="3" />
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#00f2fe" strokeWidth="3" strokeDasharray={2*Math.PI*18} strokeDashoffset={2*Math.PI*18*(1 - detection.rule_score)} />
                          </svg>
                          <span className="text-[9px] text-slate-400 pt-1 font-bold">Rule: {(detection.rule_score * 100).toFixed(0)}%</span>
                        </div>
                        <div className="flex flex-col items-center">
                          <svg className="w-12 h-12 transform -rotate-90">
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#1e293b" strokeWidth="3" />
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#bc13fe" strokeWidth="3" strokeDasharray={2*Math.PI*18} strokeDashoffset={2*Math.PI*18*(1 - detection.ewma_score)} />
                          </svg>
                          <span className="text-[9px] text-slate-400 pt-1 font-bold">EWMA: {(detection.ewma_score * 100).toFixed(0)}%</span>
                        </div>
                        <div className="flex flex-col items-center">
                          <svg className="w-12 h-12 transform -rotate-90">
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#1e293b" strokeWidth="3" />
                            <circle cx="24" cy="24" r="18" fill="transparent" stroke="#ff2a5f" strokeWidth="3" strokeDasharray={2*Math.PI*18} strokeDashoffset={2*Math.PI*18*(1 - detection.iforest_score)} />
                          </svg>
                          <span className="text-[9px] text-slate-400 pt-1 font-bold">IForest: {(detection.iforest_score * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                    </div>

                    {/* 2. Target payload diff parameters */}
                    <div className="bg-slate-950/80 p-3 rounded-lg border border-vigil-border/40 md:col-span-2 space-y-2 flex flex-col justify-between">
                      <span className="text-[9px] font-bold text-slate-500 tracking-wider uppercase block">
                        ANOMALOUS WORKFLOW INJECTION
                      </span>
                      <div className="bg-slate-900/60 p-2 rounded border border-vigil-border/10 text-[9px] overflow-x-auto text-slate-300 max-h-[80px]">
                        <div><span className="text-slate-500">Target Type:</span> {incident.event.event_type}</div>
                        <div><span className="text-slate-500">Destination Pipeline:</span> {incident.event.target}</div>
                        <div className="text-vigil-red pt-1 border-t border-slate-800 mt-1 select-text">
                          <span className="text-slate-500">Raw Input:</span> {incident.event.payload}
                        </div>
                      </div>
                      <div className="flex justify-between text-[8px] text-slate-500">
                        <span>Payload Size: {incident.event.payload_size} bytes</span>
                        <span className="text-vigil-teal font-bold uppercase">Remediation Action: {incident.action_taken}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
