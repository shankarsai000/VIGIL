import React, { useState } from 'react';
import { Incident, AgentStatus } from '../types';
import { MetricBar } from './MetricBar';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';
import { containmentOutcome, decisionBadge, enforcementLabel } from '../utils/governanceBadges';

interface IncidentPanelProps {
  incident: Incident | null;
  onClose: () => void;
}

export const IncidentPanel: React.FC<IncidentPanelProps> = ({ incident, onClose }) => {
  const { agents, gateMode } = useVigilStore();
  const [confirmingRelease, setConfirmingRelease] = useState(false);
  const [releaseReason, setReleaseReason] = useState('');
  const [releaseError, setReleaseError] = useState<string | null>(null);
  const [isReleasing, setIsReleasing] = useState(false);

  if (!incident) return null;

  const agent = agents.get(incident.agent_id);
  const isAgentQuarantined = agent?.status === AgentStatus.QUARANTINED;

  const handleConfirmRelease = async () => {
    if (!incident.agent_id || !releaseReason.trim()) return;
    setIsReleasing(true);
    setReleaseError(null);
    try {
      await vigilClient.releaseAgent(incident.agent_id, releaseReason.trim());
      setConfirmingRelease(false);
      setReleaseReason('');
    } catch (err: any) {
      setReleaseError(err.message || 'Failed to release agent');
    } finally {
      setIsReleasing(false);
    }
  };

  const scorePercent = (incident.detection_result.score * 100).toFixed(0);
  
  // Format timestamp
  const dateStr = new Date(incident.timestamp * 1000).toLocaleString();



  return (
    <div className="fixed inset-0 z-50 flex justify-end animate-fade-in">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/60 backdrop-blur-sm cursor-pointer"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="w-full max-w-[500px] h-full bg-vigil-bg border-l border-vigil-border shadow-[0_0_50px_rgba(0,0,0,0.8)] relative z-10 flex flex-col justify-between overflow-hidden animate-slide-in">
        
        {/* Header */}
        <div className="p-4 border-b border-vigil-border/60 flex justify-between items-center bg-vigil-card">
          <div className="flex flex-col">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Incident Details</h2>
            <span className="text-[10px] text-vigil-muted mono">ID: {incident.incident_id}</span>
          </div>
          <button 
            className="w-8 h-8 rounded-full border border-vigil-border flex justify-center items-center hover:bg-vigil-bg2 hover:text-white transition-all duration-200"
            onClick={onClose}
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          
          {/* Main Security Score Alert Banner */}
          <div className="p-4 bg-vigil-bg2/50 border border-vigil-border/80 rounded-xl flex items-center justify-between gap-4">
            <div className="flex-1">
              <span className="text-[9px] text-vigil-muted uppercase tracking-widest font-bold">Integrated Threat Score</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-white mono">{scorePercent}%</span>
                <span className={`text-[10px] uppercase font-bold mono text-vigil-red`}>
                  {incident.detection_result.confidence} CONFIDENCE
                </span>
              </div>
              <div className="mt-2">
                <MetricBar value={incident.detection_result.score} height={6} />
              </div>
            </div>
            <div className="flex flex-col items-center gap-1.5 p-3 bg-vigil-bg rounded-lg border border-vigil-border/60 min-w-[120px]">
              <span className="text-[8px] text-vigil-muted uppercase tracking-widest font-bold">Policy Gate</span>
              <span className={decisionBadge(incident.policy_decision).badgeClass}>
                {decisionBadge(incident.policy_decision).icon} {decisionBadge(incident.policy_decision).label}
              </span>
              <span className={enforcementLabel(gateMode).badgeClass}>
                {enforcementLabel(gateMode).label}
              </span>
            </div>
          </div>

          {/* Plain English Explanation */}
          <div className="space-y-2">
            <div className="text-[10px] text-vigil-muted uppercase tracking-wider font-bold">VIGIL Incident Narration</div>
            <div className="p-4 bg-vigil-teal/5 border border-vigil-teal/20 rounded-xl relative overflow-hidden">
              {/* Claude Branding Logo tag */}
              <div className="absolute right-3 top-3 flex items-center gap-1 text-[8px] text-vigil-teal/60 font-semibold tracking-wider uppercase mono">
                🤖 Claude Explainer
              </div>
              <p className="text-xs text-vigil-teal/95 font-medium leading-relaxed italic pr-12">
                "{incident.explanation || 'Generating explanation...'}"
              </p>
            </div>
          </div>

          {/* Combined Detection Layers Breakdown */}
          <div className="space-y-3">
            <div className="text-[10px] text-vigil-muted uppercase tracking-wider font-bold">Security Analysis Breakdown</div>
            <div className="p-4 bg-vigil-bg2/40 border border-vigil-border/60 rounded-xl space-y-4">
              
              <MetricBar 
                value={incident.detection_result.rule_score} 
                label="Deterministic Rule Engine (60% Weight)" 
                height={5}
              />
              
              <MetricBar 
                value={incident.detection_result.ewma_score} 
                label="EWMA Behavior Profiler (25% Weight)" 
                height={5}
              />
              
              <MetricBar 
                value={incident.detection_result.iforest_score} 
                label="Isolation Forest ML Scans (15% Weight)" 
                height={5}
              />
              
            </div>
          </div>

          {/* Telemetry / Payload Details */}
          <div className="space-y-3">
            <div className="text-[10px] text-vigil-muted uppercase tracking-wider font-bold">Payload Raw Telemetry</div>
            <div className="p-4 bg-vigil-bg2/40 border border-vigil-border/60 rounded-xl space-y-3 font-mono text-xs">
              
              <div className="grid grid-cols-2 gap-2 text-[11px] border-b border-vigil-border/30 pb-2">
                <div>
                  <span className="text-vigil-muted">Target Resource:</span>
                  <div className="text-white mt-0.5">{incident.event.target}</div>
                </div>
                <div>
                  <span className="text-vigil-muted">Event Method:</span>
                  <div className="text-white mt-0.5">{incident.event.event_type}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] border-b border-vigil-border/30 pb-2">
                <div>
                  <span className="text-vigil-muted">Agent Origin:</span>
                  <div className="text-white mt-0.5">{incident.agent_id}</div>
                </div>
                <div>
                  <span className="text-vigil-muted">Payload Length:</span>
                  <div className="text-white mt-0.5">{incident.event.payload_size} bytes</div>
                </div>
              </div>

              <div>
                <span className="text-[11px] text-vigil-muted">Raw Event Input Payload:</span>
                <pre className="p-3 bg-vigil-bg rounded border border-vigil-border/60 mt-1 overflow-x-auto text-[10px] leading-relaxed max-h-[150px] whitespace-pre-wrap break-all text-gray-300">
                  {incident.event.payload}
                </pre>
              </div>
            </div>
          </div>

        </div>

        {/* Footer Confinement Info */}
        <div className="p-4 border-t border-vigil-border/60 bg-vigil-card flex items-center justify-between font-mono text-[11px]">
          <div>
            <span className="text-vigil-muted">Logged:</span>
            <div className="text-white font-semibold mt-0.5">{dateStr}</div>
          </div>
          <div className="flex items-center space-x-3 text-right">
            {isAgentQuarantined && (
              <button
                onClick={() => { setConfirmingRelease(true); setReleaseError(null); }}
                className="px-2.5 py-1 text-[10px] uppercase font-bold font-mono tracking-wider bg-vigil-teal/20 text-vigil-teal border border-vigil-teal/40 hover:bg-vigil-teal hover:text-black rounded transition-all duration-200"
              >
                Release Agent
              </button>
            )}
            <div>
              <span className="text-vigil-muted block text-[10px]">Containment Status:</span>
              <div className="mt-0.5">
                <span className={containmentOutcome(incident).badgeClass}>
                  {containmentOutcome(incident).label}
                </span>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Release Confirmation Dialog */}
      {confirmingRelease && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] flex items-center justify-center p-4" onClick={(e) => e.stopPropagation()}>
          <div className="bg-slate-900 border border-vigil-border/60 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider">Confirm Quarantine Release</h3>
            <p className="text-xs text-slate-300">
              Are you sure you want to release agent <span className="text-vigil-teal font-mono font-bold">{incident.agent_id}</span> back to normal operational status?
            </p>
            <div>
              <label className="text-[10px] text-slate-400 font-mono block mb-1">Reason for release (required):</label>
              <input
                type="text"
                value={releaseReason}
                onChange={(e) => setReleaseReason(e.target.value)}
                placeholder="e.g., Security investigation complete; threat mitigated"
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-vigil-teal font-mono"
              />
            </div>
            {releaseError && <p className="text-[11px] text-vigil-red font-mono">{releaseError}</p>}
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => { setConfirmingRelease(false); setReleaseReason(''); setReleaseError(null); }}
                className="px-3 py-1.5 text-xs font-mono text-slate-400 hover:text-white bg-slate-800 rounded"
              >
                Cancel
              </button>
              <button
                disabled={!releaseReason.trim() || isReleasing}
                onClick={handleConfirmRelease}
                className="px-4 py-1.5 text-xs font-mono font-bold text-black bg-vigil-teal hover:bg-vigil-teal/80 disabled:opacity-50 rounded"
              >
                {isReleasing ? 'Releasing...' : 'Confirm Release'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
