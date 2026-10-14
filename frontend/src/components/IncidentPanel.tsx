import React from 'react';
import { Incident } from '../types';
import { PolicyBadge } from './PolicyBadge';
import { MetricBar } from './MetricBar';

interface IncidentPanelProps {
  incident: Incident | null;
  onClose: () => void;
}

export const IncidentPanel: React.FC<IncidentPanelProps> = ({ incident, onClose }) => {
  if (!incident) return null;

  const scorePercent = (incident.detection_result.score * 100).toFixed(0);
  
  // Format timestamp
  const dateStr = new Date(incident.timestamp * 1000).toLocaleString();

  // Resolve Remediation action class
  let actionColorClass = 'badge-teal';
  if (incident.action_taken === 'QUARANTINE') {
    actionColorClass = 'badge-red animate-pulse';
  } else if (incident.action_taken === 'ALERT') {
    actionColorClass = 'badge-amber';
  } else {
    actionColorClass = 'badge-gray';
  }

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
            <div className="flex flex-col items-center gap-1.5 p-3 bg-vigil-bg rounded-lg border border-vigil-border/60 min-w-[100px]">
              <span className="text-[8px] text-vigil-muted uppercase tracking-widest font-bold">Policy Gate</span>
              <PolicyBadge decision={incident.policy_decision} size="sm" />
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
          <div className="text-right">
            <span className="text-vigil-muted">Remediation Action:</span>
            <div className="mt-0.5">
              <span className={`badge ${actionColorClass} text-[10px] uppercase font-bold tracking-wider px-2 py-0.5`}>
                {incident.action_taken}
              </span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
