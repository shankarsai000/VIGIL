import React, { useState, useEffect } from 'react';
import { useVigilStore } from '../store';
import { Incident } from '../types';

export const ReplayView: React.FC = () => {
  const { incidents } = useVigilStore();
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  // Set default incident if available
  useEffect(() => {
    if (incidents.length > 0 && !selectedIncident) {
      setSelectedIncident(incidents[0]);
    }
  }, [incidents, selectedIncident]);

  // Automatic play sequence
  useEffect(() => {
    if (!isPlaying || !selectedIncident) return;

    const interval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= 4) {
          setIsPlaying(false);
          return 4;
        }
        return prev + 1;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isPlaying, selectedIncident]);

  if (incidents.length === 0) {
    return (
      <div className="flex-1 flex flex-col justify-center items-center text-center p-8 font-mono select-none">
        <svg className="w-12 h-12 text-slate-600 animate-pulse mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.91 11.672a.375.375 0 010 .656l-5.603 3.113a.375.375 0 01-.557-.328V8.887c0-.286.307-.466.557-.327l5.603 3.112z" />
        </svg>
        <span className="text-xs text-white uppercase tracking-widest">No Sandbox Incidents Available</span>
        <span className="text-[10px] text-slate-500 max-w-[280px] mt-1 font-sans">
          Threat Replay requires active incident logs in the threat stream. Run a simulator flow from the bottom console to begin.
        </span>
      </div>
    );
  }

  const activeIncident = selectedIncident || incidents[0];
  const scorePercent = (activeIncident.detection_result.score * 100).toFixed(0);

  // Reconstruct forensic propagation steps
  const replaySteps = [
    {
      step: 0,
      label: 'INJECTION',
      timeOffset: '+0.00s',
      color: '#bc13fe',
      title: 'Payload Input Registered',
      desc: `External agent requested delegation or tool usage with payload payload size ${activeIncident.event.payload_size} bytes.`,
      raw: activeIncident.event.payload,
    },
    {
      step: 1,
      label: 'DETECTION',
      timeOffset: '+0.04s',
      color: '#ff2a5f',
      title: 'Anomaly Scanned by VIGIL',
      desc: `Rule Engine matched threat conditions with ${(activeIncident.detection_result.rule_score * 100).toFixed(0)}% weight. Isolation Forest logged density distance.`,
      raw: `iForest Anomaly Score: ${activeIncident.detection_result.iforest_score.toFixed(3)}\nEWMA Rate Dev: ${activeIncident.detection_result.ewma_score.toFixed(3)}`,
    },
    {
      step: 2,
      label: 'VERIFICATION',
      timeOffset: '+0.08s',
      color: '#f59e0b',
      title: 'ArmorIQ Policy Verdict',
      desc: `ArmorIQ enforcement system parsed verdict: ${activeIncident.policy_decision}. Policy checked against authorized constraints.`,
      raw: `Verifying registered constraints...\nAllowed Tools: ${activeIncident.event.event_type}\nStatus: BLOCKED`,
    },
    {
      step: 3,
      label: 'CONTAINMENT',
      timeOffset: '+0.12s',
      color: '#00f2fe',
      title: 'Remediation Executed',
      desc: `Autonomous isolation active on pipeline. Action executed: ${activeIncident.action_taken}. Downstream execution blocked.`,
      raw: `Pipeline Isolation Level: CRITICAL\nRemediation: ${activeIncident.action_taken}`,
    },
    {
      step: 4,
      label: 'EXPLANATION',
      timeOffset: '+1.45s',
      color: '#00f2fe',
      title: 'Claw Forensic Report Generated',
      desc: `ArmorIQ Claw generated narrative explainability audit index.`,
      raw: activeIncident.explanation || 'Constructing markdown narrative graph...',
    },
  ];

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden select-none p-5 space-y-4">
      {/* Selector and Controls Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-4 border border-vigil-border/30 rounded-xl bg-slate-950/40">
        <div className="space-y-1">
          <span className="text-[10px] text-vigil-teal tracking-widest font-mono font-bold uppercase block">
            THREAT OBSERVABILITY FORENSIC SANDBOX
          </span>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-500">SELECT THREAT:</span>
            <select
              value={activeIncident.incident_id}
              onChange={(e) => {
                const found = incidents.find(i => i.incident_id === e.target.value);
                if (found) {
                  setSelectedIncident(found);
                  setCurrentStep(0);
                  setIsPlaying(false);
                }
              }}
              className="bg-slate-900 border border-vigil-border/40 rounded px-2 py-1 text-xs font-mono text-white focus:outline-none focus:border-vigil-teal"
            >
              {incidents.map((i) => (
                <option key={i.incident_id} value={i.incident_id}>
                  {i.agent_id.toUpperCase()} - {i.threat_type} ({(i.detection_result.score * 100).toFixed(0)}%)
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Playback Controls */}
        <div className="flex items-center space-x-2 bg-slate-900/60 p-1 border border-vigil-border/40 rounded-lg">
          <button
            onClick={() => setCurrentStep(0)}
            className="p-1.5 hover:text-white text-slate-400 hover:bg-slate-800 rounded transition-colors"
            title="Reset"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12.066 11.2a1 1 0 000 1.6l5.334 3.2A1 1 0 0019 15.2V8.8a1 1 0 00-1.6-.8l-5.334 3.2zM4.066 11.2a1 1 0 000 1.6l5.334 3.2A1 1 0 0011 15.2V8.8a1 1 0 00-1.6-.8l-5.334 3.2z" />
            </svg>
          </button>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="px-4 py-1 bg-vigil-teal text-black font-mono font-bold text-xs uppercase rounded transition-opacity hover:opacity-90 flex items-center space-x-1.5"
          >
            {isPlaying ? (
              <>
                <span className="w-1.5 h-1.5 bg-black rounded-full animate-ping" />
                <span>PAUSE</span>
              </>
            ) : (
              <span>PLAY SANDBOX</span>
            )}
          </button>
          <button
            onClick={() => setCurrentStep(prev => Math.min(4, prev + 1))}
            className="p-1.5 hover:text-white text-slate-400 hover:bg-slate-800 rounded transition-colors"
            title="Next Step"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      </div>

      {/* Main Sandbox Scrubber Timeline */}
      <div className="p-5 border border-vigil-border/30 rounded-xl bg-slate-950/20 flex flex-col space-y-4">
        <div className="relative flex items-center justify-between py-6">
          {/* Horizontal line */}
          <div className="absolute left-6 right-6 top-[37px] h-0.5 bg-slate-800 pointer-events-none" />
          <div
            className="absolute left-6 top-[37px] h-0.5 bg-vigil-teal pointer-events-none transition-all duration-500"
            style={{ width: `calc(${currentStep / 4 * 100}% - ${currentStep * 4}px)` }}
          />

          {replaySteps.map((step) => {
            const isActive = step.step <= currentStep;
            const isCurrent = step.step === currentStep;

            return (
              <div
                key={step.step}
                onClick={() => {
                  setCurrentStep(step.step);
                  setIsPlaying(false);
                }}
                className="z-10 flex flex-col items-center cursor-pointer group"
              >
                <div
                  className={`w-7 h-7 rounded-full border flex items-center justify-center font-mono text-xs font-bold transition-all duration-300 ${
                    isCurrent
                      ? 'bg-vigil-teal text-black stroke-vigil-teal shadow-[0_0_12px_rgba(0,242,254,0.4)] border-vigil-tealScale scale-110'
                      : isActive
                      ? 'bg-slate-900 text-vigil-teal border-vigil-teal'
                      : 'bg-slate-950 text-slate-600 border-slate-800 hover:border-slate-500'
                  }`}
                >
                  {step.step + 1}
                </div>
                <span className={`text-[9px] font-mono font-bold tracking-widest pt-2 transition-colors ${isActive ? 'text-white' : 'text-slate-600 group-hover:text-slate-400'}`}>
                  {step.label}
                </span>
                <span className="text-[8px] font-mono text-slate-500 pt-0.5">{step.timeOffset}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Forensic Report Details Grid */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-4 overflow-hidden min-h-0">
        
        {/* Left Side: Step narration details */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 overflow-y-auto space-y-4">
          <div className="border-b border-vigil-border/20 pb-3 flex justify-between items-center">
            <span className="text-[10px] text-slate-500 font-mono font-bold uppercase">
              REPLAY SEQUENCE DETAILS
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-vigil-red/10 border border-vigil-red/20 text-vigil-red font-bold">
              SEVERITY: {scorePercent}%
            </span>
          </div>

          <div className="space-y-2">
            <span className="inline-block px-2 py-0.5 text-[8px] font-mono font-bold rounded" style={{ backgroundColor: `${replaySteps[currentStep].color}15`, color: replaySteps[currentStep].color, border: `1px solid ${replaySteps[currentStep].color}25` }}>
              STEP {currentStep + 1} // {replaySteps[currentStep].label}
            </span>
            <h4 className="text-sm font-bold text-white font-sans">
              {replaySteps[currentStep].title}
            </h4>
            <p className="text-xs font-sans text-slate-400 leading-relaxed pt-1">
              {replaySteps[currentStep].desc}
            </p>
          </div>

          <div className="pt-3 border-t border-vigil-border/10 font-mono text-[9px] text-slate-500 uppercase tracking-widest">
            TARGETED pipeline: {activeIncident.event.target} // SOURCE: {activeIncident.agent_id}
          </div>
        </div>

        {/* Right Side: Step Raw Code payload trace */}
        <div className="bg-slate-950/60 border border-vigil-border/30 rounded-xl p-5 flex flex-col overflow-hidden">
          <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block pb-3 border-b border-vigil-border/20">
            RAW TRACE TERMINAL OUTPUT
          </span>
          <div className="flex-1 bg-slate-950 rounded-lg p-4 font-mono text-xs overflow-y-auto text-vigil-teal border border-vigil-border/10 mt-3 select-text whitespace-pre-wrap leading-relaxed select-all">
            {replaySteps[currentStep].raw}
          </div>
        </div>
      </div>
    </div>
  );
};
