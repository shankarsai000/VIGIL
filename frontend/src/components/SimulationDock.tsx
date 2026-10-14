import React, { useState, useEffect, useRef } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';
import { Incident } from '../types';
import { containmentOutcome, decisionBadge } from '../utils/governanceBadges';

interface AttackCardState {
  status: 'idle' | 'firing' | 'fired' | 'detected' | 'timeout';
  firedAt?: number;
  incident?: Incident;
  timeoutMessage?: string;
}

export const SimulationDock: React.FC = () => {
  const { simulationDockOpen, setSimulationDockOpen, incidents, setSelectedIncidentId, setActiveTab } = useVigilStore();
  const [cardStates, setCardStates] = useState<Record<string, AttackCardState>>({});
  const timeoutRefs = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  const attackScenarios = [
    {
      type: 'prompt_injection',
      label: 'PROMPT INJECTION',
      description: 'Inject prompt to hijack agent target instructions.',
      color: 'from-vigil-red/20 to-transparent hover:border-vigil-red/60',
      btnColor: 'bg-vigil-red hover:opacity-90 text-white',
      badge: 'HIGH IMPACT',
    },
    {
      type: 'privilege_escalation',
      label: 'PRIVILEGE ESCALATION',
      description: 'Request execution rights to non-permitted scopes.',
      color: 'from-vigil-amber/20 to-transparent hover:border-vigil-amber/60',
      btnColor: 'bg-vigil-amber hover:opacity-90 text-black',
      badge: 'CRITICAL AUTH',
    },
    {
      type: 'unauthorized_delegation',
      label: 'UNAUTHORIZED DELEGATION',
      description: 'Trigger cascaded agent delegation bypass scans.',
      color: 'from-vigil-purple/20 to-transparent hover:border-vigil-purple/60',
      btnColor: 'bg-vigil-purple hover:opacity-90 text-white',
      badge: 'WORKFLOW HIJACK',
    },
    {
      type: 'data_exfiltration',
      label: 'DATA EXFILTRATION',
      description: 'Extract raw vector database bytes down pipeline.',
      color: 'from-vigil-red/20 to-transparent hover:border-vigil-red/60',
      btnColor: 'bg-vigil-red hover:opacity-90 text-white',
      badge: 'EXFIL FILTERS',
    },
    {
      type: 'rate_anomaly',
      label: 'RATE LIMIT FLOOD',
      description: 'Flood queue with high-concurrency requests.',
      color: 'from-vigil-amber/20 to-transparent hover:border-vigil-amber/60',
      btnColor: 'bg-vigil-amber hover:opacity-90 text-black',
      badge: 'RATE LIMITER',
    },
    {
      type: 'model_integrity_drift',
      label: 'MODEL INTEGRITY DRIFT',
      description: 'Simulate model weight poisoning and parameter covariate drift.',
      color: 'from-vigil-red/20 to-transparent hover:border-vigil-red/60',
      btnColor: 'bg-vigil-red hover:opacity-90 text-white',
      badge: 'MODEL POISONING',
    },
    {
      type: 'prompt_mutation',
      label: 'PROMPT MUTATION',
      description: 'Adversarial prompt mutation and syntactic Levenshtein drift.',
      color: 'from-vigil-amber/20 to-transparent hover:border-vigil-amber/60',
      btnColor: 'bg-vigil-amber hover:opacity-90 text-black',
      badge: 'PROMPT DRIFT',
    },
    {
      type: 'capability_violation',
      label: 'CAPABILITY VIOLATION',
      description: 'Invoke unauthorized tool executions and system scopes.',
      color: 'from-vigil-purple/20 to-transparent hover:border-vigil-purple/60',
      btnColor: 'bg-vigil-purple hover:opacity-90 text-white',
      badge: 'CAPABILITY BLOCK',
    },
    {
      type: 'supply_chain_tamper',
      label: 'SUPPLY CHAIN TAMPER',
      description: 'Tamper with dependency hashes and package certificates.',
      color: 'from-vigil-red/20 to-transparent hover:border-vigil-red/60',
      btnColor: 'bg-vigil-red hover:opacity-90 text-white',
      badge: 'SUPPLY CHAIN RISK',
    },
    {
      type: 'behavioral_spoofing',
      label: 'BEHAVIORAL SPOOFING',
      description: 'Artificial footprint mimicry to hide command injection patterns.',
      color: 'from-vigil-amber/20 to-transparent hover:border-vigil-amber/60',
      btnColor: 'bg-vigil-amber hover:opacity-90 text-black',
      badge: 'MIMICRY SENSOR',
    },
  ];

  const handleSimulate = async (scenarioType: string, scenarioLabel: string) => {
    if (timeoutRefs.current[scenarioType]) {
      clearTimeout(timeoutRefs.current[scenarioType]);
    }

    const now = Date.now();
    setCardStates((prev) => ({
      ...prev,
      [scenarioType]: { status: 'firing', firedAt: now },
    }));

    try {
      await vigilClient.fireAttack(scenarioType);
      setCardStates((prev) => ({
        ...prev,
        [scenarioType]: { status: 'fired', firedAt: now },
      }));

      // 10-second timeout to alert if nothing was detected
      timeoutRefs.current[scenarioType] = setTimeout(() => {
        setCardStates((prev) => {
          const cur = prev[scenarioType];
          if (cur && (cur.status === 'fired' || cur.status === 'firing')) {
            return {
              ...prev,
              [scenarioType]: {
                status: 'timeout',
                firedAt: now,
                timeoutMessage: `Nothing detected within 10 seconds for ${scenarioLabel}`,
              },
            };
          }
          return prev;
        });
      }, 10000);
    } catch (err) {
      console.error('Failed to run attack simulation:', err);
      setCardStates((prev) => ({
        ...prev,
        [scenarioType]: {
          status: 'timeout',
          firedAt: now,
          timeoutMessage: `Simulation trigger failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
        },
      }));
    }
  };

  // Match incoming incidents from WebSocket/store to active attack cards
  useEffect(() => {
    if (!incidents || incidents.length === 0) return;

    setCardStates((prev) => {
      let changed = false;
      const next = { ...prev };

      Object.entries(prev).forEach(([type, state]) => {
        if (state.status === 'firing' || state.status === 'fired') {
          const match = incidents.find((inc) => {
            if (inc.attack_type === type) return true;
            if (inc.event?.attack_type === type) return true;
            if (
              state.firedAt &&
              inc.origin === 'user-triggered' &&
              Math.abs(inc.timestamp * 1000 - state.firedAt) < 15000
            ) {
              return true;
            }
            return false;
          });

          if (match) {
            if (timeoutRefs.current[type]) {
              clearTimeout(timeoutRefs.current[type]);
              delete timeoutRefs.current[type];
            }
            next[type] = {
              status: 'detected',
              firedAt: state.firedAt,
              incident: match,
            };
            changed = true;
          }
        }
      });

      return changed ? next : prev;
    });
  }, [incidents]);

  useEffect(() => {
    return () => {
      Object.values(timeoutRefs.current).forEach((t) => clearTimeout(t));
    };
  }, []);

  return (
    <footer className="shrink-0 border-t border-vigil-border/40 glass-panel flex flex-col z-30 select-none relative bg-slate-950/90">
      {/* Dock control tab */}
      <div 
        onClick={() => setSimulationDockOpen(!simulationDockOpen)}
        className="h-8 border-b border-vigil-border/20 flex items-center justify-between px-6 cursor-pointer hover:bg-slate-900/30 transition-colors"
      >
        <div className="flex items-center space-x-2 font-mono text-[9px] font-bold text-slate-500">
          <span className="w-1.5 h-1.5 rounded-full bg-vigil-amber animate-pulse" />
          <span>VIGIL AI FORENSIC ATTACK SANDBOX DOCK</span>
        </div>
        <div className="flex items-center space-x-1 text-slate-400 hover:text-white text-xs">
          <span className="font-mono text-[9px] uppercase tracking-wider">{simulationDockOpen ? 'Collapse Dock' : 'Expand Dock'}</span>
          <svg className={`w-4 h-4 transition-transform duration-300 ${simulationDockOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
          </svg>
        </div>
      </div>

      {/* Dock Panel */}
      {simulationDockOpen && (
        <div className="min-h-[160px] overflow-x-auto snap-x flex items-stretch px-6 gap-3 py-3 scrollbar-thin">
          {attackScenarios.map((scenario) => {
            const cardState = cardStates[scenario.type] || { status: 'idle' };
            const isFiring = cardState.status === 'firing';

            return (
              <div 
                key={scenario.type}
                className={`snap-start min-w-[280px] max-w-[320px] shrink-0 bg-gradient-to-b ${scenario.color} border border-vigil-border/30 rounded-xl p-3 flex flex-col justify-between transition-all duration-300 relative overflow-hidden group`}
              >
                {cardState.status === 'detected' && cardState.incident ? (
                  /* Detected State: reports score, decision, containment & link */
                  <div className="flex flex-col justify-between h-full space-y-2 z-10">
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] font-mono font-bold text-teal-300 flex items-center space-x-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse" />
                        <span>ATTACK DETECTED</span>
                      </span>
                      <span className="text-[8px] font-mono font-bold px-1.5 py-0.5 rounded bg-teal-950/80 text-teal-300 border border-teal-500/40">
                        {(cardState.incident.detection_result.score * 100).toFixed(0)}% THREAT
                      </span>
                    </div>

                    <div className="bg-slate-950/70 rounded p-2 border border-vigil-border/30 space-y-1 text-[8.5px] font-mono">
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Threat:</span>
                        <span className="text-slate-200 truncate max-w-[150px] font-bold">
                          {cardState.incident.threat_type}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Decision:</span>
                        <span className={decisionBadge(cardState.incident.policy_decision).badgeClass}>
                          {cardState.incident.policy_decision}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Containment:</span>
                        <span className={containmentOutcome(cardState.incident).badgeClass}>
                          {containmentOutcome(cardState.incident).label}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-1.5 pt-0.5">
                      <button
                        onClick={() => {
                          setSelectedIncidentId(cardState.incident!.incident_id);
                          setActiveTab('operations');
                        }}
                        className="flex-1 py-1 text-[8px] font-mono font-bold tracking-wider uppercase rounded bg-teal-500/20 hover:bg-teal-500/30 text-teal-300 border border-teal-500/50 flex items-center justify-center space-x-1 transition-all"
                        title="Jump to incident in Threat Console"
                      >
                        <span>VIEW INCIDENT</span>
                        <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                        </svg>
                      </button>
                      <button
                        onClick={() => handleSimulate(scenario.type, scenario.label)}
                        className="px-2.5 py-1 text-[8px] font-mono font-bold rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600/40 transition-colors"
                        title="Re-fire scenario"
                      >
                        RE-FIRE
                      </button>
                    </div>
                  </div>
                ) : cardState.status === 'timeout' ? (
                  /* Timeout State: named scenario message + retry */
                  <div className="flex flex-col justify-between h-full space-y-1.5 z-10">
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] font-mono font-bold text-vigil-amber flex items-center space-x-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-vigil-amber" />
                        <span>NO DETECTION</span>
                      </span>
                      <span className="text-[7.5px] font-mono px-1 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-600/40">
                        &gt;10s
                      </span>
                    </div>
                    <p className="text-[8.5px] font-sans text-amber-200/90 leading-tight bg-amber-950/30 p-2 rounded border border-amber-800/30">
                      {cardState.timeoutMessage || `Nothing detected within 10 seconds for ${scenario.label}`}
                    </p>
                    <button
                      onClick={() => handleSimulate(scenario.type, scenario.label)}
                      className="w-full py-1 text-[8px] font-mono font-bold uppercase rounded bg-vigil-amber hover:opacity-90 text-black tracking-wider transition-all"
                    >
                      RETRY SCENARIO
                    </button>
                  </div>
                ) : cardState.status === 'fired' || cardState.status === 'firing' ? (
                  /* Fired / Waiting Pipeline State */
                  <div className="flex flex-col justify-between h-full space-y-2 z-10 py-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] font-mono font-bold text-vigil-amber flex items-center space-x-1.5">
                        <span className="w-2 h-2 rounded-full bg-vigil-amber animate-ping" />
                        <span>ATTACK FIRED...</span>
                      </span>
                      <span className="text-[7.5px] font-mono text-slate-400">
                        10s timeout
                      </span>
                    </div>
                    <div className="bg-slate-950/60 rounded p-2.5 border border-vigil-border/30 text-center space-y-1">
                      <div className="text-[9px] font-mono text-slate-300 font-semibold">{scenario.label}</div>
                      <div className="text-[7.5px] font-mono text-slate-500">Evaluating telemetry layers &amp; ArmorIQ gate...</div>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1 overflow-hidden">
                      <div className="bg-vigil-amber h-full animate-pulse w-full" />
                    </div>
                  </div>
                ) : (
                  /* Idle State */
                  <>
                    <div className="flex justify-between items-start">
                      <span className="text-[9px] font-mono font-bold tracking-widest text-slate-400 block uppercase">
                        {scenario.label}
                      </span>
                      <span className="text-[7px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-900/80 border border-vigil-border/40 text-slate-400 uppercase">
                        {scenario.badge}
                      </span>
                    </div>
                    <p className="text-[9px] text-slate-500 leading-snug font-sans group-hover:text-slate-400 transition-colors my-2">
                      {scenario.description}
                    </p>
                    <button
                      onClick={() => handleSimulate(scenario.type, scenario.label)}
                      disabled={isFiring}
                      className={`w-full py-1.5 text-[9px] font-mono font-bold tracking-widest uppercase rounded flex items-center justify-center space-x-1.5 transition-all duration-300 ${scenario.btnColor} ${
                        isFiring ? 'opacity-40 cursor-not-allowed' : ''
                      }`}
                    >
                      <span>FIRE MITIGATION SCENARIO</span>
                    </button>
                  </>
                )}
              </div>
            );
          })}
        </div>
      )}
    </footer>
  );
};
