import React, { useState } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';

export const SimulationDock: React.FC = () => {
  const { simulationDockOpen, setSimulationDockOpen } = useVigilStore();
  const [loadingType, setLoadingType] = useState<string | null>(null);

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

  const handleSimulate = async (type: string) => {
    setLoadingType(type);
    try {
      await vigilClient.fireAttack(type);
    } catch (err) {
      console.error('Failed to run attack simulation:', err);
    } finally {
      // Simulate small cool down
      setTimeout(() => {
        setLoadingType(null);
      }, 800);
    }
  };

  return (
    <footer className="shrink-0 border-t border-vigil-border/40 glass-panel flex flex-col z-30 select-none relative bg-slate-950/85">
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
        <div className="h-[120px] overflow-x-auto overflow-y-hidden flex items-center px-6 gap-4 py-3 divide-x divide-vigil-border/10">
          {attackScenarios.map((scenario) => {
            const isLoading = loadingType === scenario.type;

            return (
              <div 
                key={scenario.type}
                className={`flex-1 min-w-[240px] max-w-[280px] bg-gradient-to-b ${scenario.color} border border-vigil-border/30 rounded-xl p-3 flex flex-col justify-between h-full transition-all duration-300 relative overflow-hidden group`}
              >
                <div className="flex justify-between items-start">
                  <span className="text-[9px] font-mono font-bold tracking-widest text-slate-400 block uppercase">
                    {scenario.label}
                  </span>
                  <span className="text-[7px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-900/80 border border-vigil-border/40 text-slate-400 uppercase">
                    {scenario.badge}
                  </span>
                </div>
                <p className="text-[9px] text-slate-500 leading-snug font-sans group-hover:text-slate-400 transition-colors">
                  {scenario.description}
                </p>
                <button
                  onClick={() => handleSimulate(scenario.type)}
                  disabled={loadingType !== null}
                  className={`w-full py-1 text-[9px] font-mono font-bold tracking-widest uppercase rounded flex items-center justify-center space-x-1.5 transition-all duration-300 ${scenario.btnColor} ${
                    loadingType !== null ? 'opacity-40 cursor-not-allowed' : ''
                  }`}
                >
                  {isLoading ? (
                    <>
                      <span className="w-1.5 h-1.5 bg-black rounded-full animate-ping" />
                      <span>FIRING SIMULATION...</span>
                    </>
                  ) : (
                    <span>FIRE MITIGATION SCENARIO</span>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </footer>
  );
};
