import React, { useState, useEffect } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';
import { ThreatIntelligenceData } from '../types';
import { AttackGraphVisualizer } from './AttackGraphVisualizer';
import { EvidenceChainViewer } from './EvidenceChainViewer';

export const ThreatIntelligenceDashboard: React.FC = () => {
  const { agents, incidents } = useVigilStore();
  const [intelData, setIntelData] = useState<ThreatIntelligenceData | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  const agentList = Array.from(agents.keys());

  const fetchIntel = async () => {
    try {
      const data = await vigilClient.getThreatIntelligence();
      setIntelData(data);
      if (data.integrity_baselines.length > 0 && !selectedAgentId) {
        setSelectedAgentId(data.integrity_baselines[0].agent_id);
      }
    } catch (err) {
      console.error('Failed to fetch threat intelligence:', err);
    }
  };

  useEffect(() => {
    fetchIntel();
    const interval = setInterval(fetchIntel, 5000);
    return () => clearInterval(interval);
  }, []);

  // Filter intelligence details for selected agent
  const currentBaseline = intelData?.integrity_baselines.find(b => b.agent_id === selectedAgentId);
  const currentIntegrityEvents = intelData?.integrity_events.filter(e => e.agent_id === selectedAgentId) || [];
  const currentCapabilityProfile = intelData?.capability_profiles.find(p => p.agent_id === selectedAgentId);
  const currentCapabilityViolations = intelData?.capability_violations.filter(v => v.agent_id === selectedAgentId) || [];
  const currentDependencies = intelData?.supply_chain_dependencies.filter(d => d.agent_id === selectedAgentId) || [];
  const currentSupplyChainEvents = intelData?.supply_chain_events.filter(e => e.agent_id === selectedAgentId) || [];
  const currentPromptMutations = intelData?.prompt_mutations.filter(m => m.agent_id === selectedAgentId) || [];
  const currentSpoofingScore = intelData?.spoofing_scores.find(s => s.agent_id === selectedAgentId);

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6 select-none max-w-7xl mx-auto w-full">
      {/* Title */}
      <div className="flex justify-between items-center">
        <div className="space-y-1">
          <h2 className="text-xl font-bold tracking-widest text-white uppercase font-sans">
            AI BEHAVIORAL THREAT INTELLIGENCE HUB
          </h2>
          <p className="text-xs text-slate-500 font-sans leading-normal">
            Real-time inspection of supply chain signatures, model weight anomalies, prompt mutations, and attack vectors.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-[10px] text-slate-400 font-mono">FILTER AGENT:</span>
          <select
            value={selectedAgentId}
            onChange={(e) => setSelectedAgentId(e.target.value)}
            className="bg-slate-900 border border-vigil-border/60 rounded px-2.5 py-1 text-xs text-white font-mono focus:outline-none focus:border-vigil-teal"
          >
            {agentList.map(id => (
              <option key={id} value={id}>{id}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Side: VIGIL 2.0 Security Vector Indicators (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          
          {/* Row 1: Model Integrity & Supply Chain */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            
            {/* Model Integrity Card */}
            <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between min-h-[220px]">
              <div>
                <div className="flex justify-between items-start border-b border-vigil-border/20 pb-2 mb-3">
                  <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider">
                    MODEL INTEGRITY SHIELD
                  </span>
                  <span className={`text-[9px] font-mono font-bold ${currentIntegrityEvents.length > 0 ? 'text-vigil-red' : 'text-vigil-teal'}`}>
                    {currentIntegrityEvents.length > 0 ? 'ANOMALOUS DRIFT' : 'VERIFIED'}
                  </span>
                </div>

                {currentBaseline ? (
                  <div className="space-y-2 text-[10px] font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">MODEL NAME:</span>
                      <span className="text-white text-right break-all">{currentBaseline.model_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">WEIGHT HASH:</span>
                      <span className="text-slate-300 font-semibold break-all text-right max-w-[120px]">
                        {currentBaseline.model_hash.substring(0, 16)}...
                      </span>
                    </div>
                    <div className="flex justify-between border-t border-vigil-border/10 pt-2 mt-2">
                      <span className="text-slate-500">DRIFT LOGS:</span>
                      <span className="text-white font-bold">{currentIntegrityEvents.length} Alerts</span>
                    </div>
                    <div className="max-h-[60px] overflow-y-auto space-y-1 text-[8px] mt-1 pr-1">
                      {currentIntegrityEvents.map((evt, idx) => (
                        <div key={idx} className="flex justify-between text-vigil-red">
                          <span>{evt.metric_name}</span>
                          <span>Drift: {evt.drift_score.toFixed(3)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <span className="text-[10px] text-slate-600 font-mono">SECURELY BASELINING AGENT weights...</span>
                )}
              </div>
            </div>

            {/* Supply Chain Security Card */}
            <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between min-h-[220px]">
              <div>
                <div className="flex justify-between items-start border-b border-vigil-border/20 pb-2 mb-3">
                  <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider">
                    SUPPLY CHAIN VERIFIER
                  </span>
                  <span className={`text-[9px] font-mono font-bold ${currentSupplyChainEvents.length > 0 ? 'text-vigil-red animate-pulse' : 'text-vigil-teal'}`}>
                    {currentSupplyChainEvents.length > 0 ? 'TAMPER ALERT' : 'SECURE'}
                  </span>
                </div>

                <div className="space-y-2 text-[10px] font-mono">
                  <div className="flex justify-between">
                    <span className="text-slate-500">DEPENDENCIES:</span>
                    <span className="text-white font-bold">{currentDependencies.length} Active</span>
                  </div>
                  <div className="max-h-[50px] overflow-y-auto space-y-1 text-[9px]">
                    {currentDependencies.map((dep, idx) => (
                      <div key={idx} className="flex justify-between text-slate-400">
                        <span>{dep.dependency_name}</span>
                        <span>v{dep.expected_version}</span>
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-between border-t border-vigil-border/10 pt-2">
                    <span className="text-slate-500">TAMPER LOGS:</span>
                    <span className="text-white font-bold">{currentSupplyChainEvents.length} Events</span>
                  </div>
                  <div className="max-h-[40px] overflow-y-auto space-y-1 text-[8px] text-vigil-red mt-1">
                    {currentSupplyChainEvents.map((evt, idx) => (
                      <div key={idx} className="flex justify-between">
                        <span>{evt.dependency_name}</span>
                        <span>{evt.issue_type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

          </div>

          {/* Row 2: Capability Enforcer & Behavioral Spoofing */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            
            {/* Capability Profiler */}
            <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between min-h-[220px]">
              <div>
                <div className="flex justify-between items-start border-b border-vigil-border/20 pb-2 mb-3">
                  <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider">
                    LEARNED CAPABILITY WHITING
                  </span>
                  <span className={`text-[9px] font-mono font-bold ${currentCapabilityViolations.length > 0 ? 'text-vigil-red' : 'text-vigil-teal'}`}>
                    {currentCapabilityViolations.length > 0 ? 'CAPABILITY EXCEEDED' : 'ENFORCED'}
                  </span>
                </div>

                {currentCapabilityProfile ? (
                  <div className="space-y-2 text-[10px] font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">PERMITTED TOOLS:</span>
                      <span className="text-white font-bold">{currentCapabilityProfile.allowed_tools.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">DESTINATIONS:</span>
                      <span className="text-slate-300 font-bold">{currentCapabilityProfile.allowed_destinations.length} Safe</span>
                    </div>
                    <div className="flex justify-between border-t border-vigil-border/10 pt-2">
                      <span className="text-slate-500">VIOLATIONS DETECTED:</span>
                      <span className="text-white font-bold">{currentCapabilityViolations.length} Logs</span>
                    </div>
                    <div className="max-h-[50px] overflow-y-auto space-y-1 text-[8px] text-vigil-red mt-1">
                      {currentCapabilityViolations.map((v, idx) => (
                        <div key={idx} className="flex justify-between">
                          <span>{v.action_type}</span>
                          <span>{v.target.substring(0, 16)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <span className="text-[10px] text-slate-600 font-mono">LEARNING CAPABILITY PARAMETERS...</span>
                )}
              </div>
            </div>

            {/* Behavioral Spoofing / Mimicry Detection */}
            <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between min-h-[220px]">
              <div>
                <div className="flex justify-between items-start border-b border-vigil-border/20 pb-2 mb-3">
                  <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider">
                    BEHAVIORAL MIMICRY SENSOR
                  </span>
                  <span className={`text-[9px] font-mono font-bold ${(currentSpoofingScore?.spoofing_likelihood || 0) > 0.65 ? 'text-vigil-red animate-pulse' : 'text-vigil-teal'}`}>
                    {(currentSpoofingScore?.spoofing_likelihood || 0) > 0.65 ? 'SPOOFING SUSPECT' : 'NORMAL FOOTPRINT'}
                  </span>
                </div>

                {currentSpoofingScore ? (
                  <div className="space-y-3 text-[10px] font-mono">
                    <div className="space-y-1">
                      <div className="flex justify-between text-[9px]">
                        <span>Timing Regularity Index:</span>
                        <span className="font-bold text-white">{(currentSpoofingScore.timing_regularity * 100).toFixed(0)}%</span>
                      </div>
                      <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-vigil-purple rounded-full" style={{ width: `${currentSpoofingScore.timing_regularity * 100}%` }} />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[9px]">
                        <span>Entropy Suppression Level:</span>
                        <span className="font-bold text-white">{(currentSpoofingScore.entropy_score * 100).toFixed(0)}%</span>
                      </div>
                      <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-vigil-red rounded-full" style={{ width: `${currentSpoofingScore.entropy_score * 100}%` }} />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[9px]">
                        <span>Pattern Repetition Factor:</span>
                        <span className="font-bold text-white">{(currentSpoofingScore.repetition_score * 100).toFixed(0)}%</span>
                      </div>
                      <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-vigil-teal rounded-full" style={{ width: `${currentSpoofingScore.repetition_score * 100}%` }} />
                      </div>
                    </div>

                    <div className="flex justify-between border-t border-vigil-border/10 pt-2 text-[10px] items-center">
                      <span className="text-slate-500">MIMICRY LIKELIHOOD:</span>
                      <span className={`font-black text-sm ${(currentSpoofingScore.spoofing_likelihood) > 0.65 ? 'text-vigil-red' : 'text-vigil-teal'}`}>
                        {(currentSpoofingScore.spoofing_likelihood * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                ) : (
                  <span className="text-[10px] text-slate-600 font-mono">CALCULATING BEHAVIOR FOOTPRINT MATRIX...</span>
                )}
              </div>
            </div>

          </div>

          {/* Prompt Mutation Timeline */}
          <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col min-h-[160px]">
            <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3 mb-3">
              <span className="text-[10px] text-slate-500 font-mono font-bold uppercase">
                PROMPT MUTATION DRIFT TIMELINE
              </span>
              <span className="bg-slate-900 text-[8px] font-mono text-slate-400 px-2 py-0.5 rounded font-semibold uppercase">
                Syntactic Levenshtein Check
              </span>
            </div>

            <div className="max-h-[140px] overflow-y-auto space-y-2 pr-2 font-mono">
              {currentPromptMutations.length === 0 ? (
                <div className="text-[9px] text-slate-600 text-center py-4">NO PROMPT MUTATIONS LOGGED</div>
              ) : (
                currentPromptMutations.map((mut, idx) => (
                  <div key={idx} className="bg-slate-900/30 p-2 rounded border border-vigil-border/20 text-[9px] space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Distance: <strong className="text-white">{mut.levenshtein_distance}</strong></span>
                      <span className="text-slate-500">Similarity: <strong className="text-white">{(mut.similarity_score * 100).toFixed(1)}%</strong></span>
                      <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${mut.is_anomaly ? 'bg-vigil-red/20 text-vigil-red' : 'bg-emerald-500/20 text-emerald-400'}`}>
                        {mut.is_anomaly ? 'MUTATION ATTACK' : 'NORMAL'}
                      </span>
                    </div>
                    <div className="text-[8px] text-slate-400 leading-normal line-clamp-2">
                      <strong className="text-slate-500 font-normal">MUTATED: </strong> {mut.mutated_prompt}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

        {/* Right Side: Network Compromise Graph & Evidence Ledger (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Incident selector */}
          <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col space-y-3">
            <span className="text-[10px] text-slate-500 font-mono font-bold uppercase">
              SELECT ACTIVE TIMELINE REPLAY INCIDENT
            </span>
            <div className="max-h-[100px] overflow-y-auto space-y-1 pr-1 font-mono text-[9px]">
              {incidents.slice(0, 10).map((inc) => (
                <div
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className={`flex justify-between items-center p-1.5 rounded cursor-pointer transition-colors ${
                    selectedIncidentId === inc.incident_id
                      ? 'bg-vigil-teal/20 border border-vigil-teal/40 text-white'
                      : 'bg-slate-900/20 border border-vigil-border/10 text-slate-400 hover:bg-slate-800/40'
                  }`}
                >
                  <span className="font-bold truncate max-w-[120px]">{inc.agent_id}</span>
                  <span className="text-vigil-red font-semibold">{inc.threat_type}</span>
                  <span className="text-[8px] text-slate-500">
                    {new Date(inc.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <AttackGraphVisualizer incidentId={selectedIncidentId} />
          
          <EvidenceChainViewer incidents={incidents} selectedIncidentId={selectedIncidentId} />
        </div>

      </div>
    </div>
  );
};
