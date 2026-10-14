import React, { useState } from 'react';
import { useVigilStore } from '../store';
import { PolicyDecision } from '../types';
import { TelegramGovernancePanel } from './TelegramGovernancePanel';

export const GovernanceView: React.FC = () => {
  const { auditLog } = useVigilStore();
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | 'APPROVED' | 'DENIED' | 'ESCALATE'>('ALL');

  const totalLogs = auditLog.length;
  const approvedCount = auditLog.filter(e => e.decision === PolicyDecision.APPROVED).length;
  const deniedCount = auditLog.filter(e => e.decision === PolicyDecision.DENIED).length;
  const escalatedCount = auditLog.filter(e => e.decision === PolicyDecision.ESCALATE).length;

  const filteredLogs = auditLog.filter((log) => {
    if (decisionFilter === 'ALL') return true;
    return log.decision === decisionFilter;
  });

  const getDecisionBadge = (decision: PolicyDecision) => {
    switch (decision) {
      case PolicyDecision.APPROVED:
        return <span className="badge badge-teal">APPROVED</span>;
      case PolicyDecision.DENIED:
        return <span className="badge badge-red">DENIED</span>;
      case PolicyDecision.ESCALATE:
        return <span className="badge badge-amber">ESCALATED</span>;
      default:
        return <span className="badge badge-gray">{decision}</span>;
    }
  };

  return (
    <div className="flex-1 overflow-hidden p-6 space-y-6 flex flex-col h-full select-none">
      
      {/* Title & Filter Tabs */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 shrink-0">
        <div className="space-y-1">
          <h2 className="text-xl font-bold tracking-widest text-white uppercase font-sans">
            IMMUTABLE GOVERNANCE & AUDIT LEDGER
          </h2>
          <p className="text-xs text-slate-500 font-sans leading-normal">
            Real-time compliance checks logged directly by ArmorIQ runtime rule deciders.
          </p>
        </div>

        {/* Audit Filter selector */}
        <div className="flex items-center space-x-1 bg-slate-900/60 p-1 border border-vigil-border/40 rounded-lg text-xs font-mono">
          <button
            onClick={() => setDecisionFilter('ALL')}
            className={`px-3 py-1 rounded transition-colors ${decisionFilter === 'ALL' ? 'bg-vigil-teal text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            ALL ({totalLogs})
          </button>
          <button
            onClick={() => setDecisionFilter('APPROVED')}
            className={`px-3 py-1 rounded transition-colors ${decisionFilter === 'APPROVED' ? 'bg-vigil-teal text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            APPROVED ({approvedCount})
          </button>
          <button
            onClick={() => setDecisionFilter('DENIED')}
            className={`px-3 py-1 rounded transition-colors ${decisionFilter === 'DENIED' ? 'bg-vigil-red text-white font-bold shadow-[0_0_10px_rgba(255,42,95,0.2)]' : 'text-slate-400 hover:text-white'}`}
          >
            DENIED ({deniedCount})
          </button>
          <button
            onClick={() => setDecisionFilter('ESCALATE')}
            className={`px-3 py-1 rounded transition-colors ${decisionFilter === 'ESCALATE' ? 'bg-vigil-amber text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            ESCALATED ({escalatedCount})
          </button>
        </div>
      </div>

      {/* Decision Summary Stat cards */}
      <div className="grid grid-cols-3 gap-4 shrink-0 font-mono">
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            COMPLIANCE RATE
          </span>
          <span className="text-xl font-bold text-vigil-teal">
            {totalLogs > 0 ? ((approvedCount / totalLogs) * 100).toFixed(0) : '100'}% Approved
          </span>
        </div>
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            BLOCKED ATTACKS
          </span>
          <span className="text-xl font-bold text-vigil-red">
            {deniedCount} Containments
          </span>
        </div>
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            SEC-OPS INTENTS
          </span>
          <span className="text-xl font-bold text-white">
            {totalLogs} Events Scanned
          </span>
        </div>
      </div>

      {/* Responsive Split Layout */}
      <div className="flex-1 flex flex-col lg:flex-row gap-6 min-h-0 overflow-hidden">
        {/* Audit ledger Table Container (Left Column) */}
        <div className="flex-[2] border border-vigil-border/30 rounded-xl bg-slate-950/40 overflow-hidden flex flex-col min-h-0">
          <div className="flex-1 overflow-y-auto">
            {filteredLogs.length === 0 ? (
              <div className="h-full flex flex-col justify-center items-center text-center py-12 space-y-2">
                <svg className="w-8 h-8 text-slate-600 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">
                  Ledger Log Stream is Empty
                </span>
              </div>
            ) : (
              <table className="w-full text-left font-mono text-[11px] border-collapse">
                <thead className="bg-slate-950/80 sticky top-0 text-slate-500 uppercase border-b border-vigil-border/30 select-none">
                  <tr>
                    <th className="p-3">ENTRY HASH</th>
                    <th className="p-3">AGENT REFERENCE</th>
                    <th className="p-3">DECISION</th>
                    <th className="p-3">INTELLIGENCE ACTION MATCH</th>
                    <th className="p-3">SEVERITY INDEX</th>
                    <th className="p-3">TIMESTAMP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-vigil-border/10 text-slate-300">
                  {filteredLogs.map((log) => (
                    <tr key={log.entry_id} className="hover:bg-slate-900/20 transition-colors">
                      <td className="p-3 text-[10px] text-slate-500 select-all font-bold">
                        {log.entry_id.substring(0, 16)}
                      </td>
                      <td className="p-3 font-bold text-white uppercase">{log.agent_id}</td>
                      <td className="p-3">{getDecisionBadge(log.decision)}</td>
                      <td className="p-3 font-sans text-slate-400 select-all">{log.action.replace(/_/g, ' ')}</td>
                      <td className="p-3 font-bold select-all">
                        <span className={log.score > 0.6 ? 'text-vigil-red' : log.score > 0.2 ? 'text-vigil-amber' : 'text-vigil-teal'}>
                          {log.score.toFixed(3)}
                        </span>
                      </td>
                      <td className="p-3 text-[10px] text-slate-500 font-bold select-none">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Telegram Governance Panel (Right Column) */}
        <div className="flex-[1] overflow-y-auto min-h-0">
          <TelegramGovernancePanel />
        </div>
      </div>
    </div>
  );
};
