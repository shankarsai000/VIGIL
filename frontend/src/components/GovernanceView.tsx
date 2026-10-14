import React, { useState, useEffect } from 'react';
import { useVigilStore } from '../store';
import { PolicyDecision } from '../types';
import { vigilClient } from '../api';
import { formatRelativeTime, formatAbsoluteTooltip } from '../utils/governanceBadges';
import { TelegramGovernancePanel } from './TelegramGovernancePanel';

export const GovernanceView: React.FC = () => {
  const { auditLog } = useVigilStore();
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | 'APPROVED' | 'DENIED' | 'ESCALATE'>('ALL');
  
  // Ledger verification state (P1-7)
  const [verification, setVerification] = useState<{
    ok: boolean;
    entries: number;
    last_hash: string | null;
    bad_seq: number | null;
    reason: string | null;
  } | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const runVerification = async () => {
    setIsVerifying(true);
    setVerifyError(null);
    try {
      const res = await vigilClient.verifyAuditLedger();
      setVerification(res);
    } catch (err: any) {
      setVerifyError(err.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  useEffect(() => {
    runVerification();
  }, []);

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
            Tamper-evident audit ledger
          </h2>
          <p className="text-xs text-slate-500 font-sans leading-normal">
            Cryptographically hash-chained execution logs verified against the ArmorIQ ledger.
          </p>
        </div>

        {/* Audit Filter selector */}
        <div className="flex items-center space-x-1 bg-slate-900/60 p-1 border border-vigil-border/40 rounded-lg text-xs font-mono shrink-0">
          <button
            onClick={() => setDecisionFilter('ALL')}
            className={`px-3 py-1 rounded transition-colors whitespace-nowrap ${decisionFilter === 'ALL' ? 'bg-vigil-teal text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            ALL ({totalLogs})
          </button>
          <button
            onClick={() => setDecisionFilter('APPROVED')}
            className={`px-3 py-1 rounded transition-colors whitespace-nowrap ${decisionFilter === 'APPROVED' ? 'bg-vigil-teal text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            APPROVED ({approvedCount})
          </button>
          <button
            onClick={() => setDecisionFilter('DENIED')}
            className={`px-3 py-1 rounded transition-colors whitespace-nowrap ${decisionFilter === 'DENIED' ? 'bg-vigil-red text-white font-bold shadow-[0_0_10px_rgba(255,42,95,0.2)]' : 'text-slate-400 hover:text-white'}`}
          >
            DENIED ({deniedCount})
          </button>
          <button
            onClick={() => setDecisionFilter('ESCALATE')}
            className={`px-3 py-1 rounded transition-colors whitespace-nowrap ${decisionFilter === 'ESCALATE' ? 'bg-vigil-amber text-black font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            ESCALATED ({escalatedCount})
          </button>
        </div>
      </div>

      {/* P1-7 Tamper-Evident Ledger Integrity Bar */}
      <div className="bg-slate-950/60 border border-vigil-border/40 rounded-xl p-3.5 flex flex-wrap items-center justify-between gap-4 font-mono text-xs shrink-0 shadow-lg">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider">LEDGER STATUS:</span>
            {verification ? (
              verification.ok ? (
                <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-vigil-teal/10 border border-vigil-teal/40 text-vigil-teal font-bold text-[11px]">
                  <span className="w-2 h-2 rounded-full bg-vigil-teal shadow-[0_0_8px_rgba(0,242,254,0.6)] animate-pulse" />
                  <span>VALID (OK)</span>
                </div>
              ) : (
                <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/40 text-rose-400 font-bold text-[11px]">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                  <span>BROKEN (SEQ #{verification.bad_seq}: {verification.reason})</span>
                </div>
              )
            ) : verifyError ? (
              <span className="text-rose-400 font-bold text-[11px]">{verifyError}</span>
            ) : (
              <span className="text-slate-500 text-[11px]">INITIALIZING...</span>
            )}
          </div>

          <div className="h-4 w-[1px] bg-vigil-border/40 hidden sm:block" />

          <div className="flex items-center space-x-2">
            <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider">CHAIN LENGTH:</span>
            <span className="text-white font-bold">{verification ? `${verification.entries} entries` : '—'}</span>
          </div>

          <div className="h-4 w-[1px] bg-vigil-border/40 hidden md:block" />

          <div className="flex items-center space-x-2">
            <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider">LAST HASH:</span>
            <span className="text-slate-300 font-mono text-[10px] max-w-[180px] truncate" title={verification?.last_hash || 'None'}>
              {verification?.last_hash ? `${verification.last_hash.substring(0, 16)}...` : 'genesis'}
            </span>
          </div>
        </div>

        <button
          onClick={runVerification}
          disabled={isVerifying}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono uppercase font-bold transition-all shadow-md ${
            isVerifying
              ? 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed'
              : 'bg-vigil-teal/15 text-vigil-teal border-vigil-teal/40 hover:bg-vigil-teal/25 hover:border-vigil-teal shadow-[0_0_12px_rgba(0,242,254,0.2)]'
          }`}
          title="Recomputes the cryptographic hash chain of the entire audit ledger from disk"
        >
          <svg className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <span>{isVerifying ? 'Verifying...' : 'Verify Ledger'}</span>
        </button>
      </div>

      {/* Decision Summary Stat cards with Denominators */}
      <div className="grid grid-cols-3 gap-4 shrink-0 font-mono">
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center" title="Approved decisions that were executed, divided by all decisions with denominator">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            COMPLIANCE RATE
          </span>
          <span className="text-xl font-bold text-vigil-teal">
            {totalLogs > 0 ? `${((approvedCount / totalLogs) * 100).toFixed(0)}%` : '0%'}
          </span>
          <span className="text-[10px] text-slate-400 block mt-0.5">
            {approvedCount} of {totalLogs} approved
          </span>
        </div>
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center" title="Incidents denied by ArmorIQ policy enforcement">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            BLOCKED ATTACKS
          </span>
          <span className="text-xl font-bold text-vigil-red">
            {deniedCount}
          </span>
          <span className="text-[10px] text-slate-400 block mt-0.5">
            policy denied
          </span>
        </div>
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-3 text-center" title="Total security events evaluated by ArmorIQ rules">
          <span className="text-[9px] font-bold text-slate-500 block uppercase">
            SEC-OPS INTENTS
          </span>
          <span className="text-xl font-bold text-white">
            {totalLogs}
          </span>
          <span className="text-[10px] text-slate-400 block mt-0.5">
            events scanned
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
                    <th className="p-3">INCIDENT</th>
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
                      <td className="p-3 text-[10px] text-slate-400 select-all font-bold">
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
                      <td
                        className="p-3 text-[10px] text-slate-400 font-bold select-none cursor-help hover:text-slate-200 transition-colors"
                        title={formatAbsoluteTooltip(log.timestamp)}
                      >
                        {formatRelativeTime(log.timestamp)}
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
