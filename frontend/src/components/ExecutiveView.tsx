import React, { useEffect, useState } from 'react';
import { useVigilStore } from '../store';
import { PolicyDecision } from '../types';

interface AuditVerifyState {
  ok: boolean;
  entries: number;
  last_hash: string;
  bad_seq?: number | null;
  reason?: string;
}

export const ExecutiveView: React.FC = () => {
  const { agents, incidents, pendingApprovals, setSelectedIncidentId, setActiveTab } = useVigilStore();
  const [auditVerify, setAuditVerify] = useState<AuditVerifyState | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    fetch('/audit/verify')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setAuditVerify(data);
      })
      .catch(() => {});
  }, []);

  const handleManualVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await fetch('/audit/verify');
      if (res.ok) {
        const data = await res.json();
        setAuditVerify(data);
      }
    } catch {
      // Keep existing state
    } finally {
      setIsVerifying(false);
    }
  };

  const totalAgents = agents.size;
  const quarantinedCount = Array.from(agents.values()).filter(
    (a) => a.status === 'QUARANTINED'
  ).length;

  const totalThreats = incidents.length;
  const activeCount = Math.max(0, totalAgents - quarantinedCount);
  const activeRatio = totalAgents > 0 ? ((activeCount / totalAgents) * 100).toFixed(1) : '100.0';

  // Threats contained = incidents whose containment outcome is QUARANTINED
  const containedIncidents = incidents.filter(
    (i) => i.action_taken === 'QUARANTINE' || (i as any).containment_outcome === 'QUARANTINED'
  );
  const containedCount = containedIncidents.length;
  const containmentRate = totalThreats > 0 ? ((containedCount / totalThreats) * 100).toFixed(1) : '0.0';

  // Compliance rate = APPROVED decisions executed / all decisions, with denominator shown
  const decidedApprovals = pendingApprovals.filter(
    (a) => a.status === 'APPROVED' || a.status === 'DENIED'
  );
  const executedApprovals = pendingApprovals.filter(
    (a) => a.status === 'APPROVED' && (a.containment_outcome === 'QUARANTINED' || a.resolved_at !== null)
  );

  const decidedIncidents = incidents.filter(
    (i) => i.policy_decision === PolicyDecision.APPROVED || i.policy_decision === PolicyDecision.DENIED
  );
  const executedIncidents = incidents.filter(
    (i) => i.policy_decision === PolicyDecision.APPROVED && (i.action_taken === 'QUARANTINE' || i.action_taken === 'ALERT')
  );

  const totalDecisions = decidedApprovals.length > 0 ? decidedApprovals.length : decidedIncidents.length;
  const executedDecisions = decidedApprovals.length > 0 ? executedApprovals.length : executedIncidents.length;
  const complianceRate = totalDecisions > 0 ? ((executedDecisions / totalDecisions) * 100).toFixed(1) : '100.0';

  // Derive distribution of threat types from real incident telemetry
  const threatTypeCounts: Record<string, number> = {};
  for (const inc of incidents) {
    const typeKey = inc.threat_type || 'OTHER';
    threatTypeCounts[typeKey] = (threatTypeCounts[typeKey] || 0) + 1;
  }

  const topThreatTypes = Object.entries(threatTypeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  // Derive SVG trend points from actual incidents over time
  const recentWindow = 8;
  const trendBuckets = Array(recentWindow).fill(0);
  if (incidents.length > 0) {
    const now = Date.now() / 1000;
    const windowSecs = 120; // past 2 minutes
    incidents.forEach((inc) => {
      const diff = Math.max(0, now - inc.timestamp);
      const bucketIdx = Math.min(recentWindow - 1, Math.floor((diff / windowSecs) * recentWindow));
      const targetIdx = recentWindow - 1 - bucketIdx;
      if (targetIdx >= 0 && targetIdx < recentWindow) {
        trendBuckets[targetIdx]++;
      }
    });
  }
  const maxBucket = Math.max(...trendBuckets, 1);
  const chartPoints = trendBuckets
    .map((val, idx) => `${idx * 80},${140 - (val / maxBucket) * 100}`)
    .join(' ');

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6 select-none max-w-6xl mx-auto">
      {/* Narrative header */}
      <div className="space-y-1">
        <h2 className="text-xl font-bold tracking-widest text-white uppercase font-sans">
          EXECUTIVE SEC-OPS INTELLIGENCE PORTAL
        </h2>
        <p className="text-xs text-slate-400 font-sans leading-normal">
          Derived operational safety telemetry, gate governance compliance, and tamper-evident audit status.
        </p>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Active Agent Pipelines */}
        <div
          title="Number of registered agents currently operating in NORMAL status vs total agents."
          className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[110px] hover:border-vigil-teal/60 transition-colors cursor-help"
        >
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-400 tracking-widest uppercase">
              OPERATIONAL AGENTS
            </span>
            <span className="text-vigil-teal text-xs font-mono font-bold">LIVE</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{activeCount}</span>
            <span className="text-xs text-slate-400">/ {totalAgents} Registered</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {activeRatio}% operational availability
          </div>
        </div>

        {/* KPI 2: Quarantined Isolations */}
        <div
          title="Number of agents currently isolated under QUARANTINED status (released only by human operator)."
          className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[110px] hover:border-vigil-red/60 transition-colors cursor-help"
        >
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-400 tracking-widest uppercase">
              QUARANTINE ISOLATIONS
            </span>
            <span className="text-vigil-red text-xs font-mono font-bold">ISOLATED</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black font-sans text-vigil-red">{quarantinedCount}</span>
            <span className="text-xs text-slate-400">Active Isolations</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Human release action required
          </div>
        </div>

        {/* KPI 3: Threats Contained (derived, not hardcoded 100%) */}
        <div
          title="Security incidents whose containment outcome is QUARANTINED, divided by total recorded incidents."
          className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[110px] hover:border-vigil-teal/60 transition-colors cursor-help"
        >
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-400 tracking-widest uppercase">
              THREATS CONTAINED
            </span>
            <span className="text-vigil-teal text-xs font-mono font-bold">{containmentRate}%</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{containedCount}</span>
            <span className="text-xs text-slate-400">/ {totalThreats} Incidents</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Outcome verified quarantined
          </div>
        </div>

        {/* KPI 4: Compliance Rate (APPROVED decisions executed / all decisions) */}
        <div
          title="Compliance rate = APPROVED governance decisions that were executed, divided by all decisions, showing the full denominator."
          className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[110px] hover:border-vigil-purple/60 transition-colors cursor-help"
        >
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-400 tracking-widest uppercase">
              COMPLIANCE RATE
            </span>
            <span className="text-vigil-purple text-xs font-mono font-bold">GOVERNED</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{complianceRate}%</span>
            <span className="text-xs text-slate-400">Executed</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {executedDecisions} / {totalDecisions} decisions executed
          </div>
        </div>
      </div>

      {/* Main Charts & Analytics Block */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend line Chart (2 columns wide) */}
        <div className="lg:col-span-2 bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between h-[300px]">
          <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3">
            <div>
              <span className="text-[10px] text-slate-400 font-mono font-bold uppercase block">
                ANOMALY RATE TELEMETRY TRENDS
              </span>
              <span className="text-[8px] text-slate-500 block">
                Derived scan volumes and security intercept frequency across observation window
              </span>
            </div>
            <span className="bg-slate-800 text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded font-semibold uppercase">
              8-Period Interval ({incidents.length} Events)
            </span>
          </div>

          {/* SVG Vector chart */}
          <div className="flex-1 relative mt-4">
            <svg className="w-full h-[150px] overflow-visible" strokeWidth="2.5" fill="none">
              <line x1="0" y1="20" x2="600" y2="20" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />
              <line x1="0" y1="70" x2="600" y2="70" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />
              <line x1="0" y1="120" x2="600" y2="120" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />

              <defs>
                <linearGradient id="chart-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00f2fe" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#00f2fe" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path
                d={`M 0,140 L ${chartPoints} L 560,140 Z`}
                fill="url(#chart-grad)"
                className="pointer-events-none"
              />
              <path
                d={`M ${chartPoints}`}
                stroke="#00f2fe"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>

          <div className="flex justify-between font-mono text-[9px] text-slate-500 border-t border-vigil-border/10 pt-2">
            <span>T-120s WINDOW</span>
            <span>T-60s MIDPOINT</span>
            <span>LIVE STREAM</span>
          </div>
        </div>

        {/* Real Threat Distribution List (1 column wide, derived from actual incidents) */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between h-[300px]">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-vigil-border/20">
              <span className="text-[10px] text-slate-400 font-mono font-bold uppercase block">
                THREAT PROFILE BREAKDOWN
              </span>
              <span className="text-[9px] font-mono text-slate-500">
                {totalThreats} Logged
              </span>
            </div>

            <div className="space-y-3.5 mt-4 text-[11px] font-sans">
              {topThreatTypes.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-xs font-mono">
                  No security incidents recorded.
                </div>
              ) : (
                topThreatTypes.map(([typeKey, count], idx) => {
                  const pct = totalThreats > 0 ? Math.round((count / totalThreats) * 100) : 0;
                  const colors = ['bg-vigil-teal', 'bg-vigil-purple', 'bg-vigil-red', 'bg-vigil-amber'];
                  const barColor = colors[idx % colors.length];
                  const label = typeKey.replace(/_/g, ' ');

                  return (
                    <div key={typeKey} className="space-y-1">
                      <div className="flex justify-between text-slate-300 font-mono text-[10px]">
                        <span className="capitalize">{label.toLowerCase()}</span>
                        <span className="font-bold">{count} ({pct}%)</span>
                      </div>
                      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div className={`h-full ${barColor} rounded-full transition-all duration-300`} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Derived Audit Readiness status */}
          <div
            title="Cryptographic verification status of the hash-chained audit ledger (/audit/verify)"
            className="pt-3 border-t border-vigil-border/20 flex items-center justify-between font-mono text-[9px] cursor-help"
          >
            <span className="text-slate-400">
              LEDGER VERIFY: {auditVerify?.entries ?? 0} BLOCKS
            </span>
            {auditVerify?.ok ? (
              <span className="text-vigil-teal font-bold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-vigil-teal animate-pulse" />
                TAMPER-EVIDENT: VALID
              </span>
            ) : auditVerify === null ? (
              <span className="text-slate-500 font-bold">CONNECTING...</span>
            ) : (
              <span className="text-vigil-red font-bold">CORRUPTED (SEQ {auditVerify.bad_seq})</span>
            )}
          </div>
        </div>
      </div>

      {/* Lower Area: Recent Incidents, Pending Approvals, Ledger Status (P1-5) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 pt-2">
        {/* Recent Incidents (2 columns wide) */}
        <div className="lg:col-span-2 bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-vigil-teal" />
              <h3 className="text-xs uppercase font-mono font-bold tracking-wider text-white">
                Recent Security Intercepts
              </h3>
            </div>
            <button
              onClick={() => setActiveTab('operations')}
              className="text-[10px] text-vigil-teal font-mono hover:underline uppercase"
            >
              View All Stream →
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 mt-3 font-mono text-xs">
            {incidents.slice(0, 4).length === 0 ? (
              <div className="text-center py-6 text-slate-500 text-xs font-mono">
                No recent security incidents logged.
              </div>
            ) : (
              incidents.slice(0, 4).map((inc) => (
                <div
                  key={inc.incident_id}
                  onClick={() => {
                    setSelectedIncidentId(inc.incident_id);
                    setActiveTab('operations');
                  }}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-900/40 px-2 rounded cursor-pointer transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <span className="text-[11px] font-bold text-white uppercase">{inc.agent_id}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {inc.threat_type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className={`text-[10px] font-bold ${
                      inc.policy_decision === PolicyDecision.APPROVED ? 'text-vigil-teal' :
                      inc.policy_decision === PolicyDecision.DENIED ? 'text-vigil-red' : 'text-vigil-amber'
                    }`}>
                      {inc.policy_decision}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                      inc.action_taken === 'QUARANTINE' ? 'bg-vigil-red/20 text-vigil-red border border-vigil-red/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {inc.action_taken === 'QUARANTINE' ? 'QUARANTINED' : inc.action_taken}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Ledger & Governance Summary (1 column wide) */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3">
              <h3 className="text-xs uppercase font-mono font-bold tracking-wider text-white">
                Tamper-Evident Ledger
              </h3>
              <button
                disabled={isVerifying}
                onClick={handleManualVerify}
                className="px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-50"
              >
                {isVerifying ? 'Checking...' : 'Verify Chain'}
              </button>
            </div>

            <div className="mt-4 space-y-3 font-mono text-[10px]">
              <div>
                <span className="text-slate-500 block">LEDGER STATUS</span>
                <span className={`font-bold text-xs ${auditVerify?.ok ? 'text-vigil-teal' : 'text-vigil-red'}`}>
                  {auditVerify?.ok ? '✓ CRYPTOGRAPHICALLY SECURED' : 'UNVERIFIED'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">TOTAL RECORDED BLOCKS</span>
                <span className="text-white text-xs font-bold">{auditVerify?.entries ?? 0} chain records</span>
              </div>
              <div>
                <span className="text-slate-500 block">LATEST BLOCK DIGEST</span>
                <span className="text-slate-400 text-[9px] break-all block bg-slate-900 p-1.5 rounded border border-slate-800 mt-1">
                  {auditVerify?.last_hash ? auditVerify.last_hash.slice(0, 32) + '...' : 'GENESIS'}
                </span>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-vigil-border/20 text-[9px] text-slate-500 font-mono">
            Pending governance approvals: <span className="text-white font-bold">{pendingApprovals.length}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
