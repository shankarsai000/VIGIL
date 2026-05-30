import React from 'react';
import { useVigilStore } from '../store';

export const ExecutiveView: React.FC = () => {
  const { agents, incidents } = useVigilStore();

  const totalAgents = agents.size;
  const quarantinedCount = Array.from(agents.values()).filter(
    (a) => a.status === 'QUARANTINED'
  ).length;

  const totalThreats = incidents.length;
  const activeCount = totalAgents - quarantinedCount;
  const integrity = totalAgents > 0 ? ((activeCount / totalAgents) * 100).toFixed(1) : '100.0';

  // SVG grid lines and threat trendline data
  const trendPoints = [20, 45, 15, 60, 30, 80, 40, 95];
  const chartPoints = trendPoints.map((val, idx) => `${idx * 80},${140 - (val / 100) * 110}`).join(' ');

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6 select-none max-w-5xl mx-auto">
      {/* Narrative header */}
      <div className="space-y-1">
        <h2 className="text-xl font-bold tracking-widest text-white uppercase font-sans">
          EXECUTIVE SEC-OPS INTELLIGENCE PORTAL
        </h2>
        <p className="text-xs text-slate-500 font-sans leading-normal">
          Strategic executive overview of AI pipeline safety factor, threat mitigation latencies, and autonomous compliance index.
        </p>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* KPI 1 */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[100px] hover:border-vigil-teal/60 transition-colors">
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-500 tracking-widest uppercase">
              ACTIVE AGENT PIPELINES
            </span>
            <span className="text-vigil-teal text-xs font-mono font-bold">LIVE</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{activeCount}</span>
            <span className="text-xs text-slate-500">/ {totalAgents} Registered</span>
          </div>
        </div>

        {/* KPI 2 */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[100px] hover:border-vigil-red/60 transition-colors">
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-500 tracking-widest uppercase">
              QUARANTINE ISOLATIONS
            </span>
            <span className="text-vigil-red text-xs font-mono font-bold">CONTAINED</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black font-sans text-vigil-red">{quarantinedCount}</span>
            <span className="text-xs text-slate-500">Manual Isolated</span>
          </div>
        </div>

        {/* KPI 3 */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[100px] hover:border-vigil-teal/60 transition-colors">
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-500 tracking-widest uppercase">
              THREATS CONTAINED
            </span>
            <span className="text-vigil-teal text-xs font-mono font-bold">✓ 100%</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{totalThreats}</span>
            <span className="text-xs text-slate-500">Zero Bypass Logs</span>
          </div>
        </div>

        {/* KPI 4 */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden h-[100px] hover:border-vigil-purple/60 transition-colors">
          <div className="flex justify-between items-start">
            <span className="text-[9px] font-mono font-bold text-slate-500 tracking-widest uppercase">
              SHIELD INTEGRITY FACTOR
            </span>
            <span className="text-vigil-purple text-xs font-mono font-bold">OPTIMAL</span>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white font-sans">{integrity}%</span>
            <span className="text-xs text-slate-500">Overall Core Safe</span>
          </div>
        </div>
      </div>

      {/* Main Charts & Analytics Block */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Trend line Chart (2 columns wide) */}
        <div className="lg:col-span-2 bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between h-[300px]">
          <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3">
            <div>
              <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block">
                ANOMALY RATE TELEMETRY TRENDS
              </span>
              <span className="text-[8px] text-slate-600 block">
                Real-time tracking of scan request volumes vs mitigation intercepts
              </span>
            </div>
            <span className="bg-slate-800 text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded font-semibold uppercase">
              8-Period Interval
            </span>
          </div>

          {/* SVG Vector chart */}
          <div className="flex-1 relative mt-4">
            <svg className="w-full h-[150px] overflow-visible" strokeWidth="2.5" fill="none">
              {/* Horizontal helper lines */}
              <line x1="0" y1="20" x2="600" y2="20" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />
              <line x1="0" y1="70" x2="600" y2="70" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />
              <line x1="0" y1="120" x2="600" y2="120" stroke="#1e293b" strokeDasharray="3,6" strokeWidth="1" />

              {/* Sparkline Gradient fill */}
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

              {/* Glowing vector line */}
              <path
                d={`M ${chartPoints}`}
                stroke="#00f2fe"
                strokeLinecap="round"
                strokeLinejoin="round"
                filter="url(#glow-teal-svg)"
              />
            </svg>
          </div>

          <div className="flex justify-between font-mono text-[9px] text-slate-500 border-t border-vigil-border/10 pt-2">
            <span>INT-1: START UP</span>
            <span>INT-4: SIMULATION LOGGED</span>
            <span>INT-8: STEADY STATE STATUS</span>
          </div>
        </div>

        {/* Boardroom Threat Distribution List (1 column wide) */}
        <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col justify-between h-[300px]">
          <div>
            <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block pb-3 border-b border-vigil-border/20">
              MITIGATION RISK PIECES
            </span>
            <div className="space-y-4 mt-4 text-[11px] font-sans">
              <div className="space-y-1">
                <div className="flex justify-between text-slate-300 font-mono text-[10px]">
                  <span>Prompt Injection Mitigations:</span>
                  <span className="font-bold">85% Rule Weight</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-vigil-teal rounded-full" style={{ width: '85%' }} />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-slate-300 font-mono text-[10px]">
                  <span>Rate Limit Exceedances:</span>
                  <span className="font-bold">60% Rule Weight</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-vigil-purple rounded-full" style={{ width: '60%' }} />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-slate-300 font-mono text-[10px]">
                  <span>Data Isolation Scans:</span>
                  <span className="font-bold">45% Rule Weight</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-vigil-red rounded-full" style={{ width: '45%' }} />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-vigil-border/20 flex items-center justify-between font-mono text-[9px] text-slate-500">
            <span>AUDIT READINESS: READY</span>
            <span className="text-vigil-teal font-bold">COMPLIANT</span>
          </div>
        </div>
      </div>
    </div>
  );
};
