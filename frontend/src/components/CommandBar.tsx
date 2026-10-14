import React, { useEffect, useState } from 'react';
import { useVigilStore } from '../store';

export const CommandBar: React.FC = () => {
  const { activeTab, setActiveTab, connected, incidents, agents, telegramStatus, pendingApprovals } = useVigilStore();
  const [time, setTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      setTime(d.toLocaleTimeString('en-US', { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const quarantinedCount = Array.from(agents.values()).filter(
    (a) => a.status === 'QUARANTINED'
  ).length;

  const totalThreats = incidents.length;

  return (
    <header className="h-[56px] border-b border-vigil-border/40 glass-panel flex items-center justify-between px-6 select-none z-50 relative shrink-0">
      {/* Brand logo & status */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-vigil-purple to-vigil-teal flex items-center justify-center font-bold text-lg text-black shadow-[0_0_15px_rgba(0,242,254,0.3)] animate-glow-pulse select-none" style={{ '--glow-color': '#00f2fe' } as React.CSSProperties}>
            V
          </div>
          <span className="font-bold font-sans tracking-widest text-lg text-white">VIGIL</span>
        </div>
        <div className="h-4 w-[1px] bg-vigil-border/50"></div>
        <div className="flex items-center space-x-2">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-vigil-teal animate-pulse"></span>
          <span className="text-[10px] text-vigil-teal tracking-widest font-mono uppercase font-bold">ARMORIQ GOVERNED</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-1 bg-slate-900/60 p-1 border border-vigil-border/30 rounded-lg">
        <button
          onClick={() => setActiveTab('operations')}
          className={`px-4 py-1.5 text-xs font-semibold tracking-wider font-mono rounded-md uppercase transition-all duration-200 ${
            activeTab === 'operations'
              ? 'bg-vigil-teal text-black shadow-[0_0_12px_rgba(0,242,254,0.2)] font-bold'
              : 'text-vigil-muted hover:text-white hover:bg-slate-800/40'
          }`}
        >
          Operations Center
        </button>
        <button
          onClick={() => setActiveTab('replay')}
          className={`px-4 py-1.5 text-xs font-semibold tracking-wider font-mono rounded-md uppercase transition-all duration-200 ${
            activeTab === 'replay'
              ? 'bg-vigil-teal text-black shadow-[0_0_12px_rgba(0,242,254,0.2)] font-bold'
              : 'text-vigil-muted hover:text-white hover:bg-slate-800/40'
          }`}
        >
          Threat Replay
        </button>
        <button
          onClick={() => setActiveTab('governance')}
          className={`px-4 py-1.5 text-xs font-semibold tracking-wider font-mono rounded-md uppercase transition-all duration-200 ${
            activeTab === 'governance'
              ? 'bg-vigil-teal text-black shadow-[0_0_12px_rgba(0,242,254,0.2)] font-bold'
              : 'text-vigil-muted hover:text-white hover:bg-slate-800/40'
          }`}
        >
          Governance
        </button>
        <button
          onClick={() => setActiveTab('executive')}
          className={`px-4 py-1.5 text-xs font-semibold tracking-wider font-mono rounded-md uppercase transition-all duration-200 ${
            activeTab === 'executive'
              ? 'bg-vigil-teal text-black shadow-[0_0_12px_rgba(0,242,254,0.2)] font-bold'
              : 'text-vigil-muted hover:text-white hover:bg-slate-800/40'
          }`}
        >
          Executive
        </button>
        <button
          onClick={() => setActiveTab('threat_intel')}
          className={`px-4 py-1.5 text-xs font-semibold tracking-wider font-mono rounded-md uppercase transition-all duration-200 ${
            activeTab === 'threat_intel'
              ? 'bg-vigil-teal text-black shadow-[0_0_12px_rgba(0,242,254,0.2)] font-bold'
              : 'text-vigil-muted hover:text-white hover:bg-slate-800/40'
          }`}
        >
          Threat Intelligence
        </button>
      </div>

      {/* Telemetry/System status bar */}
      <div className="flex items-center space-x-6">
        {/* Statistics highlights */}
        <div className="hidden lg:flex items-center space-x-4 font-mono text-[11px]">
          <div className="flex flex-col items-end">
            <span className="text-vigil-muted text-[9px] uppercase">CONTAINMENT</span>
            <span className={`font-bold ${quarantinedCount > 0 ? 'text-vigil-red' : 'text-vigil-muted'}`}>
              {quarantinedCount} QUARANTINED
            </span>
          </div>
          <div className="h-6 w-[1px] bg-vigil-border/30"></div>
          <div className="flex flex-col items-end">
            <span className="text-vigil-muted text-[9px] uppercase">THREAT LOGS</span>
            <span className="text-white font-bold">{totalThreats} PREVENTED</span>
          </div>
        </div>

        <div className="h-6 w-[1px] bg-vigil-border/30 hidden lg:block"></div>

        {/* Live Clock */}
        <div className="flex items-center space-x-2 text-vigil-muted font-mono text-xs">
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 6v6l4 2" />
          </svg>
          <span className="text-white font-bold tracking-widest">{time}</span>
        </div>

        {/* Connection status */}
        <div className="flex items-center space-x-2 pl-2">
          <div className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-vigil-teal shadow-[0_0_8px_rgba(0,242,254,0.5)] animate-pulse' : 'bg-vigil-red animate-ping'}`} />
          <span className="text-[10px] tracking-wider uppercase font-mono font-semibold">
            {connected ? 'CONNECTED' : 'DISCONNECTED'}
          </span>
        </div>

        {/* Telegram status */}
        <div className="flex items-center space-x-2 border-l border-vigil-border/30 pl-4 font-mono text-[10px] select-none relative">
          <span className="text-sm">📱</span>
          <div className={`w-2 h-2 rounded-full ${telegramStatus?.connected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-rose-500'}`} />
          <span className="text-slate-400 font-semibold tracking-wider">
            {telegramStatus?.connected ? 'BOT: ACTIVE' : 'BOT: OFFLINE'}
          </span>
          {pendingApprovals.length > 0 && (
            <span className="absolute -top-3.5 -right-2 bg-rose-500 text-white font-bold text-[8px] min-w-[15px] h-[15px] rounded-full flex items-center justify-center animate-bounce shadow-[0_0_8px_rgba(239,68,68,0.6)]">
              {pendingApprovals.length}
            </span>
          )}
        </div>
      </div>
    </header>
  );
};
