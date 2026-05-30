import React, { useEffect, useState } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';

const ElapsedTimer: React.FC<{ timestamp: number }> = ({ timestamp }) => {
  const [elapsed, setElapsed] = useState(0);
  
  useEffect(() => {
    setElapsed(Math.floor(Date.now() / 1000 - timestamp));
    const interval = setInterval(() => {
      setElapsed(Math.floor(Date.now() / 1000 - timestamp));
    }, 1000);
    return () => clearInterval(interval);
  }, [timestamp]);

  return <span className="font-mono text-[11px] text-slate-400">{elapsed}s elapsed</span>;
};

export const TelegramGovernancePanel: React.FC = () => {
  const {
    telegramStatus,
    pendingApprovals,
    telegramUsers,
    setTelegramStatus,
    setPendingApprovals,
    setTelegramUsers,
    resolvePendingApproval,
  } = useVigilStore();

  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'approvals' | 'operators'>('approvals');

  const refetchData = async () => {
    try {
      const status = await vigilClient.getTelegramStatus();
      setTelegramStatus(status);
      const approvals = await vigilClient.getTelegramApprovals();
      setPendingApprovals(approvals);
      const users = await vigilClient.getTelegramUsers();
      setTelegramUsers(users);
    } catch (err) {
      console.warn('Failed to refresh Telegram governance status:', err);
    }
  };

  useEffect(() => {
    refetchData();
    const interval = setInterval(refetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleResolve = async (requestId: string, action: 'approve' | 'deny') => {
    setResolvingId(requestId);
    try {
      await vigilClient.resolveApproval(requestId, action);
      resolvePendingApproval(requestId, action === 'approve' ? 'APPROVED' : 'DENIED', 0);
      await refetchData();
    } catch (err: any) {
      console.error(err);
      alert(`Error resolving approval: ${err.message || err}`);
    } finally {
      setResolvingId(null);
    }
  };

  return (
    <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 space-y-5 flex flex-col font-sans shrink-0">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-vigil-border/20 pb-4">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <span className="text-xl">📱</span>
            {telegramStatus?.connected ? (
              <span className="absolute -bottom-1 -right-1 flex h-3.5 w-3.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-emerald-500"></span>
              </span>
            ) : (
              <span className="absolute -bottom-1 -right-1 flex h-3.5 w-3.5">
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-rose-500"></span>
              </span>
            )}
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-widest uppercase font-sans flex items-center gap-2">
              TELEGRAM GOVERNED RUNTIME GATEWAY
              {telegramStatus?.bot_username && (
                <span className="text-[10px] lowercase font-mono bg-slate-900 border border-vigil-border/30 px-2 py-0.5 rounded text-slate-400">
                  @{telegramStatus.bot_username}
                </span>
              )}
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Secure mobile operations pipeline governing agent trust escalations in real-time.
            </p>
          </div>
        </div>

        {/* Overnight Sleep Mode status pill */}
        <div className={`text-[10px] font-mono px-3 py-1.5 rounded-lg border flex items-center space-x-2 ${
          telegramStatus?.sleep_mode 
            ? 'bg-indigo-950/40 border-indigo-500/30 text-indigo-300 shadow-[0_0_15px_rgba(99,102,241,0.15)]' 
            : 'bg-slate-900 border-vigil-border/30 text-slate-400'
        }`}>
          <span>{telegramStatus?.sleep_mode ? '🌙 Sleep Mode: ACTIVE (Auto)' : '☀️ Sleep Mode: INACTIVE (Governed)'}</span>
        </div>
      </div>

      {/* Stats Summary Panel */}
      <div className="grid grid-cols-3 gap-4 font-mono">
        <div className="bg-slate-950/60 border border-vigil-border/10 rounded-lg p-2.5 text-center">
          <span className="text-[8px] font-bold text-slate-500 block uppercase">ACTIVE SESSIONS</span>
          <span className="text-base font-bold text-white">{telegramStatus?.active_sessions ?? 0} Operators</span>
        </div>
        <div className="bg-slate-950/60 border border-vigil-border/10 rounded-lg p-2.5 text-center">
          <span className="text-[8px] font-bold text-slate-500 block uppercase">PENDING DECISIONS</span>
          <span className={`text-base font-bold ${pendingApprovals.length > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-400'}`}>
            {pendingApprovals.length} Cards
          </span>
        </div>
        <div className="bg-slate-950/60 border border-vigil-border/10 rounded-lg p-2.5 text-center">
          <span className="text-[8px] font-bold text-slate-500 block uppercase">REGISTRIES ON FILE</span>
          <span className="text-base font-bold text-white">{telegramUsers.length} Users</span>
        </div>
      </div>

      {/* Navigation Buttons for Subpanels */}
      <div className="flex border-b border-vigil-border/10 text-xs font-mono">
        <button
          onClick={() => setActiveSubTab('approvals')}
          className={`pb-2 px-4 border-b-2 transition-all ${
            activeSubTab === 'approvals' 
              ? 'border-vigil-teal text-vigil-teal font-bold' 
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          PENDING APPROVAL QUEUE ({pendingApprovals.length})
        </button>
        <button
          onClick={() => setActiveSubTab('operators')}
          className={`pb-2 px-4 border-b-2 transition-all ${
            activeSubTab === 'operators' 
              ? 'border-vigil-teal text-vigil-teal font-bold' 
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          OPERATOR DIRECTORY ({telegramUsers.length})
        </button>
      </div>

      {/* Subpanels Content */}
      <div className="flex-1 min-h-[180px]">
        {activeSubTab === 'approvals' ? (
          pendingApprovals.length === 0 ? (
            <div className="h-full flex flex-col justify-center items-center py-6 text-center space-y-2">
              <span className="text-[18px]">🛡️</span>
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                No Awaiting Governance Approvals
              </span>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {pendingApprovals.map((req) => (
                <div 
                  key={req.request_id}
                  className="bg-slate-950/80 border border-rose-500/20 rounded-lg p-4 flex flex-col justify-between hover:border-rose-500/40 transition-all shadow-[0_0_10px_rgba(239,68,68,0.05)]"
                >
                  <div className="space-y-2">
                    <div className="flex justify-between items-start">
                      <span className="text-[10px] font-mono font-bold text-rose-400 bg-rose-950/20 px-2 py-0.5 rounded border border-rose-500/20">
                        {req.proposed_action} REQUIRED
                      </span>
                      <ElapsedTimer timestamp={req.requested_at} />
                    </div>

                    <div className="space-y-1 font-mono text-[11px]">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Agent Ref:</span>
                        <span className="text-white font-bold">{req.agent_id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Threat Vector:</span>
                        <span className="text-amber-400 font-bold">{req.threat_type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Severity Index:</span>
                        <span className="text-rose-400 font-bold">{(req.threat_score * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex space-x-2 mt-4 pt-3 border-t border-vigil-border/10 font-mono text-[10px]">
                    <button
                      onClick={() => handleResolve(req.request_id, 'approve')}
                      disabled={resolvingId !== null}
                      className="flex-1 bg-rose-500/10 hover:bg-rose-500 text-rose-400 hover:text-white border border-rose-500/30 rounded py-1.5 transition-all uppercase font-bold"
                    >
                      Approve Confinement
                    </button>
                    <button
                      onClick={() => handleResolve(req.request_id, 'deny')}
                      disabled={resolvingId !== null}
                      className="flex-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-vigil-border/40 rounded py-1.5 transition-all uppercase"
                    >
                      Bypass / Deny
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )
        ) : (
          telegramUsers.length === 0 ? (
            <div className="h-full flex flex-col justify-center items-center py-6 text-center space-y-2">
              <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">
                No Operators Registered
              </span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-[10px] border-collapse">
                <thead>
                  <tr className="border-b border-vigil-border/20 text-slate-500 uppercase">
                    <th className="pb-2">Operator ID</th>
                    <th className="pb-2">Username</th>
                    <th className="pb-2">Role Assigned</th>
                    <th className="pb-2">Security Status</th>
                    <th className="pb-2">Last Active</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-vigil-border/10 text-slate-300">
                  {telegramUsers.map((user) => (
                    <tr key={user.telegram_id} className="hover:bg-slate-900/10 transition-colors">
                      <td className="py-2 text-slate-500 font-bold">{user.telegram_id}</td>
                      <td className="py-2 font-bold text-white">@{user.username || 'unknown'}</td>
                      <td className="py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                          user.role === 'ADMIN' ? 'bg-indigo-950 text-indigo-300 border border-indigo-500/20' :
                          user.role === 'SECURITY_ANALYST' ? 'bg-rose-950 text-rose-300 border border-rose-500/20' :
                          user.role === 'OBSERVER' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/20' :
                          'bg-slate-900 text-slate-400'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="py-2">
                        {user.is_active ? (
                          <span className="text-emerald-400">● Active</span>
                        ) : (
                          <span className="text-slate-500">○ Inactive</span>
                        )}
                      </td>
                      <td className="py-2 text-[9px] text-slate-500">
                        {new Date(user.last_seen * 1000).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </div>
    </div>
  );
};
