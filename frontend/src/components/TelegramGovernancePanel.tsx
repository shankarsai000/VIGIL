import React, { useEffect, useState, useMemo } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';
import { ApprovalRequest } from '../types';
import { approvalPreview } from '../utils/governanceBadges';

const ElapsedTimer: React.FC<{ timestamp: number }> = ({ timestamp }) => {
  const [elapsed, setElapsed] = useState(0);
  
  useEffect(() => {
    setElapsed(Math.floor(Date.now() / 1000 - timestamp));
    const interval = setInterval(() => {
      setElapsed(Math.floor(Date.now() / 1000 - timestamp));
    }, 1000);
    return () => clearInterval(interval);
  }, [timestamp]);

  return <span className="font-mono text-[10px] text-slate-400">{elapsed}s elapsed</span>;
};

const ExpiryTimer: React.FC<{ requestedAt: number }> = ({ requestedAt }) => {
  const [secondsLeft, setSecondsLeft] = useState(() => Math.max(0, Math.floor(requestedAt + 300 - Date.now() / 1000)));

  useEffect(() => {
    const update = () => {
      const left = Math.max(0, Math.floor(requestedAt + 300 - Date.now() / 1000));
      setSecondsLeft(left);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [requestedAt]);

  if (secondsLeft <= 0) {
    return (
      <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-600/30 font-bold">
        EXPIRED
      </span>
    );
  }

  return (
    <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-slate-900 text-amber-300 border border-amber-600/30 font-semibold">
      ⏱ {secondsLeft}s expiry
    </span>
  );
};

export const TelegramGovernancePanel: React.FC = () => {
  const {
    telegramStatus,
    pendingApprovals,
    telegramUsers,
    gateMode,
    setTelegramStatus,
    setPendingApprovals,
    setTelegramUsers,
    resolvePendingApproval,
  } = useVigilStore();

  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'approvals' | 'history' | 'operators'>('approvals');
  const [allApprovals, setAllApprovals] = useState<any[]>([]);
  
  // Collapse state (defaults to collapsed if telegram is not configured)
  const isConfigured = Boolean(telegramStatus?.connected || telegramStatus?.bot_username);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(!isConfigured);

  // Bulk action confirmation modal state
  const [bulkModal, setBulkModal] = useState<{
    action: 'approve' | 'deny';
    reqIds: string[];
    count: number;
    agentCount: number;
  } | null>(null);
  const [isBulkProcessing, setIsBulkProcessing] = useState(false);

  const refetchData = async () => {
    try {
      const status = await vigilClient.getTelegramStatus();
      setTelegramStatus(status);
      const approvals = await vigilClient.getTelegramApprovals();
      setPendingApprovals(approvals);
      const users = await vigilClient.getTelegramUsers();
      setTelegramUsers(users);
      const all = await vigilClient.getAllTelegramApprovals(25);
      setAllApprovals(all);
    } catch (err) {
      console.warn('Failed to refresh Telegram governance status:', err);
    }
  };

  useEffect(() => {
    refetchData();
    const interval = setInterval(refetchData, 4000);
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

  // Group pending approvals by agent and incident, deduplicating repeated request IDs
  const { groupedByAgent, totalUniqueCount, allUniqueReqIds } = useMemo(() => {
    const seen = new Set<string>();
    const uniqueReqs: ApprovalRequest[] = [];
    for (const r of pendingApprovals) {
      if (!seen.has(r.request_id)) {
        seen.add(r.request_id);
        uniqueReqs.push(r);
      }
    }

    const byAgent: Record<string, {
      agentId: string;
      incidents: {
        incidentId: string;
        latest: ApprovalRequest;
        requests: ApprovalRequest[];
        count: number;
      }[];
    }> = {};

    const uniqueIds: string[] = [];

    for (const req of uniqueReqs) {
      uniqueIds.push(req.request_id);
      if (!byAgent[req.agent_id]) {
        byAgent[req.agent_id] = { agentId: req.agent_id, incidents: [] };
      }
      const existing = byAgent[req.agent_id].incidents.find((i) => i.incidentId === req.incident_id);
      if (existing) {
        existing.requests.push(req);
        existing.count += 1;
        if (req.requested_at > existing.latest.requested_at) {
          existing.latest = req;
        }
      } else {
        byAgent[req.agent_id].incidents.push({
          incidentId: req.incident_id,
          latest: req,
          requests: [req],
          count: 1,
        });
      }
    }

    return {
      groupedByAgent: byAgent,
      totalUniqueCount: uniqueReqs.length,
      allUniqueReqIds: uniqueIds,
    };
  }, [pendingApprovals]);

  // Execute bulk action
  const handleConfirmBulk = async () => {
    if (!bulkModal) return;
    setIsBulkProcessing(true);
    try {
      if (vigilClient.bulkResolveApprovals) {
        await vigilClient.bulkResolveApprovals(bulkModal.reqIds, bulkModal.action);
      } else {
        for (const id of bulkModal.reqIds) {
          await vigilClient.resolveApproval(id, bulkModal.action);
        }
      }
      for (const id of bulkModal.reqIds) {
        resolvePendingApproval(id, bulkModal.action === 'approve' ? 'APPROVED' : 'DENIED', 0);
      }
      await refetchData();
      setBulkModal(null);
    } catch (err: any) {
      console.error('Failed bulk resolve:', err);
      alert(`Bulk resolution error: ${err.message || err}`);
    } finally {
      setIsBulkProcessing(false);
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
              {telegramStatus?.bot_username ? (
                <span className="text-[10px] lowercase font-mono bg-slate-900 border border-vigil-border/30 px-2 py-0.5 rounded text-slate-400">
                  @{telegramStatus.bot_username}
                </span>
              ) : (
                <span className="text-[9px] font-mono bg-amber-950/50 border border-amber-600/30 px-2 py-0.5 rounded text-amber-400">
                  NOT CONFIGURED
                </span>
              )}
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Secure mobile operations pipeline governing agent trust escalations with verified containment outcomes.
            </p>
          </div>
        </div>

        {/* Collapse toggle */}
        <div className="flex items-center space-x-2">
          {!isConfigured && (
            <span className="text-[9px] font-mono text-slate-500">
              {isCollapsed ? 'Panel collapsed (unconfigured)' : 'Expanded'}
            </span>
          )}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="px-2.5 py-1 text-[10px] font-mono font-bold uppercase rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-vigil-border/40 flex items-center space-x-1 transition-colors"
          >
            <span>{isCollapsed ? 'Expand Panel' : 'Collapse Panel'}</span>
            <svg className={`w-3.5 h-3.5 transition-transform duration-200 ${isCollapsed ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      </div>

      {!isCollapsed && (
        <>
          {/* Navigation Buttons for Subpanels */}
          <div className="flex items-center justify-between border-b border-vigil-border/10 text-xs font-mono space-x-1 pb-2">
            <div className="flex space-x-1">
              <button
                onClick={() => setActiveSubTab('approvals')}
                className={`pb-1 px-3 border-b-2 transition-all ${
                  activeSubTab === 'approvals' 
                    ? 'border-vigil-teal text-vigil-teal font-bold' 
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                PENDING QUEUE ({totalUniqueCount})
              </button>
              <button
                onClick={() => setActiveSubTab('history')}
                className={`pb-1 px-3 border-b-2 transition-all ${
                  activeSubTab === 'history' 
                    ? 'border-vigil-teal text-vigil-teal font-bold' 
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                CONTAINMENT AUDIT LOG ({allApprovals.length})
              </button>
              <button
                onClick={() => setActiveSubTab('operators')}
                className={`pb-1 px-3 border-b-2 transition-all ${
                  activeSubTab === 'operators' 
                    ? 'border-vigil-teal text-vigil-teal font-bold' 
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                OPERATOR DIRECTORY ({telegramUsers.length})
              </button>
            </div>

            {/* Bulk Action Trigger Buttons (P1-2) */}
            {activeSubTab === 'approvals' && totalUniqueCount > 0 && (
              <div className="flex items-center space-x-2">
                <button
                  onClick={() =>
                    setBulkModal({
                      action: 'approve',
                      reqIds: allUniqueReqIds,
                      count: totalUniqueCount,
                      agentCount: Object.keys(groupedByAgent).length,
                    })
                  }
                  className="px-2.5 py-1 text-[9.5px] font-mono font-bold uppercase rounded bg-teal-500/15 hover:bg-teal-500/30 text-teal-300 border border-teal-500/40 transition-colors"
                >
                  ✓ Bulk Approve All ({totalUniqueCount})
                </button>
                <button
                  onClick={() =>
                    setBulkModal({
                      action: 'deny',
                      reqIds: allUniqueReqIds,
                      count: totalUniqueCount,
                      agentCount: Object.keys(groupedByAgent).length,
                    })
                  }
                  className="px-2.5 py-1 text-[9.5px] font-mono font-bold uppercase rounded bg-rose-500/15 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 transition-colors"
                >
                  ✕ Bulk Deny All ({totalUniqueCount})
                </button>
              </div>
            )}
          </div>

          {/* Subpanels Content */}
          <div className="flex-1 min-h-[180px]">
            {activeSubTab === 'approvals' ? (
              totalUniqueCount === 0 ? (
                <div className="h-full flex flex-col justify-center items-center py-6 text-center space-y-2">
                  <span className="text-[18px]">🛡️</span>
                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                    No Awaiting Governance Approvals
                  </span>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Grouped by Agent */}
                  {Object.values(groupedByAgent).map((agentGroup) => (
                    <div key={agentGroup.agentId} className="space-y-3">
                      <div className="flex items-center justify-between border-b border-vigil-border/20 pb-1.5">
                        <div className="flex items-center space-x-2">
                          <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider">
                            AGENT: {agentGroup.agentId}
                          </span>
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700/40">
                            {agentGroup.incidents.length} Incident{agentGroup.incidents.length > 1 ? 's' : ''}
                          </span>
                        </div>
                        {/* Per-agent bulk actions */}
                        {agentGroup.incidents.length > 1 && (
                          <div className="flex space-x-1.5 text-[9px] font-mono">
                            <button
                              onClick={() => {
                                const ids = agentGroup.incidents.map((i) => i.latest.request_id);
                                setBulkModal({
                                  action: 'approve',
                                  reqIds: ids,
                                  count: ids.length,
                                  agentCount: 1,
                                });
                              }}
                              className="px-2 py-0.5 rounded bg-teal-950/60 text-teal-300 border border-teal-500/30 hover:bg-teal-900/60"
                            >
                              Approve Agent ({agentGroup.incidents.length})
                            </button>
                            <button
                              onClick={() => {
                                const ids = agentGroup.incidents.map((i) => i.latest.request_id);
                                setBulkModal({
                                  action: 'deny',
                                  reqIds: ids,
                                  count: ids.length,
                                  agentCount: 1,
                                });
                              }}
                              className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-500/30 hover:bg-rose-900/60"
                            >
                              Deny Agent ({agentGroup.incidents.length})
                            </button>
                          </div>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {agentGroup.incidents.map(({ incidentId, latest: req, count }) => {
                          const previewText = approvalPreview(gateMode, false);

                          return (
                            <div 
                              key={req.request_id}
                              className="bg-slate-950/80 border border-rose-500/20 rounded-lg p-4 flex flex-col justify-between hover:border-rose-500/40 transition-all shadow-[0_0_10px_rgba(239,68,68,0.05)] space-y-3"
                            >
                              <div className="space-y-2">
                                <div className="flex justify-between items-start">
                                  <div className="flex items-center space-x-1.5">
                                    <span className="text-[10px] font-mono font-bold text-rose-400 bg-rose-950/30 px-2 py-0.5 rounded border border-rose-500/30">
                                      {req.proposed_action} REQUIRED
                                    </span>
                                    {count > 1 && (
                                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-600/40" title="Deduplicated repeat requests">
                                        Repeat: {count}x
                                      </span>
                                    )}
                                  </div>
                                  <div className="flex items-center space-x-2">
                                    <ExpiryTimer requestedAt={req.requested_at} />
                                    <ElapsedTimer timestamp={req.requested_at} />
                                  </div>
                                </div>

                                <div className="space-y-1 font-mono text-[11px]">
                                  <div className="flex justify-between">
                                    <span className="text-slate-500">Incident Ref:</span>
                                    <span className="text-white font-mono text-[10px]">{incidentId.slice(0, 12)}...</span>
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

                                {/* P1-2: Approval impact preview */}
                                <div className="bg-slate-900/60 p-2 rounded border border-vigil-border/30 text-[9.5px] font-mono">
                                  <div className="text-slate-400 flex items-center justify-between">
                                    <span>Approval Outcome Preview:</span>
                                    <span className="text-[8.5px] uppercase text-slate-500 font-bold">{gateMode}</span>
                                  </div>
                                  <div className="text-teal-300 font-semibold mt-0.5">
                                    {previewText}
                                  </div>
                                </div>
                              </div>

                              <div className="flex space-x-2 pt-2 border-t border-vigil-border/10 font-mono text-[10px]">
                                <button
                                  onClick={() => handleResolve(req.request_id, 'approve')}
                                  disabled={resolvingId !== null}
                                  className="flex-1 bg-rose-500/10 hover:bg-rose-500 text-rose-400 hover:text-white border border-rose-500/30 rounded py-1.5 transition-all uppercase font-bold disabled:opacity-50"
                                >
                                  {resolvingId === req.request_id ? 'Executing...' : 'Approve Confinement'}
                                </button>
                                <button
                                  onClick={() => handleResolve(req.request_id, 'deny')}
                                  disabled={resolvingId !== null}
                                  className="flex-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-vigil-border/40 rounded py-1.5 transition-all uppercase disabled:opacity-50"
                                >
                                  Bypass / Deny
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )
            ) : activeSubTab === 'history' ? (
              allApprovals.length === 0 ? (
                <div className="h-full flex flex-col justify-center items-center py-6 text-center space-y-2">
                  <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">
                    No Governance Decisions Recorded
                  </span>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-[10px] border-collapse">
                    <thead>
                      <tr className="border-b border-vigil-border/20 text-slate-500 uppercase">
                        <th className="pb-2">Request ID</th>
                        <th className="pb-2">Agent ID</th>
                        <th className="pb-2">Proposed</th>
                        <th className="pb-2">Decision</th>
                        <th className="pb-2">Containment Outcome</th>
                        <th className="pb-2">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-vigil-border/10 text-slate-300">
                      {allApprovals.map((req) => {
                        const isContained = req.containment_outcome && req.containment_outcome.toUpperCase().includes('QUARANTINE');
                        const isDenied = req.status === 'DENIED';
                        const isPending = req.status === 'PENDING';
                        
                        return (
                          <tr key={req.request_id} className="hover:bg-slate-900/10 transition-colors">
                            <td className="py-2 text-slate-500 font-mono">{req.request_id.slice(0, 8)}...</td>
                            <td className="py-2 font-bold text-white">{req.agent_id}</td>
                            <td className="py-2 text-slate-300">{req.proposed_action}</td>
                            <td className="py-2">
                              <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                                req.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/20' :
                                req.status === 'DENIED' ? 'bg-rose-950 text-rose-300 border border-rose-500/20' :
                                'bg-amber-950 text-amber-300 border border-amber-500/20'
                              }`}>
                                {req.status}
                              </span>
                            </td>
                            <td className="py-2">
                              {isPending ? (
                                <span className="text-amber-400 font-mono">⏳ PENDING</span>
                              ) : req.containment_outcome ? (
                                <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                                  isContained 
                                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' 
                                    : isDenied 
                                    ? 'bg-slate-800 text-slate-300 border border-slate-700'
                                    : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                                }`}>
                                  {isContained ? '✔ ' : '✖ '} {req.containment_outcome}
                                </span>
                              ) : (
                                <span className="text-slate-500 italic">Not recorded</span>
                              )}
                            </td>
                            <td className="py-2 text-[9px] text-slate-500">
                              {new Date(req.requested_at * 1000).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
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
        </>
      )}

      {/* Confirmation Modal for Bulk Actions (P1-2) */}
      {bulkModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-950 border border-vigil-border/60 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-3">
              <span className="text-2xl">{bulkModal.action === 'approve' ? '⚠️' : '🛡️'}</span>
              <div>
                <h4 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Confirm Bulk {bulkModal.action === 'approve' ? 'Approval' : 'Denial'}
                </h4>
                <p className="text-[11px] text-slate-400">
                  Execute governance action for {bulkModal.count} queued request{bulkModal.count > 1 ? 's' : ''}.
                </p>
              </div>
            </div>

            <div className="bg-slate-900/60 p-3 rounded-lg border border-vigil-border/30 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Queued Requests:</span>
                <span className="text-white font-bold">{bulkModal.count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Agents:</span>
                <span className="text-white font-bold">{bulkModal.agentCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Governance Action:</span>
                <span className={bulkModal.action === 'approve' ? 'text-teal-400 font-bold' : 'text-rose-400 font-bold'}>
                  {bulkModal.action.toUpperCase()}
                </span>
              </div>
              <div className="pt-2 border-t border-vigil-border/20">
                <div className="text-slate-400 text-[10px]">Enforcement Outcome Preview:</div>
                <div className="text-teal-300 text-[11px] font-semibold mt-0.5">
                  {approvalPreview(gateMode, false)}
                </div>
              </div>
            </div>

            <div className="flex space-x-3 pt-2">
              <button
                onClick={() => setBulkModal(null)}
                disabled={isBulkProcessing}
                className="flex-1 py-2 text-xs font-mono font-bold uppercase rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-vigil-border/40 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmBulk}
                disabled={isBulkProcessing}
                className={`flex-1 py-2 text-xs font-mono font-bold uppercase rounded text-white transition-all ${
                  bulkModal.action === 'approve'
                    ? 'bg-teal-600 hover:bg-teal-500 shadow-[0_0_12px_rgba(20,184,166,0.3)]'
                    : 'bg-rose-600 hover:bg-rose-500 shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                } disabled:opacity-50`}
              >
                {isBulkProcessing ? 'Executing...' : `Confirm Bulk ${bulkModal.action}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
