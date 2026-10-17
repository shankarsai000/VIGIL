import React, { useState, useEffect, useMemo } from 'react';
import { useVigilStore } from '../store';
import { vigilClient } from '../api';
import { ApprovalRequest } from '../types';

export const ApprovalChannelPanel: React.FC = () => {
  const {
    approvalChannelStatus,
    pendingApprovals,
    setApprovalChannelStatus,
    setPendingApprovals,
    resolvePendingApproval,
  } = useVigilStore();

  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'pending' | 'history' | 'diagnostics'>('pending');
  const [allApprovals, setAllApprovals] = useState<ApprovalRequest[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Bulk action confirmation state
  const [bulkModal, setBulkModal] = useState<{
    action: 'approve' | 'deny';
    reqIds: string[];
    count: number;
    agentCount: number;
  } | null>(null);
  const [isBulkProcessing, setIsBulkProcessing] = useState(false);

  const refetchData = async () => {
    setIsRefreshing(true);
    try {
      const health = await vigilClient.getHealth();
      if (health.approval_channel) {
        setApprovalChannelStatus(health.approval_channel);
      }
      const pending = await vigilClient.getApprovals();
      setPendingApprovals(pending);
      const all = await vigilClient.getAllApprovals(30);
      setAllApprovals(all);
    } catch (err) {
      console.warn('Failed to refresh approval channel status:', err);
    } finally {
      setIsRefreshing(false);
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

  const handleExecuteBulk = async () => {
    if (!bulkModal) return;
    setIsBulkProcessing(true);
    try {
      await vigilClient.bulkResolveApprovals(bulkModal.reqIds, bulkModal.action);
      for (const id of bulkModal.reqIds) {
        resolvePendingApproval(id, bulkModal.action === 'approve' ? 'APPROVED' : 'DENIED', 0);
      }
      setBulkModal(null);
      await refetchData();
    } catch (err: any) {
      console.error('Bulk resolve failed:', err);
      alert(`Bulk action failed: ${err.message || err}`);
    } finally {
      setIsBulkProcessing(false);
    }
  };

  const { groupedByAgent, totalUniqueCount, allUniqueReqIds } = useMemo(() => {
    const seen = new Set<string>();
    const uniqueReqs: ApprovalRequest[] = [];
    for (const r of pendingApprovals) {
      if (!seen.has(r.request_id)) {
        seen.add(r.request_id);
        uniqueReqs.push(r);
      }
    }
    const groups: { [agentId: string]: ApprovalRequest[] } = {};
    for (const req of uniqueReqs) {
      if (!groups[req.agent_id]) groups[req.agent_id] = [];
      groups[req.agent_id].push(req);
    }
    return {
      groupedByAgent: groups,
      totalUniqueCount: uniqueReqs.length,
      allUniqueReqIds: uniqueReqs.map(r => r.request_id)
    };
  }, [pendingApprovals]);

  const channelState = approvalChannelStatus?.status || 'disabled';
  const isConnected = channelState === 'connected';
  const isConfigured = channelState === 'configured' || isConnected;

  return (
    <div className="bg-vigil-card border border-vigil-border/60 rounded-xl p-5 flex flex-col h-full shadow-2xl relative">
      {/* Panel Header */}
      <div className="flex items-center justify-between pb-4 border-b border-vigil-border/40">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-vigil-panel border border-vigil-border/60 flex items-center justify-center text-xl shadow-inner">
            💬
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-bold font-mono tracking-wider text-slate-100 uppercase">
                APPROVAL CHANNEL: SLACK
              </h2>
              <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${
                isConnected
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.2)]'
                  : isConfigured
                  ? 'bg-sky-500/10 text-sky-400 border-sky-500/30'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}>
                {channelState}
              </span>
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              Verified corporate identities · Tamper-proof webhook verification
            </p>
          </div>
        </div>

        {/* Sub-tabs */}
        <div className="flex items-center space-x-1 bg-slate-900/60 p-1 rounded-lg border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveSubTab('pending')}
            className={`px-3 py-1 rounded-md transition-all ${
              activeSubTab === 'pending'
                ? 'bg-vigil-teal/20 text-vigil-teal border border-vigil-teal/40 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            PENDING ({totalUniqueCount})
          </button>
          <button
            onClick={() => setActiveSubTab('history')}
            className={`px-3 py-1 rounded-md transition-all ${
              activeSubTab === 'history'
                ? 'bg-vigil-teal/20 text-vigil-teal border border-vigil-teal/40 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            HISTORY
          </button>
          <button
            onClick={() => setActiveSubTab('diagnostics')}
            className={`px-3 py-1 rounded-md transition-all ${
              activeSubTab === 'diagnostics'
                ? 'bg-vigil-teal/20 text-vigil-teal border border-vigil-teal/40 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            SETTINGS
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto mt-4 space-y-4 pr-1 min-h-[300px]">
        {activeSubTab === 'pending' && (
          <div>
            {totalUniqueCount > 1 && (
              <div className="flex items-center justify-between bg-slate-900/40 border border-slate-800 p-2.5 rounded-lg mb-4">
                <span className="text-xs font-mono text-slate-400">
                  Batch Operations ({totalUniqueCount} requests)
                </span>
                <div className="flex space-x-2">
                  <button
                    onClick={() => setBulkModal({
                      action: 'approve',
                      reqIds: allUniqueReqIds,
                      count: totalUniqueCount,
                      agentCount: Object.keys(groupedByAgent).length
                    })}
                    className="px-2.5 py-1 text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded hover:bg-emerald-500/30 transition-colors"
                  >
                    APPROVE ALL
                  </button>
                  <button
                    onClick={() => setBulkModal({
                      action: 'deny',
                      reqIds: allUniqueReqIds,
                      count: totalUniqueCount,
                      agentCount: Object.keys(groupedByAgent).length
                    })}
                    className="px-2.5 py-1 text-[11px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded hover:bg-rose-500/30 transition-colors"
                  >
                    DENY ALL
                  </button>
                </div>
              </div>
            )}

            {totalUniqueCount === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-center p-6 bg-slate-900/20 border border-dashed border-slate-800 rounded-lg font-mono">
                <span className="text-2xl mb-2">✨</span>
                <span className="text-slate-300 text-sm font-semibold">No Pending Approvals</span>
                <p className="text-slate-500 text-xs mt-1 max-w-sm">
                  Containment holds and policy proposals requiring human verification will appear here and deliver to Slack.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {Object.entries(groupedByAgent).map(([agentId, requests]) => (
                  <div key={agentId} className="bg-slate-900/40 border border-slate-800 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-mono font-bold text-slate-200">AGENT:</span>
                        <span className="text-xs font-mono text-vigil-teal font-semibold">{agentId}</span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {requests.length} pending
                      </span>
                    </div>

                    <div className="space-y-2.5">
                      {requests.map((req) => (
                        <div key={req.request_id} className="bg-slate-950/60 border border-slate-800/80 rounded-md p-3">
                          <div className="flex items-start justify-between">
                            <div className="space-y-1">
                              <div className="flex items-center space-x-2">
                                <span className="text-xs font-mono font-bold text-slate-300">
                                  {req.proposed_action || 'CONTAINMENT HOLD'}
                                </span>
                                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                                  (req.threat_score || 0) >= 0.8
                                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                    : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                }`}>
                                  SCORE: {(req.threat_score || 0).toFixed(2)}
                                </span>
                              </div>
                              <p className="text-[11px] font-mono text-slate-400">
                                Request ID: <span className="text-slate-300">{req.request_id}</span>
                              </p>
                              {req.incident_id && (
                                <p className="text-[10px] font-mono text-slate-500">
                                  Incident: {req.incident_id}
                                </p>
                              )}
                            </div>

                            <div className="flex space-x-1.5">
                              <button
                                disabled={resolvingId === req.request_id}
                                onClick={() => handleResolve(req.request_id, 'approve')}
                                className="px-3 py-1 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 font-mono text-xs rounded transition-colors disabled:opacity-50"
                              >
                                {resolvingId === req.request_id ? '...' : 'Approve'}
                              </button>
                              <button
                                disabled={resolvingId === req.request_id}
                                onClick={() => handleResolve(req.request_id, 'deny')}
                                className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/50 text-rose-300 font-mono text-xs rounded transition-colors disabled:opacity-50"
                              >
                                {resolvingId === req.request_id ? '...' : 'Deny'}
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'history' && (
          <div className="space-y-3 font-mono">
            {allApprovals.length === 0 ? (
              <div className="text-center py-10 text-xs text-slate-500">
                No past approvals recorded.
              </div>
            ) : (
              <div className="space-y-2">
                {allApprovals.map((req) => (
                  <div key={req.request_id} className="bg-slate-900/40 border border-slate-800 rounded p-3 text-xs flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-200">{req.agent_id}</span>
                        <span className="text-slate-400">({req.proposed_action})</span>
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                          req.status === 'APPROVED' ? 'bg-emerald-500/20 text-emerald-400' :
                          req.status === 'DENIED' ? 'bg-rose-500/20 text-rose-400' :
                          req.status === 'EXPIRED' ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {req.status}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">
                        ID: {req.request_id} · Decided by: {req.email || req.resolved_by || 'Unknown'}
                      </div>
                    </div>
                    {req.resolved_at && (
                      <span className="text-[10px] text-slate-500">
                        {new Date(req.resolved_at * 1000).toLocaleTimeString()}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'diagnostics' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 space-y-3">
              <h3 className="font-bold text-slate-200 text-sm">Channel Configuration</h3>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 bg-slate-950/60 border border-slate-800/80 rounded">
                  <span className="text-slate-400 block">PROVIDER</span>
                  <span className="text-slate-200 font-bold">Slack Bolt (v1.30.0)</span>
                </div>
                <div className="p-2 bg-slate-950/60 border border-slate-800/80 rounded">
                  <span className="text-slate-400 block">MODE</span>
                  <span className="text-slate-200 font-bold uppercase">{approvalChannelStatus?.mode || 'http'}</span>
                </div>
                <div className="p-2 bg-slate-950/60 border border-slate-800/80 rounded">
                  <span className="text-slate-400 block">WEBHOOK ROUTE</span>
                  <span className="text-slate-200 font-bold">/integrations/slack/interactions</span>
                </div>
                <div className="p-2 bg-slate-950/60 border border-slate-800/80 rounded">
                  <span className="text-slate-400 block">VERIFICATION</span>
                  <span className="text-slate-200 font-bold">HMAC-SHA256 (v0)</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 space-y-2 text-[11px] text-slate-400">
              <h4 className="font-bold text-slate-200">Security Architecture</h4>
              <ul className="list-disc pl-4 space-y-1">
                <li>Decisions are cryptographically verified using Slack's signing secret.</li>
                <li>Nonces are server-generated and consumed on first click (replay-proof).</li>
                <li>Only verified corporate emails from approved domains can authorize actions.</li>
                <li>HIGH-tier proposals require 2 distinct verified approvers.</li>
                <li>Separation of duties: proposers cannot approve their own requests.</li>
                <li>Every decision and rejection is permanently committed to the audit ledger.</li>
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Bulk Action Confirmation Modal */}
      {bulkModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-vigil-card border border-vigil-border/80 rounded-xl p-6 max-w-md w-full space-y-4 font-mono shadow-2xl">
            <h3 className="text-base font-bold text-slate-100">
              Confirm Bulk {bulkModal.action.toUpperCase()}
            </h3>
            <p className="text-xs text-slate-300">
              You are about to <span className="font-bold text-vigil-teal">{bulkModal.action}</span> {bulkModal.count} pending approval(s) across {bulkModal.agentCount} agent(s).
            </p>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                disabled={isBulkProcessing}
                onClick={() => setBulkModal(null)}
                className="px-4 py-1.5 text-xs text-slate-400 hover:text-slate-200 border border-slate-700 rounded transition-colors"
              >
                Cancel
              </button>
              <button
                disabled={isBulkProcessing}
                onClick={handleExecuteBulk}
                className={`px-4 py-1.5 text-xs font-bold rounded transition-colors ${
                  bulkModal.action === 'approve'
                    ? 'bg-emerald-500 hover:bg-emerald-600 text-white'
                    : 'bg-rose-500 hover:bg-rose-600 text-white'
                }`}
              >
                {isBulkProcessing ? 'Processing...' : `Confirm ${bulkModal.action.toUpperCase()}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
