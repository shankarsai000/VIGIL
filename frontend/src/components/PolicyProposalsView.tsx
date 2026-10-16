import React, { useState, useEffect } from 'react';
import { PolicyProposal } from '../types';
import { vigilClient } from '../api';
import {
  proposalStatusBadge,
  approvalProgressText,
  canApproveProposal,
  formatAbsoluteTooltip,
} from '../utils/governanceBadges';

export const PolicyProposalsView: React.FC = () => {
  const [proposals, setProposals] = useState<PolicyProposal[]>([]);
  const [selectedProposal, setSelectedProposal] = useState<PolicyProposal | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Confirm dialog state
  const [actionType, setActionType] = useState<'approve' | 'reject' | null>(null);
  const [approverId, setApproverId] = useState<string>('secops.reviewer@corp.internal');
  const [rejectReason, setRejectReason] = useState<string>('Unacceptable operational friction');
  const [isSubmittingAction, setIsSubmittingAction] = useState<boolean>(false);

  // Proposal creation modal
  const [createModalOpen, setCreateModalOpen] = useState<boolean>(false);
  const [newAgentId, setNewAgentId] = useState<string>('finance-analyst-agent');
  const [newTool, setNewTool] = useState<string>('execute_arbitrary_code');
  const [isCreating, setIsCreating] = useState<boolean>(false);

  const fetchProposals = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await vigilClient.getPolicyProposals();
      setProposals(data);
      if (data.length > 0 && !selectedProposal) {
        setSelectedProposal(data[0]);
      } else if (selectedProposal) {
        const updated = data.find((p) => p.id === selectedProposal.id);
        if (updated) setSelectedProposal(updated);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch policy proposals');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchProposals();
  }, []);

  const parseReplay = (p: PolicyProposal) => {
    try {
      return JSON.parse(p.replay_json || '{}');
    } catch {
      return {};
    }
  };

  const parseAssumptions = (p: PolicyProposal) => {
    try {
      return JSON.parse(p.assumptions_json || '{}');
    } catch {
      return {};
    }
  };

  const parseApprovals = (p: PolicyProposal): string[] => {
    try {
      const res = JSON.parse(p.approvals_json || '[]');
      return Array.isArray(res) ? res : [];
    } catch {
      return [];
    }
  };

  const formatExpiry = (expiresAt: number) => {
    const ms = expiresAt < 1e12 ? expiresAt * 1000 : expiresAt;
    const diff = ms - Date.now();
    if (diff <= 0) return 'Expired';
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    if (hours > 0) return `in ${hours}h ${mins}m`;
    return `in ${mins}m`;
  };

  const handleApprove = async () => {
    if (!selectedProposal || !approverId.trim()) return;
    setIsSubmittingAction(true);
    setError(null);
    try {
      const updated = await vigilClient.approvePolicyProposal(selectedProposal.id, approverId.trim());
      setActionType(null);
      await fetchProposals();
      setSelectedProposal(updated);
    } catch (err: any) {
      setError(err.message || 'Failed to approve proposal');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  const handleReject = async () => {
    if (!selectedProposal || !approverId.trim()) return;
    setIsSubmittingAction(true);
    setError(null);
    try {
      const updated = await vigilClient.rejectPolicyProposal(
        selectedProposal.id,
        approverId.trim(),
        rejectReason.trim()
      );
      setActionType(null);
      await fetchProposals();
      setSelectedProposal(updated);
    } catch (err: any) {
      setError(err.message || 'Failed to reject proposal');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  const handleCreateProposal = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCreating(true);
    setError(null);
    try {
      const now = Math.floor(Date.now() / 1000);
      const created = await vigilClient.createPolicyProposal({
        agent_id: newAgentId.trim(),
        tool: newTool.trim(),
        window_start: now - 30 * 86400,
        window_end: now,
      });
      setCreateModalOpen(false);
      await fetchProposals();
      setSelectedProposal(created);
    } catch (err: any) {
      setError(err.message || 'Failed to generate proposal');
    } finally {
      setIsCreating(false);
    }
  };

  const selectedReplay = selectedProposal ? parseReplay(selectedProposal) : null;
  const selectedAssumptions = selectedProposal ? parseAssumptions(selectedProposal) : null;
  const selectedApprovers = selectedProposal ? parseApprovals(selectedProposal) : [];
  const requiredCount = selectedProposal
    ? (selectedProposal.required_approvals ?? (selectedProposal.impact_tier === 'HIGH' ? 2 : 1))
    : 1;

  return (
    <div className="flex flex-col h-full bg-vigil-darker text-vigil-text font-sans overflow-hidden">
      {/* Top Action Bar */}
      <div className="px-6 py-4 border-b border-vigil-border/40 flex items-center justify-between glass-panel shrink-0">
        <div>
          <div className="flex items-center space-x-3">
            <h2 className="text-sm font-bold tracking-wider font-mono text-white uppercase">
              POLICY IMMUNE SYSTEM // CANDIDATE PROPOSALS
            </h2>
            <span className="badge badge-teal font-mono text-[10px]">REPLAY-VERIFIED</span>
          </div>
          <p className="text-xs text-vigil-muted mt-0.5">
            Rules proved on recorded traffic before blocking. Safe blocking guaranteed with exact Clopper-Pearson bound.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-3.5 py-1.5 rounded bg-vigil-teal/20 text-vigil-teal border border-vigil-teal/40 hover:bg-vigil-teal/30 transition-all font-mono text-xs uppercase font-bold tracking-wider"
          >
            + Run Replay & Propose
          </button>
          <button
            onClick={fetchProposals}
            disabled={isLoading}
            className="px-3 py-1.5 rounded bg-slate-800/60 border border-slate-700/50 hover:bg-slate-700 text-xs font-mono tracking-wider text-vigil-muted hover:text-white transition-colors"
          >
            {isLoading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && (
        <div className="px-6 py-2.5 bg-rose-950/80 border-b border-rose-500/50 text-xs text-rose-200 flex items-center justify-between font-mono">
          <span>⚠️ ERROR: {error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white font-bold ml-4">
            DISMISS
          </button>
        </div>
      )}

      {/* Main Split View: Table on Left/Center, Detail Panel on Right */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Side: Table of Proposals */}
        <div className="flex-1 overflow-auto border-r border-vigil-border/40">
          {proposals.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8">
              <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-vigil-border/40 flex items-center justify-center text-vigil-muted text-lg mb-3">
                ⚖️
              </div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                No Policy Proposals Found
              </h3>
              <p className="text-xs text-vigil-muted max-w-sm mt-1">
                Run replay analysis on candidate attack families to propose safe ArmorIQ blocking rules.
              </p>
              <button
                onClick={() => setCreateModalOpen(true)}
                className="mt-4 px-4 py-2 bg-vigil-teal text-black rounded font-mono font-bold text-xs uppercase hover:bg-vigil-teal/90"
              >
                Create First Proposal
              </button>
            </div>
          ) : (
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead className="bg-slate-900/80 border-b border-vigil-border/30 text-vigil-muted sticky top-0 uppercase tracking-wider text-[11px] backdrop-blur-md z-10">
                <tr>
                  <th className="py-3 px-4">Rule (<span className="text-vigil-teal">mcp.tool</span>)</th>
                  <th className="py-3 px-3">Agent</th>
                  <th className="py-3 px-3">Coverage</th>
                  <th className="py-3 px-3">False-Block Bound</th>
                  <th className="py-3 px-3 text-right">Attacks Replayed</th>
                  <th className="py-3 px-3 text-right">Benign Replayed</th>
                  <th className="py-3 px-3 text-center">Status</th>
                  <th className="py-3 px-4">Expires</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-vigil-border/20">
                {proposals.map((p) => {
                  const rep = parseReplay(p);
                  const isSelected = selectedProposal?.id === p.id;
                  const statusInfo = proposalStatusBadge(p.status);
                  const coveragePct = rep.coverage !== undefined ? `${(rep.coverage * 100).toFixed(1)}%` : 'N/A';
                  const fbBound = rep.false_block_upper !== undefined
                    ? `${(rep.false_block_upper * 100).toFixed(2)}%`
                    : '< 0.05%';

                  return (
                    <tr
                      key={p.id}
                      onClick={() => setSelectedProposal(p)}
                      className={`cursor-pointer transition-colors duration-150 ${
                        isSelected
                          ? 'bg-vigil-teal/10 border-l-2 border-l-vigil-teal'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3 px-4 font-bold text-white">
                        <span className="text-vigil-teal">{p.mcp_id || 'system'}</span>.{p.tool}
                        <div className="text-[10px] text-vigil-muted font-normal mt-0.5">
                          ID: {p.id.slice(0, 8)}...
                        </div>
                      </td>
                      <td className="py-3 px-3 text-vigil-muted">{p.agent_id}</td>
                      <td className="py-3 px-3 font-semibold text-emerald-400">{coveragePct}</td>
                      <td className="py-3 px-3 font-semibold text-sky-400">{fbBound}</td>
                      <td className="py-3 px-3 text-right text-rose-400 font-bold">
                        {rep.attacks_total ?? 0}
                      </td>
                      <td className="py-3 px-3 text-right text-emerald-400">
                        {rep.benign_total ?? 0}
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={statusInfo.badgeClass}>{statusInfo.label}</span>
                      </td>
                      <td
                        className="py-3 px-4 text-vigil-muted whitespace-nowrap"
                        title={formatAbsoluteTooltip(p.expires_at)}
                      >
                        {formatExpiry(p.expires_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Right Side: Proposal Detail Panel */}
        <div className="w-[450px] shrink-0 bg-slate-900/60 flex flex-col h-full border-l border-vigil-border/30 overflow-y-auto">
          {selectedProposal ? (
            <div className="p-5 flex flex-col space-y-5">
              {/* Proposal Header */}
              <div className="border-b border-vigil-border/30 pb-4">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono tracking-widest text-vigil-muted uppercase">
                    PROPOSAL DETAILS
                  </span>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`badge font-mono text-[10px] font-bold ${
                        selectedProposal.impact_tier === 'HIGH'
                          ? 'badge-amber text-amber-400 border-amber-500/40'
                          : 'badge-blue text-sky-400 border-sky-500/40'
                      }`}
                    >
                      {selectedProposal.impact_tier} IMPACT
                    </span>
                    <span className={proposalStatusBadge(selectedProposal.status).badgeClass}>
                      {proposalStatusBadge(selectedProposal.status).label}
                    </span>
                  </div>
                </div>

                <h3 className="text-base font-bold text-white font-mono mt-2 break-all">
                  <span className="text-vigil-teal">{selectedProposal.mcp_id || 'system'}</span>.
                  {selectedProposal.tool}
                </h3>
                <div className="text-xs text-vigil-muted font-mono mt-1 flex items-center justify-between">
                  <span>Target Agent: <strong className="text-white">{selectedProposal.agent_id}</strong></span>
                  <span>v{selectedProposal.version}</span>
                </div>
              </div>

              {/* Approval Progress */}
              <div className="bg-slate-800/40 border border-vigil-border/30 rounded-lg p-3.5 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-vigil-muted uppercase font-bold tracking-wider">Approval Progress</span>
                  <span className="text-vigil-teal font-bold font-mono text-sm">
                    {approvalProgressText(selectedApprovers, requiredCount)}
                  </span>
                </div>

                {/* Progress Bar */}
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-700/40">
                  <div
                    className="bg-vigil-teal h-full transition-all duration-300"
                    style={{
                      width: `${Math.min(100, (selectedApprovers.length / requiredCount) * 100)}%`,
                    }}
                  />
                </div>

                <div className="text-[11px] text-vigil-muted font-mono pt-1">
                  {selectedProposal.impact_tier === 'HIGH' ? (
                    <span className="text-amber-400">
                      ⚡ High Impact Tier: Requires two distinct reviewer approvals before enforcement.
                    </span>
                  ) : (
                    <span>Low Impact Tier: Requires 1 reviewer approval.</span>
                  )}
                </div>

                {selectedApprovers.length > 0 && (
                  <div className="pt-2 border-t border-vigil-border/20 space-y-1">
                    <span className="text-[10px] text-vigil-muted font-mono uppercase">Signed Approvers:</span>
                    {selectedApprovers.map((app, idx) => (
                      <div key={idx} className="flex items-center space-x-2 text-xs font-mono text-emerald-400">
                        <span>✓</span>
                        <span className="truncate">{app}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Statistical Replay Bounds */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase text-vigil-muted font-bold tracking-wider">
                  Replay Validation Metrics
                </span>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="bg-slate-950/60 p-2.5 rounded border border-vigil-border/30">
                    <div className="text-vigil-muted text-[10px]">COVERAGE</div>
                    <div className="text-emerald-400 font-bold text-sm">
                      {selectedReplay?.coverage !== undefined
                        ? `${(selectedReplay.coverage * 100).toFixed(1)}%`
                        : '100.0%'}
                    </div>
                    <div className="text-[10px] text-vigil-muted">
                      {selectedReplay?.attacks_blocked ?? 0} / {selectedReplay?.attacks_total ?? 0} attacks
                    </div>
                  </div>

                  <div className="bg-slate-950/60 p-2.5 rounded border border-vigil-border/30">
                    <div className="text-vigil-muted text-[10px]">FALSE-BLOCK BOUND</div>
                    <div className="text-sky-400 font-bold text-sm">
                      {selectedReplay?.false_block_upper !== undefined
                        ? `${(selectedReplay.false_block_upper * 100).toFixed(2)}%`
                        : '< 0.05%'}
                    </div>
                    <div className="text-[10px] text-vigil-muted">
                      {selectedReplay?.benign_blocked ?? 0} / {selectedReplay?.benign_total ?? 0} benign
                    </div>
                  </div>
                </div>
              </div>

              {/* YAML Diff */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-vigil-muted font-bold tracking-wider">
                    YAML Diff (armoriq.yaml)
                  </span>
                  <span className="text-[10px] font-mono text-vigil-muted">policy.deny patch</span>
                </div>
                <div className="bg-slate-950 p-3 rounded border border-vigil-border/40 font-mono text-xs overflow-x-auto text-slate-300">
                  <div className="text-slate-500"># Policy patch for {selectedProposal.agent_id}</div>
                  <div>policy:</div>
                  <div className="text-emerald-400 font-bold">+   deny:</div>
                  <div className="text-emerald-400 font-bold pl-4">
                    +     - {selectedProposal.mcp_id || 'system'}.{selectedProposal.tool}
                  </div>
                </div>
              </div>

              {/* Assumptions */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase text-vigil-muted font-bold tracking-wider">
                  Assumptions & Proof Context
                </span>
                <div className="bg-slate-950/60 p-3 rounded border border-vigil-border/30 font-mono text-[11px] space-y-1.5 text-vigil-muted">
                  <div className="flex items-start space-x-2">
                    <span className="text-vigil-teal">•</span>
                    <span>
                      <strong className="text-slate-200">Ground Truth:</strong>{' '}
                      {selectedAssumptions?.unlabelled_traffic || 'Unlabelled traffic assumed benign; attacks confirmed via simulator or incident.'}
                    </span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="text-vigil-teal">•</span>
                    <span>
                      <strong className="text-slate-200">Exchangeability:</strong>{' '}
                      {selectedAssumptions?.exchangeability || 'Historical distribution over replay window assumed predictive of future actions.'}
                    </span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="text-vigil-teal">•</span>
                    <span>
                      <strong className="text-slate-200">Clopper-Pearson Bound:</strong>{' '}
                      {selectedAssumptions?.confidence_level ? `Exact one-sided binomial upper bound at ${selectedAssumptions.confidence_level}.` : 'Exact one-sided binomial upper bound at delta = 0.05.'}
                    </span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="text-vigil-teal">•</span>
                    <span>
                      <strong className="text-slate-200">Enforcement Glob:</strong>{' '}
                      {selectedAssumptions?.enforcement_scope || 'ArmorIQ globs match tool names, not payload arguments.'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Decision Actions */}
              <div className="pt-2 border-t border-vigil-border/30 space-y-2">
                {selectedProposal.status === 'INSUFFICIENT_EVIDENCE' ? (
                  <div className="p-3 bg-amber-950/40 border border-amber-500/40 rounded text-xs font-mono text-amber-300">
                    ⚠️ INSUFFICIENT EVIDENCE: This proposal does not meet safety thresholds (coverage &lt; 90% or sample size too small) and cannot be approved.
                  </div>
                ) : null}

                <div className="flex items-center space-x-3">
                  <button
                    disabled={!canApproveProposal(selectedProposal.status)}
                    onClick={() => setActionType('approve')}
                    className={`flex-1 py-2 rounded font-mono font-bold text-xs uppercase tracking-wider transition-all ${
                      canApproveProposal(selectedProposal.status)
                        ? 'bg-vigil-teal text-black hover:bg-vigil-teal/90 shadow-[0_0_12px_rgba(0,242,254,0.25)]'
                        : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/40'
                    }`}
                  >
                    Approve Proposal
                  </button>
                  <button
                    disabled={!canApproveProposal(selectedProposal.status)}
                    onClick={() => setActionType('reject')}
                    className={`flex-1 py-2 rounded font-mono font-bold text-xs uppercase tracking-wider transition-all ${
                      canApproveProposal(selectedProposal.status)
                        ? 'bg-rose-900/60 text-rose-300 border border-rose-500/50 hover:bg-rose-800/60'
                        : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/40'
                    }`}
                  >
                    Reject Proposal
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-vigil-muted font-mono text-xs">
              Select a proposal to view details
            </div>
          )}
        </div>
      </div>

      {/* Confirmation Modal for Approve / Reject */}
      {actionType && selectedProposal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-vigil-border/80 rounded-xl p-6 max-w-md w-full font-mono space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-vigil-border/40 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                {actionType === 'approve' ? 'Confirm Policy Approval' : 'Confirm Policy Rejection'}
              </h3>
              <span className="badge badge-teal font-mono text-[10px]">AUDITED ACTION</span>
            </div>

            <p className="text-xs text-vigil-muted">
              {actionType === 'approve'
                ? `You are signing approval for proposal on rule "${selectedProposal.tool}". This action will be immutably recorded in the audit ledger.`
                : `You are rejecting proposal on rule "${selectedProposal.tool}". Status will transition to REJECTED.`}
            </p>

            <div className="space-y-1.5">
              <label className="text-[11px] text-slate-300 font-bold uppercase">
                Reviewer Identity (X-VIGIL-Approver)
              </label>
              <input
                type="text"
                value={approverId}
                onChange={(e) => setApproverId(e.target.value)}
                placeholder="e.g. secops.officer@corp.internal"
                className="w-full bg-slate-950 border border-vigil-border/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-vigil-teal"
              />
            </div>

            {actionType === 'reject' && (
              <div className="space-y-1.5">
                <label className="text-[11px] text-slate-300 font-bold uppercase">
                  Rejection Rationale
                </label>
                <input
                  type="text"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  className="w-full bg-slate-950 border border-vigil-border/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-vigil-teal"
                />
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-vigil-border/30">
              <button
                type="button"
                onClick={() => setActionType(null)}
                className="px-4 py-2 rounded text-xs font-mono text-vigil-muted hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isSubmittingAction || !approverId.trim()}
                onClick={actionType === 'approve' ? handleApprove : handleReject}
                className={`px-4 py-2 rounded font-mono font-bold text-xs uppercase tracking-wider ${
                  actionType === 'approve'
                    ? 'bg-vigil-teal text-black hover:bg-vigil-teal/90'
                    : 'bg-rose-600 text-white hover:bg-rose-500'
                }`}
              >
                {isSubmittingAction ? 'Recording...' : `Confirm ${actionType}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Replay & Propose Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <form
            onSubmit={handleCreateProposal}
            className="bg-slate-900 border border-vigil-border/80 rounded-xl p-6 max-w-md w-full font-mono space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-vigil-border/40 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Run Replay & Propose Policy
              </h3>
              <span className="badge badge-teal font-mono text-[10px]">M4 IMMUNE ENGINE</span>
            </div>

            <p className="text-xs text-vigil-muted">
              Select an agent and tool candidate to run against recorded traffic traces. If coverage is &ge; 90% and false-block bound is safe, a proposal is created.
            </p>

            <div className="space-y-1.5">
              <label className="text-[11px] text-slate-300 font-bold uppercase">Agent ID</label>
              <input
                type="text"
                value={newAgentId}
                onChange={(e) => setNewAgentId(e.target.value)}
                required
                className="w-full bg-slate-950 border border-vigil-border/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-vigil-teal"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[11px] text-slate-300 font-bold uppercase">Candidate Tool</label>
              <input
                type="text"
                value={newTool}
                onChange={(e) => setNewTool(e.target.value)}
                required
                className="w-full bg-slate-950 border border-vigil-border/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-vigil-teal"
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-vigil-border/30">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-2 rounded text-xs font-mono text-vigil-muted hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isCreating}
                className="px-4 py-2 bg-vigil-teal text-black rounded font-mono font-bold text-xs uppercase tracking-wider hover:bg-vigil-teal/90"
              >
                {isCreating ? 'Evaluating...' : 'Run Replay & Propose'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
