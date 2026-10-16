import React from 'react';
import { PolicyDecision } from '../types';

export type ContainmentType = 'QUARANTINED' | 'NOT_CONTAINED' | 'PENDING_APPROVAL' | 'NO_ACTION';

export interface ContainmentResult {
  outcome: ContainmentType;
  label: string;
  reason?: string;
  badgeClass: string;
}

export interface DecisionResult {
  label: 'APPROVED' | 'DENIED' | 'ESCALATE' | string;
  badgeClass: string;
  icon: string;
}

/**
 * P0-4: Resolves honest containment outcome separated from the policy decision.
 * Tests every action_taken the backend can emit:
 * 'QUARANTINE', 'ALERT', 'LOG', 'AWAITING_APPROVAL', 'PENDING_APPROVAL', 'none', null, undefined.
 */
export function containmentOutcome(incident: {
  action_taken?: string | null;
  policy_decision?: PolicyDecision | string;
  containment_outcome?: string | null;
}): ContainmentResult {
  const action = (incident.action_taken || '').toUpperCase().trim();
  const decision = (incident.policy_decision || '').toUpperCase().trim();
  const explicitOutcome = (incident.containment_outcome || '').toUpperCase().trim();

  // 1. Quarantined
  if (action === 'QUARANTINE' || explicitOutcome === 'QUARANTINED') {
    return {
      outcome: 'QUARANTINED',
      label: 'QUARANTINED',
      badgeClass: 'badge badge-red font-mono font-bold animate-pulse',
    };
  }

  // 2. Pending Approval
  if (action === 'AWAITING_APPROVAL' || action === 'PENDING_APPROVAL' || action === 'PENDING') {
    return {
      outcome: 'PENDING_APPROVAL',
      label: 'PENDING APPROVAL',
      reason: 'Requires operator confirmation',
      badgeClass: 'badge badge-amber font-mono font-bold',
    };
  }

  // 3. No Action
  if (!action || action === 'NONE' || action === 'NO_ACTION' || action === 'NULL') {
    return {
      outcome: 'NO_ACTION',
      label: 'NO ACTION',
      badgeClass: 'badge badge-gray font-mono font-semibold',
    };
  }

  // 4. Not Contained with explicit reason
  if (action === 'ALERT') {
    return {
      outcome: 'NOT_CONTAINED',
      label: 'NOT CONTAINED (Alert Dispatched)',
      reason: 'Alert Dispatched',
      badgeClass: 'badge badge-amber font-mono font-semibold',
    };
  }

  if (decision === 'DENIED') {
    return {
      outcome: 'NOT_CONTAINED',
      label: 'NOT CONTAINED (Policy Denied)',
      reason: 'Policy Denied',
      badgeClass: 'badge badge-red font-mono font-semibold',
    };
  }

  if (decision === 'ESCALATE') {
    return {
      outcome: 'NOT_CONTAINED',
      label: 'NOT CONTAINED (Escalated to SecOps)',
      reason: 'Escalated to SecOps',
      badgeClass: 'badge badge-amber font-mono font-semibold',
    };
  }

  if (action === 'LOG') {
    return {
      outcome: 'NOT_CONTAINED',
      label: 'NOT CONTAINED (Audited Only)',
      reason: 'Audited Only',
      badgeClass: 'badge badge-gray font-mono font-semibold',
    };
  }

  return {
    outcome: 'NOT_CONTAINED',
    label: `NOT CONTAINED (${action})`,
    reason: action,
    badgeClass: 'badge badge-gray font-mono font-semibold',
  };
}

/**
 * P0-4: Decision badge helper.
 * Replaces fixed 'PASSED' badges and renders true Decision (APPROVED / DENIED / ESCALATE).
 */
export function decisionBadge(decision: PolicyDecision | string): DecisionResult {
  const norm = (decision || '').toUpperCase().trim();
  switch (norm) {
    case 'APPROVED':
    case PolicyDecision.APPROVED:
      return {
        label: 'APPROVED',
        badgeClass: 'badge badge-teal font-mono font-bold',
        icon: '✓',
      };
    case 'DENIED':
    case PolicyDecision.DENIED:
      return {
        label: 'DENIED',
        badgeClass: 'badge badge-red font-mono font-bold',
        icon: '✕',
      };
    case 'ESCALATE':
    case PolicyDecision.ESCALATE:
      return {
        label: 'ESCALATE',
        badgeClass: 'badge badge-amber font-mono font-bold',
        icon: '⚠',
      };
    default:
      return {
        label: norm || 'UNKNOWN',
        badgeClass: 'badge badge-gray font-mono font-semibold',
        icon: '',
      };
  }
}

/**
 * P0-4: Enforcement authority label helper.
 */
export function enforcementLabel(mode?: string): { label: string; badgeClass: string } {
  const m = (mode || '').toLowerCase().trim();
  if (m === 'live' || m === 'armoriq-live') {
    return {
      label: 'armoriq-live',
      badgeClass: 'text-[9px] font-mono font-bold text-vigil-teal bg-vigil-teal/10 px-1.5 py-0.5 rounded border border-vigil-teal/30',
    };
  }
  if (m === 'disabled') {
    return {
      label: 'disabled',
      badgeClass: 'text-[9px] font-mono font-bold text-slate-400 bg-slate-800/40 px-1.5 py-0.5 rounded border border-slate-700/40',
    };
  }
  return {
    label: 'local-demo (NOT ArmorIQ)',
    badgeClass: 'text-[9px] font-mono font-bold text-vigil-amber bg-vigil-amber/10 px-1.5 py-0.5 rounded border border-vigil-amber/30',
  };
}

export const DecisionBadgeView: React.FC<{ decision: PolicyDecision | string }> = ({ decision }) => {
  const d = decisionBadge(decision);
  return (
    <span className={d.badgeClass}>
      {d.icon} {d.label}
    </span>
  );
};

export const ContainmentBadgeView: React.FC<{
  incident: { action_taken?: string | null; policy_decision?: PolicyDecision | string; containment_outcome?: string | null };
}> = ({ incident }) => {
  const c = containmentOutcome(incident);
  return <span className={c.badgeClass}>{c.label}</span>;
};

/**
 * P1-2: Previews what approval will do given enforcement mode and platform hold.
 */
export function approvalPreview(mode: string, hasPlatformHold?: boolean): string {
  const m = (mode || '').toLowerCase().trim();
  if (m === 'disabled') {
    return 'will not contain';
  }
  if (m === 'live' || m === 'armoriq-live') {
    if (hasPlatformHold) {
      return 'ArmorIQ hold active; approval cannot override';
    }
    return 'will quarantine (ArmorIQ governed)';
  }
  return 'will quarantine (local demo, not ArmorIQ)';
}

export const EnforcementBadgeView: React.FC<{ mode?: string }> = ({ mode }) => {
  const e = enforcementLabel(mode);
  return <span className={e.badgeClass}>{e.label}</span>;
};

/**
 * P2: Relative timestamp helper with ms/s normalization and absolute tooltip helper.
 */
export function formatRelativeTime(ts: number): string {
  const ms = ts < 1e12 ? ts * 1000 : ts;
  const elapsedSecs = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (elapsedSecs < 60) return `${elapsedSecs}s ago`;
  const mins = Math.floor(elapsedSecs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatAbsoluteTooltip(ts: number): string {
  const ms = ts < 1e12 ? ts * 1000 : ts;
  return new Date(ms).toLocaleString();
}

/**
 * M4: Policy Proposal status badges and approval progress.
 */
export interface ProposalStatusResult {
  label: string;
  badgeClass: string;
}

export function proposalStatusBadge(status: string): ProposalStatusResult {
  const s = (status || '').toUpperCase().trim();
  switch (s) {
    case 'PROPOSED':
      return {
        label: 'PROPOSED',
        badgeClass: 'badge badge-blue font-mono font-bold',
      };
    case 'APPROVED':
      return {
        label: 'APPROVED',
        badgeClass: 'badge badge-teal font-mono font-bold',
      };
    case 'REJECTED':
      return {
        label: 'REJECTED',
        badgeClass: 'badge badge-red font-mono font-bold',
      };
    case 'EXPIRED':
      return {
        label: 'EXPIRED',
        badgeClass: 'badge badge-gray font-mono font-bold',
      };
    case 'INSUFFICIENT_EVIDENCE':
      return {
        label: 'INSUFFICIENT EVIDENCE',
        badgeClass: 'badge badge-amber font-mono font-bold',
      };
    default:
      return {
        label: s || 'UNKNOWN',
        badgeClass: 'badge badge-gray font-mono font-semibold',
      };
  }
}

export function approvalProgressText(
  currentApprovals: number | string[] | any,
  requiredApprovals: number | string = 1
): string {
  let count = 0;
  if (Array.isArray(currentApprovals)) {
    count = currentApprovals.length;
  } else if (typeof currentApprovals === 'number') {
    count = currentApprovals;
  } else if (typeof currentApprovals === 'string') {
    try {
      const parsed = JSON.parse(currentApprovals);
      count = Array.isArray(parsed) ? parsed.length : Number(currentApprovals) || 0;
    } catch {
      count = Number(currentApprovals) || 0;
    }
  }

  const req = typeof requiredApprovals === 'number' ? requiredApprovals : (Number(requiredApprovals) || 1);
  return `${count} of ${req}`;
}

export function canApproveProposal(status: string): boolean {
  const s = (status || '').toUpperCase().trim();
  return s === 'PROPOSED';
}


