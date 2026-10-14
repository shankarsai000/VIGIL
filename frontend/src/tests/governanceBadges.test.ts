import { describe, it, expect } from 'vitest';
import {
  containmentOutcome,
  decisionBadge,
  enforcementLabel,
  approvalPreview,
} from '../utils/governanceBadges';
import { calculateTrustScore } from '../components/AgentSidebar';
import { PolicyDecision } from '../types';

describe('VIGIL Governance & UI Helpers (Vitest)', () => {
  describe('P0-4: containmentOutcome mapping (every action_taken backend can emit)', () => {
    it('maps QUARANTINE action to QUARANTINED', () => {
      const res = containmentOutcome({
        action_taken: 'QUARANTINE',
        policy_decision: PolicyDecision.APPROVED,
      });
      expect(res.outcome).toBe('QUARANTINED');
      expect(res.label).toBe('QUARANTINED');
      expect(res.badgeClass).toContain('badge-red');
    });

    it('maps explicit containment_outcome QUARANTINED', () => {
      const res = containmentOutcome({
        action_taken: 'LOG',
        containment_outcome: 'QUARANTINED',
      });
      expect(res.outcome).toBe('QUARANTINED');
      expect(res.label).toBe('QUARANTINED');
    });

    it('maps AWAITING_APPROVAL and PENDING_APPROVAL to PENDING_APPROVAL', () => {
      const res1 = containmentOutcome({ action_taken: 'AWAITING_APPROVAL' });
      expect(res1.outcome).toBe('PENDING_APPROVAL');
      expect(res1.label).toBe('PENDING APPROVAL');

      const res2 = containmentOutcome({ action_taken: 'PENDING_APPROVAL' });
      expect(res2.outcome).toBe('PENDING_APPROVAL');

      const res3 = containmentOutcome({ action_taken: 'PENDING' });
      expect(res3.outcome).toBe('PENDING_APPROVAL');
    });

    it('maps ALERT action to NOT CONTAINED (Alert Dispatched)', () => {
      const res = containmentOutcome({ action_taken: 'ALERT' });
      expect(res.outcome).toBe('NOT_CONTAINED');
      expect(res.label).toBe('NOT CONTAINED (Alert Dispatched)');
      expect(res.reason).toBe('Alert Dispatched');
    });

    it('maps DENIED decision to NOT CONTAINED (Policy Denied)', () => {
      const res = containmentOutcome({
        action_taken: 'LOG',
        policy_decision: PolicyDecision.DENIED,
      });
      expect(res.outcome).toBe('NOT_CONTAINED');
      expect(res.label).toBe('NOT CONTAINED (Policy Denied)');
      expect(res.reason).toBe('Policy Denied');
    });

    it('maps ESCALATE decision to NOT CONTAINED (Escalated to SecOps)', () => {
      const res = containmentOutcome({
        action_taken: 'LOG',
        policy_decision: PolicyDecision.ESCALATE,
      });
      expect(res.outcome).toBe('NOT_CONTAINED');
      expect(res.label).toBe('NOT CONTAINED (Escalated to SecOps)');
      expect(res.reason).toBe('Escalated to SecOps');
    });

    it('maps LOG action to NOT CONTAINED (Audited Only)', () => {
      const res = containmentOutcome({
        action_taken: 'LOG',
        policy_decision: PolicyDecision.APPROVED,
      });
      expect(res.outcome).toBe('NOT_CONTAINED');
      expect(res.label).toBe('NOT CONTAINED (Audited Only)');
    });

    it('maps none / null / undefined / empty to NO ACTION', () => {
      expect(containmentOutcome({ action_taken: 'none' }).outcome).toBe('NO_ACTION');
      expect(containmentOutcome({ action_taken: null }).outcome).toBe('NO_ACTION');
      expect(containmentOutcome({ action_taken: undefined }).outcome).toBe('NO_ACTION');
      expect(containmentOutcome({ action_taken: '' }).outcome).toBe('NO_ACTION');
      expect(containmentOutcome({ action_taken: 'NO_ACTION' }).outcome).toBe('NO_ACTION');
    });
  });

  describe('P0-4: decisionBadge mapping', () => {
    it('maps APPROVED to teal badge and check icon', () => {
      const res = decisionBadge(PolicyDecision.APPROVED);
      expect(res.label).toBe('APPROVED');
      expect(res.badgeClass).toContain('badge-teal');
      expect(res.icon).toBe('✓');
    });

    it('maps DENIED to red badge and cross icon', () => {
      const res = decisionBadge(PolicyDecision.DENIED);
      expect(res.label).toBe('DENIED');
      expect(res.badgeClass).toContain('badge-red');
      expect(res.icon).toBe('✕');
    });

    it('maps ESCALATE to amber badge and warning icon', () => {
      const res = decisionBadge(PolicyDecision.ESCALATE);
      expect(res.label).toBe('ESCALATE');
      expect(res.badgeClass).toContain('badge-amber');
      expect(res.icon).toBe('⚠');
    });
  });

  describe('P0-2: Header enforcement badge in each mode', () => {
    it('shows armoriq-live in live mode (teal)', () => {
      const res = enforcementLabel('live');
      expect(res.label).toBe('armoriq-live');
      expect(res.badgeClass).toContain('text-vigil-teal');
    });

    it('shows local-demo (NOT ArmorIQ) in local-demo mode (amber)', () => {
      const res = enforcementLabel('local-demo');
      expect(res.label).toBe('local-demo (NOT ArmorIQ)');
      expect(res.badgeClass).toContain('text-vigil-amber');
    });

    it('shows disabled in disabled mode (grey)', () => {
      const res = enforcementLabel('disabled');
      expect(res.label).toBe('disabled');
      expect(res.badgeClass).toContain('text-slate-400');
    });
  });

  describe('P1-2: Approval preview in each mode', () => {
    it('previews disabled mode: will not contain', () => {
      expect(approvalPreview('disabled')).toBe('will not contain');
    });

    it('previews live with a platform hold: ArmorIQ hold active; approval cannot override', () => {
      expect(approvalPreview('live', true)).toBe('ArmorIQ hold active; approval cannot override');
      expect(approvalPreview('armoriq-live', true)).toBe('ArmorIQ hold active; approval cannot override');
    });

    it('previews local-demo: will quarantine (local demo, not ArmorIQ)', () => {
      expect(approvalPreview('local-demo')).toBe('will quarantine (local demo, not ArmorIQ)');
    });
  });

  describe('P1-4: NaN ring unit test with undefined input', () => {
    it('handles undefined anomaly score with safe default 100% trust score', () => {
      const score = calculateTrustScore(undefined);
      expect(score).toBe(100);
      expect(Number.isNaN(score)).toBe(false);
    });

    it('handles null anomaly score with safe default 100% trust score', () => {
      const score = calculateTrustScore(null);
      expect(score).toBe(100);
      expect(Number.isNaN(score)).toBe(false);
    });

    it('handles NaN anomaly score safely', () => {
      const score = calculateTrustScore(Number.NaN);
      expect(score).toBe(100);
      expect(Number.isNaN(score)).toBe(false);
    });

    it('calculates proper trust score for valid numeric scores', () => {
      expect(calculateTrustScore(0.2)).toBe(80);
      expect(calculateTrustScore(0.85)).toBe(15);
      expect(calculateTrustScore(0.0)).toBe(100);
      expect(calculateTrustScore(1.0)).toBe(0);
    });
  });
});
