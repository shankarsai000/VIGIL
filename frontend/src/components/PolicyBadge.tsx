import React from 'react';
import { PolicyDecision } from '../types';

interface PolicyBadgeProps {
  decision: PolicyDecision;
  size?: 'sm' | 'md';
}

export const PolicyBadge: React.FC<PolicyBadgeProps> = ({ decision, size = 'md' }) => {
  const isSm = size === 'sm';
  
  const baseClasses = "badge mono uppercase tracking-wider font-semibold animate-fade-in";
  
  if (decision === PolicyDecision.APPROVED) {
    return (
      <span className={`${baseClasses} badge-teal ${isSm ? 'text-[10px] px-2 py-0.2' : 'text-xs px-2.5 py-0.5'}`}>
        ✓ APPROVED
      </span>
    );
  }
  
  if (decision === PolicyDecision.DENIED) {
    return (
      <span className={`${baseClasses} badge-red ${isSm ? 'text-[10px] px-2 py-0.2' : 'text-xs px-2.5 py-0.5'}`}>
        ✕ DENIED
      </span>
    );
  }
  
  // ESCALATE
  return (
    <span className={`${baseClasses} badge-amber ${isSm ? 'text-[10px] px-2 py-0.2 animate-pulse' : 'text-xs px-2.5 py-0.5 animate-pulse'}`}>
      ⚠ ESCALATED
    </span>
  );
};
