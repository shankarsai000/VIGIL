import React from 'react';

export type ContainmentTierType = 'LOG_ONLY' | 'DOWNGRADE_SCOPE' | 'SHADOW_SANDBOX' | 'QUARANTINE_ROLLBACK';

export interface ContainmentPillProps {
  tier: ContainmentTierType | string;
  ledgerEntryId?: string | null;
  sessionId?: string;
  onViewLedger?: (ledgerEntryId: string) => void;
}

export interface TierConfig {
  label: string;
  classes: string;
  dotColor: string;
  description: string;
}

export const TIER_CONFIGS: Record<ContainmentTierType, TierConfig> = {
  LOG_ONLY: {
    label: 'NORMAL',
    classes: 'bg-slate-800 text-slate-300 border-slate-700',
    dotColor: 'bg-emerald-400',
    description: 'Active auditing and anomaly observation',
  },
  DOWNGRADE_SCOPE: {
    label: 'SCOPED DOWNGRADE',
    classes: 'bg-amber-950/80 text-amber-300 border-amber-600/50',
    dotColor: 'bg-amber-400 animate-pulse',
    description: 'Write and administrative tools stripped in intent token',
  },
  SHADOW_SANDBOX: {
    label: 'MIRAGE HONEYPOT',
    classes: 'bg-purple-950/80 text-purple-300 border-purple-500/50 shadow-purple-900/20 shadow-lg',
    dotColor: 'bg-purple-400 animate-ping',
    description: 'Session queries transparently routed to synthetic Mirage database',
  },
  QUARANTINE_ROLLBACK: {
    label: 'QUARANTINED + ROLLED BACK',
    classes: 'bg-rose-950/90 text-rose-300 border-rose-600/80',
    dotColor: 'bg-rose-500',
    description: 'Full agent quarantine and backward compensating transactional rollback',
  },
};

export const ContainmentPill: React.FC<ContainmentPillProps> = ({
  tier,
  ledgerEntryId,
  sessionId,
  onViewLedger,
}) => {
  const normTier = (tier as ContainmentTierType) in TIER_CONFIGS ? (tier as ContainmentTierType) : 'LOG_ONLY';
  const config = TIER_CONFIGS[normTier];

  return (
    <div
      data-testid="containment-pill"
      data-tier={normTier}
      data-session-id={sessionId}
      className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wider border transition-all duration-300 ${config.classes}`}
      title={config.description}
    >
      <span className={`w-2 h-2 rounded-full ${config.dotColor}`} />
      <span>{config.label}</span>
      {ledgerEntryId && (
        <button
          type="button"
          data-testid="pill-ledger-link"
          onClick={() => onViewLedger && onViewLedger(ledgerEntryId)}
          className="ml-1 text-[10px] underline hover:text-white opacity-80"
          title={`Ledger ID: ${ledgerEntryId}`}
        >
          {`#${ledgerEntryId.slice(0, 8)}`}
        </button>
      )}
    </div>
  );
};
