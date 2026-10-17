import React from 'react';

export interface AntibodyBacktestData {
  candidate: {
    pattern: {
      tool: string;
      argument_shape_class: string;
      sequence_constraint?: string | null;
    };
    armoriq_constraint: string;
    rationale: string;
  };
  benign_trials: number;
  observed_false_blocks: number;
  one_sided_95_upper_bound: number;
  attack_trials: number;
  observed_attack_blocks: number;
  recall: number;
  is_ready_for_review: boolean;
  status_summary: string;
  rejection_reason?: string | null;
}

export interface AntibodyCardProps {
  data: AntibodyBacktestData;
  onSubmitForApproval?: (candidate: AntibodyBacktestData['candidate']) => void;
  submitting?: boolean;
}

export const AntibodyCard: React.FC<AntibodyCardProps> = ({
  data,
  onSubmitForApproval,
  submitting = false,
}) => {
  const {
    candidate,
    benign_trials,
    observed_false_blocks,
    one_sided_95_upper_bound,
    recall,
    is_ready_for_review,
    rejection_reason,
  } = data;

  const boundPercentage = (one_sided_95_upper_bound * 100).toFixed(1);
  const recallPercentage = (recall * 100).toFixed(1);
  const boundClaim = `${observed_false_blocks} of ${benign_trials}; upper bound ${boundPercentage}%`;

  return (
    <div
      data-testid="antibody-card"
      className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col gap-4 text-slate-200"
    >
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-emerald-400">
            {candidate.pattern.tool}
          </span>
          <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
            {candidate.armoriq_constraint.toUpperCase()}
          </span>
        </div>
        <span
          data-testid="antibody-status-badge"
          className={`text-xs px-2.5 py-1 rounded-full font-bold uppercase tracking-wider ${
            is_ready_for_review
              ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
              : 'bg-rose-950 text-rose-300 border border-rose-700/50'
          }`}
        >
          {is_ready_for_review ? 'READY FOR REVIEW' : 'REJECTED IN BACKTEST'}
        </span>
      </div>

      <p className="text-xs text-slate-400 leading-relaxed italic">
        {candidate.rationale}
      </p>

      <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
        <div>
          <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">
            Replay False-Block Bound
          </div>
          <div data-testid="antibody-bound-text" className="font-mono text-xs font-semibold text-slate-200 mt-0.5">
            {boundClaim}
          </div>
        </div>
        <div>
          <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">
            Attack Family Recall
          </div>
          <div data-testid="antibody-recall-text" className="font-mono text-xs font-semibold text-emerald-400 mt-0.5">
            {`${recallPercentage}%`}
          </div>
        </div>
      </div>

      {rejection_reason && (
        <div data-testid="antibody-rejection-reason" className="text-xs text-rose-400 bg-rose-950/30 p-2 rounded border border-rose-900/40">
          {rejection_reason}
        </div>
      )}

      <div className="pt-2 flex justify-end">
        <button
          type="button"
          data-testid="antibody-submit-btn"
          disabled={!is_ready_for_review || submitting}
          onClick={() => onSubmitForApproval && onSubmitForApproval(candidate)}
          className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all duration-200 ${
            is_ready_for_review && !submitting
              ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/30 active:scale-95'
              : 'bg-slate-800 text-slate-500 cursor-not-allowed opacity-60'
          }`}
        >
          {submitting ? 'Submitting...' : 'Submit for approval'}
        </button>
      </div>
    </div>
  );
};
