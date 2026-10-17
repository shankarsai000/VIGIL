import React from 'react';

export interface ArchitectureStep {
  id: string;
  phase: string;
  title: string;
  description: string;
  evidence_path: string;
}

export interface ArchitectureExplorerProps {
  steps?: ArchitectureStep[];
  onSelectStep?: (step: ArchitectureStep) => void;
}

const DEFAULT_STEPS: ArchitectureStep[] = [
  {
    id: 'v0-spec',
    phase: 'V0',
    title: 'PDF Triage and v3 Specification',
    description: 'Systematic triage of proposal claims, Mermaid architecture boundary, and consolidated thresholds.',
    evidence_path: 'evidence/V0/report.md',
  },
  {
    id: 'v1-provenance',
    phase: 'V1',
    title: 'Provenance & Lineage DIFC Taint',
    description: 'Cryptographic lineage records, monotonic propagation, and ArmorIQ OPA policy sink enforcement.',
    evidence_path: 'evidence/V1/live_taint_enforcement.json',
  },
  {
    id: 'v2-containment',
    phase: 'V2',
    title: 'Graduated Containment Ladder',
    description: 'Four-tier graduated response: LOG_ONLY, DOWNGRADE_SCOPE, SHADOW_SANDBOX, and QUARANTINE_ROLLBACK.',
    evidence_path: 'evidence/V2/live_containment_ladder.json',
  },
  {
    id: 'v3-budgets',
    phase: 'V3',
    title: 'Low-and-Slow Budgets & Canaries',
    description: 'Sliding window exfiltration limits, Shannon entropy estimation, and HMAC decoy canaries.',
    evidence_path: 'evidence/V3/benchmark.json',
  },
  {
    id: 'v4-scanning',
    phase: 'V4',
    title: 'Schema Pinning & Output Scanning',
    description: 'Hash-chained tool schema pinning and Stage 1 deterministic indirect prompt injection scanning.',
    evidence_path: 'evidence/V4/output_scanning_evaluation.json',
  },
  {
    id: 'v5-antibodies',
    phase: 'V5',
    title: 'Antibody Candidate Proposals',
    description: 'Deterministic and model-assisted candidate synthesis with 500-record counterfactual replay bounds.',
    evidence_path: 'evidence/V5/candidate_backtest.json',
  },
  {
    id: 'v6-rollback',
    phase: 'V6',
    title: 'Compensating Rollback & Blast Radius',
    description: 'Pre-state checkpointing, backward Saga-style compensation, and blast radius DAG generation.',
    evidence_path: 'evidence/V6/rollback_receipt.json',
  },
];

export const ArchitectureExplorer: React.FC<ArchitectureExplorerProps> = ({
  steps = DEFAULT_STEPS,
  onSelectStep,
}) => {
  return (
    <div data-testid="architecture-explorer" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl flex flex-col gap-4">
      <div className="border-b border-slate-800 pb-3">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
          VIGIL v3 Architecture & Innovation Explorer
        </h3>
        <p className="text-xs text-slate-400 mt-0.5">
          Step-by-step structural pipeline linking directly to verified offline and live evidence files
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {steps.map((step) => (
          <div
            key={step.id}
            data-testid={`arch-step-${step.id}`}
            onClick={() => onSelectStep && onSelectStep(step)}
            className="bg-slate-950/70 border border-slate-800 hover:border-slate-700 rounded-lg p-4 flex flex-col justify-between gap-2 transition-all duration-200 hover:scale-[1.02] cursor-pointer"
          >
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                  {`Phase ${step.phase}`}
                </span>
              </div>
              <h4 className="text-xs font-bold text-slate-200">{step.title}</h4>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                {step.description}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-900 flex items-center justify-between">
              <span className="text-[10px] font-mono text-emerald-400 truncate max-w-[180px]">
                {step.evidence_path}
              </span>
              <span className="text-[10px] text-slate-500 hover:text-slate-300">
                View &rarr;
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
