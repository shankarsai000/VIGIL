import React from 'react';

export type BlastNodeStatus = 'REVERSED' | 'IRREVERSIBLE' | 'FAILED' | 'NOT_APPLICABLE';

export interface BlastRadiusNode {
  id: string;
  tool: string;
  agent_id: string;
  is_state_changing: boolean;
  status: BlastNodeStatus | string;
  pre_hash?: string | null;
  reason?: string | null;
  timestamp: number;
}

export interface BlastRadiusEdge {
  from: string;
  to: string;
}

export interface BlastRadiusDAG {
  trace_id: string;
  total_nodes: number;
  nodes: BlastRadiusNode[];
  edges: BlastRadiusEdge[];
}

export interface BlastRadiusViewProps {
  dag: BlastRadiusDAG;
}

const STATUS_BADGES: Record<BlastNodeStatus, { label: string; classes: string }> = {
  REVERSED: {
    label: 'REVERSED',
    classes: 'bg-emerald-950 text-emerald-300 border-emerald-600/60',
  },
  IRREVERSIBLE: {
    label: 'IRREVERSIBLE',
    classes: 'bg-amber-950 text-amber-300 border-amber-600/60',
  },
  FAILED: {
    label: 'FAILED',
    classes: 'bg-rose-950 text-rose-300 border-rose-600/60',
  },
  NOT_APPLICABLE: {
    label: 'READ ONLY',
    classes: 'bg-slate-800 text-slate-400 border-slate-700',
  },
};

export const BlastRadiusView: React.FC<BlastRadiusViewProps> = ({ dag }) => {
  const { trace_id, total_nodes, nodes, edges } = dag;

  return (
    <div data-testid="blast-radius-view" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl flex flex-col gap-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            Compensating Rollback Blast Radius DAG
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Trace ID: {trace_id} ({total_nodes} operations, {edges.length} edges)
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
            Reversed
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
            Irreversible
          </span>
          <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
            Failed
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {nodes.map((node) => {
          const statusNorm = (node.status as BlastNodeStatus) in STATUS_BADGES ? (node.status as BlastNodeStatus) : 'NOT_APPLICABLE';
          const badge = STATUS_BADGES[statusNorm];

          return (
            <div
              key={node.id}
              data-testid={`blast-node-${node.id}`}
              className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between gap-3 shadow-inner"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono text-xs font-bold text-slate-200">
                    {node.tool}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                    {node.agent_id} | {node.id.slice(0, 12)}
                  </div>
                </div>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${badge.classes}`}>
                  {badge.label}
                </span>
              </div>

              {node.pre_hash && (
                <div className="text-[10px] font-mono text-slate-400 bg-slate-900/80 p-1.5 rounded border border-slate-800/60 truncate">
                  Pre-hash: {node.pre_hash.slice(0, 16)}...
                </div>
              )}

              {node.reason && (
                <div className="text-[11px] text-amber-400/90 bg-amber-950/20 p-2 rounded border border-amber-900/30">
                  {node.reason}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
