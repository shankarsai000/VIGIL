import React, { useState } from 'react';

export type TaintLevelName = 'SYSTEM_TRUSTED' | 'VERIFIED_INTERNAL' | 'USER_UNTRUSTED' | 'EXTERNAL_UNTRUSTED';

export interface TaintNode {
  id: string;
  label: string;
  role: string;
  taint: TaintLevelName;
  x: number;
  y: number;
}

export interface TaintEdge {
  from: string;
  to: string;
  taint: TaintLevelName;
  payloadLabel: string;
}

export interface TaintGraphProps {
  nodes?: TaintNode[];
  edges?: TaintEdge[];
  reducedMotion?: boolean;
}

export const TAINT_COLORS: Record<TaintLevelName, { stroke: string; bg: string; fill: string; border: string }> = {
  SYSTEM_TRUSTED: { stroke: '#10b981', bg: 'bg-emerald-950/60', fill: '#10b981', border: 'border-emerald-500' },
  VERIFIED_INTERNAL: { stroke: '#3b82f6', bg: 'bg-blue-950/60', fill: '#3b82f6', border: 'border-blue-500' },
  USER_UNTRUSTED: { stroke: '#f59e0b', bg: 'bg-amber-950/60', fill: '#f59e0b', border: 'border-amber-500' },
  EXTERNAL_UNTRUSTED: { stroke: '#f43f5e', bg: 'bg-rose-950/60', fill: '#f43f5e', border: 'border-rose-500' },
};

const DEFAULT_NODES: TaintNode[] = [
  { id: 'customer-bot', label: 'CustomerBot', role: 'Ingestion & Support', taint: 'EXTERNAL_UNTRUSTED', x: 80, y: 150 },
  { id: 'analytics-agent', label: 'AnalyticsAgent', role: 'Summarizer & Planning', taint: 'EXTERNAL_UNTRUSTED', x: 300, y: 150 },
  { id: 'billing-agent', label: 'BillingAgent', role: 'Privileged DB Ledger', taint: 'EXTERNAL_UNTRUSTED', x: 520, y: 150 },
];

const DEFAULT_EDGES: TaintEdge[] = [
  { from: 'customer-bot', to: 'analytics-agent', taint: 'EXTERNAL_UNTRUSTED', payloadLabel: 'TicketSummary' },
  { from: 'analytics-agent', to: 'billing-agent', taint: 'EXTERNAL_UNTRUSTED', payloadLabel: 'ExportRecordsRequest' },
];

export const TaintGraph: React.FC<TaintGraphProps> = ({
  nodes = DEFAULT_NODES,
  edges = DEFAULT_EDGES,
  reducedMotion = false,
}) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  return (
    <div data-testid="taint-graph-container" className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-2xl relative">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            DIFC Lineage Taint Topology
          </h3>
          <p className="text-xs text-slate-400">
            Multi-hop delegation graph with monotonic taint propagation
          </p>
        </div>
        <div className="flex items-center gap-3 text-[11px]">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-500" /> Trusted
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-blue-500" /> Internal
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-amber-500" /> Untrusted
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-rose-500" /> External Taint
          </span>
        </div>
      </div>

      <svg
        data-testid="taint-svg"
        viewBox="0 0 620 300"
        className="w-full h-64 overflow-visible"
      >
        <defs>
          <linearGradient id="taintGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#f43f5e" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
          <marker
            id="arrowhead-external"
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#f43f5e" />
          </marker>
        </defs>

        {/* Render Edges */}
        {edges.map((edge, idx) => {
          const fromNode = nodeMap.get(edge.from);
          const toNode = nodeMap.get(edge.to);
          if (!fromNode || !toNode) return null;

          const color = TAINT_COLORS[edge.taint] || TAINT_COLORS.EXTERNAL_UNTRUSTED;
          const midX = (fromNode.x + toNode.x) / 2;
          const midY = (fromNode.y + toNode.y) / 2 - 15;

          return (
            <g key={`edge-${idx}`} data-testid={`taint-edge-${edge.from}-${edge.to}`}>
              <line
                x1={fromNode.x + 50}
                y1={fromNode.y}
                x2={toNode.x - 50}
                y2={toNode.y}
                stroke={color.stroke}
                strokeWidth="2.5"
                strokeDasharray={reducedMotion ? undefined : '6,4'}
                className={reducedMotion ? '' : 'animate-[dash_1s_linear_infinite]'}
                markerEnd="url(#arrowhead-external)"
              />
              <text
                x={midX}
                y={midY}
                textAnchor="middle"
                fill="#94a3b8"
                className="text-[10px] font-mono select-none"
              >
                {edge.payloadLabel}
              </text>
            </g>
          );
        })}

        {/* Render Nodes */}
        {nodes.map((node) => {
          const color = TAINT_COLORS[node.taint] || TAINT_COLORS.EXTERNAL_UNTRUSTED;
          const isSelected = selectedNode === node.id;

          return (
            <g
              key={node.id}
              data-testid={`taint-node-${node.id}`}
              transform={`translate(${node.x - 60}, ${node.y - 40})`}
              onClick={() => setSelectedNode(node.id)}
              className="cursor-pointer transition-transform duration-200 hover:scale-105"
            >
              <rect
                width="120"
                height="80"
                rx="10"
                fill="#0f172a"
                stroke={color.stroke}
                strokeWidth={isSelected ? '3' : '1.5'}
                className="filter drop-shadow-md"
              />
              <text
                x="60"
                y="26"
                textAnchor="middle"
                fill="#f8fafc"
                className="text-xs font-bold font-sans"
              >
                {node.label}
              </text>
              <text
                x="60"
                y="44"
                textAnchor="middle"
                fill="#64748b"
                className="text-[9px] font-mono"
              >
                {node.role}
              </text>
              <rect
                x="15"
                y="54"
                width="90"
                height="16"
                rx="4"
                fill={color.stroke}
                fillOpacity="0.2"
              />
              <text
                x="60"
                y="66"
                textAnchor="middle"
                fill={color.stroke}
                className="text-[8px] font-bold tracking-wider"
              >
                {node.taint}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
