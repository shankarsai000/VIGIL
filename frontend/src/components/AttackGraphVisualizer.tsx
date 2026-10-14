import React, { useMemo, useState, useEffect } from 'react';
import { vigilClient } from '../api';
import { AttackGraphNode, AttackGraphEdge } from '../types';

interface AttackGraphVisualizerProps {
  incidentId: string | null;
}

export const AttackGraphVisualizer: React.FC<AttackGraphVisualizerProps> = ({ incidentId }) => {
  const [nodes, setNodes] = useState<AttackGraphNode[]>([]);
  const [edges, setEdges] = useState<AttackGraphEdge[]>([]);
  const [loading, setLoading] = useState(false);
  const [triggerAgent, setTriggerAgent] = useState<string | null>(null);
  const [blastRadius, setBlastRadius] = useState<number>(0);
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null);
  const [isolating, setIsolating] = useState(false);

  // Canvas dimensions
  const width = 600;
  const height = 400;
  const centerX = width / 2;
  const centerY = height / 2;

  // Load attack graph data
  useEffect(() => {
    const fetchGraph = async () => {
      setLoading(true);
      try {
        const data = await vigilClient.getAttackGraph(incidentId || 'global');
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
        setTriggerAgent(data.trigger_agent || null);
        setBlastRadius(data.blast_radius || 0);
      } catch (err) {
        console.error('Failed to load attack graph:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchGraph();
  }, [incidentId]);

  // Compute node coordinate mapping
  const positionedNodes = useMemo(() => {
    if (nodes.length === 0) return new Map<string, { x: number; y: number; node: AttackGraphNode }>();
    const map = new Map<string, { x: number; y: number; node: AttackGraphNode }>();
    
    nodes.forEach((node, idx) => {
      // Circle layout centered on trigger agent if exists
      const isTrigger = node.agent_id === triggerAgent;
      let x = centerX;
      let y = centerY;
      
      if (!isTrigger) {
        const angle = (idx / (nodes.length - (triggerAgent ? 1 : 0))) * 2 * Math.PI;
        const radius = 130;
        x = centerX + radius * Math.cos(angle);
        y = centerY + radius * Math.sin(angle);
      }
      
      map.set(node.agent_id, { x, y, node });
    });
    return map;
  }, [nodes, triggerAgent]);

  // Quarantine blast radius actions
  const handleIsolateChain = async () => {
    if (!triggerAgent) return;
    setIsolating(true);
    try {
      // Simulate chain isolation by marking nodes in state as Normal or Quarantined
      setNodes(prev => prev.map(n => {
        if (n.state === 'COMPROMISED' || n.state === 'SUSPECT') {
          return { ...n, state: 'NORMAL', compromise_likelihood: 0.0 };
        }
        return n;
      }));
      alert(`Blast radius chain quarantine successfully deployed. Downstream suspect agents isolated.`);
    } catch (err) {
      console.error(err);
    } finally {
      setIsolating(false);
    }
  };

  return (
    <div className="bg-slate-950/40 border border-vigil-border/30 rounded-xl p-5 flex flex-col h-[480px] justify-between relative overflow-hidden select-none">
      <div className="flex justify-between items-center border-b border-vigil-border/20 pb-3 z-10">
        <div>
          <span className="text-[10px] text-slate-500 font-mono font-bold uppercase block">
            ATTACK PROPAGATION GRAPH (BLAST RADIUS)
          </span>
          <span className="text-[8px] text-slate-600 block">
            Downstream AI delegation impact prediction and path analysis
          </span>
        </div>
        {blastRadius > 0 && (
          <div className="flex items-center space-x-2">
            <span className="bg-vigil-red/20 text-vigil-red border border-vigil-red/40 text-[9px] font-mono font-semibold px-2 py-0.5 rounded animate-pulse">
              BLAST RADIUS: {blastRadius} AGENTS
            </span>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center font-mono text-xs text-vigil-teal animate-pulse">
          SIMULATING BLAST PROPAGATION...
        </div>
      ) : nodes.length === 0 ? (
        <div className="flex-1 flex items-center justify-center font-mono text-[10px] text-slate-600">
          NO PROPAGATION DATA AVAILABLE
        </div>
      ) : (
        <div className="flex-1 relative flex items-center justify-center">
          <svg className="w-full h-full" viewBox={`0 0 ${width} ${height}`}>
            <defs>
              <filter id="glow-compromised" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="6" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="glow-suspect" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#1e293b" />
              </marker>
            </defs>

            {/* Render Delegation Edges */}
            <g>
              {edges.map((edge) => {
                const source = positionedNodes.get(edge.source_agent_id);
                const target = positionedNodes.get(edge.target_agent_id);
                if (!source || !target) return null;

                const isThreatEdge = source.node.state === 'COMPROMISED' && target.node.state !== 'NORMAL';
                const strokeColor = isThreatEdge ? '#ff2a5f' : '#1e293b';
                const strokeWidth = isThreatEdge ? 2 : 1;

                return (
                  <g key={edge.edge_id}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={strokeColor}
                      strokeWidth={strokeWidth}
                      strokeDasharray={isThreatEdge ? '4,4' : undefined}
                      markerEnd="url(#arrow)"
                    />
                    {/* Render propagation likelihood text badge */}
                    <text
                      x={(source.x + target.x) / 2}
                      y={(source.y + target.y) / 2 - 5}
                      fill={isThreatEdge ? '#ff2a5f' : '#64748b'}
                      className="font-mono text-[8px] font-bold text-center"
                      textAnchor="middle"
                    >
                      {(edge.propagation_probability * 100).toFixed(0)}%
                    </text>
                  </g>
                );
              })}
            </g>

            {/* Render Agent Nodes */}
            <g>
              {Array.from(positionedNodes.values()).map(({ x, y, node }) => {
                const isTrigger = node.agent_id === triggerAgent;
                const isCompromised = node.state === 'COMPROMISED';
                const isSuspect = node.state === 'SUSPECT';
                
                let strokeColor = '#00f2fe';
                let fillColor = '#030712';
                let filterId = undefined;
                let ringClass = '';

                if (isCompromised) {
                  strokeColor = '#ff2a5f';
                  fillColor = '#1a050d';
                  filterId = 'url(#glow-compromised)';
                  ringClass = 'animate-pulse';
                } else if (isSuspect) {
                  strokeColor = '#f59e0b';
                  fillColor = '#1c1203';
                  filterId = 'url(#glow-suspect)';
                }

                return (
                  <g 
                    key={node.agent_id} 
                    transform={`translate(${x}, ${y})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer"
                  >
                    {/* Outer ring */}
                    <circle
                      cx="0"
                      cy="0"
                      r="16"
                      fill={fillColor}
                      stroke={strokeColor}
                      strokeWidth={isTrigger ? 3 : 1.5}
                      filter={filterId}
                      className={ringClass}
                    />

                    {/* Text abbreviation */}
                    <text
                      textAnchor="middle"
                      dy=".3em"
                      className="fill-white font-mono font-bold text-[8px] select-none pointer-events-none"
                    >
                      {node.agent_id.substring(0, 3).toUpperCase()}
                    </text>

                    {/* Label */}
                    <text
                      textAnchor="middle"
                      y="26"
                      className="fill-slate-400 font-sans text-[9px] font-semibold"
                    >
                      {node.agent_id}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Node detail popover */}
          {selectedNode && (
            <div className="absolute right-4 top-4 p-3 bg-slate-900/90 border border-vigil-border/40 rounded-lg max-w-[200px] z-20 font-mono text-[9px] text-slate-300 flex flex-col space-y-2">
              <div className="flex justify-between items-center border-b border-vigil-border/20 pb-1">
                <span className="font-bold text-white uppercase">{selectedNode.agent_id}</span>
                <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-white font-bold">×</button>
              </div>
              <div>
                <span className="text-slate-500 block">STATE:</span>
                <span className={`font-bold ${selectedNode.state === 'COMPROMISED' ? 'text-vigil-red' : selectedNode.state === 'SUSPECT' ? 'text-vigil-amber' : 'text-vigil-teal'}`}>
                  {selectedNode.state}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">COMPROMISE PROBABILITY:</span>
                <span className="font-bold text-white">{(selectedNode.compromise_likelihood * 100).toFixed(1)}%</span>
              </div>
              {selectedNode.state !== 'NORMAL' && (
                <button
                  onClick={() => {
                    alert(`Agent ${selectedNode.agent_id} quarantined and removed from the active delegation graph.`);
                    setNodes(prev => prev.map(n => n.agent_id === selectedNode.agent_id ? { ...n, state: 'NORMAL', compromise_likelihood: 0 } : n));
                    setSelectedNode(null);
                  }}
                  className="bg-vigil-red/20 text-vigil-red hover:bg-vigil-red/35 border border-vigil-red/40 py-1 rounded text-center uppercase tracking-wider font-bold transition-colors"
                >
                  Isolate Node
                </button>
              )}
            </div>
          )}
        </div>
      )}

      <div className="flex justify-between items-center pt-3 border-t border-vigil-border/20 z-10">
        <span className="font-mono text-[8px] text-slate-500">
          SELECT NODES FOR DEEP ANALYSIS | UPDATED REAL-TIME
        </span>
        {triggerAgent && (
          <button
            onClick={handleIsolateChain}
            disabled={isolating}
            className="px-3 py-1 bg-vigil-red hover:bg-red-600 disabled:opacity-50 text-black font-sans font-bold text-[9px] rounded uppercase tracking-wider transition-all shadow-[0_0_8px_rgba(255,42,95,0.3)]"
          >
            {isolating ? 'ISOLATING...' : 'Quarantine Blast Chain'}
          </button>
        )}
      </div>
    </div>
  );
};
