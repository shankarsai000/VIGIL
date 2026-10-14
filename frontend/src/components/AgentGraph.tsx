import React, { useMemo, useState, useEffect } from 'react';
import { useVigilStore } from '../store';
import { AgentStatus } from '../types';

export const AgentGraph: React.FC = () => {
  const { 
    agents, 
    incidents, 
    selectedAgentId, 
    setSelectedAgentId, 
    activeGraphHighlight, 
    setActiveGraphHighlight 
  } = useVigilStore();

  const [threatParticles, setThreatParticles] = useState<{ id: string; x: number; y: number; edgeId: string; progress: number }[]>([]);

  // Setup layout constants
  const width = 800;
  const height = 480;
  const centerX = width / 2;
  const centerY = height / 2;

  // Process agent nodes
  const agentList = Array.from(agents.values());
  const agentNodes = useMemo(() => {
    return agentList.map((agent, index) => {
      // Place agents in a beautiful circle
      const angle = (index / agentList.length) * 2 * Math.PI - Math.PI / 2;
      const radius = 150;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      return {
        id: agent.agent_id,
        name: agent.name,
        x,
        y,
        status: agent.status,
        anomalyScore: agent.anomaly_score,
        permittedTools: agent.permitted_tools,
        permittedAgents: agent.permitted_agents,
      };
    });
  }, [agentList.length, agents]);

  // Extract all tools and create tool nodes orbiting their respective agent nodes
  const graphData = useMemo(() => {
    const nodes: any[] = [];
    const edges: any[] = [];
    
    // Add agents as primary nodes
    agentNodes.forEach(agent => {
      nodes.push({
        id: agent.id,
        label: agent.name,
        type: 'agent',
        x: agent.x,
        y: agent.y,
        status: agent.status,
        score: agent.anomalyScore,
      });

      // Add allowed delegation edges between agents
      agent.permittedAgents.forEach(targetId => {
        const targetAgent = agentNodes.find(a => a.id === targetId);
        if (targetAgent) {
          edges.push({
            id: `edge-${agent.id}-to-${targetId}`,
            source: agent.id,
            target: targetId,
            sourceX: agent.x,
            sourceY: agent.y,
            targetX: targetAgent.x,
            targetY: targetAgent.y,
            type: 'delegation',
            status: agent.status === AgentStatus.QUARANTINED || targetAgent.status === AgentStatus.QUARANTINED ? 'quarantined' :
                    agent.status === AgentStatus.ALERT || targetAgent.status === AgentStatus.ALERT ? 'threat' : 'normal'
          });
        }
      });

      // Add tools orbiting this agent node
      agent.permittedTools.forEach((tool, tIdx) => {
        // Place tools orbiting around their specific agent
        const tAngle = (tIdx / agent.permittedTools.length) * 2 * Math.PI;
        const orbitRadius = 48;
        const tx = agent.x + orbitRadius * Math.cos(tAngle);
        const ty = agent.y + orbitRadius * Math.sin(tAngle);
        const toolNodeId = `tool-${agent.id}-${tool}`;

        nodes.push({
          id: toolNodeId,
          label: tool,
          type: 'tool',
          x: tx,
          y: ty,
          status: agent.status === AgentStatus.QUARANTINED ? 'quarantined' : 'normal',
        });

        // Add edge from agent to tool
        edges.push({
          id: `edge-${agent.id}-to-${toolNodeId}`,
          source: agent.id,
          target: toolNodeId,
          sourceX: agent.x,
          sourceY: agent.y,
          targetX: tx,
          targetY: ty,
          type: 'tool_call',
          status: agent.status === AgentStatus.QUARANTINED ? 'quarantined' : 'normal'
        });
      });
    });

    return { nodes, edges };
  }, [agentNodes]);

  // Live particle animation down active edges when threats fire
  useEffect(() => {
    const latestIncident = incidents[0];
    if (!latestIncident || latestIncident.timestamp < Date.now() - 5000) return;

    const sourceAgent = latestIncident.agent_id;
    const matchingEdges = graphData.edges.filter(e => e.source === sourceAgent);

    if (matchingEdges.length === 0) return;

    // Fire some threat particles down the delegation/tool chains!
    const newParticles = matchingEdges.map(edge => ({
      id: `p-${Math.random().toString(36).substring(2, 9)}`,
      x: edge.sourceX,
      y: edge.sourceY,
      edgeId: edge.id,
      progress: 0,
    }));

    setThreatParticles(prev => [...prev, ...newParticles]);
  }, [incidents.length]);

  // Animate threat particles flowing along edges
  useEffect(() => {
    if (threatParticles.length === 0) return;

    const interval = setInterval(() => {
      setThreatParticles(prev => 
        prev
          .map(p => {
            const edge = graphData.edges.find(e => e.id === p.edgeId);
            if (!edge) return null;
            const nextProgress = p.progress + 0.05;
            if (nextProgress >= 1) return null; // particle reached destination

            const px = edge.sourceX + (edge.targetX - edge.sourceX) * nextProgress;
            const py = edge.sourceY + (edge.targetY - edge.sourceY) * nextProgress;

            return {
              ...p,
              x: px,
              y: py,
              progress: nextProgress,
            };
          })
          .filter((p): p is any => p !== null)
      );
    }, 30);

    return () => clearInterval(interval);
  }, [threatParticles.length, graphData.edges]);

  // Highlight selection sets
  const activeHighlightAgent = activeGraphHighlight || selectedAgentId;

  return (
    <div className="relative w-full h-full flex flex-col justify-between select-none overflow-hidden animated-grid-bg">
      {/* Background Cyber-grid scan animation and title overlay */}
      <div className="absolute top-4 left-4 font-mono z-10 flex flex-col space-y-1">
        <span className="text-[10px] text-vigil-teal tracking-widest font-bold uppercase">
          GRAPH OBSERVER MODE: ACTIVE
        </span>
        <span className="text-[9px] text-slate-500 uppercase">
          Double-click canvas to center | Hover nodes to highlight dependencies
        </span>
      </div>

      {/* SVG Canvas */}
      <svg
        className="w-full h-full"
        viewBox={`0 0 ${width} ${height}`}
        style={{ background: 'transparent' }}
      >
        {/* SVG Glow Filter Definitions */}
        <defs>
          <filter id="glow-teal-svg" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="glow-red-svg" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="glow-amber-svg" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="gradient-edge-normal" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00f2fe" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#bc13fe" stopOpacity="0.4" />
          </linearGradient>
          <linearGradient id="gradient-edge-threat" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ff2a5f" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.6" />
          </linearGradient>
        </defs>

        {/* 1. Render Edges (Paths) */}
        <g className="edges">
          {graphData.edges.map((edge) => {
            const isRelated = activeHighlightAgent 
              ? (edge.source === activeHighlightAgent || edge.target === activeHighlightAgent)
              : true;

            const isQuarantined = edge.status === 'quarantined';
            const isThreat = edge.status === 'threat';

            let strokeColor = 'url(#gradient-edge-normal)';
            let dashArray = '5,5';
            let strokeWidth = 1.5;

            if (isQuarantined) {
              strokeColor = '#ff2a5f';
              dashArray = '2,8';
              strokeWidth = 1;
            } else if (isThreat) {
              strokeColor = 'url(#gradient-edge-threat)';
              dashArray = '4,4';
              strokeWidth = 2.5;
            }

            return (
              <g key={edge.id} className="transition-all duration-300">
                {/* Visual line backing for glowing hover */}
                <line
                  x1={edge.sourceX}
                  y1={edge.sourceY}
                  x2={edge.targetX}
                  y2={edge.targetY}
                  stroke={isThreat ? '#ff2a5f' : '#00f2fe'}
                  strokeWidth={strokeWidth + 4}
                  strokeOpacity={activeHighlightAgent && isRelated ? 0.15 : 0}
                  className="transition-all duration-300"
                />
                
                {/* Main edge connection path */}
                <path
                  d={`M ${edge.sourceX} ${edge.sourceY} L ${edge.targetX} ${edge.targetY}`}
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={dashArray}
                  strokeLinecap="round"
                  strokeOpacity={activeHighlightAgent ? (isRelated ? 1.0 : 0.15) : 0.6}
                  className="transition-all duration-300"
                >
                  {/* Animating dash array offsets */}
                  {!isQuarantined && (
                    <animate
                      attributeName="stroke-dashoffset"
                      values="100;0"
                      dur={isThreat ? '1.5s' : '4s'}
                      repeatCount="indefinite"
                    />
                  )}
                </path>
              </g>
            );
          })}
        </g>

        {/* 2. Render Threat Particles */}
        <g className="particles">
          {threatParticles.map((particle) => (
            <circle
              key={particle.id}
              cx={particle.x}
              cy={particle.y}
              r="4.5"
              fill="#ff2a5f"
              filter="url(#glow-red-svg)"
              className="pointer-events-none"
            />
          ))}
        </g>

        {/* 3. Render Nodes */}
        <g className="nodes">
          {graphData.nodes.map((node) => {
            const isAgent = node.type === 'agent';
            const isSelected = selectedAgentId === node.id;
            const isHighlighted = activeGraphHighlight === node.id;
            const isRelated = activeHighlightAgent
              ? (node.id === activeHighlightAgent || graphData.edges.some(e => 
                  (e.source === activeHighlightAgent && e.target === node.id) || 
                  (e.target === activeHighlightAgent && e.source === node.id)
                ))
              : true;

            const isQuarantined = node.status === AgentStatus.QUARANTINED;
            const isThreatened = node.status === AgentStatus.ALERT || node.status === AgentStatus.ANOMALOUS;

            const opacity = activeHighlightAgent ? (isRelated ? 1.0 : 0.25) : 1.0;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={(e) => {
                  e.stopPropagation();
                  if (isAgent) {
                    setSelectedAgentId(isSelected ? null : node.id);
                  }
                }}
                onMouseEnter={() => isAgent && setActiveGraphHighlight(node.id)}
                onMouseLeave={() => isAgent && setActiveGraphHighlight(null)}
                className="cursor-pointer select-none transition-all duration-300"
                style={{ opacity }}
              >
                {isAgent ? (
                  /* AGENT NODE */
                  <g>
                    {/* Glowing Aura backdrop */}
                    <circle
                      cx="0"
                      cy="0"
                      r="22"
                      fill="transparent"
                      stroke={isQuarantined ? '#ff2a5f' : isThreatened ? '#f59e0b' : '#00f2fe'}
                      strokeWidth={isSelected || isHighlighted ? 6 : 2}
                      strokeOpacity={isSelected || isHighlighted ? 0.8 : 0.2}
                      filter={isQuarantined ? 'url(#glow-red-svg)' : isThreatened ? 'url(#glow-amber-svg)' : 'url(#glow-teal-svg)'}
                      className="transition-all duration-300"
                    />

                    {/* Threat pulsing ring overlay */}
                    {isThreatened && (
                      <circle
                        cx="0"
                        cy="0"
                        r="32"
                        fill="transparent"
                        stroke="#f59e0b"
                        strokeWidth="1.5"
                        strokeOpacity="0.4"
                        className="animate-ping"
                      />
                    )}

                    {/* Quarantine shield dome */}
                    {isQuarantined && (
                      <g>
                        <circle
                          cx="0"
                          cy="0"
                          r="34"
                          fill="transparent"
                          stroke="#ff2a5f"
                          strokeWidth="2.5"
                          strokeDasharray="4,6"
                          className="animate-spin"
                          style={{ animationDuration: '8s' }}
                        />
                        <circle
                          cx="0"
                          cy="0"
                          r="34"
                          fill="rgba(255, 42, 95, 0.05)"
                        />
                      </g>
                    )}

                    {/* Core Agent circle */}
                    <circle
                      cx="0"
                      cy="0"
                      r="18"
                      fill={isQuarantined ? '#1f0d14' : isThreatened ? '#261b0c' : '#080f1a'}
                      stroke={isQuarantined ? '#ff2a5f' : isThreatened ? '#f59e0b' : '#00f2fe'}
                      strokeWidth="2"
                      className="transition-all duration-300"
                    />

                    {/* Text initials inside agent */}
                    <text
                      textAnchor="middle"
                      dy=".3em"
                      className="fill-white font-mono font-bold text-[10px] tracking-tighter"
                    >
                      {node.label.split('_').map((n: string) => n[0]).join('').substring(0, 3).toUpperCase()}
                    </text>

                    {/* Label below node */}
                    <text
                      textAnchor="middle"
                      y="32"
                      className="fill-slate-300 font-sans text-[10px] font-bold tracking-wide transition-all duration-300"
                    >
                      {node.label}
                    </text>
                  </g>
                ) : (
                  /* ORBITING TOOL NODE */
                  <g>
                    {/* Tool base block */}
                    <rect
                      x="-7"
                      y="-7"
                      width="14"
                      height="14"
                      rx="3"
                      fill="#070c14"
                      stroke={isQuarantined ? '#ff2a5f' : '#bc13fe'}
                      strokeWidth="1.5"
                      strokeOpacity="0.8"
                      className="transition-all duration-300"
                    />
                    
                    {/* Tool icon dot */}
                    <circle
                      cx="0"
                      cy="0"
                      r="2"
                      fill={isQuarantined ? '#ff2a5f' : '#bc13fe'}
                    />

                    {/* Tool Text tooltip on hover or graph active highlight */}
                    <text
                      textAnchor="middle"
                      y="-12"
                      className="fill-slate-400 font-mono text-[8px] font-semibold uppercase tracking-wider transition-opacity duration-300 select-none opacity-0 hover:opacity-100"
                      style={{ opacity: isRelated && activeHighlightAgent ? 1.0 : 0.0 }}
                    >
                      {node.label}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* Floating Graph Stats Panel bottom left */}
      <div className="absolute bottom-4 left-4 p-3 bg-slate-950/80 border border-vigil-border/40 rounded-lg flex flex-col space-y-1 z-10 font-mono text-[9px]">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-vigil-teal" />
          <span className="text-slate-300">NORMAL RELATIONSHIP EDGE</span>
        </div>
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-vigil-purple" />
          <span className="text-slate-300">AUTHORIZED SYSTEM TOOLCHAIN</span>
        </div>
        <div className="flex items-center space-x-2 flex-wrap">
          <span className="w-2 h-2 rounded-full bg-vigil-red animate-ping" />
          <span className="text-vigil-red font-bold uppercase">CONTAINED ANOMALY FLOWS</span>
        </div>
      </div>
    </div>
  );
};
