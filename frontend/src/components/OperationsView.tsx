import React from 'react';
import { AgentGraph } from './AgentGraph';
import { ThreatConsole } from './ThreatConsole';

export const OperationsView: React.FC = () => {
  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden min-h-0">
      {/* Top 60% area: Interactive Agent Relationship Graph centerpiece */}
      <div className="h-[60%] border-b border-vigil-border/30 relative min-h-0 select-none">
        <AgentGraph />
      </div>

      {/* Bottom 40% area: Real-time intelligence feed stream */}
      <div className="h-[40%] min-h-0">
        <ThreatConsole />
      </div>
    </div>
  );
};
