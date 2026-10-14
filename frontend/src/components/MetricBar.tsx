import React from 'react';

interface MetricBarProps {
  value: number; // 0 to 1
  label?: string;
  height?: number;
}

export const MetricBar: React.FC<MetricBarProps> = ({ value, label, height = 8 }) => {
  const percentage = Math.min(Math.max(value * 100, 0), 100);
  
  // Resolve color bucket based on security thresholds:
  // - < 0.45: Gray (Low/Safe)
  // - 0.45 - 0.65: Amber (Medium Threat)
  // - 0.65 - 0.85: Red (High Threat)
  // - >= 0.85: Pulsing Red (Critical Containment)
  let barColorClass = 'bg-gray-500';
  let glowClass = '';
  
  if (value >= 0.85) {
    barColorClass = 'bg-vigil-red animate-pulse';
    glowClass = 'shadow-[0_0_8px_#FF3D3D]';
  } else if (value >= 0.65) {
    barColorClass = 'bg-vigil-red';
  } else if (value >= 0.45) {
    barColorClass = 'bg-vigil-amber';
  } else {
    barColorClass = 'bg-vigil-teal';
  }

  return (
    <div className="w-full text-xs animate-fade-in">
      {(label || label === '') && (
        <div className="flex justify-between items-center mb-1 text-[11px] font-medium tracking-wide text-vigil-muted">
          <span>{label}</span>
          <span className="mono font-semibold">{percentage.toFixed(0)}%</span>
        </div>
      )}
      <div 
        className="w-full bg-vigil-bg2 rounded-full overflow-hidden border border-vigil-border/30"
        style={{ height: `${height}px` }}
      >
        <div
          className={`h-full rounded-full transition-all duration-700 cubic-bezier(0.4, 0, 0.2, 1) ${barColorClass} ${glowClass}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
};
