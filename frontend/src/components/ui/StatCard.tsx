import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  highlightColor?: string;
  badgeText?: string;
  badgeColor?: string;
  isGap?: boolean;
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtext,
  highlightColor = 'text-slate-100',
  badgeText,
  badgeColor = 'bg-brand/10 text-brand border-brand/30',
  isGap = false,
  className = '',
}) => {
  return (
    <div
      className={`relative p-3.5 rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col justify-between ${className}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="font-mono text-xs uppercase tracking-wider text-slate-400 truncate">
          {label}
        </span>
        {badgeText && (
          <span
            className={`font-mono text-[10px] px-1.5 py-0.5 rounded-tactical border ${badgeColor}`}
          >
            {badgeText}
          </span>
        )}
      </div>

      <div className="flex items-baseline gap-2">
        <span className={`font-sans text-2xl font-bold tracking-tight ${highlightColor}`}>
          {value}
        </span>
        {subtext && (
          <span className="font-mono text-xs text-slate-400 truncate">
            {subtext}
          </span>
        )}
      </div>

      {isGap && (
        <div className="mt-1 pt-1 border-t border-border-subdued flex items-center justify-between">
          <span className="font-mono text-[9px] text-amber-400">
            * Backend Gap (Proposed in Phase 9B/10)
          </span>
        </div>
      )}
    </div>
  );
};
