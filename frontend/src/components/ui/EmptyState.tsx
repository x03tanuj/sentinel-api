import React from 'react';
import { ShieldCheck, Crosshair } from 'lucide-react';

interface EmptyStateProps {
  icon?: 'shield' | 'crosshair';
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  className?: string;
  checkedSummary?: string[];
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon = 'crosshair',
  title,
  description,
  actionText,
  onAction,
  className = '',
  checkedSummary,
}) => {
  return (
    <div
      role="status"
      className={`p-8 rounded-panel bg-canvas-panel border border-border-structural flex flex-col items-center justify-center text-center max-w-xl mx-auto my-6 ${className}`}
    >
      <div className="w-12 h-12 rounded-full bg-brand/10 border border-brand/30 flex items-center justify-center text-brand mb-4">
        {icon === 'shield' ? <ShieldCheck size={24} /> : <Crosshair size={24} />}
      </div>

      <h3 className="font-sans text-lg font-semibold text-slate-100 mb-2">{title}</h3>
      <p className="font-sans text-xs text-slate-400 mb-6 leading-relaxed max-w-md">{description}</p>

      {checkedSummary && checkedSummary.length > 0 && (
        <div className="w-full text-left bg-canvas-elevated p-3 rounded-tactical border border-border-subdued mb-6">
          <div className="font-mono text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Coverage Verification Summary:
          </div>
          <ul className="space-y-1 font-mono text-xs text-slate-300">
            {checkedSummary.map((item, idx) => (
              <li key={idx} className="flex items-center gap-2">
                <span className="text-severity-secure">✓</span> {item}
              </li>
            ))}
          </ul>
          <div className="mt-2 text-[10px] text-slate-500 font-mono">
            * Note: SentinelAPI verifies object-level and function-level authorization, data exposure, and rate limits.
          </div>
        </div>
      )}

      {actionText && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 rounded-tactical bg-brand text-canvas-base font-sans font-semibold text-xs hover:bg-brand-hover transition-colors shadow-glow-primary focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-2 focus:ring-offset-canvas-base"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
