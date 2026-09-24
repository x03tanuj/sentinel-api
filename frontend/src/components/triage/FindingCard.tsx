import React from 'react';
import type { Finding } from '../../types';
import { SeverityChip } from '../ui/SeverityChip';
import { MethodBadge } from '../ui/MethodBadge';
import { ConfidenceBar } from '../ui/ConfidenceBar';

interface FindingCardProps {
  finding: Finding;
  isSelected?: boolean;
  onSelect: (finding: Finding) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  isSelected = false,
  onSelect,
}) => {
  const attacker = finding.evidence?.identity || 'anonymous';

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(finding)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(finding);
        }
      }}
      className={`p-3 rounded-tactical cursor-pointer transition-all border text-left flex flex-col gap-2 relative ${
        isSelected
          ? 'bg-canvas-elevated border-brand shadow-glow-primary'
          : 'bg-canvas-panel border-border-structural hover:border-border-focus/60 hover:bg-canvas-elevated/50'
      }`}
    >
      {isSelected && (
        <div className="absolute left-0 top-0 bottom-0 w-1 bg-brand rounded-l-tactical" />
      )}

      {/* Top Row: Method, Path, Severity */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <MethodBadge method={finding.method} size="sm" />
          <span className="font-mono text-xs font-semibold text-slate-200 truncate">
            {finding.endpoint}
          </span>
        </div>
        <SeverityChip severity={finding.severity} size="sm" />
      </div>

      {/* Title */}
      <div className="font-sans text-xs font-semibold text-slate-100 line-clamp-2">
        {finding.title}
      </div>

      {/* Bottom Metadata: OWASP, Attacker, Confidence */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-border-subdued">
        <div className="flex items-center gap-2 truncate">
          {finding.owasp_id && (
            <span className="px-1 rounded bg-canvas-base border border-border-subdued text-slate-300">
              {finding.owasp_id}
            </span>
          )}
          <span className="truncate">
            by: <span className="text-brand font-medium">{attacker}</span>
          </span>
        </div>
        <ConfidenceBar confidence={finding.confidence} showText={false} className="shrink-0" />
      </div>
    </div>
  );
};
