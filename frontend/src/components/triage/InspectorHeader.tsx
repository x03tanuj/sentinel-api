import React, { useState } from 'react';
import type { Finding } from '../../types';
import { MethodBadge } from '../ui/MethodBadge';
import { SeverityChip } from '../ui/SeverityChip';
import { ConfidenceBar } from '../ui/ConfidenceBar';
import { ShieldAlert, Link as LinkIcon, Check } from 'lucide-react';

interface InspectorHeaderProps {
  finding: Finding;
  riskScore?: number;
}

export const InspectorHeader: React.FC<InspectorHeaderProps> = ({
  finding,
  riskScore,
}) => {
  const [copiedLink, setCopiedLink] = useState(false);

  const handleCopyLink = () => {
    const url = new URL(window.location.href);
    url.searchParams.set('finding', finding.id);
    navigator.clipboard.writeText(url.toString());
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const score = riskScore !== undefined ? riskScore : Math.round(finding.confidence * 85);
  let scoreBadgeColor = 'text-brand border-brand/40 bg-brand/10';
  if (score >= 80) {
    scoreBadgeColor = 'text-severity-critical border-severity-critical/40 bg-severity-critical/10';
  } else if (score >= 60) {
    scoreBadgeColor = 'text-severity-high border-severity-high/40 bg-severity-high/10';
  } else if (score >= 35) {
    scoreBadgeColor = 'text-severity-medium border-severity-medium/40 bg-severity-medium/10';
  }

  return (
    <div className="space-y-3 pb-4 border-b border-border-structural">
      {/* Top Meta: Method, Path, Badges */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <MethodBadge method={finding.method} />
          <span className="font-mono text-sm font-semibold text-slate-100 bg-canvas-base px-2 py-0.5 rounded-tactical border border-border-structural">
            {finding.endpoint}
          </span>
          <SeverityChip severity={finding.severity} />
          {finding.owasp_id && (
            <span className="px-2 py-0.5 rounded-tactical border border-border-structural bg-canvas-base font-mono text-xs font-semibold text-slate-300">
              {finding.owasp_id}
            </span>
          )}
        </div>

        {/* Action Buttons & Risk Score */}
        <div className="flex items-center gap-3">
          <div
            className={`px-3 py-1 rounded-tactical border font-mono text-xs flex items-center gap-1.5 ${scoreBadgeColor}`}
          >
            <ShieldAlert size={14} />
            <span className="font-bold">{score} / 100</span>
            <span className="text-[10px] uppercase tracking-wider text-slate-400">
              Risk Score
            </span>
          </div>

          <button
            onClick={handleCopyLink}
            aria-label="Copy deep link to finding"
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-tactical border border-border-structural text-slate-300 text-xs font-mono hover:bg-canvas-elevated transition-colors"
          >
            {copiedLink ? <Check size={13} className="text-severity-secure" /> : <LinkIcon size={13} />}
            <span>{copiedLink ? 'Copied' : 'Share'}</span>
          </button>
        </div>
      </div>

      {/* Main Title */}
      <h2 className="font-sans text-xl font-bold tracking-tight text-slate-100">
        {finding.title}
      </h2>

      {/* Confidence rating */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-slate-400">Scanner Confidence:</span>
        <ConfidenceBar confidence={finding.confidence} />
      </div>
    </div>
  );
};
