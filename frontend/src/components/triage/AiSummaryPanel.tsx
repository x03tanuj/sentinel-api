import React, { useState } from 'react';
import {
  Sparkles,
  ChevronDown,
  RotateCw,
  FileCheck,
  ShieldAlert,
} from 'lucide-react';
import { useAiStatus, useAiSummary } from '../../api/hooks';
import type { AiSummaryData } from '../../types';

interface AiSummaryPanelProps {
  scanId: string;
  existingSummary?: AiSummaryData | null;
  className?: string;
}

export const AiSummaryPanel: React.FC<AiSummaryPanelProps> = ({
  scanId,
  existingSummary,
  className = '',
}) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const { data: aiStatus } = useAiStatus();
  const summaryMutation = useAiSummary(scanId);

  const summary = (summaryMutation.data as AiSummaryData | undefined) || existingSummary;

  if (!aiStatus?.enabled && !summary) {
    return null;
  }

  return (
    <div
      className={`border border-purple-500/30 rounded-panel bg-canvas-panel overflow-hidden shadow-lg ${className}`}
      data-testid="ai-summary-panel"
    >
      <div className="px-4 py-3 bg-canvas-elevated border-b border-border-structural flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          aria-expanded={isExpanded}
          className="flex items-center gap-2 flex-wrap text-left font-mono text-xs text-slate-200 hover:text-white"
        >
          <Sparkles size={15} className="text-purple-400" />
          <span className="font-bold text-sm text-slate-100">AI Executive Summary</span>
          <span className="px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[10px]">
            verify before use
          </span>
          <ChevronDown
            size={14}
            className={`text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          />
        </button>

        {aiStatus?.enabled && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => summaryMutation.mutate()}
              disabled={summaryMutation.isPending}
              data-testid="generate-ai-summary-btn"
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-tactical font-mono text-xs font-semibold bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white shadow-glow-primary transition-colors focus:ring-1 focus:ring-purple-400 focus:outline-none"
            >
              {summaryMutation.isPending ? (
                <>
                  <RotateCw size={12} className="animate-spin" />
                  <span>Synthesizing...</span>
                </>
              ) : (
                <>
                  <Sparkles size={12} />
                  <span>{summary ? 'Regenerate Summary' : 'Generate AI Summary'}</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {isExpanded && (
        <div className="p-4 space-y-3 font-sans text-xs">
          {summaryMutation.isError && (
            <div
              role="alert"
              className="p-3 rounded-tactical bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono space-y-1"
            >
              <div className="font-semibold flex items-center gap-1.5">
                <ShieldAlert size={14} />
                <span>Executive Summary Generation Failed</span>
              </div>
              <div className="text-[11px] text-rose-200">
                {summaryMutation.error.message || 'Unable to generate scan summary.'}
              </div>
            </div>
          )}

          {summary ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-semibold">
                  <FileCheck size={10} />
                  <span>Source: {summary.source === 'llm' ? 'LLM' : 'Template Fallback'}</span>
                </span>
                {summary.model && (
                  <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-[10px]">
                    Model: {summary.model}
                  </span>
                )}
                {summary.generated_at && (
                  <span className="text-[10px] font-mono text-slate-400">
                    Generated: {new Date(summary.generated_at).toLocaleTimeString()}
                  </span>
                )}
              </div>

              <div
                className="p-3.5 rounded bg-canvas-base border border-border-structural text-slate-200 leading-relaxed whitespace-pre-wrap select-text font-sans text-xs"
                data-testid="ai-summary-text"
              >
                {summary.text}
              </div>
            </div>
          ) : (
            <div className="p-4 text-center text-slate-400 font-mono text-xs space-y-1">
              <div>No executive summary generated yet.</div>
              <div className="text-[11px] text-slate-400">
                Click &quot;Generate AI Summary&quot; to synthesize an overview of audit findings and business risk.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
