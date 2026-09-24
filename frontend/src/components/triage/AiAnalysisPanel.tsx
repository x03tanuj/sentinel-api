import React, { useState } from 'react';
import {
  Sparkles,
  ChevronDown,
  AlertTriangle,
  RotateCw,
  Copy,
  Check,
  Code2,
  ExternalLink,
  ShieldAlert,
} from 'lucide-react';
import { useAiStatus, useExplainFinding } from '../../api/hooks';
import { AiConsentModal } from './AiConsentModal';
import { Skeleton } from '../ui/Skeleton';
import type { Finding, AiAnalysisData } from '../../types';

const FRAMEWORK_HINTS = [
  'generic',
  'fastapi',
  'express',
  'django',
  'flask',
  'spring',
  'rails',
  'laravel',
  'dotnet',
] as const;

const CONSENT_STORAGE_KEY = 'sentinel_ai_consent';

interface AiAnalysisPanelProps {
  scanId: string;
  finding: Finding;
  className?: string;
}

export const AiAnalysisPanel: React.FC<AiAnalysisPanelProps> = ({
  scanId,
  finding,
  className = '',
}) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [frameworkHint, setFrameworkHint] = useState<string>('generic');
  const [isConsentOpen, setIsConsentOpen] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);

  const { data: aiStatus, isLoading: isStatusLoading } = useAiStatus();
  const explainMutation = useExplainFinding(scanId);

  const analysis: AiAnalysisData | undefined =
    finding.ai_analysis || (explainMutation.data as AiAnalysisData | undefined);

  const handleCopyCode = (codeText: string) => {
    navigator.clipboard.writeText(codeText);
    setCodeCopied(true);
    setTimeout(() => setCodeCopied(false), 2000);
  };

  const handleStartExplain = (forceRefresh = false) => {
    const hasConsent = sessionStorage.getItem(CONSENT_STORAGE_KEY) === 'true';
    if (!hasConsent) {
      setIsConsentOpen(true);
      return;
    }
    executeExplain(forceRefresh);
  };

  const executeExplain = (forceRefresh = false) => {
    explainMutation.mutate({
      findingId: finding.id,
      frameworkHint,
      forceRefresh,
    });
  };

  const handleConsentConfirm = () => {
    sessionStorage.setItem(CONSENT_STORAGE_KEY, 'true');
    setIsConsentOpen(false);
    executeExplain(false);
  };

  return (
    <>
      <div
        className={`border border-border-structural rounded-panel overflow-hidden bg-canvas-base ${className}`}
        data-testid="ai-analysis-panel"
      >
        {/* Panel Header */}
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          aria-expanded={isExpanded}
          className="w-full px-3.5 py-2.5 flex items-center justify-between text-left hover:bg-canvas-elevated transition-colors font-mono text-xs"
        >
          <div className="flex items-center gap-2 flex-wrap">
            <Sparkles size={14} className="text-purple-400 shrink-0" />
            <span className="text-slate-200 font-semibold tracking-wide">
              AI Security Analysis &amp; Remediation
            </span>
            <span className="px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[10px] shrink-0">
              verify before use
            </span>
          </div>
          <ChevronDown
            size={14}
            className={`text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          />
        </button>

        {isExpanded && (
          <div className="p-4 border-t border-border-structural space-y-4">
            {/* Case 1: Checking status */}
            {isStatusLoading && (
              <div className="space-y-2">
                <Skeleton className="h-4 w-1/3" />
                <Skeleton className="h-16 w-full" />
              </div>
            )}

            {/* Case 2: AI disabled or unconfigured on server */}
            {!isStatusLoading && !aiStatus?.enabled && (
              <div
                className="p-3.5 rounded-tactical bg-canvas-panel border border-border-subdued flex items-start gap-3 text-xs"
                data-testid="ai-disabled-banner"
              >
                <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="text-slate-200 font-medium">
                    AI analysis is not configured on this server
                  </div>
                  <p className="text-slate-400 font-sans leading-relaxed">
                    Set <code className="font-mono text-purple-300 bg-canvas-base px-1 rounded">AI_ENABLED=true</code> and{' '}
                    <code className="font-mono text-purple-300 bg-canvas-base px-1 rounded">LLM_API_KEY</code> in your environment to enable AI-powered remediation guidance.
                  </p>
                  <a
                    href="https://github.com/sentinel-api/sentinel#ai-analyst"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-[11px] text-brand hover:underline pt-1"
                  >
                    <span>View AI Setup Documentation</span>
                    <ExternalLink size={11} />
                  </a>
                </div>
              </div>
            )}

            {/* Case 3: AI configured */}
            {!isStatusLoading && aiStatus?.enabled && (
              <>
                {/* Control bar: Framework selector + Explain button */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 rounded-tactical bg-canvas-panel border border-border-structural font-mono text-xs">
                  <div className="flex items-center gap-2">
                    <label htmlFor="framework-select" className="text-slate-400">
                      Framework:
                    </label>
                    <select
                      id="framework-select"
                      aria-label="Target framework"
                      value={frameworkHint}
                      onChange={(e) => setFrameworkHint(e.target.value)}
                      disabled={explainMutation.isPending}
                      className="px-2 py-1 rounded bg-canvas-base border border-border-subdued text-slate-200 focus:outline-none focus:border-brand font-mono text-xs"
                    >
                      {FRAMEWORK_HINTS.map((h) => (
                        <option key={h} value={h}>
                          {h}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleStartExplain(!!analysis)}
                      disabled={explainMutation.isPending}
                      data-testid="explain-ai-button"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical font-mono text-xs font-semibold bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white shadow-glow-primary transition-colors focus:ring-1 focus:ring-purple-400 focus:outline-none"
                    >
                      {explainMutation.isPending ? (
                        <>
                          <RotateCw size={13} className="animate-spin" />
                          <span>Analyzing...</span>
                        </>
                      ) : (
                        <>
                          <Sparkles size={13} />
                          <span>{analysis ? 'Re-explain' : 'Explain with AI'}</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Error Banner */}
                {explainMutation.isError && (
                  <div
                    role="alert"
                    className="p-3 rounded-tactical bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono space-y-1"
                  >
                    <div className="font-semibold flex items-center gap-1.5">
                      <ShieldAlert size={14} />
                      <span>AI Analysis Request Failed</span>
                    </div>
                    <div className="text-[11px] text-rose-200">
                      {explainMutation.error.message || 'Unable to generate analysis.'}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleStartExplain(true)}
                      className="text-[11px] text-rose-300 hover:text-white underline pt-1 block"
                    >
                      Retry analysis
                    </button>
                  </div>
                )}

                {/* Loading Skeleton */}
                {explainMutation.isPending && (
                  <div className="space-y-3 pt-2" data-testid="ai-loading-skeleton">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-4 w-1/2" />
                    <Skeleton className="h-24 w-full" />
                  </div>
                )}

                {/* Rendered Analysis */}
                {analysis && !explainMutation.isPending && (
                  <div className="space-y-4 pt-1" data-testid="ai-analysis-content">
                    {/* Header Badges */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-semibold">
                        <Sparkles size={10} />
                        <span>AI-generated - verify before use</span>
                      </span>

                      {analysis.source === 'llm' && analysis.model && (
                        <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-[10px]">
                          Model: {analysis.model}
                        </span>
                      )}

                      {analysis.source === 'template' && (
                        <span
                          className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono text-[10px]"
                          title={analysis.warning || undefined}
                          data-testid="template-fallback-badge"
                        >
                          Template fallback
                        </span>
                      )}
                    </div>

                    {/* Warning if present */}
                    {analysis.warning && (
                      <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs font-mono">
                        {analysis.warning}
                      </div>
                    )}

                    {/* Section 1: Plain Explanation */}
                    <div className="space-y-1">
                      <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Plain Explanation
                      </h4>
                      <p className="font-sans text-xs text-slate-200 leading-relaxed bg-canvas-panel p-2.5 rounded border border-border-structural whitespace-pre-wrap">
                        {analysis.plain_explanation}
                      </p>
                    </div>

                    {/* Section 2: Business Impact */}
                    <div className="space-y-1">
                      <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Business Impact
                      </h4>
                      <p className="font-sans text-xs text-slate-200 leading-relaxed bg-canvas-panel p-2.5 rounded border border-border-structural whitespace-pre-wrap">
                        {analysis.business_impact}
                      </p>
                    </div>

                    {/* Section 3: Attacker Scenario */}
                    <div className="space-y-1">
                      <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Attacker Scenario
                      </h4>
                      <p className="font-sans text-xs text-slate-200 leading-relaxed bg-canvas-panel p-2.5 rounded border border-border-structural whitespace-pre-wrap">
                        {analysis.attacker_scenario}
                      </p>
                    </div>

                    {/* Section 4: Remediation Steps */}
                    {analysis.remediation_steps?.length > 0 && (
                      <div className="space-y-1.5">
                        <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                          Remediation Steps
                        </h4>
                        <ol className="list-decimal list-inside space-y-1 p-3 rounded bg-canvas-panel border border-border-structural text-xs font-sans text-slate-200">
                          {analysis.remediation_steps.map((step, idx) => (
                            <li key={idx} className="leading-relaxed">
                              <span>{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {/* Section 5: Code Fix Example */}
                    {analysis.code_fix_example && (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                            Code Fix Example
                          </h4>
                          <span className="font-mono text-[10px] text-purple-300 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/30">
                            {analysis.code_language || frameworkHint}
                          </span>
                        </div>

                        {/* Code block with copy button */}
                        <div className="rounded-panel bg-canvas-base border border-border-structural overflow-hidden font-mono text-xs">
                          <div className="bg-canvas-panel px-3 py-1.5 border-b border-border-structural flex items-center justify-between">
                            <div className="flex items-center gap-1.5 text-slate-400">
                              <Code2 size={13} className="text-purple-400" />
                              <span className="text-[11px]">
                                {analysis.code_language || frameworkHint} snippet
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleCopyCode(analysis.code_fix_example)}
                              aria-label="Copy remediation code"
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-canvas-elevated hover:bg-canvas-overlay text-slate-300 border border-border-structural text-[11px] transition-colors focus:ring-1 focus:ring-brand focus:outline-none"
                            >
                              {codeCopied ? (
                                <>
                                  <Check size={12} className="text-severity-secure" />
                                  <span className="text-severity-secure font-semibold">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy size={12} className="text-slate-400" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre
                            tabIndex={0}
                            className="p-3 text-slate-200 overflow-x-auto whitespace-pre leading-relaxed select-text font-mono text-xs"
                          >
                            {analysis.code_fix_example}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Section 6: Verification Steps */}
                    {analysis.verification_steps?.length > 0 && (
                      <div className="space-y-1.5">
                        <h4 className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
                          Verification Steps
                        </h4>
                        <ol className="list-decimal list-inside space-y-1 p-3 rounded bg-canvas-panel border border-border-structural text-xs font-sans text-slate-200">
                          {analysis.verification_steps.map((step, idx) => (
                            <li key={idx} className="leading-relaxed">
                              <span>{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <AiConsentModal
        isOpen={isConsentOpen}
        providerName={aiStatus?.provider || 'AI Provider'}
        onConfirm={handleConsentConfirm}
        onCancel={() => setIsConsentOpen(false)}
      />
    </>
  );
};
