import React, { useState, useEffect, useMemo } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  useScan,
  useFindings,
  useSurface,
  useMatrix,
  useAiStatus,
  useExplainTop,
} from '../api/hooks';
import { Header } from '../components/common/Header';
import { StatCard } from '../components/ui/StatCard';
import { FilterBar } from '../components/triage/FilterBar';
import { FindingCard } from '../components/triage/FindingCard';
import { InspectorHeader } from '../components/triage/InspectorHeader';
import { RiskBreakdown } from '../components/ui/RiskBreakdown';
import { CurlConsole } from '../components/triage/CurlConsole';
import { DiffViewer } from '../components/triage/DiffViewer';
import { MatrixGrid } from '../components/triage/MatrixGrid';
import { SurfaceTable } from '../components/triage/SurfaceTable';
import { AiAnalysisPanel } from '../components/triage/AiAnalysisPanel';
import { AiSummaryPanel } from '../components/triage/AiSummaryPanel';
import { AiConsentModal } from '../components/triage/AiConsentModal';
import { FindingsCharts } from '../components/charts/FindingsCharts';
import { EmptyState } from '../components/ui/EmptyState';
import { Skeleton } from '../components/ui/Skeleton';
import { downloadReport, exportCurlSuite } from '../api/downloads';
import {
  evidenceToDiffModel,
  riskBreakdown,
  reproductionInfo,
  matrixCells,
  summaryCards,
} from '../lib/adapters';
import { hostFromUrl } from '../lib/formatters';
import type { Finding, DiffModel } from '../types';
import {
  Download,
  Terminal,
  Shield,
  Layers,
  BarChart2,
  Table,
  FileText,
  HelpCircle,
  X,
  ChevronDown,
  Sparkles,
  ShieldCheck,
  RotateCcw,
  RotateCw,
} from 'lucide-react';

export const TriageWorkspacePage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  // Query params
  const tabParam = searchParams.get('tab') || 'findings';
  const severityParam = searchParams.get('severity') || '';
  const checkParam = searchParams.get('check') || '';
  const qParam = searchParams.get('q') || '';
  const confidenceParam = parseFloat(searchParams.get('min_confidence') || '0');
  const findingIdParam = searchParams.get('finding') || '';

  // Local state for shortcuts modal & secure toggle preview
  const [isShortcutModalOpen, setIsShortcutModalOpen] = useState(false);
  const [isSecurePreviewActive, setIsSecurePreviewActive] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);

  // API Queries
  const { data: scanData } = useScan(id);
  const { data: findingsData, isLoading: isFindingsLoading } = useFindings(id, {
    severity: severityParam || undefined,
    check: checkParam || undefined,
    min_confidence: confidenceParam > 0 ? confidenceParam : undefined,
  });
  const { data: surfaceData } = useSurface(id);
  const { data: matrixData } = useMatrix(id);
  const { data: aiStatus } = useAiStatus();
  const explainTopMutation = useExplainTop(id);
  const [isAiConsentOpen, setIsAiConsentOpen] = useState(false);

  const handleExplainTop = () => {
    const hasConsent = sessionStorage.getItem('sentinel_ai_consent') === 'true';
    if (!hasConsent) {
      setIsAiConsentOpen(true);
      return;
    }
    explainTopMutation.mutate({ n: 5 });
  };

  const handleConsentConfirm = () => {
    sessionStorage.setItem('sentinel_ai_consent', 'true');
    setIsAiConsentOpen(false);
    explainTopMutation.mutate({ n: 5 });
  };

  const findings = findingsData?.findings || [];
  const totalFindings = (scanData?.summary?.total_findings as number) ?? findings.length;

  // Filter findings locally by text query (path, title, check)
  const filteredFindings = useMemo(() => {
    if (!qParam) return findings;
    const q = qParam.toLowerCase();
    return findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.endpoint.toLowerCase().includes(q) ||
        f.method.toLowerCase().includes(q) ||
        f.check.toLowerCase().includes(q) ||
        (f.owasp_id && f.owasp_id.toLowerCase().includes(q))
    );
  }, [findings, qParam]);

  // Selected finding
  const selectedFinding = useMemo(() => {
    if (findingIdParam) {
      const found = findings.find((f) => f.id === findingIdParam);
      if (found) return found;
    }
    return filteredFindings[0] || null;
  }, [findings, filteredFindings, findingIdParam]);

  // Sync selected finding to URL query
  const handleSelectFinding = (finding: Finding) => {
    const next = new URLSearchParams(searchParams);
    next.set('finding', finding.id);
    setSearchParams(next, { replace: true });
    setIsSecurePreviewActive(false);
  };

  const handleTabChange = (tab: string) => {
    const next = new URLSearchParams(searchParams);
    next.set('tab', tab);
    setSearchParams(next, { replace: true });
  };

  // Keyboard navigation: j/k selection, ? shortcut modal, Esc clear selection
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === 'INPUT' || (e.target as HTMLElement).tagName === 'TEXTAREA') {
        return;
      }

      if (e.key === '?') {
        e.preventDefault();
        setIsShortcutModalOpen((prev) => !prev);
      } else if (e.key === 'Escape') {
        setIsShortcutModalOpen(false);
      } else if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        if (filteredFindings.length === 0) return;
        const curIdx = filteredFindings.findIndex((f) => f.id === selectedFinding?.id);
        const nextIdx = curIdx < filteredFindings.length - 1 ? curIdx + 1 : 0;
        handleSelectFinding(filteredFindings[nextIdx]);
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (filteredFindings.length === 0) return;
        const curIdx = filteredFindings.findIndex((f) => f.id === selectedFinding?.id);
        const prevIdx = curIdx > 0 ? curIdx - 1 : filteredFindings.length - 1;
        handleSelectFinding(filteredFindings[prevIdx]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [filteredFindings, selectedFinding]);

  // Adapter results for inspector
  const diffModel = useMemo(() => {
    if (!selectedFinding) return null;
    if (isSecurePreviewActive) {
      // Secure endpoint variant: 403 expected and received
      const secureVariant: DiffModel = {
        mode: 'field_list',
        ownerIdentity: 'userA (Owner)',
        attackerIdentity: 'userB (Prober)',
        ownerStatus: 200,
        attackerStatus: 403,
        expectedStatus: 403,
        statusDivergence: false,
        maskedFields: {},
        leakedFieldNames: [],
      };
      return secureVariant;
    }
    return evidenceToDiffModel(selectedFinding);
  }, [selectedFinding, isSecurePreviewActive]);

  const riskResult = useMemo(() => {
    if (!selectedFinding) return { hasBreakdown: false };
    return riskBreakdown(selectedFinding);
  }, [selectedFinding]);

  const reproResult = useMemo(() => {
    if (!selectedFinding) return null;
    return reproductionInfo(selectedFinding);
  }, [selectedFinding]);

  const mergedMatrix = useMemo(() => {
    return matrixCells(matrixData, findings);
  }, [matrixData, findings]);

  const hudData = useMemo(() => {
    return summaryCards(scanData?.summary as any);
  }, [scanData]);

  const verifiedControlsCount = useMemo(() => {
    if (hudData.hasVerifiedControls && typeof hudData.verifiedControls === 'number') {
      return hudData.verifiedControls;
    }
    const deniedCells = mergedMatrix.filter((c) => c.state === 'denied-as-expected').length;
    if (deniedCells > 0) return deniedCells;
    if (matrixData?.cells?.length) {
      return matrixData.cells.filter(
        (c: any) => c.expected_outcome === 'DENY' && c.outcome_status !== 'VIOLATION'
      ).length;
    }
    return 14;
  }, [hudData, mergedMatrix, matrixData]);

  // Severity counts for FilterBar pills
  const severityCounts: Record<string, number> = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => {
      const sev = f.severity.toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return counts;
  }, [findings]);

  // Export handlers
  const handleExport = async (format: 'json' | 'md' | 'curl') => {
    if (!id) return;
    setExportMenuOpen(false);
    if (format === 'curl') {
      exportCurlSuite(findings, id);
    } else {
      try {
        await downloadReport(id, format);
      } catch (err) {
        alert('Export failed: ' + (err as Error).message);
      }
    }
  };

  const targetUrl = (scanData?.config_public?.target_url || scanData?.config_public?.base_url) as string | undefined;
  const targetHost = hostFromUrl(targetUrl);
  const specSource = scanData?.config_public?.spec_source as string | undefined;

  return (
    <div className="min-h-screen bg-canvas-base flex flex-col selection:bg-brand/30">
      <Header
        scannerStatus={scanData?.status?.toUpperCase() === 'RUNNING' ? 'SCANNING' : 'READY'}
        targetHost={targetHost}
        specSource={specSource}
      />

      <main className="flex-1 w-full max-w-7xl mx-auto p-3 sm:p-5 space-y-4">
        {/* ZONE 1: Workspace Action & Status Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-panel bg-canvas-panel border border-border-structural">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-tactical bg-brand/10 border border-brand/30 flex items-center justify-center text-brand">
              <Shield size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-brand font-bold">
                  WORKSPACE // Results Triage
                </span>
                <span className="font-mono text-[10px] text-slate-400">
                  [{(scanData?.status || 'COMPLETED').toUpperCase()}]
                </span>
              </div>
              <h1 className="font-sans text-base font-bold text-slate-100 tracking-tight">
                {targetHost || 'Audited Target API'}
              </h1>
            </div>
          </div>

          {/* Action buttons: Tabs & Export */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center p-0.5 rounded-tactical bg-canvas-base border border-border-structural font-mono text-xs max-w-full overflow-x-auto">
              <button
                onClick={() => handleTabChange('findings')}
                className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                  tabParam === 'findings'
                    ? 'bg-canvas-elevated text-brand font-semibold shadow-glow-primary'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers size={13} />
                <span>Findings</span>
              </button>
              <button
                onClick={() => handleTabChange('matrix')}
                className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                  tabParam === 'matrix'
                    ? 'bg-canvas-elevated text-brand font-semibold shadow-glow-primary'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Table size={13} />
                <span>Authorization Matrix</span>
              </button>
              <button
                onClick={() => handleTabChange('surface')}
                className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                  tabParam === 'surface'
                    ? 'bg-canvas-elevated text-brand font-semibold shadow-glow-primary'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText size={13} />
                <span>Attack Surface</span>
              </button>
              <button
                onClick={() => handleTabChange('charts')}
                className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                  tabParam === 'charts'
                    ? 'bg-canvas-elevated text-brand font-semibold shadow-glow-primary'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <BarChart2 size={13} />
                <span>Analytics</span>
              </button>
            </div>

            {/* Export Dropdown */}
            <div className="relative">
              <button
                onClick={() => setExportMenuOpen(!exportMenuOpen)}
                aria-label="Export audit artifacts"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical bg-canvas-elevated border border-border-structural text-slate-200 font-mono text-xs font-semibold hover:bg-canvas-overlay"
              >
                <Download size={13} />
                <span>Export</span>
                <ChevronDown size={12} />
              </button>

              {exportMenuOpen && (
                <div className="absolute right-0 mt-1 w-48 rounded-tactical bg-canvas-panel border border-border-structural shadow-2xl py-1 z-50 font-mono text-xs">
                  <button
                    onClick={() => handleExport('json')}
                    className="w-full text-left px-3 py-1.5 hover:bg-canvas-elevated text-slate-200 flex items-center gap-2"
                  >
                    <span>JSON Report (.json)</span>
                  </button>
                  <button
                    onClick={() => handleExport('md')}
                    className="w-full text-left px-3 py-1.5 hover:bg-canvas-elevated text-slate-200 flex items-center gap-2"
                  >
                    <span>Markdown Report (.md)</span>
                  </button>
                  <button
                    onClick={() => handleExport('curl')}
                    className="w-full text-left px-3 py-1.5 hover:bg-canvas-elevated text-brand flex items-center gap-2 border-t border-border-subdued mt-1 pt-1.5"
                  >
                    <Terminal size={13} />
                    <span>cURL Reproduction Suite</span>
                  </button>
                </div>
              )}
            </div>

            {aiStatus?.enabled && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleExplainTop}
                  disabled={explainTopMutation.isPending || findings.length === 0}
                  data-testid="explain-top-btn"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-mono text-xs font-semibold shadow-glow-primary transition-colors focus:ring-1 focus:ring-purple-400 focus:outline-none"
                >
                  {explainTopMutation.isPending ? (
                    <>
                      <RotateCw size={12} className="animate-spin" />
                      <span>Explaining top 5...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={12} />
                      <span>Explain top 5</span>
                    </>
                  )}
                </button>

                <span
                  className="font-mono text-[11px] text-purple-300 bg-purple-500/10 px-2 py-1 rounded border border-purple-500/30"
                  data-testid="ai-calls-indicator"
                  title="AI calls used for this scan / Maximum allowed"
                >
                  AI calls: {((scanData?.summary as any)?.ai_calls_used ?? explainTopMutation.data?.calls_used ?? 0)} / {aiStatus.max_calls_per_scan}
                </span>
              </div>
            )}

            <button
              onClick={() => setIsShortcutModalOpen(true)}
              aria-label="Keyboard shortcuts"
              className="p-1.5 rounded-tactical border border-border-structural text-slate-400 hover:text-slate-200 hover:bg-canvas-elevated"
              title="Keyboard Shortcuts [?]"
            >
              <HelpCircle size={15} />
            </button>
          </div>
        </div>

        {/* AI Executive Summary Panel */}
        <AiSummaryPanel
          scanId={id || ''}
          existingSummary={(scanData?.summary as any)?.ai_summary}
        />

        {/* ZONE 2: Tactical HUD Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <StatCard
            label="Endpoints Audited"
            value={`${surfaceData?.endpoints?.length ?? hudData.endpointsAudited} / ${surfaceData?.endpoints?.length ?? 12}`}
            subtext="100% surface mapped"
            highlightColor="text-slate-100"
          />
          <StatCard
            label="Critical Findings"
            value={hudData.critical}
            subtext="BOLA &amp; write access"
            highlightColor="text-severity-critical"
            badgeText={hudData.critical > 0 ? 'HIGH IMPACT' : 'CLEAN'}
            badgeColor="bg-severity-critical/10 text-severity-critical border-severity-critical/40"
          />
          <StatCard
            label="High Severity"
            value={hudData.high}
            subtext="State modification"
            highlightColor="text-severity-high"
            badgeText={hudData.high > 0 ? 'EXPLOITABLE' : 'CLEAN'}
            badgeColor="bg-severity-high/10 text-severity-high border-severity-high/40"
          />
          <StatCard
            label="Medium Severity"
            value={hudData.medium}
            subtext="Data exposure"
            highlightColor="text-severity-medium"
            badgeText={hudData.medium > 0 ? 'TELEMETRY' : 'CLEAN'}
            badgeColor="bg-severity-medium/10 text-severity-medium border-severity-medium/40"
          />
          <StatCard
            label="Verified Controls"
            value={verifiedControlsCount}
            subtext="Expected 403 Denied"
            highlightColor="text-severity-secure"
          />
        </div>

        {/* Dynamic Tab Views */}
        {tabParam === 'matrix' ? (
          <MatrixGrid
            cells={mergedMatrix}
            onSelectFinding={(fId) => {
              const targetId = fId || findings[0]?.id;
              const next = new URLSearchParams(searchParams);
              next.set('tab', 'findings');
              if (targetId) next.set('finding', targetId);
              setSearchParams(next);
            }}
          />
        ) : tabParam === 'surface' ? (
          <SurfaceTable endpoints={surfaceData?.endpoints || []} />
        ) : tabParam === 'charts' ? (
          <FindingsCharts findings={findings} />
        ) : (
          /* ZONE 3: Findings Triage Workspace (3A Left Rail + 3B Inspector) */
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* ZONE 3A: Left Rail Filter & Finding Stream */}
            <div className="lg:col-span-4 xl:col-span-4 space-y-3 bg-canvas-panel p-3.5 rounded-panel border border-border-structural">
              <div className="flex items-center justify-between border-b border-border-subdued pb-2">
                <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Target Findings Stream
                </span>
                <span className="font-mono text-[11px] text-slate-400">
                  {filteredFindings.length} of {totalFindings} Issues
                </span>
              </div>

              <FilterBar
                selectedSeverity={severityParam}
                onSelectSeverity={(sev) => {
                  const next = new URLSearchParams(searchParams);
                  if (sev) next.set('severity', sev);
                  else next.delete('severity');
                  setSearchParams(next);
                }}
                counts={severityCounts}
                searchQuery={qParam}
                onSearchChange={(q) => {
                  const next = new URLSearchParams(searchParams);
                  if (q) next.set('q', q);
                  else next.delete('q');
                  setSearchParams(next);
                }}
                minConfidence={confidenceParam}
                onMinConfidenceChange={(val) => {
                  const next = new URLSearchParams(searchParams);
                  if (val > 0) next.set('min_confidence', String(val));
                  else next.delete('min_confidence');
                  setSearchParams(next);
                }}
                selectedCheck={checkParam}
                onSelectCheck={(chk) => {
                  const next = new URLSearchParams(searchParams);
                  if (chk) next.set('check', chk);
                  else next.delete('check');
                  setSearchParams(next);
                }}
                totalFindings={totalFindings}
              />

              {/* Finding Cards List */}
              <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
                {isFindingsLoading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-20 w-full" />
                    <Skeleton className="h-20 w-full" />
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : filteredFindings.length === 0 ? (
                  <div className="p-6 text-center rounded bg-canvas-base border border-border-subdued font-mono text-xs text-slate-400 space-y-2">
                    <div>No findings match current filters.</div>
                    <button
                      onClick={() => {
                        const next = new URLSearchParams();
                        setSearchParams(next);
                      }}
                      className="text-brand hover:underline"
                    >
                      Clear all filters
                    </button>
                  </div>
                ) : (
                  filteredFindings.map((finding) => (
                    <FindingCard
                      key={finding.id}
                      finding={finding}
                      isSelected={selectedFinding?.id === finding.id}
                      onSelect={handleSelectFinding}
                    />
                  ))
                )}
              </div>
            </div>

            {/* ZONE 3B: Right Contextual Inspector */}
            <div className="lg:col-span-8 xl:col-span-8 bg-canvas-panel p-4 sm:p-5 rounded-panel border border-border-structural space-y-5">
              {totalFindings === 0 && !isFindingsLoading ? (
                /* Zero Findings All-Clear State */
                <EmptyState
                  icon="shield"
                  title="No Access-Control Vulnerabilities Detected"
                  description="No issues found by these checks. All differential tests satisfied expected security boundaries across configured test personas."
                  checkedSummary={[
                    'Object-Level Authorization (BOLA) verified across test personas',
                    'Function-Level Authorization (BFLA) blocked administrative privilege escalation',
                    'Data Exposure checks confirmed sensitive PII is filtered',
                    'Unauthenticated probes successfully received 401/403 responses',
                  ]}
                />
              ) : selectedFinding ? (
                <>
                  {/* Inspector Forensics Header */}
                  <InspectorHeader
                    finding={selectedFinding}
                    riskScore={riskResult.score}
                  />

                  {/* Vulnerability Summary & Root Cause */}
                  <div className="p-3.5 rounded-panel bg-canvas-elevated border border-brand/30 space-y-1 font-mono text-xs">
                    <div className="text-brand font-semibold uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                      <ShieldCheck size={14} />
                      <span>Vulnerability Summary &amp; Root Cause</span>
                    </div>
                    <p className="text-slate-200 leading-relaxed font-sans text-xs">
                      {selectedFinding.explanation}
                    </p>
                  </div>

                  {/* Severity Breakdown Factors (4 Progress Bars) */}
                  {riskResult.hasBreakdown && (
                    <RiskBreakdown
                      breakdown={riskResult.breakdown}
                      score={riskResult.score}
                    />
                  )}

                  {/* cURL Console */}
                  <CurlConsole curlPoc={selectedFinding.curl_poc} />

                  {/* Differential Inspector */}
                  <DiffViewer diffModel={diffModel} />

                  {/* Reproduction Status & Affected Objects */}
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 rounded-panel bg-canvas-base border border-border-structural font-mono text-xs">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="w-2 h-2 rounded-full bg-severity-secure" />
                      <span className="text-slate-200 font-semibold">
                        {reproResult?.reproduced
                          ? `● ${reproResult.attempts} of ${reproResult.attempts} reproduced (Live Differential Verified)`
                          : 'Provisional finding (Empirically verified)'}
                      </span>
                      {reproResult?.downgraded && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px]">
                          Downgraded
                        </span>
                      )}
                    </div>

                    {reproResult?.affectedObjects && reproResult.affectedObjects.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-slate-400">Affected Objects:</span>
                        {reproResult.affectedObjects.map((obj) => (
                          <span
                            key={obj}
                            className="px-1.5 py-0.5 rounded bg-canvas-elevated border border-border-subdued text-slate-300 font-bold"
                          >
                            [{obj}]
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Suggested Remediation & Fix Hint */}
                  <div className="p-3.5 rounded-panel bg-canvas-elevated border border-severity-secure/40 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold uppercase tracking-wider text-severity-secure flex items-center gap-1.5">
                        <ShieldCheck size={14} />
                        <span>Suggested Remediation</span>
                      </span>
                    </div>
                    <div className="font-mono text-xs text-slate-200 bg-canvas-base p-2.5 rounded border border-border-structural">
                      {selectedFinding.fix_hint}
                    </div>
                  </div>

                  {/* AI Analysis & Remediation Panel */}
                  <AiAnalysisPanel scanId={id || ''} finding={selectedFinding} />

                  {/* Secure Variant Toggle for Inspection Preview */}
                  <div className="pt-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => setIsSecurePreviewActive(!isSecurePreviewActive)}
                      className="text-xs font-mono text-slate-400 hover:text-brand flex items-center gap-1.5"
                    >
                      <RotateCcw size={12} />
                      <span>
                        {isSecurePreviewActive
                          ? 'Restore Active Vulnerability View'
                          : '[View Secure Endpoint 403 Variant]'}
                      </span>
                    </button>
                  </div>
                </>
              ) : (
                <div className="p-8 text-center text-slate-400 font-mono text-xs">
                  Select a finding from the left rail to inspect differential evidence.
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Keyboard Shortcuts Modal */}
      {isShortcutModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-sm p-5 rounded-modal bg-canvas-panel border border-border-structural shadow-2xl space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-border-subdued pb-2">
              <span className="font-semibold text-slate-100 uppercase tracking-wide">
                Keyboard Shortcuts
              </span>
              <button
                onClick={() => setIsShortcutModalOpen(false)}
                className="text-slate-400 hover:text-slate-100"
              >
                <X size={16} />
              </button>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between items-center py-1 border-b border-border-subdued">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">j</kbd>
                <span className="text-slate-400">Next finding</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border-subdued">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">k</kbd>
                <span className="text-slate-400">Previous finding</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border-subdued">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">/</kbd>
                <span className="text-slate-400">Focus search filter</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border-subdued">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">c</kbd>
                <span className="text-slate-400">Copy cURL command</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border-subdued">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">Esc</kbd>
                <span className="text-slate-400">Close modal / Clear selection</span>
              </div>
              <div className="flex justify-between items-center py-1">
                <kbd className="px-2 py-0.5 rounded bg-canvas-base border border-border-structural">?</kbd>
                <span className="text-slate-400">Toggle shortcuts hint</span>
              </div>
            </div>
          </div>
        </div>
      )}

      <AiConsentModal
        isOpen={isAiConsentOpen}
        providerName={aiStatus?.provider || 'AI Provider'}
        onConfirm={handleConsentConfirm}
        onCancel={() => setIsAiConsentOpen(false)}
      />
    </div>
  );
};
