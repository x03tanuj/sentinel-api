import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useScan, useScanEvents, useCancelScan } from '../api/hooks';
import { Header } from '../components/common/Header';
import { StageStepper } from '../components/live/StageStepper';
import { EventLog } from '../components/live/EventLog';
import { StatCard } from '../components/ui/StatCard';
import { formatDuration, hostFromUrl } from '../lib/formatters';
import { StopCircle, ArrowRight, Radio, AlertOctagon } from 'lucide-react';

export const LiveScanPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: scanData } = useScan(id);
  const { events, latestEvent, isConnected, isFinished } = useScanEvents(id);
  const cancelMutation = useCancelScan();

  const [showCancelModal, setShowCancelModal] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  // Timer for elapsed runtime
  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const statusUpper = (scanData?.status || latestEvent?.status || '').toUpperCase();
  const isCompleted =
    isFinished ||
    statusUpper === 'COMPLETED' ||
    latestEvent?.percent === 100;

  // Auto-navigate to results when finished successfully
  useEffect(() => {
    if (isCompleted) {
      const timer = setTimeout(() => {
        navigate(`/scans/${id}`);
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [isCompleted, id, navigate]);

  const currentStage =
    latestEvent?.stage ||
    (scanData?.progress as any)?.stage ||
    (isCompleted ? 'FINALIZING' : 'RUNNING_CHECKS');

  const percent = latestEvent?.percent ?? (scanData?.progress as any)?.percent ?? (isCompleted ? 100 : 0);
  const requestsSent = latestEvent?.requests_sent ?? (scanData?.progress as any)?.requests_sent ?? 0;
  const requestBudget = latestEvent?.request_budget ?? (scanData?.progress as any)?.request_budget ?? 300;
  const findingsCount =
    latestEvent?.findings_count ??
    (scanData?.summary?.total_findings as number) ??
    0;

  const targetUrl = (scanData?.config_public?.target_url || scanData?.config_public?.base_url) as string | undefined;
  const targetHost = hostFromUrl(targetUrl);
  const specSource = scanData?.config_public?.spec_source as string | undefined;

  const handleConfirmCancel = async () => {
    if (!id) return;
    try {
      await cancelMutation.mutateAsync(id);
      setShowCancelModal(false);
    } catch {
      // Handled by query mutation
    }
  };

  // If scan is in terminal non-completed state (FAILED, CANCELLED, INTERRUPTED)
  const isTerminatedNonSuccess =
    statusUpper === 'FAILED' ||
    statusUpper === 'CANCELLED' ||
    statusUpper === 'INTERRUPTED';

  return (
    <div className="min-h-screen bg-canvas-base flex flex-col">
      <Header
        scannerStatus={isCompleted ? 'READY' : 'SCANNING'}
        targetHost={targetHost}
        specSource={specSource}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Top Header Row */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-border-structural pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-brand font-semibold flex items-center gap-1.5">
                <Radio size={14} className="animate-spin text-brand" />
                <span>Active Audit Execution:</span>
              </span>
              <span className="font-mono text-xs text-slate-300 font-bold bg-canvas-panel px-2 py-0.5 rounded border border-border-structural">
                {id}
              </span>
            </div>
            <h1 className="font-sans text-2xl font-bold text-slate-100 tracking-tight mt-1">
              Live Scan Progress &amp; Telemetry Monitor
            </h1>
          </div>

          <div className="flex items-center gap-2">
            {isCompleted ? (
              <Link
                to={`/scans/${id}`}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-tactical bg-severity-secure text-canvas-base font-semibold text-xs hover:bg-severity-secure/90 transition-all shadow-glow-secure"
              >
                <span>View Results Workspace</span>
                <ArrowRight size={14} />
              </Link>
            ) : !isTerminatedNonSuccess ? (
              <button
                onClick={() => setShowCancelModal(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical border border-severity-critical/50 bg-severity-critical/10 text-severity-critical font-mono text-xs font-semibold hover:bg-severity-critical/20 transition-all"
              >
                <StopCircle size={14} />
                <span>Cancel Audit</span>
              </button>
            ) : null}
          </div>
        </div>

        {/* Diagnostic States if Cancelled, Failed, or Interrupted */}
        {isTerminatedNonSuccess && (
          <div className="p-4 rounded-panel bg-canvas-panel border border-severity-critical/40 space-y-3">
            <div className="flex items-center gap-2 text-severity-critical font-mono text-sm font-semibold">
              <AlertOctagon size={16} />
              <span>Scan execution status: {statusUpper}</span>
            </div>
            <p className="font-sans text-xs text-slate-300">
              {statusUpper === 'CANCELLED'
                ? 'Execution safely halted by user request. All temporary test fixtures and created orders have been cleanly removed by shielded cleanup.'
                : scanData?.status === 'FAILED'
                ? 'Scan encountered an execution failure against the target host. Partial telemetry was persisted.'
                : 'Scan was interrupted by server restart. Progress snapshot saved.'}
            </p>
            <div className="flex items-center gap-3 pt-2">
              <Link
                to={`/scans/${id}`}
                className="px-3 py-1.5 rounded-tactical bg-brand text-canvas-base font-semibold text-xs font-mono"
              >
                View Partial Findings ({findingsCount})
              </Link>
              <Link
                to="/"
                className="px-3 py-1.5 rounded-tactical border border-border-structural text-slate-300 text-xs font-mono"
              >
                Back to History
              </Link>
            </div>
          </div>
        )}

        {/* HUD Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard
            label="Overall Progress"
            value={`${percent}%`}
            subtext={`Stage ${currentStage}`}
            highlightColor="text-brand"
            badgeText={isConnected ? 'STREAMING' : 'POLLING'}
            badgeColor="bg-brand/10 border-brand/30 text-brand"
          />
          <StatCard
            label="Requests Sent"
            value={`${requestsSent} / ${requestBudget}`}
            subtext={`${Math.round((requestsSent / (requestBudget || 1)) * 100)}% budget consumed`}
            highlightColor="text-slate-100"
          />
          <StatCard
            label="Time Elapsed"
            value={formatDuration(elapsedSeconds)}
            subtext="Live timer"
            highlightColor="text-emerald-400"
          />
          <StatCard
            label="Findings Detected"
            value={findingsCount}
            subtext="Vulnerabilities proven"
            highlightColor={findingsCount > 0 ? 'text-severity-critical' : 'text-slate-400'}
            badgeText={findingsCount > 0 ? 'ALERT' : 'CLEAN'}
            badgeColor={findingsCount > 0 ? 'bg-severity-critical/10 text-severity-critical border-severity-critical/30' : 'bg-severity-secure/10 text-severity-secure border-severity-secure/30'}
          />
        </div>

        {/* 8-Stage Execution Stepper */}
        <StageStepper currentStage={currentStage} />

        {/* Monospace Event Log */}
        <div className="space-y-2">
          <EventLog events={events} />
        </div>
      </main>

      {/* Cancel Confirmation Modal */}
      {showCancelModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-md p-6 rounded-modal bg-canvas-panel border border-severity-critical/50 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-tactical bg-severity-critical/20 text-severity-critical border border-severity-critical/40">
                <StopCircle size={20} />
              </div>
              <h2 className="font-sans text-base font-semibold text-slate-100">
                Cancel Active Security Audit?
              </h2>
            </div>

            <p className="font-sans text-xs text-slate-300 leading-relaxed">
              Cancelling will safely abort all pending test cases. In-flight requests will complete,
              and scanner-created test objects will be deleted immediately via shielded cleanup.
            </p>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-border-subdued">
              <button
                type="button"
                onClick={() => setShowCancelModal(false)}
                className="px-3 py-1.5 rounded-tactical border border-border-structural text-slate-300 font-mono text-xs hover:bg-canvas-elevated"
              >
                Resume Audit
              </button>
              <button
                type="button"
                onClick={handleConfirmCancel}
                disabled={cancelMutation.isPending}
                className="px-4 py-1.5 rounded-tactical bg-severity-critical text-slate-100 font-semibold text-xs font-mono hover:bg-severity-critical/90 shadow-glow-critical"
              >
                {cancelMutation.isPending ? 'Aborting...' : 'Confirm Cancel'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
