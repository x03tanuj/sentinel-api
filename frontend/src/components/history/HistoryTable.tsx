import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import type { ScanSummary } from '../../types';
import { formatDuration, hostFromUrl } from '../../lib/formatters';
import { downloadReport } from '../../api/downloads';
import { Download, Trash2, ArrowRight, AlertCircle } from 'lucide-react';

interface HistoryTableProps {
  scans: ScanSummary[];
  onDeleteScan?: (scanId: string) => void;
  className?: string;
}

export const HistoryTable: React.FC<HistoryTableProps> = ({
  scans,
  onDeleteScan,
  className = '',
}) => {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'COMPLETED':
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-severity-secure/10 border border-severity-secure/40 text-severity-secure font-mono text-[11px] font-semibold flex items-center gap-1 w-max">
            <span className="w-1.5 h-1.5 rounded-full bg-severity-secure" />
            <span>COMPLETED</span>
          </span>
        );
      case 'RUNNING':
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-brand/10 border border-brand/40 text-brand font-mono text-[11px] font-semibold flex items-center gap-1 animate-pulse w-max">
            <span className="w-1.5 h-1.5 rounded-full bg-brand animate-ping" />
            <span>RUNNING</span>
          </span>
        );
      case 'FAILED':
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-severity-critical/10 border border-severity-critical/40 text-severity-critical font-mono text-[11px] font-semibold flex items-center gap-1 w-max">
            <AlertCircle size={11} />
            <span>FAILED</span>
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-amber-500/10 border border-amber-500/40 text-amber-400 font-mono text-[11px] font-semibold flex items-center gap-1 w-max">
            <span>CANCELLED</span>
          </span>
        );
      case 'INTERRUPTED':
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-purple-500/10 border border-purple-500/40 text-purple-400 font-mono text-[11px] font-semibold flex items-center gap-1 w-max">
            <span>INTERRUPTED</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded-tactical bg-slate-800 border border-slate-700 text-slate-400 font-mono text-[11px] w-max">
            {status}
          </span>
        );
    }
  };

  const handleDownload = async (scanId: string, format: 'json' | 'md') => {
    try {
      setDownloadingId(`${scanId}-${format}`);
      await downloadReport(scanId, format);
    } catch (err) {
      alert('Failed to download report: ' + (err as Error).message);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="overflow-x-auto rounded-panel border border-border-structural bg-canvas-panel">
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-canvas-elevated text-left font-mono text-xs text-slate-300">
              <th className="p-3 border-b border-border-structural">Scan ID</th>
              <th className="p-3 border-b border-border-structural">Status</th>
              <th className="p-3 border-b border-border-structural">Target Host</th>
              <th className="p-3 border-b border-border-structural">Started</th>
              <th className="p-3 border-b border-border-structural">Duration</th>
              <th className="p-3 border-b border-border-structural">Severity Distribution</th>
              <th className="p-3 border-b border-border-structural text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-structural/50">
            {scans.map((scan) => {
              const st = (scan.status || '').toUpperCase();
              const isRunning = st === 'RUNNING' || st === 'QUEUED';
              const targetHost = hostFromUrl(scan.target_url);

              return (
                <tr key={scan.scan_id} className="hover:bg-canvas-elevated/40 transition-colors">
                  <td className="p-3 font-mono text-xs font-semibold text-slate-200">
                    <Link
                      to={isRunning ? `/scans/${scan.scan_id}/live` : `/scans/${scan.scan_id}`}
                      className="text-brand hover:underline"
                    >
                      {scan.scan_id.slice(0, 12)}...
                    </Link>
                  </td>

                  <td className="p-3">{getStatusBadge(scan.status)}</td>

                  <td className="p-3 font-mono text-xs text-slate-300">
                    <span className="truncate max-w-[180px] block" title={scan.target_url}>
                      {targetHost || scan.target_url}
                    </span>
                  </td>

                  <td className="p-3 font-mono text-xs text-slate-400">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>

                  <td className="p-3 font-mono text-xs text-slate-400">
                    {formatDuration(scan.duration_seconds)}
                  </td>

                  {/* Severity mini-chips */}
                  <td className="p-3">
                    <div className="flex items-center gap-1.5 flex-wrap font-mono text-[11px]">
                      {scan.critical > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-severity-critical/10 border border-severity-critical/40 text-severity-critical font-bold">
                          {scan.critical} Crit
                        </span>
                      )}
                      {scan.high > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-severity-high/10 border border-severity-high/40 text-severity-high font-semibold">
                          {scan.high} High
                        </span>
                      )}
                      {scan.medium > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-severity-medium/10 border border-severity-medium/40 text-severity-medium">
                          {scan.medium} Med
                        </span>
                      )}
                      {scan.low > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-severity-low/10 border border-severity-low/40 text-severity-low">
                          {scan.low} Low
                        </span>
                      )}
                      {scan.critical === 0 && scan.high === 0 && scan.medium === 0 && scan.low === 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-severity-secure/10 border border-severity-secure/40 text-severity-secure text-[10px]">
                          0 Findings
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Actions */}
                  <td className="p-3 text-right">
                    <div className="flex items-center justify-end gap-2 font-mono text-xs">
                      {isRunning ? (
                        <Link
                          to={`/scans/${scan.scan_id}/live`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-tactical bg-brand text-canvas-base font-semibold hover:bg-brand-hover shadow-glow-primary"
                        >
                          <span>Live Progress</span>
                          <ArrowRight size={13} />
                        </Link>
                      ) : (
                        <Link
                          to={`/scans/${scan.scan_id}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-tactical bg-brand/10 border border-brand/40 text-brand font-semibold hover:bg-brand/20"
                        >
                          <span>Open Triage</span>
                          <ArrowRight size={13} />
                        </Link>
                      )}

                      {!isRunning && (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleDownload(scan.scan_id, 'md')}
                            disabled={downloadingId === `${scan.scan_id}-md`}
                            title="Download Markdown Report"
                            className="p-1.5 rounded-tactical border border-border-structural text-slate-400 hover:text-slate-100 hover:bg-canvas-elevated"
                          >
                            <Download size={13} />
                          </button>

                          {onDeleteScan && (
                            <button
                              onClick={() => {
                                if (confirm(`Delete scan ${scan.scan_id}?`)) {
                                  onDeleteScan(scan.scan_id);
                                }
                              }}
                              title="Delete Scan from Vault"
                              className="p-1.5 rounded-tactical border border-border-structural text-slate-500 hover:text-severity-critical hover:bg-severity-critical/10"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
