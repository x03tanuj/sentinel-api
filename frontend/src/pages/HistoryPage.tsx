import React from 'react';
import { Link } from 'react-router-dom';
import { useScans, useDeleteScan } from '../api/hooks';
import { Header } from '../components/common/Header';
import { HistoryTable } from '../components/history/HistoryTable';
import { EmptyState } from '../components/ui/EmptyState';
import { Skeleton } from '../components/ui/Skeleton';
import { ErrorState } from '../components/ui/ErrorState';
import { Play, Shield } from 'lucide-react';

export const HistoryPage: React.FC = () => {
  const { data: scans, isLoading, error, refetch } = useScans();
  const deleteMutation = useDeleteScan();

  const activeScans =
    scans?.filter((s) => {
      const st = (s.status || '').toUpperCase();
      return st === 'RUNNING' || st === 'QUEUED';
    }) || [];

  return (
    <div className="min-h-screen bg-canvas-base flex flex-col">
      <Header
        scannerStatus={activeScans.length > 0 ? 'SCANNING' : 'READY'}
        targetHost={scans?.[0]?.target_url}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-border-structural pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                Audit Vault // Historical Execution Log
              </span>
            </div>
            <h1 className="font-sans text-2xl font-bold text-slate-100 tracking-tight mt-1">
              Scan Audit History
            </h1>
            <p className="font-mono text-xs text-slate-400 mt-1">
              Historical scan records, vulnerability distributions, and compliance report downloads
            </p>
          </div>

          <Link
            to="/scans/new"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-tactical bg-brand text-canvas-base font-semibold text-xs hover:bg-brand-hover transition-all shadow-glow-primary focus:ring-2 focus:ring-brand focus:outline-none"
          >
            <Play size={14} fill="currentColor" />
            <span>Launch New Scan</span>
          </Link>
        </div>

        {/* Content Area */}
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : error ? (
          <ErrorState
            title="Failed to Load Audit History"
            message={(error as Error).message}
            onRetry={() => refetch()}
          />
        ) : scans && scans.length > 0 ? (
          <HistoryTable
            scans={scans}
            onDeleteScan={(id) => deleteMutation.mutate(id)}
          />
        ) : (
          <EmptyState
            icon="shield"
            title="No Audit Scans Found in History"
            description="Initiate an automated authorization and BOLA scan against an authorized target host to generate forensic audit reports and risk baselines."
            actionText="Launch First Scan"
            onAction={() => {
              window.location.href = '/scans/new';
            }}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-border-structural py-3 px-6 bg-canvas-panel text-slate-400 font-mono text-[11px] flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield size={12} className="text-brand" />
          <span>SentinelAPI Engine v0.9.0-alpha</span>
          <span>•</span>
          <span>Zero Data Leakage Vault</span>
        </div>
        <div>
          <span>Scans strictly restricted to allow-listed hosts</span>
        </div>
      </footer>
    </div>
  );
};
