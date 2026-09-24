import React from 'react';
import { Link } from 'react-router-dom';
import { Header } from '../components/common/Header';
import { ShieldAlert, ArrowLeft, Plus } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-canvas-base flex flex-col">
      <Header />

      <main className="flex-1 flex items-center justify-center p-6">
        <div className="p-8 rounded-panel bg-canvas-panel border border-border-structural text-center max-w-md w-full space-y-4">
          <div className="w-14 h-14 rounded-full bg-severity-critical/10 border border-severity-critical/30 flex items-center justify-center text-severity-critical mx-auto">
            <ShieldAlert size={28} />
          </div>

          <div className="space-y-1">
            <span className="font-mono text-xs text-severity-high font-semibold">
              ERR_RESOURCE_NOT_FOUND
            </span>
            <h1 className="font-sans text-2xl font-bold text-slate-100">
              Scan Not Found [404]
            </h1>
          </div>

          <p className="font-sans text-xs text-slate-400 leading-relaxed">
            The requested scan record does not exist or may have been evicted by the maximum retention policy (50 scans limit).
          </p>

          <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-3 font-mono text-xs">
            <Link
              to="/"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-tactical bg-brand text-canvas-base font-semibold hover:bg-brand-hover shadow-glow-primary transition-all w-full sm:w-auto justify-center"
            >
              <ArrowLeft size={14} />
              <span>Back to Scan History</span>
            </Link>

            <Link
              to="/scans/new"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-tactical border border-border-structural text-slate-300 hover:bg-canvas-elevated transition-all w-full sm:w-auto justify-center"
            >
              <Plus size={14} />
              <span>Launch New Scan</span>
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
};
