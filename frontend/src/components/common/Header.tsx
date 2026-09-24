import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Play, Settings as SettingsIcon, Radio } from 'lucide-react';
import { ScopeBanner } from '../ui/ScopeBanner';
import { SettingsDialog } from './SettingsDialog';
import { subscribeToUnauthorized } from '../../api/auth';

interface HeaderProps {
  scannerStatus?: 'READY' | 'SCANNING' | 'ERROR';
  targetHost?: string;
  specSource?: string;
  onOpenSettings?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  scannerStatus = 'READY',
  targetHost,
  specSource,
}) => {
  const location = useLocation();
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  useEffect(() => {
    // Automatically trigger settings modal on 401 response
    return subscribeToUnauthorized(() => {
      setIsSettingsOpen(true);
    });
  }, []);

  const getStatusBadge = () => {
    switch (scannerStatus) {
      case 'SCANNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-tactical border border-brand/40 bg-brand/10 text-brand font-mono text-[11px] animate-pulse">
            <Radio size={12} className="animate-spin" />
            <span>SCANNING</span>
          </span>
        );
      case 'ERROR':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-tactical border border-severity-critical/40 bg-severity-critical/10 text-severity-critical font-mono text-[11px]">
            <span>ERROR</span>
          </span>
        );
      case 'READY':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-tactical border border-severity-secure/40 bg-severity-secure/10 text-severity-secure font-mono text-[11px]">
            <span className="w-1.5 h-1.5 rounded-full bg-severity-secure" />
            <span>READY</span>
          </span>
        );
    }
  };

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-border-structural bg-canvas-panel/95 backdrop-blur-xs px-4 py-2.5 flex items-center justify-between gap-4">
        {/* Left: Brand & Navigation */}
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2 group focus:outline-none">
            <div className="w-7 h-7 rounded-tactical bg-brand/10 border border-brand/30 flex items-center justify-center text-brand group-hover:shadow-glow-primary transition-all">
              <Shield size={16} />
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="font-sans font-bold text-base tracking-tight text-slate-100">
                Sentinel<span className="text-brand">API</span>
              </span>
              <span className="font-mono text-[10px] px-1 rounded-tactical bg-canvas-elevated text-slate-400 border border-border-subdued">
                v0.9.0-alpha
              </span>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-1 border-l border-border-structural pl-4 font-mono text-xs">
            <Link
              to="/"
              className={`px-2.5 py-1 rounded-tactical transition-colors ${
                location.pathname === '/'
                  ? 'bg-canvas-elevated text-brand font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan History
            </Link>
          </nav>
        </div>

        {/* Center: Target & Scope Guard Indicator */}
        <div className="hidden lg:flex items-center gap-3">
          {targetHost && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-tactical border border-border-structural bg-canvas-base font-mono text-xs">
              <span className="text-slate-400">Target:</span>
              <span className="text-brand font-semibold truncate max-w-[200px]">{targetHost}</span>
              {specSource && (
                <span className="text-[10px] text-slate-500 truncate max-w-[120px]">
                  ({specSource.split('/').pop() || specSource})
                </span>
              )}
            </div>
          )}

          <ScopeBanner targetUrl={targetHost} />
          {getStatusBadge()}
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsSettingsOpen(true)}
            aria-label="Open Security Settings"
            className="p-1.5 rounded-tactical border border-border-structural text-slate-400 hover:text-slate-200 hover:bg-canvas-elevated transition-colors focus:ring-2 focus:ring-brand focus:outline-none"
            title="Configure API Key"
          >
            <SettingsIcon size={16} />
          </button>

          <Link
            to="/scans/new"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical bg-brand text-canvas-base font-sans font-semibold text-xs hover:bg-brand-hover shadow-glow-primary transition-all focus:ring-2 focus:ring-brand focus:outline-none"
          >
            <Play size={13} fill="currentColor" />
            <span>Run Scan</span>
          </Link>
        </div>
      </header>

      <SettingsDialog isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
    </>
  );
};
