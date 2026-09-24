import React from 'react';
import { ShieldCheck, Lock } from 'lucide-react';

interface ScopeBannerProps {
  targetUrl?: string;
  allowListed?: boolean;
  className?: string;
}

export const ScopeBanner: React.FC<ScopeBannerProps> = ({
  targetUrl: _targetUrl = 'http://target_api:9000',
  allowListed = true,
  className = '',
}) => {
  return (
    <div
      role="region"
      aria-label="Scope Guard Indicator"
      className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-tactical border border-severity-secure/40 bg-severity-secure/10 text-xs font-mono ${className}`}
    >
      <ShieldCheck size={14} className="text-severity-secure shrink-0" />
      <span className="text-slate-300">
        Scope Guard: <span className="text-severity-secure font-semibold">Active</span>
      </span>
      <span className="text-slate-400">
        ({allowListed ? 'allow-listed only' : 'restricted'})
      </span>
      <Lock size={12} className="text-slate-500 shrink-0 ml-1" />
    </div>
  );
};
