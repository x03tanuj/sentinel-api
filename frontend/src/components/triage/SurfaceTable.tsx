import React, { useState } from 'react';
import type { EndpointData } from '../../types';
import { MethodBadge } from '../ui/MethodBadge';
import { Lock, Unlock, Search } from 'lucide-react';

interface SurfaceTableProps {
  endpoints: EndpointData[];
  className?: string;
}

export const SurfaceTable: React.FC<SurfaceTableProps> = ({ endpoints, className = '' }) => {
  const [search, setSearch] = useState('');
  const [selectedMethod, setSelectedMethod] = useState('');
  const [authFilter, setAuthFilter] = useState<'all' | 'auth' | 'public'>('all');

  const filtered = endpoints.filter((ep) => {
    if (selectedMethod && ep.method.toUpperCase() !== selectedMethod.toUpperCase()) {
      return false;
    }
    if (authFilter === 'auth' && !ep.auth_required) return false;
    if (authFilter === 'public' && ep.auth_required) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        ep.path.toLowerCase().includes(q) ||
        (ep.resource && ep.resource.toLowerCase().includes(q)) ||
        (ep.summary && ep.summary.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const methods = Array.from(new Set(endpoints.map((e) => e.method.toUpperCase())));

  return (
    <div className={`space-y-3 ${className}`}>
      {/* Top Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-panel bg-canvas-panel border border-border-structural">
        <div className="flex items-center gap-2 flex-1">
          <div className="relative flex-1 max-w-sm">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter endpoints by path or resource..."
              className="w-full pl-8 pr-3 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-200 placeholder-slate-500 font-mono text-xs focus:outline-none focus:border-brand"
            />
          </div>

          <select
            value={selectedMethod}
            onChange={(e) => setSelectedMethod(e.target.value)}
            aria-label="Filter by HTTP method"
            className="px-2 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-300 font-mono text-xs focus:outline-none focus:border-brand"
          >
            <option value="">All Methods</option>
            {methods.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          <select
            value={authFilter}
            onChange={(e) => setAuthFilter(e.target.value as any)}
            aria-label="Filter by authentication requirement"
            className="px-2 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-300 font-mono text-xs focus:outline-none focus:border-brand"
          >
            <option value="all">Auth: All</option>
            <option value="auth">Authenticated Only</option>
            <option value="public">Public Only</option>
          </select>
        </div>

        <span className="font-mono text-xs text-slate-400">
          Showing {filtered.length} of {endpoints.length} endpoints
        </span>
      </div>

      {/* Endpoints Table */}
      <div className="overflow-x-auto rounded-panel border border-border-structural bg-canvas-panel">
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-canvas-elevated text-left font-mono text-xs text-slate-300">
              <th className="p-2.5 border-b border-border-structural">Method</th>
              <th className="p-2.5 border-b border-border-structural">Endpoint Path</th>
              <th className="p-2.5 border-b border-border-structural">Auth</th>
              <th className="p-2.5 border-b border-border-structural">Classification</th>
              <th className="p-2.5 border-b border-border-structural">Resource</th>
              <th className="p-2.5 border-b border-border-structural text-right">Risk Priority</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-structural/50">
            {filtered.map((ep, idx) => {
              const priority = ep.priority_score ?? ep.risk_score ?? 50;
              let priorityColor = 'bg-brand';
              if (priority >= 80) priorityColor = 'bg-severity-critical';
              else if (priority >= 60) priorityColor = 'bg-severity-high';
              else if (priority >= 35) priorityColor = 'bg-severity-medium';

              return (
                <tr key={`${ep.method}-${ep.path}-${idx}`} className="hover:bg-canvas-elevated/40">
                  <td className="p-2.5">
                    <MethodBadge method={ep.method} size="sm" />
                  </td>
                  <td className="p-2.5 font-mono text-xs font-semibold text-slate-200">
                    {ep.path}
                    {ep.summary && (
                      <span className="block text-[11px] font-sans font-normal text-slate-400 truncate max-w-md">
                        {ep.summary}
                      </span>
                    )}
                  </td>
                  <td className="p-2.5 font-mono text-xs">
                    {ep.auth_required ? (
                      <span className="inline-flex items-center gap-1 text-amber-400">
                        <Lock size={12} />
                        <span>Bearer JWT</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-400">
                        <Unlock size={12} />
                        <span>Public</span>
                      </span>
                    )}
                  </td>
                  <td className="p-2.5 font-mono text-xs">
                    <div className="flex items-center gap-1 flex-wrap">
                      {ep.is_object_level && (
                        <span className="px-1.5 py-0.5 rounded bg-brand/10 border border-brand/30 text-brand text-[10px]">
                          Object-Level
                        </span>
                      )}
                      {ep.is_privileged && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px]">
                          Privileged Admin
                        </span>
                      )}
                      {!ep.is_object_level && !ep.is_privileged && (
                        <span className="text-slate-500 text-[11px]">-</span>
                      )}
                    </div>
                  </td>
                  <td className="p-2.5 font-mono text-xs text-slate-300">
                    {ep.resource ? (
                      <span className="px-1.5 py-0.5 rounded bg-canvas-base border border-border-subdued text-slate-300">
                        {ep.resource}
                      </span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  <td className="p-2.5 text-right font-mono text-xs">
                    <div className="flex items-center justify-end gap-2">
                      <span className="font-semibold text-slate-200">{priority} / 100</span>
                      <div className="w-16 h-1.5 bg-canvas-base rounded-full overflow-hidden border border-border-structural">
                        <div
                          className={`h-full ${priorityColor}`}
                          style={{ width: `${priority}%` }}
                        />
                      </div>
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
