import React, { useRef, useEffect } from 'react';
import { Search, X } from 'lucide-react';

interface FilterBarProps {
  selectedSeverity: string;
  onSelectSeverity: (severity: string) => void;
  counts: Record<string, number>;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  minConfidence: number;
  onMinConfidenceChange: (val: number) => void;
  selectedCheck: string;
  onSelectCheck: (check: string) => void;
  availableChecks?: string[];
  totalFindings: number;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  selectedSeverity,
  onSelectSeverity,
  counts,
  searchQuery,
  onSearchChange,
  minConfidence,
  onMinConfidenceChange,
  selectedCheck,
  onSelectCheck,
  availableChecks = ['bola', 'bfla', 'data_exposure', 'rate_limit', 'unauth_access', 'input_handling'],
  totalFindings,
}) => {
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut: '/' focuses search input
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current && (e.target as HTMLElement).tagName !== 'INPUT') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const pills: { id: string; label: string; count?: number; color: string }[] = [
    { id: '', label: 'All', count: totalFindings, color: 'hover:border-slate-400' },
    { id: 'CRITICAL', label: 'Critical', count: counts['CRITICAL'] || 0, color: 'text-severity-critical border-severity-critical/40 bg-severity-critical/10' },
    { id: 'HIGH', label: 'High', count: counts['HIGH'] || 0, color: 'text-severity-high border-severity-high/40 bg-severity-high/10' },
    { id: 'MEDIUM', label: 'Medium', count: counts['MEDIUM'] || 0, color: 'text-severity-medium border-severity-medium/40 bg-severity-medium/10' },
    { id: 'LOW', label: 'Low', count: counts['LOW'] || 0, color: 'text-severity-low border-severity-low/40 bg-severity-low/10' },
    { id: 'INFO', label: 'Info', count: counts['INFO'] || 0, color: 'text-severity-info border-severity-info/40 bg-severity-info/10' },
    { id: 'SECURE', label: 'Secure', count: counts['SECURE'] !== undefined ? counts['SECURE'] : undefined, color: 'text-severity-secure border-severity-secure/40 bg-severity-secure/10' },
  ];

  return (
    <div className="space-y-2.5 pb-2">
      {/* Top Filter Pills */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {pills.map((pill) => {
          const isSelected = selectedSeverity === pill.id;
          return (
            <button
              key={pill.id}
              onClick={() => onSelectSeverity(pill.id)}
              className={`px-2 py-1 rounded-tactical font-mono text-xs border transition-all flex items-center gap-1.5 ${
                isSelected
                  ? 'border-brand bg-brand/20 text-brand font-bold shadow-glow-primary'
                  : `border-border-structural bg-canvas-panel text-slate-300 hover:bg-canvas-elevated ${pill.color}`
              }`}
            >
              <span>{pill.label}</span>
              {pill.count !== undefined && (
                <span className="text-[10px] px-1 rounded bg-canvas-base border border-border-subdued text-slate-400">
                  {pill.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Search Input & Check Filter */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            ref={searchInputRef}
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings (e.g. /orders, BOLA)... [Press /]"
            className="w-full pl-8 pr-7 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-200 placeholder-slate-500 font-mono text-xs focus:outline-none focus:border-brand focus:ring-1 focus:ring-brand"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              aria-label="Clear search query"
            >
              <X size={12} />
            </button>
          )}
        </div>

        {/* Check suite filter dropdown */}
        <select
          value={selectedCheck}
          onChange={(e) => onSelectCheck(e.target.value)}
          aria-label="Filter by security check suite"
          className="px-2 py-1.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-300 font-mono text-xs focus:outline-none focus:border-brand"
        >
          <option value="">All Checks</option>
          {availableChecks.map((chk) => (
            <option key={chk} value={chk}>
              {chk.toUpperCase()}
            </option>
          ))}
        </select>
      </div>

      {/* Min-Confidence Slider */}
      <div className="flex items-center justify-between gap-3 px-1 text-slate-400 font-mono text-[11px]">
        <span>Min Confidence:</span>
        <div className="flex items-center gap-2 flex-1 max-w-[180px]">
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={minConfidence}
            onChange={(e) => onMinConfidenceChange(parseFloat(e.target.value))}
            className="w-full accent-brand cursor-pointer"
            aria-label="Minimum confidence threshold slider"
          />
          <span className="font-semibold text-slate-200 w-8 text-right">
            {Math.round(minConfidence * 100)}%
          </span>
        </div>
      </div>
    </div>
  );
};
