import React, { useState, useRef, useEffect } from 'react';
import type { ProgressEvent } from '../../types';
import { Terminal, Download, ArrowDownCircle } from 'lucide-react';

interface EventLogProps {
  events: ProgressEvent[];
  className?: string;
}

export const EventLog: React.FC<EventLogProps> = ({ events, className = '' }) => {
  const [autoscroll, setAutoscroll] = useState(true);
  const [filter, setFilter] = useState('');
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoscroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [events, autoscroll]);

  const filteredEvents = events.filter((e) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      e.message.toLowerCase().includes(q) ||
      e.stage.toLowerCase().includes(q)
    );
  });

  const handleExport = () => {
    const text = events
      .map((e) => `[${e.timestamp}] [${e.stage}] ${e.message}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelapi-telemetry-${new Date().toISOString().replace(/[:.]/g, '-')}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={`rounded-panel bg-canvas-base border border-border-structural flex flex-col font-mono text-xs overflow-hidden ${className}`}
    >
      {/* Terminal Title Bar */}
      <div className="bg-canvas-panel px-3 py-2 border-b border-border-structural flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-brand" />
          <span className="text-slate-200 font-semibold tracking-wide">
            telemetry-stream.log
          </span>
          <span className="text-[10px] text-slate-500">
            ({events.length} events buffered)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter logs..."
            className="px-2 py-0.5 rounded-tactical bg-canvas-base border border-border-structural text-slate-200 placeholder-slate-500 text-[11px] focus:outline-none focus:border-brand w-28 sm:w-36"
          />

          <button
            onClick={() => setAutoscroll(!autoscroll)}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-tactical text-[11px] border transition-colors ${
              autoscroll
                ? 'bg-brand/20 border-brand text-brand font-semibold'
                : 'bg-canvas-elevated border-border-structural text-slate-400'
            }`}
          >
            <ArrowDownCircle size={12} />
            <span>Autoscroll</span>
          </button>

          <button
            onClick={handleExport}
            title="Export raw execution log"
            className="p-1 rounded-tactical bg-canvas-elevated border border-border-structural text-slate-400 hover:text-slate-200"
          >
            <Download size={13} />
          </button>
        </div>
      </div>

      {/* Terminal Stream Output */}
      <div
        ref={logContainerRef}
        className="p-3.5 space-y-1 overflow-y-auto max-h-[380px] bg-canvas-base selection:bg-brand/30"
      >
        {filteredEvents.length === 0 ? (
          <div className="text-slate-500 italic">No telemetry messages received yet...</div>
        ) : (
          filteredEvents.map((evt) => {
            let badgeColor = 'text-slate-400';
            if (evt.message.includes('VIOLATION') || evt.message.includes('CRITICAL')) {
              badgeColor = 'text-severity-critical font-bold';
            } else if (evt.message.includes('WARN') || evt.message.includes('HIGH')) {
              badgeColor = 'text-severity-high';
            } else if (evt.message.includes('INFO') || evt.message.includes('AUTH')) {
              badgeColor = 'text-brand';
            }

            return (
              <div key={evt.seq} className="leading-relaxed hover:bg-canvas-elevated/30 px-1 rounded flex items-start gap-2">
                <span className="text-slate-500 shrink-0 text-[11px]">
                  [{new Date(evt.timestamp).toLocaleTimeString()}]
                </span>
                <span className="text-slate-400 shrink-0 text-[11px] font-semibold">
                  [{evt.stage}]
                </span>
                <span className={`break-all ${badgeColor}`}>{evt.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
