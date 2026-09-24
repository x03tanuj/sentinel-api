import React, { useState, useEffect } from 'react';
import { Copy, Check, Terminal } from 'lucide-react';

interface CurlConsoleProps {
  curlPoc: string;
  className?: string;
}

export const CurlConsole: React.FC<CurlConsoleProps> = ({ curlPoc, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(curlPoc);
    setCopied(true);
    setTimeout(() => {
      setCopied(false);
    }, 2000);
  };

  // Keyboard shortcut: 'c' copies cURL PoC
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'c' && (e.target as HTMLElement).tagName !== 'INPUT' && (e.target as HTMLElement).tagName !== 'TEXTAREA') {
        e.preventDefault();
        handleCopy();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [curlPoc]);

  return (
    <div
      className={`rounded-panel bg-canvas-base border border-border-structural overflow-hidden font-mono text-xs ${className}`}
    >
      {/* Title Bar */}
      <div className="bg-canvas-panel px-3 py-2 border-b border-border-structural flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-brand" />
          <span className="text-slate-300 font-semibold tracking-wide">bash — curl</span>
          <span className="text-[10px] text-slate-400 hidden sm:inline">[Press 'c' to copy]</span>
        </div>

        <button
          onClick={handleCopy}
          aria-label="Copy cURL command to clipboard"
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-tactical bg-canvas-elevated hover:bg-canvas-overlay text-slate-200 border border-border-structural transition-colors focus:ring-1 focus:ring-brand focus:outline-none"
        >
          {copied ? (
            <>
              <Check size={13} className="text-severity-secure" />
              <span className="text-severity-secure font-semibold">Copied!</span>
            </>
          ) : (
            <>
              <Copy size={13} className="text-slate-400" />
              <span>Copy cURL</span>
            </>
          )}
        </button>
      </div>

      {/* Screen reader live notification */}
      <div className="sr-only" aria-live="polite">
        {copied ? 'cURL command copied to clipboard' : ''}
      </div>

      {/* Console Code Body */}
      <div
        tabIndex={0}
        role="region"
        aria-label="cURL PoC command"
        className="p-3.5 space-y-2 overflow-x-auto text-slate-300 leading-relaxed selection:bg-brand/30 focus:outline-none focus:ring-1 focus:ring-brand"
      >
        <div className="text-slate-400 italic select-none">
          # Note: export TOKEN=&lt;attacker token&gt; first
        </div>
        <pre className="text-emerald-400 select-all whitespace-pre-wrap break-all">
          {curlPoc}
        </pre>
      </div>
    </div>
  );
};
