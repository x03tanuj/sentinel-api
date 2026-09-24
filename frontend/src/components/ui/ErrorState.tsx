import React from 'react';
import { AlertCircle, RefreshCw, ArrowLeft } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  stage?: string;
  onRetry?: () => void;
  onBack?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Execution Diagnostic Error',
  message,
  stage,
  onRetry,
  onBack,
  className = '',
}) => {
  return (
    <div
      role="alert"
      className={`p-6 rounded-panel bg-canvas-panel border border-severity-critical/50 shadow-glow-critical flex flex-col items-start gap-4 max-w-xl mx-auto my-6 ${className}`}
    >
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-tactical bg-severity-critical/20 text-severity-critical border border-severity-critical/40">
          <AlertCircle size={20} />
        </div>
        <div>
          <h3 className="font-sans text-base font-semibold text-slate-100">{title}</h3>
          {stage && (
            <span className="font-mono text-xs text-severity-high">
              Failed during pipeline stage: {stage}
            </span>
          )}
        </div>
      </div>

      <div className="w-full p-3 rounded-tactical bg-canvas-base border border-border-structural font-mono text-xs text-slate-300 break-words">
        {message}
      </div>

      <div className="flex items-center gap-3 pt-2">
        {onRetry && (
          <button
            onClick={onRetry}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical bg-brand text-canvas-base font-semibold text-xs hover:bg-brand-hover transition-colors focus:ring-2 focus:ring-brand focus:outline-none"
          >
            <RefreshCw size={13} />
            <span>Retry Operation</span>
          </button>
        )}
        {onBack && (
          <button
            onClick={onBack}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-tactical border border-border-structural text-slate-300 font-semibold text-xs hover:bg-canvas-elevated transition-colors focus:ring-2 focus:ring-brand focus:outline-none"
          >
            <ArrowLeft size={13} />
            <span>Return to History</span>
          </button>
        )}
      </div>
    </div>
  );
};
