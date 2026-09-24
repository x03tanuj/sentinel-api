import React from 'react';
import { ShieldAlert, ExternalLink, X } from 'lucide-react';

interface AiConsentModalProps {
  isOpen: boolean;
  providerName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export const AiConsentModal: React.FC<AiConsentModalProps> = ({
  isOpen,
  providerName,
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-consent-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs"
    >
      <div className="relative w-full max-w-md p-6 bg-canvas-panel border border-border-structural rounded-panel shadow-2xl space-y-4">
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close dialog"
          className="absolute top-4 right-4 p-1 text-slate-400 hover:text-slate-100 rounded focus:outline-none focus:ring-1 focus:ring-brand"
        >
          <X size={16} />
        </button>

        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-tactical bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <ShieldAlert size={20} />
          </div>
          <div>
            <h2 id="ai-consent-title" className="font-sans text-sm font-bold text-slate-100">
              AI Security &amp; Data Egress Notice
            </h2>
            <span className="font-mono text-[10px] text-purple-400 uppercase tracking-wider">
              Session Consent Required
            </span>
          </div>
        </div>

        <p className="font-sans text-xs text-slate-300 leading-relaxed">
          AI analysis sends redacted finding metadata (endpoint path templates, field names,
          status codes; never tokens, passwords, response values, hosts, or curl commands) to{' '}
          <span className="font-mono font-bold text-purple-300">{providerName || 'the configured LLM provider'}</span>.
          Continue?
        </p>

        <div className="p-3 bg-canvas-base rounded border border-border-subdued text-[11px] font-mono text-slate-400 space-y-1">
          <div className="text-slate-300 font-semibold">Strict Data Egress Safeguards:</div>
          <ul className="list-disc list-inside space-y-0.5 text-slate-400">
            <li>Zero credentials, tokens, or session headers leave your machine.</li>
            <li>Real object IDs and request/response bodies are stripped.</li>
            <li>Outbound payload safety regex assertion enforced on every call.</li>
          </ul>
        </div>

        <div className="flex items-center justify-between pt-2">
          <a
            href="https://github.com/sentinel-api/sentinel#ai-analyst"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-xs text-brand hover:underline"
          >
            <span>Data-handling docs</span>
            <ExternalLink size={12} />
          </a>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="px-3 py-1.5 rounded-tactical font-mono text-xs text-slate-300 hover:bg-canvas-elevated border border-border-structural"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              className="px-3.5 py-1.5 rounded-tactical font-mono text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow-glow-primary transition-colors focus:ring-2 focus:ring-purple-400 focus:outline-none"
            >
              Accept &amp; Continue
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
