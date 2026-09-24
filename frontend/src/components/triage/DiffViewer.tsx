import React from 'react';
import type { DiffModel } from '../../types';
import { ShieldCheck, AlertTriangle } from 'lucide-react';

interface DiffViewerProps {
  diffModel: DiffModel | null;
  className?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diffModel, className = '' }) => {
  if (!diffModel) {
    return (
      <div className="p-4 rounded-panel bg-canvas-panel border border-border-structural text-slate-400 font-mono text-xs">
        No differential response captured for this finding.
      </div>
    );
  }

  const {
    mode,
    ownerIdentity,
    attackerIdentity,
    ownerStatus = 200,
    attackerStatus,
    expectedStatus = 403,
    ownerBodyFormatted,
    attackerBodyFormatted,
    maskedFields,
    leakedFieldNames,
  } = diffModel;

  const isSecureVariant = expectedStatus === attackerStatus && attackerStatus >= 400;

  return (
    <div className={`space-y-2 ${className}`}>
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
          Dual-Identity Response Differential
        </span>
        <span className="font-mono text-[11px] text-slate-400">
          Left: Owner Baseline vs Right: Attacker Probe
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Left Panel: Owner Baseline */}
        <div className="rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col">
          <div className="bg-canvas-elevated px-3 py-2 border-b border-border-structural flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-mono text-xs">
              <span className="w-2 h-2 rounded-full bg-severity-secure" />
              <span className="text-slate-200 font-semibold">{ownerIdentity}</span>
              <span className="text-[10px] text-slate-400">(Legitimate Owner)</span>
            </div>

            <span className="font-mono text-[11px] px-2 py-0.5 rounded-tactical bg-emerald-950/60 text-emerald-200 border border-emerald-500/50 font-semibold">
              {ownerStatus} OK
            </span>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-label="Owner baseline response"
            className="p-3 font-mono text-xs bg-canvas-base flex-1 overflow-x-auto min-h-[140px] text-slate-300 selection:bg-brand/30 focus:outline-none focus:ring-1 focus:ring-brand"
          >
            {mode === 'full_bodies' && ownerBodyFormatted ? (
              <pre className="whitespace-pre-wrap">{ownerBodyFormatted}</pre>
            ) : (
              <div className="space-y-1 text-slate-400">
                <div className="text-[11px] text-slate-400"># Owner Baseline Fields:</div>
                {Object.keys(maskedFields).length > 0 ? (
                  Object.keys(maskedFields).map((field) => (
                    <div key={field} className="flex justify-between py-0.5 border-b border-border-subdued">
                      <span className="text-slate-300">{field}:</span>
                      <span className="text-slate-400 font-semibold">[Authorized Value]</span>
                    </div>
                  ))
                ) : (
                  <div>200 OK — Resource baseline established</div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Panel: Attacker Probe */}
        <div className="rounded-panel bg-canvas-panel border border-border-structural overflow-hidden flex flex-col">
          <div className="bg-canvas-elevated px-3 py-2 border-b border-border-structural flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-mono text-xs">
              <span
                className={`w-2 h-2 rounded-full ${
                  isSecureVariant ? 'bg-severity-secure' : 'bg-severity-critical animate-pulse'
                }`}
              />
              <span className="text-slate-200 font-semibold">{attackerIdentity}</span>
              <span className="text-[10px] text-slate-400">(Attacker Persona)</span>
            </div>

            {/* Status Divergence Badge */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-mono text-[11px] px-2 py-0.5 rounded-tactical bg-slate-800 text-slate-200 border border-slate-700 font-semibold">
                Expected: {expectedStatus} {expectedStatus === 403 ? 'Forbidden' : expectedStatus === 401 ? 'Unauthorized' : ''}
              </span>
              <span
                className={`font-mono text-[11px] px-2 py-0.5 rounded-tactical font-semibold border flex items-center gap-1 ${
                  isSecureVariant
                    ? 'bg-emerald-950/60 text-emerald-200 border-emerald-500/50'
                    : 'bg-red-950/60 text-red-200 border-red-500/50'
                }`}
              >
                {isSecureVariant ? <ShieldCheck size={12} /> : <AlertTriangle size={12} />}
                <span>
                  Actual: {attackerStatus} {attackerStatus === 200 ? 'OK' : attackerStatus === 403 ? 'Forbidden' : ''}
                </span>
              </span>
            </div>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-label="Attacker probe response"
            className="p-3 font-mono text-xs bg-canvas-base flex-1 overflow-x-auto min-h-[140px] text-slate-300 selection:bg-brand/30 focus:outline-none focus:ring-1 focus:ring-brand"
          >
            {mode === 'full_bodies' && attackerBodyFormatted ? (
              <div className="space-y-1">
                <pre className="whitespace-pre-wrap">{attackerBodyFormatted}</pre>
                {Object.entries(maskedFields).map(([key, val]) => (
                  <div
                    key={key}
                    className="p-1 rounded bg-severity-critical/10 border border-severity-critical/40 text-severity-critical text-[11px] flex items-center justify-between"
                  >
                    <span>"{key}": "{val}"</span>
                    <span className="font-bold tracking-wider">[LEAKED PII]</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-1.5">
                <div className="text-[11px] text-slate-400"># Exfiltrated Fields &amp; Masked Telemetry:</div>
                {Object.entries(maskedFields).map(([field, val]) => (
                  <div
                    key={field}
                    className="flex items-center justify-between p-1.5 rounded bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-xs"
                  >
                    <span className="font-semibold">{field}:</span>
                    <span className="font-bold">{val} &lt;-- [LEAKED]</span>
                  </div>
                ))}
                {leakedFieldNames.filter((f) => !maskedFields[f]).map((field) => (
                  <div
                    key={field}
                    className="flex items-center justify-between p-1 rounded bg-severity-high/10 border border-severity-high/30 text-severity-high text-xs"
                  >
                    <span>{field}</span>
                    <span className="text-[10px]">[EXPOSED FIELD]</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
