import React from 'react';
import { Check, CircleDot, Clock } from 'lucide-react';

interface StageStepperProps {
  currentStage: string;
  className?: string;
}

interface StageDef {
  key: string;
  label: string;
  sub: string;
}

const STAGES: StageDef[] = [
  { key: 'LOADING_SPEC', label: 'Loading Spec', sub: 'Parse OpenAPI schema' },
  { key: 'MAPPING_SURFACE', label: 'Mapping Surface', sub: 'Validate endpoints' },
  { key: 'AUTHENTICATING', label: 'Authenticating', sub: 'Personas logged in' },
  { key: 'DISCOVERING', label: 'Discovering', sub: 'Map owned objects' },
  { key: 'PLANNING', label: 'Planning', sub: 'Budget test cases' },
  { key: 'RUNNING_CHECKS', label: 'Running Checks', sub: 'Active auth probes' },
  { key: 'REPRODUCING', label: 'Reproducing', sub: 'Empirical verification' },
  { key: 'FINALIZING', label: 'Finalizing', sub: 'Atomic report & cleanup' },
];

export const StageStepper: React.FC<StageStepperProps> = ({ currentStage, className = '' }) => {
  const normCurrent = currentStage.toUpperCase();
  const currentIndex = STAGES.findIndex((s) => s.key === normCurrent);

  return (
    <div className={`p-4 rounded-panel bg-canvas-panel border border-border-structural space-y-3 ${className}`}>
      <div className="flex items-center justify-between border-b border-border-subdued pb-2">
        <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
          Tactical Audit Pipeline Execution
        </span>
        <span className="font-mono text-[11px] text-brand">
          {currentIndex >= 0 ? `Stage ${currentIndex + 1} of 8: ${STAGES[currentIndex]?.label}` : 'Initializing'}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
        {STAGES.map((stage, idx) => {
          let status: 'completed' | 'active' | 'queued' = 'queued';
          if (currentIndex > idx) {
            status = 'completed';
          } else if (currentIndex === idx) {
            status = 'active';
          }

          return (
            <div
              key={stage.key}
              className={`p-2.5 rounded-tactical border flex flex-col justify-between text-left transition-all ${
                status === 'completed'
                  ? 'bg-canvas-elevated border-severity-secure/40 text-slate-300'
                  : status === 'active'
                  ? 'bg-brand/10 border-brand shadow-glow-primary text-slate-100'
                  : 'bg-canvas-base border-border-structural/50 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-[10px] uppercase font-semibold">
                  0{idx + 1}
                </span>
                {status === 'completed' && (
                  <Check size={13} className="text-severity-secure" />
                )}
                {status === 'active' && (
                  <CircleDot size={13} className="text-brand animate-pulse" />
                )}
                {status === 'queued' && (
                  <Clock size={12} className="text-slate-600" />
                )}
              </div>

              <div>
                <div className={`font-mono text-xs font-semibold truncate ${
                  status === 'active' ? 'text-brand' : status === 'completed' ? 'text-slate-200' : 'text-slate-500'
                }`}>
                  {stage.label}
                </div>
                <div className="font-mono text-[9px] text-slate-500 truncate mt-0.5">
                  {stage.sub}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
