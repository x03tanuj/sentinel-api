import React from 'react';
import type { RiskBreakdownData } from '../../types';

interface RiskBreakdownProps {
  breakdown?: RiskBreakdownData;
  score?: number;
  className?: string;
}

export const RiskBreakdown: React.FC<RiskBreakdownProps> = ({
  breakdown,
  className = '',
}) => {
  if (!breakdown) {
    return null;
  }

  const {
    impact = 0,
    exploitability = 0,
    data_sensitivity = 0,
    evidence_strength = 0,
  } = breakdown;

  const factors = [
    {
      name: 'Impact',
      current: impact,
      max: 40,
      description: 'Unauthorized access & system state influence',
      color: 'bg-severity-critical',
      textColor: 'text-severity-critical',
    },
    {
      name: 'Exploitability',
      current: exploitability,
      max: 25,
      description: 'Attacker privilege & request complexity',
      color: 'bg-severity-high',
      textColor: 'text-severity-high',
    },
    {
      name: 'Data Sensitivity',
      current: data_sensitivity,
      max: 30,
      description: 'PII, credentials & financial records exposure',
      color: 'bg-severity-medium',
      textColor: 'text-severity-medium',
    },
    {
      name: 'Evidence Strength',
      current: evidence_strength,
      max: 15,
      description: 'Empirical reproduction & differential confidence',
      color: 'bg-brand',
      textColor: 'text-brand',
    },
  ];

  return (
    <div className={`space-y-3 p-4 rounded-panel bg-canvas-panel border border-border-structural ${className}`}>
      <div className="flex items-center justify-between border-b border-border-subdued pb-2">
        <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
          Severity Breakdown Factors
        </span>
        <span className="font-mono text-[10px] text-slate-400">
          Deterministic Telemetry Assessment
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {factors.map((factor) => {
          const ratio = Math.min(1, Math.max(0, factor.current / factor.max));
          const percent = Math.round(ratio * 100);

          return (
            <div key={factor.name} className="space-y-1">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300">
                  {factor.name}: <span className="font-semibold">{factor.current}</span> / {factor.max}
                </span>
                <span className={`font-semibold ${factor.textColor}`}>{percent}%</span>
              </div>
              <div
                className="w-full h-1.5 bg-canvas-base rounded-full overflow-hidden border border-border-structural"
                role="progressbar"
                aria-valuenow={factor.current}
                aria-valuemin={0}
                aria-valuemax={factor.max}
                aria-label={`${factor.name}: ${factor.current} out of ${factor.max}`}
              >
                <div
                  className={`h-full ${factor.color} transition-all duration-300`}
                  style={{ width: `${percent}%` }}
                />
              </div>
              <p className="text-[10px] text-slate-400 truncate">{factor.description}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
