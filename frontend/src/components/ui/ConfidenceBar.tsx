import React from 'react';

interface ConfidenceBarProps {
  confidence: number; // 0.0 to 1.0
  className?: string;
  showText?: boolean;
}

export const ConfidenceBar: React.FC<ConfidenceBarProps> = ({
  confidence,
  className = '',
  showText = true,
}) => {
  const clamped = Math.max(0, Math.min(1, confidence));
  const percent = Math.round(clamped * 100);

  let barColor = 'bg-brand';
  if (percent >= 85) {
    barColor = 'bg-severity-critical';
  } else if (percent >= 70) {
    barColor = 'bg-severity-high';
  } else if (percent >= 50) {
    barColor = 'bg-severity-medium';
  }

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div
        className="w-16 h-1.5 bg-canvas-base rounded-full overflow-hidden border border-border-structural"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Confidence: ${percent}%`}
      >
        <div
          className={`h-full ${barColor} transition-all duration-300`}
          style={{ width: `${percent}%` }}
        />
      </div>
      {showText && (
        <span className="font-mono text-xs text-slate-400">
          {percent}% <span className="text-[10px] text-slate-400">({clamped.toFixed(2)})</span>
        </span>
      )}
    </div>
  );
};
