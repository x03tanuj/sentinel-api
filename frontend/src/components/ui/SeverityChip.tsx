import React from 'react';
import type { Severity } from '../../types';
import { severityColorClass } from '../../lib/formatters';
import { AlertOctagon, AlertTriangle, Diamond, Circle, Info, CheckCircle2 } from 'lucide-react';

interface SeverityChipProps {
  severity: Severity | 'SECURE';
  size?: 'sm' | 'md';
  className?: string;
}

export const SeverityChip: React.FC<SeverityChipProps> = ({
  severity,
  size = 'md',
  className = '',
}) => {
  const getIcon = () => {
    const iconSize = size === 'sm' ? 12 : 14;
    switch (severity) {
      case 'CRITICAL':
        return <AlertOctagon size={iconSize} className="shrink-0 animate-pulse text-severity-critical" />;
      case 'HIGH':
        return <AlertTriangle size={iconSize} className="shrink-0 text-severity-high" />;
      case 'MEDIUM':
        return <Diamond size={iconSize} className="shrink-0 text-severity-medium" />;
      case 'LOW':
        return <Circle size={iconSize} className="shrink-0 text-severity-low" />;
      case 'INFO':
        return <Info size={iconSize} className="shrink-0 text-severity-info" />;
      case 'SECURE':
        return <CheckCircle2 size={iconSize} className="shrink-0 text-severity-secure" />;
      default:
        return <Circle size={iconSize} className="shrink-0" />;
    }
  };

  const label = severity.toUpperCase();
  const colorClasses = severityColorClass(severity);
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs';

  return (
    <span
      role="status"
      aria-label={`Severity: ${label}`}
      className={`inline-flex items-center gap-1.5 font-mono font-semibold rounded-tactical border ${colorClasses} ${sizeClasses} ${className}`}
    >
      {getIcon()}
      <span>{label}</span>
    </span>
  );
};
