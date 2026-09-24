import React from 'react';
import { methodColorClass } from '../../lib/formatters';

interface MethodBadgeProps {
  method: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const MethodBadge: React.FC<MethodBadgeProps> = ({
  method,
  size = 'md',
  className = '',
}) => {
  const norm = method.toUpperCase();
  const colorClasses = methodColorClass(norm);
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-bold tracking-wider rounded-tactical border ${colorClasses} ${sizeClasses} ${className}`}
    >
      {norm}
    </span>
  );
};
