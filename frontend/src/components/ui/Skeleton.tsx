import React from 'react';

interface SkeletonProps {
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = 'h-4 w-full' }) => {
  return (
    <div
      className={`animate-pulse rounded bg-canvas-elevated/70 border border-border-subdued ${className}`}
      aria-hidden="true"
    />
  );
};
