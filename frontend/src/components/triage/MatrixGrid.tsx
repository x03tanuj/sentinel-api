import React, { useState } from 'react';
import type { MergedMatrixCell } from '../../lib/adapters';
import { AlertOctagon, CheckCircle2, ShieldAlert, Key, Filter } from 'lucide-react';

interface MatrixGridProps {
  cells: MergedMatrixCell[];
  onSelectFinding?: (findingId: string) => void;
  className?: string;
}

export const MatrixGrid: React.FC<MatrixGridProps> = ({
  cells,
  onSelectFinding,
  className = '',
}) => {
  const [selectedResource, setSelectedResource] = useState<string>('');

  if (!cells || cells.length === 0) {
    return (
      <div className="p-8 rounded-panel bg-canvas-panel border border-border-structural text-center font-mono text-xs text-slate-400">
        No authorization matrix data captured for this scan.
      </div>
    );
  }

  // Extract unique identities (columns) and resources/objects (rows)
  const identities = Array.from(new Set(cells.map((c) => c.identity)));
  const resources = Array.from(new Set(cells.map((c) => c.resource)));

  // Group objects: Map from object key to map of identity -> cell
  interface ObjectRow {
    resource: string;
    objectId: string;
    owner: string;
    cellsByIdentity: Map<string, MergedMatrixCell>;
  }

  const rowsMap = new Map<string, ObjectRow>();
  cells.forEach((cell) => {
    if (selectedResource && cell.resource !== selectedResource) {
      return;
    }
    const rowKey = `${cell.resource}:${cell.objectId}`;
    if (!rowsMap.has(rowKey)) {
      rowsMap.set(rowKey, {
        resource: cell.resource,
        objectId: cell.objectId,
        owner: cell.owner,
        cellsByIdentity: new Map(),
      });
    }
    rowsMap.get(rowKey)!.cellsByIdentity.set(cell.identity, cell);
  });

  const rows = Array.from(rowsMap.values());

  const getCellRendering = (cell: MergedMatrixCell | undefined, key: string) => {
    if (!cell) {
      return (
        <td key={key} className="p-2 border border-border-structural bg-canvas-base/30 text-center font-mono text-xs text-slate-600">
          -
        </td>
      );
    }

    const { state, identity, objectId, findingId } = cell;
    const ariaLabel = `${identity} on ${cell.resource} ${objectId}: ${state.replace(/-/g, ' ')}`;

    switch (state) {
      case 'violation':
        return (
          <td
            key={key}
            tabIndex={0}
            role="button"
            aria-label={ariaLabel}
            onClick={() => onSelectFinding?.(findingId || '')}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onSelectFinding?.(findingId || '');
              }
            }}
            className="p-2 border border-severity-critical/60 bg-severity-critical/20 text-severity-critical font-mono text-xs text-center cursor-pointer hover:bg-severity-critical/30 hover:shadow-glow-critical transition-all focus:outline-none focus:ring-2 focus:ring-severity-critical"
          >
            <div className="flex items-center justify-center gap-1 font-bold">
              <AlertOctagon size={13} className="shrink-0 animate-pulse" />
              <span>VIOLATION</span>
            </div>
            <div className="text-[10px] text-slate-200 mt-0.5 font-semibold">
              {cell.actualStatus || 200} OK
            </div>
          </td>
        );

      case 'owns':
        return (
          <td
            key={key}
            aria-label={ariaLabel}
            className="p-2 border border-brand/30 bg-brand/10 text-brand font-mono text-xs text-center"
          >
            <div className="font-semibold flex items-center justify-center gap-1">
              <Key size={12} />
              <span>OWNS</span>
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">200 OK</div>
          </td>
        );

      case 'allowed-by-role':
        return (
          <td
            key={key}
            aria-label={ariaLabel}
            className="p-2 border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-mono text-xs text-center"
          >
            <div className="font-semibold flex items-center justify-center gap-1">
              <CheckCircle2 size={12} />
              <span>ALLOWED</span>
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">200 OK</div>
          </td>
        );

      case 'denied-as-expected':
      default:
        return (
          <td
            key={key}
            aria-label={ariaLabel}
            className="p-2 border border-border-structural bg-canvas-base/60 text-slate-400 font-mono text-xs text-center"
          >
            <div className="font-medium text-slate-300">DENIED</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{cell.actualStatus || 403}</div>
          </td>
        );
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Top Banner & Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-panel bg-canvas-panel border border-border-structural">
        <div>
          <h3 className="font-sans text-sm font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert size={16} className="text-brand" />
            <span>Ground-Truth Authorization Matrix</span>
          </h3>
          <p className="font-mono text-xs text-slate-400 mt-0.5">
            Cross-identity permissions vs proven runtime access boundaries
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Filter size={13} className="text-slate-400" />
          <select
            value={selectedResource}
            onChange={(e) => setSelectedResource(e.target.value)}
            aria-label="Filter matrix by resource type"
            className="px-2.5 py-1 rounded-tactical bg-canvas-base border border-border-structural text-slate-200 font-mono text-xs focus:outline-none focus:border-brand"
          >
            <option value="">All Resources</option>
            {resources.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Legend & Red warning */}
      <div className="flex items-center gap-3 text-xs font-mono flex-wrap bg-canvas-panel p-2.5 rounded-tactical border border-border-structural">
        <span className="text-slate-400 font-semibold">Legend:</span>
        <span className="px-2 py-0.5 rounded border border-brand/40 bg-brand/10 text-brand">OWNS</span>
        <span className="px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">ALLOWED (Role)</span>
        <span className="px-2 py-0.5 rounded border border-border-structural bg-canvas-base text-slate-400">DENIED (Expected)</span>
        <span className="px-2 py-0.5 rounded border border-severity-critical/50 bg-severity-critical/20 text-severity-critical font-bold">
          VIOLATION (Broken Auth)
        </span>
      </div>

      <div className="p-2.5 rounded-tactical bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-xs font-mono">
        <strong>Differential Vulnerability Alert:</strong> Red cells are proven access-control failures where an unauthorized persona bypassed controls. Click any red cell to view the finding.
      </div>

      {/* Heatmap Table */}
      <div className="overflow-x-auto rounded-panel border border-border-structural bg-canvas-panel">
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-canvas-elevated text-left">
              <th className="p-2.5 border-b border-border-structural font-mono text-xs text-slate-300">
                Resource &amp; Object ID
              </th>
              <th className="p-2.5 border-b border-border-structural font-mono text-xs text-slate-300">
                Owner
              </th>
              {identities.map((id) => (
                <th
                  key={id}
                  className="p-2.5 border-b border-border-structural font-mono text-xs text-center text-slate-200"
                >
                  {id}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.resource}:${row.objectId}`} className="hover:bg-canvas-elevated/40">
                <td className="p-2 border border-border-structural font-mono text-xs text-slate-200 font-semibold">
                  {row.resource}:{row.objectId}
                </td>
                <td className="p-2 border border-border-structural font-mono text-xs text-slate-400">
                  <span className="px-1.5 py-0.5 rounded bg-canvas-base border border-border-subdued text-slate-300">
                    {row.owner}
                  </span>
                </td>
                {identities.map((id) => getCellRendering(row.cellsByIdentity.get(id), id))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
