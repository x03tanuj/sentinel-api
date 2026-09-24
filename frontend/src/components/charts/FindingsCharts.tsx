import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import type { Finding } from '../../types';

interface FindingsChartsProps {
  findings: Finding[];
  className?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  HIGH: '#F97316',
  MEDIUM: '#F59E0B',
  LOW: '#3B82F6',
  INFO: '#64748B',
};

export const FindingsCharts: React.FC<FindingsChartsProps> = ({ findings, className = '' }) => {
  // Compute severity distribution
  const severityCounts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  const checkCounts: Record<string, number> = {};

  findings.forEach((f) => {
    const sev = f.severity.toUpperCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;

    const chk = f.check.toUpperCase();
    checkCounts[chk] = (checkCounts[chk] || 0) + 1;
  });

  const pieData = Object.entries(severityCounts)
    .filter(([_, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  const barData = Object.entries(checkCounts).map(([name, count]) => ({
    name,
    count,
  }));

  if (findings.length === 0) {
    return null;
  }

  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 ${className}`}>
      {/* Chart 1: Severity Donut */}
      <div className="p-4 rounded-panel bg-canvas-panel border border-border-structural">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
          Severity Breakdown
        </h3>
        <p className="sr-only">
          Donut chart showing vulnerability counts by severity:
          {pieData.map((d) => ` ${d.name}: ${d.value};`)}
        </p>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={65}
                paddingAngle={4}
                dataKey="value"
              >
                {pieData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name] || '#38BDF8'}
                    stroke="#0D111C"
                    strokeWidth={2}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0D111C',
                  borderColor: '#232D42',
                  borderRadius: '4px',
                  fontFamily: 'JetBrains Mono',
                  fontSize: '12px',
                  color: '#F1F5F9',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Accessible hidden table alternative */}
        <table className="sr-only">
          <caption>Vulnerability count by severity</caption>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {pieData.map((d) => (
              <tr key={d.name}>
                <td>{d.name}</td>
                <td>{d.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Chart 2: Findings by Check Bar */}
      <div className="p-4 rounded-panel bg-canvas-panel border border-border-structural">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
          Findings by Security Check
        </h3>
        <p className="sr-only">
          Bar chart showing vulnerability counts by security check suite:
          {barData.map((d) => ` ${d.name}: ${d.count};`)}
        </p>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis
                dataKey="name"
                stroke="#64748B"
                fontSize={10}
                fontFamily="JetBrains Mono"
                tickLine={false}
              />
              <YAxis
                stroke="#64748B"
                fontSize={10}
                fontFamily="JetBrains Mono"
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0D111C',
                  borderColor: '#232D42',
                  borderRadius: '4px',
                  fontFamily: 'JetBrains Mono',
                  fontSize: '12px',
                  color: '#F1F5F9',
                }}
              />
              <Bar dataKey="count" fill="#38BDF8" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Accessible hidden table alternative */}
        <table className="sr-only">
          <caption>Vulnerability count by check rule</caption>
          <thead>
            <tr>
              <th scope="col">Check Rule</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {barData.map((d) => (
              <tr key={d.name}>
                <td>{d.name}</td>
                <td>{d.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
