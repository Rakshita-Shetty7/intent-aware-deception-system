import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import EmptyState from '../common/EmptyState';
import { PieChart as PieIcon } from 'lucide-react';

const INTENT_COLORS = {
  RECONNAISSANCE: '#06b6d4', // Cyan
  DISCOVERY: '#3b82f6',     // Blue
  CREDENTIAL_ACCESS: '#f59e0b', // Amber
  EXECUTION: '#ef4444',     // Red
  PRIVILEGE_ESCALATION: '#a855f7', // Purple
  PERSISTENCE: '#6366f1',   // Indigo
  EXPLOITATION: '#f43f5e',  // Rose
  EXFILTRATION: '#d946ef',  // Fuchsia
  CLEANUP: '#14b8a6',       // Teal
  OTHER: '#64748b',         // Slate
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-[#111726] border border-[#2e3d5c] p-2.5 rounded shadow-lg text-xs font-mono">
        <p className="font-bold text-slate-200">{data.intent}</p>
        <p className="text-cyan-400">Events: {data.count} ({data.percentage}%)</p>
      </div>
    );
  }
  return null;
};

export default function IntentDistributionChart({ data = [] }) {
  if (!data || data.length === 0) {
    return <EmptyState title="No Classified Intents" message="No intent distribution data available." icon={PieIcon} />;
  }

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="intent"
            cx="50%"
            cy="50%"
            outerRadius={80}
            innerRadius={45}
            paddingAngle={3}
            stroke="#0a0d14"
            strokeWidth={2}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={INTENT_COLORS[entry.intent] || '#64748b'}
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value) => (
              <span className="text-[11px] font-mono text-slate-400">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
