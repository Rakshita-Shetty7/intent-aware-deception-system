import React from 'react';
import { Terminal, Clock, Server } from 'lucide-react';
import IntentBadge from '../common/IntentBadge';
import SeverityBadge from '../common/SeverityBadge';
import RiskIndicator from '../common/RiskIndicator';
import EmptyState from '../common/EmptyState';

export default function RecentEvents({ events = [] }) {
  if (!events || events.length === 0) {
    return <EmptyState title="No Recent Events" message="Waiting for honeypot telemetry..." icon={Terminal} />;
  }

  return (
    <div className="space-y-2">
      {events.map((ev) => (
        <div
          key={ev.event_id}
          className="bg-[#0e1320] border border-[#1f293d] rounded-md p-3 hover:border-[#2e3d5c] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
        >
          <div className="flex items-start md:items-center gap-3">
            <div className="p-1.5 bg-[#161f33] border border-[#2e3d5c]/60 rounded text-cyan-400 font-mono">
              <Terminal className="w-3.5 h-3.5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono font-medium text-slate-200">
                  {ev.command ? (
                    <code className="bg-[#161f33] px-1.5 py-0.5 rounded text-cyan-300 font-mono">
                      {ev.command.length > 50 ? `${ev.command.substring(0, 50)}...` : ev.command}
                    </code>
                  ) : (
                    <span className="text-slate-400 font-mono">{ev.event_type}</span>
                  )}
                </span>
                <IntentBadge intent={ev.intent} />
                <SeverityBadge severity={ev.severity} />
              </div>
              <div className="flex items-center gap-4 mt-1 text-[11px] text-slate-400 font-mono">
                <span>IP: {ev.source_ip || 'N/A'}</span>
                <span>Session: {ev.session_id ? ev.session_id.substring(0, 8) : 'N/A'}</span>
                {ev.username && <span>User: {ev.username}</span>}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between md:justify-end gap-4 border-t md:border-t-0 border-[#1f293d] pt-2 md:pt-0">
            <RiskIndicator score={ev.risk_score} size="sm" />
            <span className="text-[11px] text-slate-500 font-mono flex items-center gap-1 flex-shrink-0">
              <Clock className="w-3 h-3" />
              {new Date(ev.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
