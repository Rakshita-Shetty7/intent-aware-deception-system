import React, { useEffect, useState } from 'react';
import { Shield, Radio, Terminal, Wifi, WifiOff } from 'lucide-react';
import api from '../../services/api';
import useWebSocket from '../../hooks/useWebSocket';

export default function Navbar() {
  const [health, setHealth] = useState({ status: 'checking', database: 'checking' });
  const [time, setTime] = useState(new Date().toUTCString());

  // Connect to events channel to monitor live streaming status
  const { status: wsStatus } = useWebSocket('/ws/events', () => {});

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString());
    }, 1000);

    const checkHealth = async () => {
      try {
        const data = await api.getHealth();
        setHealth(data);
      } catch (err) {
        setHealth({ status: 'degraded', database: 'disconnected' });
      }
    };

    checkHealth();
    const healthInterval = setInterval(checkHealth, 15000);

    return () => {
      clearInterval(timer);
      clearInterval(healthInterval);
    };
  }, []);

  return (
    <header className="h-16 bg-[#0d121d] border-b border-[#1f293d] px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-cyan-950/40 border border-cyan-800/60 rounded-md text-cyan-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">
            Intent-Aware Deception System
          </h1>
          <p className="text-[10px] text-slate-400 font-mono tracking-wide">
            REAL-TIME ATTACKER PROFILING & HONEYPOT TELEMETRY
          </p>
        </div>
      </div>

      <div className="flex items-center gap-5">
        {/* System Time */}
        <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400">
          <Terminal className="w-3.5 h-3.5 text-slate-500" />
          <span>{time}</span>
        </div>

        {/* Real-Time WebSocket Streaming Indicator */}
        <div className="flex items-center gap-2 px-3 py-1 bg-[#111726] border border-[#1f293d] rounded-full text-xs font-mono">
          <span className={`w-2 h-2 rounded-full ${
            wsStatus === 'LIVE' ? 'bg-emerald-400 animate-pulse' :
            wsStatus === 'CONNECTING' ? 'bg-amber-400 animate-ping' : 'bg-rose-500'
          }`} />
          <span className={`font-semibold ${
            wsStatus === 'LIVE' ? 'text-emerald-400' :
            wsStatus === 'CONNECTING' ? 'text-amber-400' : 'text-rose-400'
          }`}>
            {wsStatus === 'LIVE' ? 'LIVE STREAM' : wsStatus === 'CONNECTING' ? 'CONNECTING...' : 'DISCONNECTED'}
          </span>
        </div>

        {/* Database Health Status */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 bg-[#0d121d] border border-[#1f293d]/80 rounded text-[11px] font-mono text-slate-400">
          <span className={`w-1.5 h-1.5 rounded-full ${health.database === 'connected' ? 'bg-cyan-400' : 'bg-rose-400'}`} />
          <span>DB: {health.database === 'connected' ? 'OK' : 'ERR'}</span>
        </div>
      </div>
    </header>
  );
}
