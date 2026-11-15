import React, { useState, useEffect } from 'react';

export default function App() {
  const [systemStatus, setSystemStatus] = useState({ status: 'Connecting...', version: '0.1.0' });

  useEffect(() => {
    fetch('http://127.0.0.1:8000/health')
      .then(res => res.json())
      .then(data => setSystemStatus(data))
      .catch(() => setSystemStatus({ status: 'Offline / Standby', version: '0.1.0' }));
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-4 w-4 rounded-full bg-cyan-400 animate-pulse"></div>
          <h1 className="text-xl font-bold tracking-wider text-cyan-400 uppercase">CyberSentinel</h1>
          <span className="text-xs bg-slate-800 text-slate-400 px-2.5 py-0.5 rounded border border-slate-700">Autonomous Multi-Agent SOC</span>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-slate-400">Backend API:</span>
          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${systemStatus.status === 'healthy' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}`}>
            {systemStatus.status.toUpperCase()}
          </span>
        </div>
      </header>

      {/* Main SOC Dashboard View */}
      <main className="flex-1 p-6 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
          <h2 className="text-base font-semibold text-slate-200 mb-2">Multi-Agent Swarm Status</h2>
          <p className="text-xs text-slate-400 mb-4">Autonomous detection, triage, and forensic agents.</p>
          <div className="space-y-3">
            <div className="flex justify-between items-center bg-slate-800/40 p-2.5 rounded border border-slate-800 text-sm">
              <span>Triage Agent</span>
              <span className="text-cyan-400 text-xs font-mono">STANDBY</span>
            </div>
            <div className="flex justify-between items-center bg-slate-800/40 p-2.5 rounded border border-slate-800 text-sm">
              <span>Forensic Agent</span>
              <span className="text-cyan-400 text-xs font-mono">STANDBY</span>
            </div>
            <div className="flex justify-between items-center bg-slate-800/40 p-2.5 rounded border border-slate-800 text-sm">
              <span>Threat Intel Agent</span>
              <span className="text-cyan-400 text-xs font-mono">STANDBY</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
          <h2 className="text-base font-semibold text-slate-200 mb-2">Detection Engine</h2>
          <p className="text-xs text-slate-400 mb-4">Deep Tabular & Tree Classifiers</p>
          <div className="space-y-2 text-sm text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-400">Architecture:</span>
              <span className="font-mono text-xs">PyTorch TabNet + CPU</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Explainability:</span>
              <span className="font-mono text-xs">SHAP Game Theoretic</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Topology Isolation:</span>
              <span className="text-emerald-400 font-mono text-xs">ENFORCED (No IP/Port Bias)</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
          <h2 className="text-base font-semibold text-slate-200 mb-2">Ingestion Telemetry</h2>
          <p className="text-xs text-slate-400 mb-4">CICIDS2017 Dataset Lineage</p>
          <div className="space-y-2 text-sm text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-400">Status:</span>
              <span className="text-emerald-400 font-semibold text-xs">READY</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Features Extracted:</span>
              <span className="font-mono text-xs">65 Invariant Dimensions</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Storage Backend:</span>
              <span className="font-mono text-xs">SQLite (cybersentinel.db)</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

