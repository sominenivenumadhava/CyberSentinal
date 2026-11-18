import React from 'react';
import { Play, ShieldAlert, CheckCircle, Database } from 'lucide-react';

export default function Header({ activePageTitle, onQuickAnalyze, isAnalyzing, activeAnalysisId }) {
  return (
    <header className="h-16 bg-[#14213d] border-b border-[#f4eded]/15 px-6 flex items-center justify-between text-[#f4eded]">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-bold tracking-tight text-[#f4eded]">{activePageTitle}</h2>
        {activeAnalysisId && (
          <span className="text-xs px-2.5 py-0.5 rounded border border-[#ff6b5b] bg-[#ff6b5b]/10 text-[#ff6b5b] font-mono">
            Active: {activeAnalysisId}
          </span>
        )}
      </div>

      <div className="flex items-center gap-4">
        {/* Quick Launch Demo */}
        <button
          onClick={onQuickAnalyze}
          disabled={isAnalyzing}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] disabled:opacity-50 transition-all shadow-md"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>{isAnalyzing ? 'Swarm Running...' : 'One-Click Swarm Run (50 Flows)'}</span>
        </button>

        {/* Database Status */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-[#f4eded]/70 bg-[#14213d] border border-[#f4eded]/15 px-2.5 py-1 rounded-md">
          <Database className="w-3.5 h-3.5 text-[#ff6b5b]" />
          <span>SQLite: Connected</span>
        </div>
      </div>
    </header>
  );
}
