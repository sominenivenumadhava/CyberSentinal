import React from 'react';
import { CheckCircle2, Clock, Bot, Cpu, ShieldAlert, FileText, ArrowRight, Loader2 } from 'lucide-react';

export default function AnalysisProgress({ activeAnalysisId, analysisData, isAnalyzing, onNavigate }) {
  const trace = analysisData?.execution_trace || {};

  const stages = [
    {
      agent: 'Data Processing Agent',
      role: 'Agent 1: Ingestion & Invariant Preprocessing',
      icon: Bot,
      status: trace['DataProcessingAgent'] ? 'COMPLETED' : isAnalyzing ? 'PROCESSING' : 'READY',
      latency: trace['DataProcessingAgent']?.latency_ms,
      description: 'Validated feature schema (65 numeric features), isolated network identifiers into metadata store.',
    },
    {
      agent: 'Attack Classification Agent (TabNet)',
      role: 'Agent 2: Concurrent Supervised Discriminator',
      icon: Cpu,
      status: trace['AttackClassificationAgent'] ? 'COMPLETED' : isAnalyzing ? 'PROCESSING' : 'READY',
      latency: trace['AttackClassificationAgent']?.latency_ms,
      description: 'Calculated softmax attack probability and extracted top feature attention masks.',
    },
    {
      agent: 'Anomaly Detection Agent (Autoencoder)',
      role: 'Agent 3: Concurrent Unsupervised Sensor',
      icon: ShieldAlert,
      status: trace['AnomalyDetectionAgent'] ? 'COMPLETED' : isAnalyzing ? 'PROCESSING' : 'READY',
      latency: trace['AnomalyDetectionAgent']?.latency_ms,
      description: 'Calculated Mean Squared Reconstruction Error against calibrated baseline threshold τ* = 0.185111.',
    },
    {
      agent: 'Threat Investigation Agent',
      role: 'Agent 4: Incident Correlation & Timeline',
      icon: Bot,
      status: trace['ThreatInvestigationAgent'] ? 'COMPLETED' : isAnalyzing ? 'PROCESSING' : 'READY',
      latency: trace['ThreatInvestigationAgent']?.latency_ms,
      description: 'Correlated suspicious flow findings by Source IP into attack campaigns (Port Scan, DoS, Brute Force).',
    },
    {
      agent: 'Risk Assessment & Reporting Agent',
      role: 'Agent 5: Multi-Criteria Scorer & Playbooks',
      icon: FileText,
      status: trace['RiskAssessmentAgent'] ? 'COMPLETED' : isAnalyzing ? 'PROCESSING' : 'READY',
      latency: trace['RiskAssessmentAgent']?.latency_ms,
      description: 'Calculated composite risk score (0-100), mapped severity tiers, and formulated human-gated response actions.',
    },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header Info */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase tracking-widest text-[#ff6b5b] font-mono font-semibold">
              Workflow Execution Trace
            </span>
            {isAnalyzing && (
              <span className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-[#ff6b5b] text-[#14213d] font-bold animate-pulse">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>IN PROGRESS</span>
              </span>
            )}
          </div>
          <h2 className="text-xl font-black text-[#f4eded] mt-1">
            Task ID: {activeAnalysisId || 'DEMO-SWARM-2026'}
          </h2>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Orchestrated concurrently via ThreadPoolExecutor on Windows 11 CPU.
          </p>
        </div>

        {analysisData && (
          <div className="flex gap-2">
            <button
              onClick={() => onNavigate('threats')}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] transition-colors flex items-center gap-1.5 shadow"
            >
              <span>Explore Findings</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Pipeline Stage Timeline */}
      <div className="space-y-3">
        {stages.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = stage.status === 'COMPLETED';
          return (
            <div
              key={idx}
              className={`p-4 rounded-xl border transition-all ${
                isDone
                  ? 'bg-[#14213d] border-[#f4eded]/20'
                  : 'bg-[#14213d]/60 border-[#f4eded]/10 opacity-70'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div
                    className={`w-9 h-9 rounded-lg flex items-center justify-center font-bold ${
                      isDone ? 'bg-[#ff6b5b] text-[#14213d]' : 'bg-[#f4eded]/10 text-[#f4eded]'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-[#f4eded]">{stage.agent}</h4>
                      <span className="text-[10px] font-mono text-[#f4eded]/60">Stage {idx + 1}</span>
                    </div>
                    <div className="text-xs text-[#ff6b5b] font-medium">{stage.role}</div>
                    <p className="text-xs text-[#f4eded]/70 mt-1 max-w-xl">{stage.description}</p>
                  </div>
                </div>

                <div className="text-right flex flex-col items-end">
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                      isDone
                        ? 'bg-[#ff6b5b]/15 text-[#ff6b5b] border border-[#ff6b5b]/40'
                        : 'bg-[#f4eded]/10 text-[#f4eded]/60'
                    }`}
                  >
                    {isDone ? 'SUCCESS' : stage.status}
                  </span>
                  {stage.latency && (
                    <span className="text-[11px] text-[#f4eded]/60 font-mono mt-1 flex items-center gap-1">
                      <Clock className="w-3 h-3 text-[#ff6b5b]" />
                      <span>{stage.latency.toFixed(2)} ms</span>
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Consensus Resolution Audit */}
      {analysisData?.conflict_resolution && (
        <div className="p-4 rounded-xl bg-[#14213d] border border-[#ff6b5b]/40 text-xs">
          <div className="font-bold text-[#ff6b5b] mb-1">Model Consensus & Conflict Audit</div>
          <div className="text-[#f4eded]/80 font-mono text-[11px]">
            {analysisData.conflict_resolution}
          </div>
        </div>
      )}
    </div>
  );
}
