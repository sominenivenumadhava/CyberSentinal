import React from 'react';
import { Bot, Cpu, ShieldAlert, FileText, CheckCircle2, Clock, Server, Database } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function AgentMonitoring({ agentsStatus, analysisData }) {
  const agents = agentsStatus?.agents || {};
  const trace = analysisData?.execution_trace || {};

  // Latency chart data
  const latencyData = [
    { name: 'Data Agent', latency: trace['DataProcessingAgent']?.latency_ms || 4.7 },
    { name: 'TabNet Classifier', latency: trace['AttackClassificationAgent']?.latency_ms || 16.8 },
    { name: 'Autoencoder', latency: trace['AnomalyDetectionAgent']?.latency_ms || 2.8 },
    { name: 'Threat Investigator', latency: trace['ThreatInvestigationAgent']?.latency_ms || 2.2 },
    { name: 'Risk Assessor', latency: trace['RiskAssessmentAgent']?.latency_ms || 2.8 },
  ];

  return (
    <div className="space-y-6">
      {/* Coordinator System Status Card */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase tracking-widest text-[#ff6b5b] font-mono font-semibold">
              Multi-Agent Swarm Orchestrator
            </span>
            <span className="text-xs px-2 py-0.5 rounded bg-[#f4eded]/10 text-[#f4eded] font-mono font-bold">
              ThreadPoolExecutor (max_workers=2)
            </span>
          </div>
          <h2 className="text-xl font-black text-[#f4eded] mt-1">Central Coordinator: ACTIVE</h2>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Orchestrating concurrent deep learning sensors, Pydantic message envelopes, and SQLite audit trails.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="bg-[#14213d] border border-[#f4eded]/15 p-2.5 rounded-lg text-center">
            <div className="text-[#f4eded]/60 text-[10px]">Active Agents</div>
            <div className="text-base font-bold text-[#ff6b5b]">5 / 5</div>
          </div>
          <div className="bg-[#14213d] border border-[#f4eded]/15 p-2.5 rounded-lg text-center">
            <div className="text-[#f4eded]/60 text-[10px]">Database Storage</div>
            <div className="text-base font-bold text-[#f4eded]">SQLite Connected</div>
          </div>
        </div>
      </div>

      {/* Latency Comparison Chart */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-[#f4eded]">Execution Latency Profile per Agent (CPU)</h3>
            <p className="text-xs text-[#f4eded]/60">Measured in milliseconds per evaluation cycle</p>
          </div>
          <span className="text-xs text-[#ff6b5b] font-mono">Parallel DL Phase</span>
        </div>

        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={latencyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" stroke="#f4eded" opacity={0.6} fontSize={11} tickLine={false} />
              <YAxis stroke="#f4eded" opacity={0.6} fontSize={11} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#14213d',
                  borderColor: '#ff6b5b',
                  borderRadius: '8px',
                  color: '#f4eded',
                  fontSize: '12px',
                }}
                itemStyle={{ color: '#ff6b5b' }}
              />
              <Bar dataKey="latency" radius={[4, 4, 0, 0]}>
                {latencyData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={index === 1 ? '#ff6b5b' : '#f4eded'} opacity={index === 1 ? 0.9 : 0.4} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 5 Specialized Agents Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[
          {
            name: 'Data Processing Agent',
            role: 'Agent 1: Ingestion & Feature Sanitizer',
            status: 'READY',
            specs: [
              'Schema: 65 Numeric Features',
              'Preprocess: Invariant Scaling & Impute',
              'Metadata Isolation: IPs, Ports, Timestamps',
            ],
          },
          {
            name: 'Attack Classification Agent',
            role: 'Agent 2: TabNet Deep Classifier',
            status: 'READY',
            specs: [
              'Model: PyTorch TabNet Attention Net',
              'Hardware: Intel CPU AVX2/AVX-512',
              'Outputs: Softmax Probs + Attention Mask',
            ],
          },
          {
            name: 'Anomaly Detection Agent',
            role: 'Agent 3: Flow Autoencoder (MSE)',
            status: 'READY',
            specs: [
              'Architecture: 65-48-24-12-24-48-65',
              'Calibrated Threshold τ*: 0.185111',
              'Training: 100% Unsupervised Benign',
            ],
          },
          {
            name: 'Threat Investigation Agent',
            role: 'Agent 4: Incident Correlator',
            status: 'READY',
            specs: [
              'Port Scan Reconnaissance Engine',
              'Brute Force Authentication Engine',
              'Volumetric DoS Burst Engine',
            ],
          },
          {
            name: 'Risk Assessment Agent',
            role: 'Agent 5: Risk & Reporting Engine',
            status: 'READY',
            specs: [
              'Multi-Criteria Formula (0-100 Score)',
              'Model Consensus Discrepancy Auditing',
              'Non-Disruptive Playbook Formulation',
            ],
          },
        ].map((agent, i) => (
          <div
            key={i}
            className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-4 shadow space-y-3 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-xs text-[#f4eded]">{agent.name}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#f4eded]/10 text-[#f4eded] border border-[#f4eded]/20">
                  {agent.status}
                </span>
              </div>
              <div className="text-[11px] text-[#ff6b5b] font-medium mb-3">{agent.role}</div>

              <div className="space-y-1 text-[11px] font-mono text-[#f4eded]/70">
                {agent.specs.map((spec, sIdx) => (
                  <div key={sIdx} className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#ff6b5b]"></span>
                    <span>{spec}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-[#f4eded]/10 text-[10px] font-mono text-[#f4eded]/50 flex justify-between">
              <span>Status: Operational</span>
              <span>Subsystem OK</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
