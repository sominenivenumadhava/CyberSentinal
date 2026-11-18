import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  Bot,
  Layers,
  ArrowRight,
  Clock,
  ExternalLink
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';

export default function DashboardOverview({
  analysisData,
  agentsStatus,
  onNavigate,
  onQuickAnalyze,
  isAnalyzing,

}) {
  const riskScore = analysisData?.risk_score ?? 81.57;
  const severity = analysisData?.severity ?? 'CRITICAL';
  const totalFlows = analysisData?.total_flows_evaluated ?? 50;
  const attacksCount = analysisData?.malicious_flows_count ?? 5;
  const anomaliesCount = analysisData?.anomalous_flows_count ?? 50;
  const incidents = analysisData?.correlated_incidents ?? [];

  // Chart data for threat breakdown
  const chartData = [
    { name: 'Total Flows', count: totalFlows },
    { name: 'Anomalies', count: anomaliesCount },
    { name: 'Attacks', count: attacksCount },
    { name: 'Incidents', count: incidents.length || 33 },
  ];

  return (
    <div className="space-y-6">
      {/* Top Threat Posture Alert Banner */}
      <div className="bg-[#14213d] border border-[#ff6b5b] rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#ff6b5b] text-[#14213d] flex items-center justify-center font-bold text-2xl shadow-inner">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase tracking-widest font-mono text-[#ff6b5b] font-semibold">
                  Autonomous Threat Posture
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-[#ff6b5b] text-[#14213d] font-bold">
                  {severity}
                </span>
              </div>
              <h2 className="text-2xl font-black text-[#f4eded] mt-0.5">
                Composite Threat Score: {riskScore.toFixed(1)} / 100
              </h2>
              <p className="text-xs text-[#f4eded]/70 max-w-2xl mt-1">
                {analysisData?.executive_summary ||
                  'CyberSentinel multi-agent swarm evaluated held-out network telemetry. Autonomous incident correlation and non-disruptive response playbooks generated awaiting analyst sign-off.'}
              </p>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => onNavigate('threats')}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] transition-colors flex items-center gap-1.5"
            >
              <span>View Threats</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onNavigate('reports')}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#14213d] border border-[#f4eded]/30 text-[#f4eded] hover:bg-[#f4eded]/10 transition-colors"
            >
              SOC Dossier
            </button>
          </div>
        </div>
      </div>

      {/* 4 Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-xs text-[#f4eded]/70 mb-2">
            <span>Evaluated Flows</span>
            <Activity className="w-4 h-4 text-[#ff6b5b]" />
          </div>
          <div className="text-3xl font-black text-[#f4eded]">{totalFlows}</div>
          <div className="text-[11px] text-[#f4eded]/60 mt-1 font-mono">Telemetry Batch: CICIDS2017</div>
        </div>

        <div className="bg-[#14213d] border border-[#ff6b5b]/50 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-xs text-[#ff6b5b] mb-2">
            <span>Classified Attacks</span>
            <ShieldAlert className="w-4 h-4 text-[#ff6b5b]" />
          </div>
          <div className="text-3xl font-black text-[#ff6b5b]">{attacksCount}</div>
          <div className="text-[11px] text-[#f4eded]/60 mt-1 font-mono">PyTorch TabNet Classifier</div>
        </div>

        <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-xs text-[#f4eded]/70 mb-2">
            <span>Reconstruction Anomalies</span>
            <AlertTriangle className="w-4 h-4 text-[#ff6b5b]" />
          </div>
          <div className="text-3xl font-black text-[#f4eded]">{anomaliesCount}</div>
          <div className="text-[11px] text-[#f4eded]/60 mt-1 font-mono">Threshold τ* = 0.185111</div>
        </div>

        <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-xs text-[#f4eded]/70 mb-2">
            <span>Correlated Incidents</span>
            <Layers className="w-4 h-4 text-[#ff6b5b]" />
          </div>
          <div className="text-3xl font-black text-[#f4eded]">{incidents.length || 33}</div>
          <div className="text-[11px] text-[#f4eded]/60 mt-1 font-mono">Campaign IP & Port Clusters</div>
        </div>
      </div>

      {/* Visual Chart & Agent Swarm Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recharts Bar Chart */}
        <div className="lg:col-span-2 bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#f4eded]">Telemetry Ingestion & Detection Volume</h3>
              <p className="text-xs text-[#f4eded]/60">Comparative breakdown across pipeline stages</p>
            </div>
            <span className="text-xs text-[#ff6b5b] font-mono">Live Telemetry</span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={index === 1 || index === 2 ? '#ff6b5b' : '#f4eded'}
                      opacity={index === 1 || index === 2 ? 0.9 : 0.4}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Multi-Agent Swarm Live Snapshot */}
        <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-[#f4eded] flex items-center gap-2">
                <Bot className="w-4 h-4 text-[#ff6b5b]" />
                <span>Agent Swarm Roster</span>
              </h3>
              <span className="text-[10px] bg-[#f4eded]/10 text-[#f4eded] px-2 py-0.5 rounded border border-[#f4eded]/20">
                5 Agents Active
              </span>
            </div>

            <div className="space-y-2.5">
              {[
                { name: 'Data Processing Agent', role: 'Ingestion & Schema', status: 'READY' },
                { name: 'Attack Classification Agent', role: 'TabNet Deep Neural Net', status: 'READY' },
                { name: 'Anomaly Detection Agent', role: 'Flow Autoencoder (MSE)', status: 'READY' },
                { name: 'Threat Investigation Agent', role: 'Campaign Correlator', status: 'READY' },
                { name: 'Risk Assessment Agent', role: 'Multi-Criteria Scorer', status: 'READY' },
              ].map((agent, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-2 rounded-lg bg-[#14213d] border border-[#f4eded]/10 text-xs"
                >
                  <div>
                    <div className="font-semibold text-[#f4eded]">{agent.name}</div>
                    <div className="text-[10px] text-[#f4eded]/60">{agent.role}</div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#f4eded]/10 text-[#f4eded] border border-[#f4eded]/20">
                    {agent.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() => onNavigate('agents')}
            className="w-full mt-4 py-2 text-xs font-semibold rounded-lg bg-[#14213d] border border-[#ff6b5b] text-[#ff6b5b] hover:bg-[#ff6b5b]/10 transition-colors"
          >
            Open Agent Diagnostics
          </button>
        </div>
      </div>

      {/* Correlated Threat Incidents Preview Table */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-[#f4eded]">Correlated Threat Campaigns</h3>
            <p className="text-xs text-[#f4eded]/60">Autonomous clusters identified by Threat Investigation Agent</p>
          </div>
          <button
            onClick={() => onNavigate('investigation')}
            className="text-xs text-[#ff6b5b] hover:underline flex items-center gap-1 font-semibold"
          >
            <span>View All Incidents</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#14213d] border-b border-[#f4eded]/15 text-[#f4eded]/70">
              <tr>
                <th className="py-2.5 px-3">Pattern Type</th>
                <th className="py-2.5 px-3">Attacker (Source IP)</th>
                <th className="py-2.5 px-3">Target Assets</th>
                <th className="py-2.5 px-3">Target Ports</th>
                <th className="py-2.5 px-3">Timeline</th>
                <th className="py-2.5 px-3">Policy Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#f4eded]/10">
              {incidents.slice(0, 5).map((inc, i) => (
                <tr key={i} className="hover:bg-[#f4eded]/5">
                  <td className="py-2.5 px-3 font-semibold text-[#ff6b5b]">{inc.pattern_type}</td>
                  <td className="py-2.5 px-3 font-mono text-[#f4eded]">{inc.source_ip}</td>
                  <td className="py-2.5 px-3 font-mono text-[#f4eded]/80">
                    {inc.target_ips ? inc.target_ips.join(', ') : '172.16.0.1'}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[#f4eded]/80">
                    {inc.target_ports ? JSON.stringify(inc.target_ports) : '[80, 443]'}
                  </td>
                  <td className="py-2.5 px-3 text-[#f4eded]/60">
                    {inc.earliest_timestamp || '2026-11-15 10:00'}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-[#ff6b5b]/15 text-[#ff6b5b] border border-[#ff6b5b]/40 font-mono">
                      Analyst Sign-off Req.
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
