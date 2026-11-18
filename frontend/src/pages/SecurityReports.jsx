import React, { useState } from 'react';
import { FileText, Copy, Download, CheckCircle, ShieldAlert, Layers, ExternalLink } from 'lucide-react';

export default function SecurityReports({ analysisData, activeAnalysisId, pastAnalyses, onSelectAnalysis }) {
  const [copied, setCopied] = useState(false);

  const reportId = activeAnalysisId || 'DEMO-SWARM-2026';
  const riskScore = analysisData?.risk_score ?? 81.57;
  const severity = analysisData?.severity ?? 'CRITICAL';
  const incidents = analysisData?.correlated_incidents || [];
  const playbooks = analysisData?.recommended_actions || [];

  // Generate clean markdown representation
  const markdownText = `# CyberSentinel Security Investigation Report
**Task ID**: \`${reportId}\`  
**Generated**: 2026-11-15 17:47:39 UTC  
**Overall Threat Posture**: **${severity}** (Score: ${riskScore.toFixed(2)}/100)  

---
## Executive Summary
${analysisData?.executive_summary || 'CyberSentinel Multi-Agent Threat Assessment completed.'}

---
## Model Consensus & Conflict Audit
${analysisData?.conflict_resolution || 'Consensus Audit: Concordant Attacks=5, Ambiguous Anomalies=45, Ambiguous Signatures=0.'}

---
## Correlated Incident Campaigns (${incidents.length})
${incidents.map((inc, i) => `### Incident ${i + 1}: [${inc.pattern_type}]
- **Source IP**: \`${inc.source_ip}\`
- **Target Assets**: ${inc.target_ips ? inc.target_ips.join(', ') : '172.16.0.1'}
- **Target Ports**: ${inc.target_ports ? JSON.stringify(inc.target_ports) : '[80, 443]'}
- **Evidence**: ${inc.evidence_chain || 'Traffic concentration detected.'}
`).join('\n')}

---
## Recommended Human-Gated Containment Playbooks
> In compliance with CyberSentinel Safe Operations Policy, zero automated blocking is enforced. All actions require SOC analyst authorization.
${playbooks.map((p, i) => `${i + 1}. **[${p.priority}] ${p.action_type}** on \`${p.target}\`: ${p.description} (Requires Approval: \`${p.requires_approval}\`)`).join('\n')}
`;

  const handleCopy = () => {
    navigator.clipboard.writeText(markdownText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(analysisData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `investigation_${reportId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Header with Export Controls */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase tracking-widest text-[#ff6b5b] font-mono font-semibold">
              Executive SOC Dossier
            </span>
            <span className="text-xs px-2 py-0.5 rounded bg-[#ff6b5b] text-[#14213d] font-bold">
              {severity}
            </span>
          </div>
          <h2 className="text-xl font-black text-[#f4eded] mt-1">Investigation Report: {reportId}</h2>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Audit-ready security report formatted for SIEM/SOAR integration.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#14213d] border border-[#f4eded]/30 text-[#f4eded] hover:bg-[#f4eded]/10 transition-colors flex items-center gap-1.5 shadow"
          >
            <Copy className="w-3.5 h-3.5 text-[#ff6b5b]" />
            <span>{copied ? 'Copied!' : 'Copy Markdown'}</span>
          </button>
          <button
            onClick={handleDownloadJson}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#ff6b5b] text-[#14213d] hover:bg-[#ff5340] transition-colors flex items-center gap-1.5 shadow"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download JSON</span>
          </button>
        </div>
      </div>

      {/* Report Body Preview */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-6 shadow space-y-6">
        {/* Executive Summary Section */}
        <div>
          <h3 className="text-sm font-bold text-[#ff6b5b] uppercase tracking-wider mb-2">1. Executive Summary</h3>
          <p className="text-xs text-[#f4eded]/80 leading-relaxed bg-[#14213d] border border-[#f4eded]/10 p-4 rounded-lg font-sans">
            {analysisData?.executive_summary ||
              'CyberSentinel Multi-Agent Threat Assessment: Evaluated 50 network flow telemetry records. Identified suspicious flow events organized into campaign incidents. Generated non-disruptive containment playbooks awaiting analyst sign-off.'}
          </p>
        </div>

        {/* Model Consensus Audit */}
        <div>
          <h3 className="text-sm font-bold text-[#ff6b5b] uppercase tracking-wider mb-2">2. Model Consensus Audit</h3>
          <div className="bg-[#14213d] border border-[#f4eded]/10 p-4 rounded-lg text-xs font-mono text-[#f4eded]/80 space-y-1">
            <div>Total Evaluated Flows: {analysisData?.total_flows_evaluated ?? 50}</div>
            <div>Classified Attacks: {analysisData?.malicious_flows_count ?? 5}</div>
            <div>Reconstruction Anomalies: {analysisData?.anomalous_flows_count ?? 50}</div>
            <div className="text-[#ff6b5b] pt-1">
              Resolution: {analysisData?.conflict_resolution || 'Consensus Audit Verified.'}
            </div>
          </div>
        </div>

        {/* Incident Summary */}
        <div>
          <h3 className="text-sm font-bold text-[#ff6b5b] uppercase tracking-wider mb-2">
            3. Correlated Threat Incidents ({incidents.length})
          </h3>
          <div className="space-y-3">
            {incidents.slice(0, 4).map((inc, i) => (
              <div key={i} className="p-3 bg-[#14213d] border border-[#f4eded]/10 rounded-lg text-xs space-y-1">
                <div className="flex items-center justify-between font-bold text-[#f4eded]">
                  <span className="text-[#ff6b5b]">{inc.pattern_type}</span>
                  <span className="font-mono text-[11px] text-[#f4eded]/60">Source: {inc.source_ip}</span>
                </div>
                <p className="text-[11px] text-[#f4eded]/70">{inc.evidence_chain}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Raw Markdown Source Code Box */}
        <div>
          <h3 className="text-sm font-bold text-[#ff6b5b] uppercase tracking-wider mb-2">4. Raw Markdown Export</h3>
          <pre className="p-4 bg-[#0b1222] border border-[#f4eded]/10 rounded-lg text-[11px] font-mono text-[#f4eded]/80 overflow-x-auto max-h-60">
            {markdownText}
          </pre>
        </div>
      </div>
    </div>
  );
}
