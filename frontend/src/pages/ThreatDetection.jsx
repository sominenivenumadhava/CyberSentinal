import React, { useState } from 'react';
import { Search, Filter, ShieldAlert, AlertTriangle, Eye, ChevronDown, ChevronUp } from 'lucide-react';

export default function ThreatDetection({ analysisData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterConflict, setFilterConflict] = useState('ALL');
  const [expandedRow, setExpandedRow] = useState(null);

  const rawFindings = analysisData?.flows_sample || [];

  // Filter findings based on search and conflict filter
  const filteredFindings = rawFindings.filter((finding) => {
    const meta = finding.metadata || {};
    const conflict = finding.conflict || '';
    const srcIp = meta.source_ip || '';
    const dstIp = meta.destination_ip || '';
    const port = String(meta.destination_port || '');

    const matchesSearch =
      srcIp.includes(searchTerm) || dstIp.includes(searchTerm) || port.includes(searchTerm);
    const matchesFilter = filterConflict === 'ALL' || conflict === filterConflict;

    return matchesSearch && matchesFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-[#f4eded]">Flow Telemetry Detection Matrix</h2>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Per-sample predictions from TabNet supervised attention classifier and deep flow autoencoder reconstruction engine.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#f4eded]/50 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP or Port..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-[#14213d] border border-[#f4eded]/30 text-xs text-[#f4eded] placeholder-[#f4eded]/40 focus:border-[#ff6b5b] outline-none"
            />
          </div>

          {/* Filter */}
          <div className="flex items-center gap-1.5 text-xs text-[#f4eded]/70">
            <Filter className="w-3.5 h-3.5 text-[#ff6b5b]" />
            <select
              value={filterConflict}
              onChange={(e) => setFilterConflict(e.target.value)}
              className="py-1.5 px-2 rounded-lg bg-[#14213d] border border-[#f4eded]/30 text-xs text-[#f4eded] outline-none"
            >
              <option value="ALL">All Consensus Tiers</option>
              <option value="CONCORDANT_ATTACK">Concordant Attacks</option>
              <option value="AMBIGUOUS_ANOMALY">Ambiguous Anomaly (Zero-Day)</option>
              <option value="AMBIGUOUS_SIGNATURE">Ambiguous Signature</option>
              <option value="CONCORDANT_BENIGN">Concordant Benign</option>
            </select>
          </div>
        </div>
      </div>

      {/* Detections Table */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl shadow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#14213d] border-b border-[#f4eded]/15 text-[#f4eded]/70 font-semibold">
              <tr>
                <th className="py-3 px-4">Flow Index</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Target (IP:Port)</th>
                <th className="py-3 px-4">TabNet Decision</th>
                <th className="py-3 px-4">Autoencoder MSE</th>
                <th className="py-3 px-4">Consensus Status</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#f4eded]/10 font-mono text-[11px]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-[#f4eded]/60 font-sans text-xs">
                    No suspicious flows found matching search criteria.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding, idx) => {
                  const meta = finding.metadata || {};
                  const cls = finding.classification || {};
                  const anom = finding.anomaly || {};
                  const isExpanded = expandedRow === idx;
                  const isAttack = cls.predicted_label === 1;

                  return (
                    <React.Fragment key={idx}>
                      <tr className="hover:bg-[#f4eded]/5 transition-colors">
                        <td className="py-3 px-4 text-[#f4eded]/60">#{meta.flow_index ?? idx}</td>
                        <td className="py-3 px-4 text-[#f4eded] font-bold">{meta.source_ip || 'N/A'}</td>
                        <td className="py-3 px-4 text-[#f4eded]/80">
                          {meta.destination_ip}:{meta.destination_port}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              isAttack
                                ? 'bg-[#ff6b5b] text-[#14213d]'
                                : 'bg-[#f4eded]/10 text-[#f4eded]'
                            }`}
                          >
                            {isAttack ? 'ATTACK' : 'BENIGN'} ({(cls.confidence * 100).toFixed(1)}%)
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-[#ff6b5b] font-bold">
                            {(anom.reconstruction_error ?? 0).toFixed(4)}
                          </span>
                          <span className="text-[10px] text-[#f4eded]/60 ml-1">
                            ({(anom.anomaly_ratio ?? 0).toFixed(1)}x τ*)
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              finding.conflict === 'CONCORDANT_ATTACK'
                                ? 'bg-[#ff6b5b] text-[#14213d]'
                                : 'bg-[#ff6b5b]/15 text-[#ff6b5b] border border-[#ff6b5b]/30'
                            }`}
                          >
                            {finding.conflict || 'EVALUATED'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setExpandedRow(isExpanded ? null : idx)}
                            className="p-1 rounded hover:bg-[#f4eded]/10 text-[#f4eded]/80"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Feature Attribution Detail */}
                      {isExpanded && (
                        <tr className="bg-[#14213d]/90 font-sans">
                          <td colSpan="7" className="p-4 border-t border-[#f4eded]/10">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              <div>
                                <div className="font-bold text-[#ff6b5b] mb-1.5 flex items-center gap-1.5">
                                  <span>TabNet Top Attention Features</span>
                                </div>
                                <div className="space-y-1">
                                  {(cls.top_attention_features || [
                                    'Bwd Packet Length Std',
                                    'Destination Port',
                                    'Flow Duration',
                                    'Total Length of Fwd Packets'
                                  ]).map((feat, fIdx) => (
                                    <div
                                      key={fIdx}
                                      className="flex items-center justify-between bg-[#14213d] border border-[#f4eded]/15 px-2.5 py-1 rounded text-[11px]"
                                    >
                                      <span className="font-mono text-[#f4eded]">{feat}</span>
                                      <span className="text-[#ff6b5b] font-mono text-[10px]">Rank #{fIdx + 1}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              <div>
                                <div className="font-bold text-[#f4eded] mb-1.5">Reconstruction Diagnostics</div>
                                <div className="bg-[#14213d] border border-[#f4eded]/15 p-3 rounded-lg space-y-1.5 text-[11px] font-mono">
                                  <div className="flex justify-between">
                                    <span className="text-[#f4eded]/60">Reconstruction MSE:</span>
                                    <span className="text-[#ff6b5b] font-bold">
                                      {(anom.reconstruction_error ?? 0).toFixed(6)}
                                    </span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-[#f4eded]/60">Validation Threshold τ*:</span>
                                    <span className="text-[#f4eded]">0.185111</span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-[#f4eded]/60">Deviation Ratio:</span>
                                    <span className="text-[#ff6b5b] font-bold">
                                      {(anom.anomaly_ratio ?? 0).toFixed(2)}x
                                    </span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-[#f4eded]/60">Anomaly Decision:</span>
                                    <span className="text-[#ff6b5b] font-bold">
                                      {anom.is_anomaly ? 'TRUE (EXCEEDS τ*)' : 'FALSE'}
                                    </span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
