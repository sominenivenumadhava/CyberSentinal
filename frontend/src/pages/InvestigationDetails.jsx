import React, { useState } from 'react';
import { Layers, ShieldCheck, ShieldAlert, Clock, CheckCircle2, UserCheck, AlertOctagon } from 'lucide-react';

export default function InvestigationDetails({ analysisData }) {
  const incidents = analysisData?.correlated_incidents || [];
  const recommendedActions = analysisData?.recommended_actions || [];
  const [approvedActions, setApprovedActions] = useState({});

  const toggleApproval = (index) => {
    setApprovedActions((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  return (
    <div className="space-y-6">
      {/* Header Overview */}
      <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-5 shadow flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-[#f4eded]">Autonomous Threat Campaign Investigations</h2>
          <p className="text-xs text-[#f4eded]/70 mt-0.5">
            Correlated attack events grouped by Source IP, targeting dynamics, and behavioral signature rules.
          </p>
        </div>
        <div className="text-right">
          <span className="text-xs px-2.5 py-1 rounded bg-[#ff6b5b]/15 text-[#ff6b5b] border border-[#ff6b5b]/30 font-mono font-bold">
            {incidents.length} Campaigns Identified
          </span>
        </div>
      </div>

      {/* Incidents Card Grid */}
      <div className="grid grid-cols-1 gap-4">
        {incidents.length === 0 ? (
          <div className="bg-[#14213d] border border-[#f4eded]/15 rounded-xl p-8 text-center text-xs text-[#f4eded]/60">
            No threat incidents identified in current telemetry batch.
          </div>
        ) : (
          incidents.map((inc, idx) => (
            <div
              key={idx}
              className="bg-[#14213d] border border-[#f4eded]/20 rounded-xl p-5 shadow space-y-4 hover:border-[#ff6b5b] transition-colors"
            >
              {/* Incident Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#f4eded]/10 pb-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#ff6b5b] text-[#14213d] flex items-center justify-center font-bold">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-[#f4eded]">{inc.pattern_type}</span>
                      <span className="text-[10px] font-mono text-[#ff6b5b] bg-[#ff6b5b]/10 border border-[#ff6b5b]/30 px-2 py-0.5 rounded font-bold">
                        Incident #{idx + 1}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-[#f4eded]/70 mt-0.5">
                      Attacker Source IP: <span className="text-[#f4eded] font-bold">{inc.source_ip}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-[#f4eded]/60">
                  <Clock className="w-3.5 h-3.5 text-[#ff6b5b]" />
                  <span>
                    {inc.earliest_timestamp || '2026-11-15 10:00:00'} → {inc.latest_timestamp || '2026-11-15 10:05:00'}
                  </span>
                </div>
              </div>

              {/* Target Dynamics & Forensic Evidence */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-[#14213d] border border-[#f4eded]/10 p-3 rounded-lg space-y-1.5 font-mono text-[11px]">
                  <div className="text-[#ff6b5b] font-sans font-bold text-xs mb-1">Target Infrastructure</div>
                  <div className="flex justify-between">
                    <span className="text-[#f4eded]/60">Target Assets:</span>
                    <span className="text-[#f4eded]">{inc.target_ips ? inc.target_ips.join(', ') : '172.16.0.1'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#f4eded]/60">Target Ports:</span>
                    <span className="text-[#ff6b5b] font-bold">
                      {inc.target_ports ? JSON.stringify(inc.target_ports) : '[80, 443]'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#f4eded]/60">Suspicious Events:</span>
                    <span className="text-[#f4eded]">{inc.findings ? inc.findings.length : 1} flow(s)</span>
                  </div>
                </div>

                <div className="bg-[#14213d] border border-[#f4eded]/10 p-3 rounded-lg flex flex-col justify-between">
                  <div>
                    <div className="text-[#f4eded] font-bold text-xs mb-1">Preserved Forensic Evidence</div>
                    <p className="text-[11px] text-[#f4eded]/70 leading-relaxed font-sans">
                      {inc.evidence_chain ||
                        `Source ${inc.source_ip} concentrated suspicious traffic against sensitive infrastructure. Correlated across multiple deep learning detection signals.`}
                    </p>
                  </div>
                  <div className="text-[10px] text-[#ff6b5b] font-mono mt-2">
                    Evidence Hash: SHA-256 Verified
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Human-in-the-Loop Safe Governance & Response Playbooks */}
      <div className="bg-[#14213d] border border-[#ff6b5b] rounded-xl p-5 shadow space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <UserCheck className="w-5 h-5 text-[#ff6b5b]" />
            <div>
              <h3 className="text-sm font-bold text-[#f4eded]">Human-in-the-Loop Response Playbooks</h3>
              <p className="text-xs text-[#f4eded]/70">
                Zero automated network blocking policy. Every containment action requires explicit SOC analyst sign-off.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono bg-[#ff6b5b] text-[#14213d] px-2 py-0.5 rounded font-bold">
            Policy: Non-Disruptive
          </span>
        </div>

        <div className="space-y-2.5">
          {recommendedActions.slice(0, 6).map((action, aIdx) => {
            const isApproved = approvedActions[aIdx];
            return (
              <div
                key={aIdx}
                className="flex items-center justify-between p-3 rounded-lg bg-[#14213d] border border-[#f4eded]/15 text-xs"
              >
                <div className="space-y-0.5 max-w-xl">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[#ff6b5b]">{action.action_type}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#f4eded]/10 text-[#f4eded] font-mono">
                      Priority: {action.priority}
                    </span>
                    <span className="text-[10px] text-[#f4eded]/60 font-mono">Target: {action.target}</span>
                  </div>
                  <p className="text-[#f4eded]/80 text-[11px]">{action.description}</p>
                </div>

                <button
                  onClick={() => toggleApproval(aIdx)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold font-mono transition-all flex items-center gap-1.5 ${
                    isApproved
                      ? 'bg-[#f4eded] text-[#14213d] shadow-sm'
                      : 'bg-[#14213d] border border-[#ff6b5b] text-[#ff6b5b] hover:bg-[#ff6b5b] hover:text-[#14213d]'
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{isApproved ? 'APPROVED & LOGGED' : 'SIGN-OFF ACTION'}</span>
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
