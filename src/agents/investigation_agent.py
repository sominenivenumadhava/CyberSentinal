"""
Agent 4: Threat Investigation Agent for CyberSentinel.
Correlates multi-model detections with isolated network telemetry identifiers,
reconstructs chronological attack timelines, groups coordinated campaigns,
and establishes tamper-evident forensic evidence chains.
"""
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime
import logging

from src.agents.base import BaseAgent
from src.agents.protocols import (
    AgentRole,
    AgentStatus,
    AgentMessage,
    FlowMetadata,
    FlowClassification,
    FlowAnomaly,
    SuspiciousFinding,
    InvestigationIncident,
    ConflictStatus,
)

logger = logging.getLogger(__name__)


class ThreatInvestigationAgent(BaseAgent):
    """
    Forensic correlation agent that reconnects behavioral model inferences with
    isolated network identifiers, building chronological incident timelines.
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(role=AgentRole.THREAT_INVESTIGATOR, agent_id=agent_id)

    @staticmethod
    def determine_conflict_state(pred_label: int, is_anomaly: bool) -> ConflictStatus:
        """Evaluate consensus between supervised classification and unsupervised anomaly detection."""
        if pred_label == 1 and is_anomaly:
            return ConflictStatus.CONCORDANT_ATTACK
        elif pred_label == 0 and not is_anomaly:
            return ConflictStatus.CONCORDANT_BENIGN
        elif pred_label == 0 and is_anomaly:
            return ConflictStatus.AMBIGUOUS_ANOMALY  # High reconstruction error despite benign label -> zero-day candidate
        else:
            return ConflictStatus.AMBIGUOUS_SIGNATURE  # TabNet flagged attack, but reconstruction is normal

    def process(self, message: AgentMessage) -> AgentMessage:
        """
        Correlate metadata, classification outputs, and anomaly detections.
        """
        payload = message.payload
        metadata_list = payload.get("metadata", [])
        classifications = payload.get("classifications", [])
        anomalies = payload.get("anomalies", [])

        if not (len(metadata_list) == len(classifications) == len(anomalies)):
            raise ValueError(
                f"Payload alignment error: metadata ({len(metadata_list)}), "
                f"classifications ({len(classifications)}), anomalies ({len(anomalies)})"
            )

        n_flows = len(metadata_list)
        all_findings: List[SuspiciousFinding] = []
        suspicious_by_ip = defaultdict(list)

        # 1. Correlate individual flow records
        for i in range(n_flows):
            m_dict = metadata_list[i]
            c_dict = classifications[i]
            a_dict = anomalies[i]

            m_obj = FlowMetadata(**m_dict)
            c_obj = FlowClassification(**c_dict)
            a_obj = FlowAnomaly(**a_dict)

            conflict = self.determine_conflict_state(c_obj.predicted_label, a_obj.is_anomaly)

            # Consider suspicious if either model flagged it or if there is an anomaly
            is_suspicious = (c_obj.predicted_label == 1) or a_obj.is_anomaly

            if is_suspicious:
                finding = SuspiciousFinding(
                    flow_index=i,
                    metadata=m_obj,
                    classification=c_obj,
                    anomaly=a_obj,
                    conflict=conflict,
                )
                all_findings.append(finding)
                suspicious_by_ip[m_obj.source_ip].append(finding)

        logger.info(f"[{self.role.value}] Identified {len(all_findings)} suspicious flows across {len(suspicious_by_ip)} distinct source IPs.")

        # 2. Correlate into Incidents by Source IP & Pattern
        incidents: List[InvestigationIncident] = []
        for src_ip, findings in suspicious_by_ip.items():
            target_ips = sorted(list({f.metadata.destination_ip for f in findings}))
            target_ports = sorted(list({f.metadata.destination_port for f in findings}))
            timestamps = [f.metadata.timestamp for f in findings if f.metadata.timestamp]

            # Detect pattern type
            if len(target_ports) >= 3:
                pattern = "PORT_SCAN_RECONNAISSANCE"
            elif any(p in (21, 22) for p in target_ports) and len(findings) >= 5:
                pattern = "BRUTE_FORCE_AUTHENTICATION_ATTEMPT"
            elif len(findings) >= 20:
                pattern = "VOLUMETRIC_DOS_BURST"
            elif any(f.conflict == ConflictStatus.AMBIGUOUS_ANOMALY for f in findings):
                pattern = "ZERO_DAY_ANOMALY_CLUSTER"
            else:
                pattern = "SUSPICIOUS_NETWORK_ACTIVITY"

            evidence_summary = (
                f"Source {src_ip} generated {len(findings)} suspicious flow events targeting {len(target_ips)} host(s) "
                f"on port(s) {target_ports[:5]}. Pattern identified: {pattern}. "
                f"Classification detections: {sum(1 for f in findings if f.classification.predicted_label == 1)}. "
                f"Reconstruction anomalies: {sum(1 for f in findings if f.anomaly.is_anomaly)}."
            )

            inc = InvestigationIncident(
                pattern_type=pattern,
                source_ip=src_ip,
                target_ips=target_ips,
                target_ports=target_ports,
                start_time=timestamps[0] if timestamps else None,
                end_time=timestamps[-1] if timestamps else None,
                flow_count=len(findings),
                findings=findings,
                evidence_summary=evidence_summary,
            )
            incidents.append(inc)

        output_payload = {
            "total_suspicious_flows": len(all_findings),
            "total_incidents": len(incidents),
            "incidents": [inc.model_dump(mode="json") for inc in incidents],
            "findings": [f.model_dump(mode="json") for f in all_findings],
        }

        return self.create_message(
            task_id=message.task_id,
            recipient=AgentRole.COORDINATOR,
            payload=output_payload,
            status=AgentStatus.SUCCESS,
        )
