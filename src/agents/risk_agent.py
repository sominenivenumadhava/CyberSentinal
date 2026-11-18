"""
Agent 5: Risk Assessment and Reporting Agent for CyberSentinel.
Integrates supervised and unsupervised detection evidence, quantifies threat severity,
resolves model disagreements via manual-review statuses, and synthesizes executive reports.
"""
from typing import Dict, Any, List, Optional
import logging

from src.agents.base import BaseAgent
from src.agents.protocols import (
    AgentRole,
    AgentStatus,
    AgentMessage,
    SeverityLevel,
    ConflictStatus,
    SuspiciousFinding,
    InvestigationIncident,
    RecommendedAction,
    RiskReport,
)
from src.agents.risk_engine import RiskScoringEngine

logger = logging.getLogger(__name__)


class RiskAssessmentAgent(BaseAgent):
    """
    Synthesizes multi-model evidence into prioritized risk scores, human-in-the-loop playbooks,
    and comprehensive investigation summaries.
    """

    def __init__(
        self,
        risk_engine: Optional[RiskScoringEngine] = None,
        agent_id: Optional[str] = None,
    ):
        super().__init__(role=AgentRole.RISK_ASSESSOR, agent_id=agent_id)
        self.risk_engine = risk_engine or RiskScoringEngine()

    def process(self, message: AgentMessage) -> AgentMessage:
        """
        Evaluate correlated incidents, compute composite risk, and generate action recommendations.
        """
        payload = message.payload
        incidents_data = payload.get("incidents", [])
        findings_data = payload.get("findings", [])
        total_evaluated = payload.get("total_flows_evaluated", len(findings_data))

        # Convert dictionaries back to typed models
        findings = [SuspiciousFinding(**f) for f in findings_data]
        incidents = [InvestigationIncident(**inc) for inc in incidents_data]

        # 1. Analyze model consensus and conflict distribution
        conflict_counts = {
            ConflictStatus.CONCORDANT_ATTACK.value: 0,
            ConflictStatus.CONCORDANT_BENIGN.value: 0,
            ConflictStatus.AMBIGUOUS_ANOMALY.value: 0,
            ConflictStatus.AMBIGUOUS_SIGNATURE.value: 0,
        }
        for f in findings:
            conflict_counts[f.conflict.value] = conflict_counts.get(f.conflict.value, 0) + 1

        has_conflicts = (
            conflict_counts[ConflictStatus.AMBIGUOUS_ANOMALY.value] > 0
            or conflict_counts[ConflictStatus.AMBIGUOUS_SIGNATURE.value] > 0
        )

        conflict_summary = (
            f"Consensus Audit: Concordant Attacks={conflict_counts[ConflictStatus.CONCORDANT_ATTACK.value]}, "
            f"Ambiguous Anomalies (Possible Zero-Day)={conflict_counts[ConflictStatus.AMBIGUOUS_ANOMALY.value]}, "
            f"Ambiguous Signatures={conflict_counts[ConflictStatus.AMBIGUOUS_SIGNATURE.value]}."
        )

        # 2. Compute Incident-level and Overall Risk Scores
        incident_scores = []
        all_recommended_actions: List[RecommendedAction] = []

        for inc in incidents:
            inc_score = self.risk_engine.calculate_incident_risk(inc.findings)
            inc_sev = self.risk_engine.map_score_to_severity(inc_score)
            incident_scores.append(inc_score)

            # Generate playbooks for this incident
            inc_has_ambiguity = any(
                f.conflict in (ConflictStatus.AMBIGUOUS_ANOMALY, ConflictStatus.AMBIGUOUS_SIGNATURE)
                for f in inc.findings
            )
            actions = self.risk_engine.generate_recommended_actions(
                severity=inc_sev,
                pattern_type=inc.pattern_type,
                source_ip=inc.source_ip,
                target_ips=inc.target_ips,
                has_ambiguity=inc_has_ambiguity,
            )
            all_recommended_actions.extend(actions)

        # Overall risk score is weighted peak of incidents or findings
        if incident_scores:
            overall_score = round(min(100.0, max(incident_scores) * 0.7 + (sum(incident_scores) / len(incident_scores)) * 0.3), 2)
        elif findings:
            finding_scores = [self.risk_engine.score_single_finding(f) for f in findings]
            overall_score = round(max(finding_scores), 2)
        else:
            overall_score = 0.0

        overall_severity = self.risk_engine.map_score_to_severity(overall_score)

        # 3. Formulate Executive Summary
        exec_summary = (
            f"CyberSentinel Multi-Agent Threat Assessment: Evaluated {total_evaluated} network flow telemetry records. "
            f"Identified {len(findings)} suspicious flow events organized into {len(incidents)} distinct campaign incident(s). "
            f"Overall System Threat Posture: {overall_severity.value} (Risk Score: {overall_score}/100). "
            f"{conflict_summary} "
            f"Generated {len(all_recommended_actions)} proposed containment and verification playbooks awaiting analyst sign-off."
        )

        # 4. Construct Final Risk Report
        report = RiskReport(
            overall_risk_score=overall_score,
            severity=overall_severity,
            conflict_resolution=conflict_summary,
            total_flows_evaluated=total_evaluated,
            malicious_flows_count=sum(1 for f in findings if f.classification.predicted_label == 1),
            anomalous_flows_count=sum(1 for f in findings if f.anomaly.is_anomaly),
            correlated_incidents=incidents,
            recommended_actions=all_recommended_actions,
            executive_summary=exec_summary,
            scoring_method_documentation=self.risk_engine.get_scoring_method_documentation(),
        )

        logger.info(f"[{self.role.value}] Completed risk assessment: Severity={overall_severity.value}, Score={overall_score}")

        return self.create_message(
            task_id=message.task_id,
            recipient=AgentRole.COORDINATOR,
            payload=report.model_dump(mode="json"),
            status=AgentStatus.CONFLICT_DETECTED if has_conflicts else AgentStatus.SUCCESS,
        )
