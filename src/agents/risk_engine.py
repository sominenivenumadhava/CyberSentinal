"""
Configurable Multi-Criteria Risk Scoring Engine for CyberSentinel.
Quantifies threat risk (0-100) by combining supervised classification probabilities,
unsupervised reconstruction error deviations, consensus agreement, and asset sensitivity.
"""
from typing import Dict, Any, List
import logging
from src.agents.protocols import (
    SeverityLevel,
    ConflictStatus,
    SuspiciousFinding,
    RecommendedAction,
)

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Configurable multi-factor risk quantification engine.
    """

    def __init__(
        self,
        weight_classification: float = 0.40,
        weight_anomaly: float = 0.35,
        weight_consensus: float = 0.15,
        weight_asset_sensitivity: float = 0.10,
    ):
        self.w_cls = weight_classification
        self.w_anom = weight_anomaly
        self.w_cons = weight_consensus
        self.w_asset = weight_asset_sensitivity

        # Sensitive administrative and infrastructure service ports
        self.sensitive_ports = {22, 21, 23, 3389, 445, 135, 139, 80, 443, 8080, 53}

    def score_single_finding(self, finding: SuspiciousFinding) -> float:
        """
        Calculate individual flow risk score between 0.0 and 100.0.
        """
        # 1. Classification Component (0.0 to 1.0)
        p_attack = finding.classification.probability_attack

        # 2. Anomaly Component (0.0 to 1.0)
        # Scaled by deviation from threshold: ratio >= 2.0 saturates to 1.0
        ratio = finding.anomaly.deviation_ratio
        anom_component = min(1.0, max(0.0, ratio / 2.0))

        # 3. Consensus Component
        # Concordant attack gets 1.0; ambiguous gets 0.5; concordant benign gets 0.0
        if finding.conflict == ConflictStatus.CONCORDANT_ATTACK:
            consensus_component = 1.0
        elif finding.conflict in (ConflictStatus.AMBIGUOUS_ANOMALY, ConflictStatus.AMBIGUOUS_SIGNATURE):
            consensus_component = 0.6  # High uncertainty warrants investigation
        else:
            consensus_component = 0.1

        # 4. Port / Asset Sensitivity Component
        target_port = finding.metadata.destination_port or 0
        asset_component = 1.0 if target_port in self.sensitive_ports else 0.3

        # Weighted combination
        raw_score = (
            self.w_cls * p_attack
            + self.w_anom * anom_component
            + self.w_cons * consensus_component
            + self.w_asset * asset_component
        )

        return round(float(raw_score * 100.0), 2)

    def calculate_incident_risk(self, findings: List[SuspiciousFinding]) -> float:
        """
        Calculate aggregated risk score for a multi-flow incident.
        Incorporates volume multipliers.
        """
        if not findings:
            return 0.0

        scores = [self.score_single_finding(f) for f in findings]
        mean_score = sum(scores) / len(scores)
        max_score = max(scores)

        # Volume multiplier (more suspicious flows increase confidence)
        volume_factor = min(1.25, 1.0 + (len(findings) / 50.0))

        # Blend peak severity with sustained pattern
        blended = (0.6 * max_score + 0.4 * mean_score) * volume_factor
        return round(min(100.0, max(0.0, blended)), 2)

    @staticmethod
    def map_score_to_severity(score: float) -> SeverityLevel:
        """Map 0-100 numerical risk score to categorical severity."""
        if score >= 75.0:
            return SeverityLevel.CRITICAL
        elif score >= 50.0:
            return SeverityLevel.HIGH
        elif score >= 25.0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def generate_recommended_actions(
        self,
        severity: SeverityLevel,
        pattern_type: str,
        source_ip: str,
        target_ips: List[str],
        has_ambiguity: bool,
    ) -> List[RecommendedAction]:
        """
        Generate human-auditable remediation playbooks without auto-blocking traffic.
        """
        actions = []

        # 1. Tier-specific investigation action
        if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            actions.append(
                RecommendedAction(
                    action_type="SOC_ANALYST_ESCALATION",
                    priority=severity,
                    target=source_ip,
                    description=f"Immediate escalation to Tier-2 SOC Analyst for source {source_ip} due to {severity.value} {pattern_type}.",
                    requires_approval=True,
                )
            )

        # 2. Ambiguity / Model conflict handling
        if has_ambiguity:
            actions.append(
                RecommendedAction(
                    action_type="MANUAL_PAYLOAD_INSPECTION",
                    priority=SeverityLevel.MEDIUM,
                    target=source_ip,
                    description=f"Model conflict detected (TabNet vs Autoencoder). Review full PCAP payload for potential zero-day or benign false positive.",
                    requires_approval=True,
                )
            )

        # 3. Defensive mitigation proposal
        if pattern_type in ("PORT_SCAN_RECONNAISSANCE", "VOLUMETRIC_DOS_BURST"):
            actions.append(
                RecommendedAction(
                    action_type="FIREWALL_RATE_LIMIT_PROPOSAL",
                    priority=severity,
                    target=source_ip,
                    description=f"Propose 60-minute rate-limiting rule on ingress gateway for {source_ip}. Awaiting security admin sign-off.",
                    requires_approval=True,
                )
            )
        elif pattern_type == "BRUTE_FORCE_AUTHENTICATION_ATTEMPT":
            actions.append(
                RecommendedAction(
                    action_type="AUTHENTICATION_DEFENSE_PROPOSAL",
                    priority=SeverityLevel.HIGH,
                    target=source_ip,
                    description=f"Propose enforcing exponential backoff and MFA challenge on targeted endpoints {target_ips[:3]}.",
                    requires_approval=True,
                )
            )
        else:
            actions.append(
                RecommendedAction(
                    action_type="HOST_MONITORING_PROPOSAL",
                    priority=SeverityLevel.LOW,
                    target=source_ip,
                    description=f"Enable enhanced NetFlow logging on telemetry tap for {source_ip}.",
                    requires_approval=True,
                )
            )

        return actions
