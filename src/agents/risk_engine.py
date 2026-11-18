"""
Configurable Multi-Criteria Risk Scoring Engine for CyberSentinel.
Quantifies threat risk (0-100) by combining supervised classification probabilities,
unsupervised reconstruction error deviations, consensus agreement, and asset sensitivity.
"""
from typing import Dict, Any, List, Optional
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
        threshold_critical: float = 75.0,
        threshold_high: float = 50.0,
        threshold_medium: float = 25.0,
    ):
        self.w_cls = weight_classification
        self.w_anom = weight_anomaly
        self.w_cons = weight_consensus
        self.w_asset = weight_asset_sensitivity

        # Configurable Severity Thresholds
        self.th_critical = threshold_critical
        self.th_high = threshold_high
        self.th_medium = threshold_medium

        # Sensitive administrative and infrastructure service ports
        self.sensitive_ports = {22, 21, 23, 3389, 445, 135, 139, 80, 443, 8080, 53}

    def update_configuration(
        self,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
    ):
        """Dynamically update risk scoring parameters and severity thresholds."""
        if weights:
            self.w_cls = weights.get("classification", self.w_cls)
            self.w_anom = weights.get("anomaly", self.w_anom)
            self.w_cons = weights.get("consensus", self.w_cons)
            self.w_asset = weights.get("asset", self.w_asset)
        if thresholds:
            self.th_critical = thresholds.get("critical", self.th_critical)
            self.th_high = thresholds.get("high", self.th_high)
            self.th_medium = thresholds.get("medium", self.th_medium)

    def get_scoring_method_documentation(self) -> str:
        """Return comprehensive mathematical documentation of the scoring method."""
        return (
            "CyberSentinel Multi-Criteria Risk Scoring Formulation:\n"
            "Risk Score = 100 * [ w_cls * P(Attack) + w_anom * min(1.0, MSE / (2 * tau*)) "
            "+ w_cons * C + w_asset * S_port ]\n\n"
            f"Active Parameters:\n"
            f"  - Supervised Weight (w_cls)      : {self.w_cls:.2f} (Discriminative TabNet probability)\n"
            f"  - Unsupervised Weight (w_anom)   : {self.w_anom:.2f} (Reconstruction error deviation ratio)\n"
            f"  - Consensus Weight (w_cons)      : {self.w_cons:.2f} (Model agreement coefficient)\n"
            f"  - Asset Sensitivity (w_asset)    : {self.w_asset:.2f} (Critical port multiplier)\n\n"
            f"Severity Tier Thresholds:\n"
            f"  - CRITICAL : Score >= {self.th_critical:.1f}\n"
            f"  - HIGH     : {self.th_high:.1f} <= Score < {self.th_critical:.1f}\n"
            f"  - MEDIUM   : {self.th_medium:.1f} <= Score < {self.th_high:.1f}\n"
            f"  - LOW      : Score < {self.th_medium:.1f}\n"
        )

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

    def map_score_to_severity(self, score: float) -> SeverityLevel:
        """Map 0-100 numerical risk score to categorical severity using configurable thresholds."""
        th_crit = getattr(self, "th_critical", 75.0)
        th_hi = getattr(self, "th_high", 50.0)
        th_med = getattr(self, "th_medium", 25.0)

        if score >= th_crit:
            return SeverityLevel.CRITICAL
        elif score >= th_hi:
            return SeverityLevel.HIGH
        elif score >= th_med:
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

