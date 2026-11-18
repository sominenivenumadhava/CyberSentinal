"""
Pydantic Schemas and Communication Protocols for CyberSentinel Multi-Agent Swarm.
Enforces strict typing, JSON serialization, and message integrity across all agents.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
import uuid
from pydantic import BaseModel, Field


class AgentRole(str, Enum):
    DATA_PROCESSOR = "DataProcessingAgent"
    ATTACK_CLASSIFIER = "AttackClassificationAgent"
    ANOMALY_DETECTOR = "AnomalyDetectionAgent"
    THREAT_INVESTIGATOR = "ThreatInvestigationAgent"
    RISK_ASSESSOR = "RiskAssessmentAgent"
    COORDINATOR = "CentralCoordinator"


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    PROCESSING = "PROCESSING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CONFLICT_DETECTED = "CONFLICT_DETECTED"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConflictStatus(str, Enum):
    CONCORDANT_BENIGN = "CONCORDANT_BENIGN"
    CONCORDANT_ATTACK = "CONCORDANT_ATTACK"
    AMBIGUOUS_ANOMALY = "AMBIGUOUS_ANOMALY_MANUAL_REVIEW"       # AE anomaly, TabNet benign (potential zero-day)
    AMBIGUOUS_SIGNATURE = "AMBIGUOUS_SIGNATURE_MANUAL_REVIEW"   # TabNet attack, AE normal (possible low-volume signature)


class FlowMetadata(BaseModel):
    """Network flow identifiers preserved for audit and triage (NOT model features)."""
    flow_id: Optional[str] = None
    source_ip: Optional[str] = "0.0.0.0"
    destination_ip: Optional[str] = "0.0.0.0"
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 0
    timestamp: Optional[str] = None
    protocol: Optional[str] = "TCP"


class FlowClassification(BaseModel):
    """Output from Attack Classification Agent."""
    flow_index: int
    predicted_label: int  # 0 = Benign, 1 = Attack
    confidence: float
    probability_benign: float
    probability_attack: float
    top_attention_features: List[str] = Field(default_factory=list)


class FlowAnomaly(BaseModel):
    """Output from Anomaly Detection Agent."""
    flow_index: int
    is_anomaly: bool
    reconstruction_error: float
    threshold: float
    deviation_ratio: float  # reconstruction_error / threshold


class SuspiciousFinding(BaseModel):
    """Individual correlated finding linking metadata, classification, and anomaly."""
    flow_index: int
    metadata: FlowMetadata
    classification: FlowClassification
    anomaly: FlowAnomaly
    conflict: ConflictStatus
    shap_explanation: Optional[Dict[str, Any]] = None


class InvestigationIncident(BaseModel):
    """Correlated cluster of suspicious network events."""
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    pattern_type: str  # e.g., "PORT_SCAN", "DOS_BURST", "BRUTE_FORCE", "ANOMALY_CLUSTER"
    source_ip: str
    target_ips: List[str]
    target_ports: List[int]
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    flow_count: int
    findings: List[SuspiciousFinding]
    evidence_summary: str
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    uncertainty_score: float = 0.0
    analyst_review_priority: str = "STANDARD"


class RecommendedAction(BaseModel):
    """Safe, non-disruptive response recommendation."""
    action_type: str  # "ANALYST_ALERT", "TRAFFIC_INSPECTION", "RATE_LIMIT_PROPOSAL", "HOST_ISOLATION_PROPOSAL"
    priority: SeverityLevel
    target: str
    description: str
    requires_approval: bool = True  # Always requires human approval; no auto-blocking


class RiskReport(BaseModel):
    """Synthesized risk assessment and incident summary."""
    assessment_id: str = Field(default_factory=lambda: f"RISK-{uuid.uuid4().hex[:8].upper()}")
    overall_risk_score: float = Field(..., ge=0.0, le=100.0)
    severity: SeverityLevel
    conflict_resolution: str
    total_flows_evaluated: int
    malicious_flows_count: int
    anomalous_flows_count: int
    correlated_incidents: List[InvestigationIncident]
    recommended_actions: List[RecommendedAction]
    executive_summary: str
    shap_summary: Optional[Dict[str, Any]] = None
    scoring_method_documentation: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentMessage(BaseModel):
    """Standardized envelope for all inter-agent communication."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str
    sender: AgentRole
    recipient: AgentRole
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: AgentStatus = AgentStatus.SUCCESS
    payload: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
