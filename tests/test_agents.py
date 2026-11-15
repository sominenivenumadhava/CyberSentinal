"""
Automated Unit and Integration Tests for CyberSentinel Multi-Agent Swarm.
Tests all five specialized agents independently, verifies consensus and conflict logic,
and validates the complete Central Coordinator orchestration workflow.
"""
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from src.agents.protocols import (
    AgentRole,
    AgentStatus,
    AgentMessage,
    SeverityLevel,
    ConflictStatus,
    SuspiciousFinding,
    FlowMetadata,
    FlowClassification,
    FlowAnomaly,
)
from src.agents.data_agent import DataProcessingAgent
from src.agents.classification_agent import AttackClassificationAgent
from src.agents.anomaly_agent import AnomalyDetectionAgent
from src.agents.investigation_agent import ThreatInvestigationAgent
from src.agents.risk_engine import RiskScoringEngine
from src.agents.risk_agent import RiskAssessmentAgent
from src.agents.coordinator import CentralCoordinator
from src.core.database import SessionLocal
from src.core.models import Alert, Investigation, AgentAuditLog


@pytest.fixture
def mock_flow_records():
    """Create sample raw flow telemetry records matching CICIDS2017 schema."""
    records = []
    # 5 Port scan flows from single IP
    for i in range(5):
        records.append({
            " Flow ID": f"192.168.1.100-10.0.0.5-{1000+i}-80-TCP",
            " Source IP": "192.168.1.100",
            " Destination IP": "10.0.0.5",
            " Source Port": 1000 + i,
            " Destination Port": 80 + i,
            " Timestamp": f"07/07/2017 08:30:0{i}",
            " Flow Duration": 25000 + i * 100,
            " Total Fwd Packets": 10 + i,
            " Total Backward Packets": 8,
            "Total Length of Fwd Packets": 1200.0,
            " Total Length of Bwd Packets": 2400.0,
            "Fwd Packet Length Max": 500.0,
            " Fwd Packet Length Min": 40.0,
            " Fwd Packet Length Mean": 120.0,
            " Fwd Packet Length Std": 50.0,
            "Bwd Packet Length Max": 600.0,
            " Bwd Packet Length Min": 40.0,
            " Bwd Packet Length Mean": 300.0,
            " Bwd Packet Length Std": 80.0,
            "Flow Bytes/s": 4500.0,
            " Flow Packets/s": 150.0,
            " Flow IAT Mean": 200.0,
            " Flow IAT Std": 50.0,
            " Flow IAT Max": 500.0,
            " Flow IAT Min": 10.0,
            "Fwd IAT Total": 20000.0,
            " Fwd IAT Mean": 200.0,
            " Fwd IAT Std": 50.0,
            " Fwd IAT Max": 500.0,
            " Fwd IAT Min": 10.0,
            "Bwd IAT Total": 18000.0,
            " Bwd IAT Mean": 200.0,
            " Bwd IAT Std": 50.0,
            " Bwd IAT Max": 500.0,
            " Bwd IAT Min": 10.0,
            "Fwd PSH Flags": 1,
            " Bwd PSH Flags": 0,
            " Fwd URG Flags": 0,
            " Bwd URG Flags": 0,
            " Fwd Header Length": 32,
            " Bwd Header Length": 32,
            "Fwd Packets/s": 80.0,
            " Bwd Packets/s": 70.0,
            " Min Packet Length": 40.0,
            " Max Packet Length": 600.0,
            " Packet Length Mean": 200.0,
            " Packet Length Std": 80.0,
            " Packet Length Variance": 6400.0,
            "FIN Flag Count": 0,
            " SYN Flag Count": 1,
            " RST Flag Count": 0,
            " PSH Flag Count": 1,
            " ACK Flag Count": 1,
            " URG Flag Count": 0,
            " CWE Flag Count": 0,
            " ECE Flag Count": 0,
            " Down/Up Ratio": 1,
            " Average Packet Size": 210.0,
            " Avg Fwd Segment Size": 120.0,
            " Avg Bwd Segment Size": 300.0,
            " Fwd Header Length.1": 32,
            "Fwd Avg Bytes/Bulk": 0,
            " Fwd Avg Packets/Bulk": 0,
            " Fwd Avg Bulk Rate": 0,
            " Bwd Avg Bytes/Bulk": 0,
            " Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": 10 + i,
            " Subflow Fwd Bytes": 1200.0,
            " Subflow Bwd Packets": 8,
            " Subflow Bwd Bytes": 2400.0,
            "Init_Win_bytes_forward": 29200,
            " Init_Win_bytes_backward": 8192,
            " act_data_pkt_fwd": 8,
            " min_seg_size_forward": 32,
            "Active Mean": 1000.0,
            " Active Std": 200.0,
            " Active Max": 1500.0,
            " Active Min": 50.0,
            "Idle Mean": 8000.0,
            " Idle Std": 500.0,
            " Idle Max": 12000.0,
            " Idle Min": 100.0,
        })
    return records


# =========================================================================
# 1. Independent Agent Tests
# =========================================================================

def test_data_processing_agent_independent(mock_flow_records):
    """Test Agent 1: validation, schema compliance, and identifier isolation."""
    agent = DataProcessingAgent()
    msg = AgentMessage(
        task_id="TEST-001",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.DATA_PROCESSOR,
        payload={"data": mock_flow_records},
    )

    response = agent.execute(msg)

    assert response.status == AgentStatus.SUCCESS
    assert response.sender == AgentRole.DATA_PROCESSOR
    payload = response.payload
    assert "feature_matrix" in payload
    assert len(payload["feature_matrix"]) == 5
    assert len(payload["metadata"]) == 5
    assert payload["metadata"][0]["source_ip"] == "192.168.1.100"
    assert payload["metadata"][0]["destination_port"] == 80


def test_classification_agent_independent():
    """Test Agent 2: TabNet inference, confidence, and attention importances."""
    agent = AttackClassificationAgent()
    dummy_features = np.random.randn(4, 65).astype(np.float32).tolist()
    dummy_names = [f"feat_{i}" for i in range(65)]

    msg = AgentMessage(
        task_id="TEST-002",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.ATTACK_CLASSIFIER,
        payload={"feature_matrix": dummy_features, "feature_names": dummy_names},
    )

    response = agent.execute(msg)

    assert response.status == AgentStatus.SUCCESS
    payload = response.payload
    assert payload["total_flows"] == 4
    assert len(payload["classifications"]) == 4
    for item in payload["classifications"]:
        assert item["predicted_label"] in (0, 1)
        assert 0.0 <= item["confidence"] <= 1.0
        assert round(item["probability_benign"] + item["probability_attack"], 2) == 1.0


def test_anomaly_detection_agent_independent():
    """Test Agent 3: Autoencoder reconstruction error and anomaly flagging."""
    agent = AnomalyDetectionAgent()
    dummy_features = np.random.randn(4, 65).astype(np.float32).tolist()

    msg = AgentMessage(
        task_id="TEST-003",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.ANOMALY_DETECTOR,
        payload={"feature_matrix": dummy_features},
    )

    response = agent.execute(msg)

    assert response.status == AgentStatus.SUCCESS
    payload = response.payload
    assert payload["total_flows"] == 4
    assert len(payload["anomalies"]) == 4
    for item in payload["anomalies"]:
        assert isinstance(item["is_anomaly"], bool)
        assert item["reconstruction_error"] >= 0.0
        assert item["threshold"] > 0.0


def test_threat_investigation_agent_independent():
    """Test Agent 4: temporal and topological correlation and incident clustering."""
    agent = ThreatInvestigationAgent()

    metadata = [
        {"flow_id": "F1", "source_ip": "10.0.0.99", "destination_ip": "192.168.1.1", "source_port": 1001, "destination_port": 80, "timestamp": "07/07/2017 08:30:00"},
        {"flow_id": "F2", "source_ip": "10.0.0.99", "destination_ip": "192.168.1.1", "source_port": 1002, "destination_port": 443, "timestamp": "07/07/2017 08:30:01"},
        {"flow_id": "F3", "source_ip": "10.0.0.99", "destination_ip": "192.168.1.1", "source_port": 1003, "destination_port": 8080, "timestamp": "07/07/2017 08:30:02"},
    ]
    classifications = [
        {"flow_index": 0, "predicted_label": 1, "confidence": 0.8, "probability_benign": 0.1, "probability_attack": 0.9, "top_attention_features": []},
        {"flow_index": 1, "predicted_label": 1, "confidence": 0.85, "probability_benign": 0.05, "probability_attack": 0.95, "top_attention_features": []},
        {"flow_index": 2, "predicted_label": 0, "confidence": 0.4, "probability_benign": 0.7, "probability_attack": 0.3, "top_attention_features": []},
    ]
    anomalies = [
        {"flow_index": 0, "is_anomaly": True, "reconstruction_error": 0.45, "threshold": 0.18, "deviation_ratio": 2.5},
        {"flow_index": 1, "is_anomaly": True, "reconstruction_error": 0.50, "threshold": 0.18, "deviation_ratio": 2.7},
        {"flow_index": 2, "is_anomaly": True, "reconstruction_error": 0.60, "threshold": 0.18, "deviation_ratio": 3.3},  # Model conflict: TabNet says benign, AE says anomaly
    ]

    msg = AgentMessage(
        task_id="TEST-004",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.THREAT_INVESTIGATOR,
        payload={"metadata": metadata, "classifications": classifications, "anomalies": anomalies},
    )

    response = agent.execute(msg)

    assert response.status == AgentStatus.SUCCESS
    payload = response.payload
    assert payload["total_suspicious_flows"] == 3
    assert payload["total_incidents"] == 1
    incident = payload["incidents"][0]
    assert incident["source_ip"] == "10.0.0.99"
    assert incident["pattern_type"] == "PORT_SCAN_RECONNAISSANCE"
    # Verify conflict detection: flow 2 is ambiguous anomaly
    assert payload["findings"][2]["conflict"] == ConflictStatus.AMBIGUOUS_ANOMALY.value


def test_risk_assessment_agent_and_engine_independent():
    """Test Agent 5 & RiskScoringEngine: scoring, severity tiers, conflict handling, and playbooks."""
    engine = RiskScoringEngine()
    agent = RiskAssessmentAgent(risk_engine=engine)

    finding1 = SuspiciousFinding(
        flow_index=0,
        metadata=FlowMetadata(source_ip="1.2.3.4", destination_ip="10.0.0.1", destination_port=22),
        classification=FlowClassification(flow_index=0, predicted_label=1, confidence=0.9, probability_benign=0.05, probability_attack=0.95),
        anomaly=FlowAnomaly(flow_index=0, is_anomaly=True, reconstruction_error=0.4, threshold=0.18, deviation_ratio=2.2),
        conflict=ConflictStatus.CONCORDANT_ATTACK,
    )
    score1 = engine.score_single_finding(finding1)
    assert 70.0 <= score1 <= 100.0  # High/Critical concordant attack on port 22

    msg = AgentMessage(
        task_id="TEST-005",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.RISK_ASSESSOR,
        payload={
            "incidents": [{
                "incident_id": "INC-TEST",
                "pattern_type": "BRUTE_FORCE_AUTHENTICATION_ATTEMPT",
                "source_ip": "1.2.3.4",
                "target_ips": ["10.0.0.1"],
                "target_ports": [22],
                "flow_count": 1,
                "findings": [finding1.model_dump(mode="json")],
                "evidence_summary": "Test incident",
            }],
            "findings": [finding1.model_dump(mode="json")],
            "total_flows_evaluated": 10,
        },
    )

    response = agent.execute(msg)

    assert response.status == AgentStatus.SUCCESS
    payload = response.payload
    assert payload["overall_risk_score"] > 50.0
    assert payload["severity"] in (SeverityLevel.HIGH.value, SeverityLevel.CRITICAL.value)
    # Ensure playbooks require human approval (never auto-block)
    for action in payload["recommended_actions"]:
        assert action["requires_approval"] is True


# =========================================================================
# 2. Complete Central Coordinator Orchestration Test
# =========================================================================

def test_central_coordinator_complete_workflow(mock_flow_records, tmp_path):
    """
    Integration test: run full end-to-end multi-agent pipeline through Central Coordinator.
    Verifies concurrent model execution, database audit logs, alerts, and report export.
    """
    coordinator = CentralCoordinator()
    task_id = "INTEG-TASK-001"

    result = coordinator.run_investigation(
        telemetry_data=mock_flow_records,
        task_id=task_id,
        save_to_db=True,
        output_report_dir=tmp_path,
    )

    assert result["task_id"] == task_id
    assert "execution_trace" in result
    trace = result["execution_trace"]

    # Verify all 5 agents executed successfully
    for role in [
        AgentRole.DATA_PROCESSOR.value,
        AgentRole.ATTACK_CLASSIFIER.value,
        AgentRole.ANOMALY_DETECTOR.value,
        AgentRole.THREAT_INVESTIGATOR.value,
        AgentRole.RISK_ASSESSOR.value,
    ]:
        assert role in trace
        assert trace[role]["status"] in (AgentStatus.SUCCESS.value, AgentStatus.CONFLICT_DETECTED.value)

    # Verify risk report contents
    risk_rep = result["risk_report"]
    assert risk_rep["total_flows_evaluated"] == len(mock_flow_records)
    assert len(risk_rep["correlated_incidents"]) >= 1

    # Verify SQLite DB persistence
    db = SessionLocal()
    inv_case = db.query(Investigation).filter(Investigation.title == f"Incident Analysis {task_id}").first()
    assert inv_case is not None

    audit_logs = db.query(AgentAuditLog).filter(AgentAuditLog.target_id == task_id).all()
    assert len(audit_logs) >= 5
    db.close()

    # Verify exported JSON report
    report_file = tmp_path / f"investigation_{task_id}.json"
    assert report_file.exists()
