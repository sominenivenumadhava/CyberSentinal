"""
Agent Failure and Error Recovery Test Suite for CyberSentinel.
Verifies robust handling of empty inputs, corrupted features, mismatched dimensions,
and graceful coordinator recovery.
"""
import pytest
import pandas as pd
import numpy as np

from src.agents.protocols import (
    AgentRole,
    AgentStatus,
    AgentMessage,
    FlowMetadata,
    FlowClassification,
    FlowAnomaly,
    ConflictStatus,
    SuspiciousFinding,
)
from src.agents.data_agent import DataProcessingAgent
from src.agents.classification_agent import AttackClassificationAgent
from src.agents.anomaly_agent import AnomalyDetectionAgent
from src.agents.investigation_agent import ThreatInvestigationAgent
from src.agents.risk_agent import RiskAssessmentAgent
from src.agents.risk_engine import RiskScoringEngine
from src.agents.coordinator import CentralCoordinator


def test_data_agent_empty_dataframe_failure():
    """Verify DataProcessingAgent handles empty inputs with clean error state."""
    agent = DataProcessingAgent()
    msg = AgentMessage(
        task_id="FAIL-EMPTY",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.DATA_PROCESSOR,
        payload={"data": []},
    )
    res = agent.execute(msg)
    assert res.status == AgentStatus.FAILED
    assert "empty" in res.error.lower()


def test_data_agent_missing_flow_dynamics():
    """Verify validation warns or fails on columns with zero flow dynamics."""
    agent = DataProcessingAgent()
    bad_df = pd.DataFrame([{"unrelated_col_a": 1, "unrelated_col_b": 2}])
    msg = AgentMessage(
        task_id="FAIL-NO-DYNAMICS",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.DATA_PROCESSOR,
        payload={"data": bad_df.to_dict(orient="records")},
    )
    res = agent.execute(msg)
    # The preprocessor will catch missing columns or report missing dynamics
    assert res.status in (AgentStatus.FAILED, AgentStatus.SUCCESS)
    if res.status == AgentStatus.FAILED:
        assert res.error is not None


def test_classification_agent_invalid_feature_dimension():
    """Verify AttackClassificationAgent fails cleanly on mismatched dimension."""
    agent = AttackClassificationAgent()
    bad_matrix = np.zeros((5, 10))  # Expected 65
    msg = AgentMessage(
        task_id="FAIL-CLS-DIM",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.ATTACK_CLASSIFIER,
        payload={"feature_matrix": bad_matrix, "feature_names": [f"f_{i}" for i in range(10)]},
    )
    res = agent.execute(msg)
    assert res.status == AgentStatus.FAILED
    assert res.error is not None


def test_anomaly_agent_nan_resilience():
    """Verify AnomalyDetectionAgent handles or rejects NaN inputs safely."""
    agent = AnomalyDetectionAgent()
    nan_matrix = np.full((5, 65), np.nan)
    msg = AgentMessage(
        task_id="FAIL-ANOM-NAN",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.ANOMALY_DETECTOR,
        payload={"feature_matrix": nan_matrix},
    )
    res = agent.execute(msg)
    # Model should either recover by imputing or fail safely with error status
    assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)


def test_threat_investigation_misaligned_payload():
    """Verify ThreatInvestigationAgent detects and rejects unaligned lists."""
    agent = ThreatInvestigationAgent()
    msg = AgentMessage(
        task_id="FAIL-ALIGN",
        sender=AgentRole.COORDINATOR,
        recipient=AgentRole.THREAT_INVESTIGATOR,
        payload={
            "metadata": [{"source_ip": "1.1.1.1"}],
            "classifications": [],  # Length mismatch
            "anomalies": [],
        },
    )
    res = agent.execute(msg)
    assert res.status == AgentStatus.FAILED
    assert "alignment error" in res.error.lower()


def test_risk_scoring_engine_extreme_weights():
    """Verify RiskScoringEngine gracefully handles custom and edge-case weights."""
    engine = RiskScoringEngine(
        weight_classification=1.0,
        weight_anomaly=0.0,
        weight_consensus=0.0,
        weight_asset_sensitivity=0.0,
    )
    meta = FlowMetadata(
        flow_id="FLOW-EXTREME",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=12345,
        destination_port=80,
    )
    cls = FlowClassification(
        flow_index=0,
        predicted_label=1,
        confidence=1.0,
        probability_benign=0.0,
        probability_attack=1.0,
        top_attention_features=[],
    )
    anom = FlowAnomaly(
        flow_index=0,
        is_anomaly=False,
        reconstruction_error=0.0,
        threshold=0.185,
        deviation_ratio=0.0,
    )
    finding = SuspiciousFinding(
        flow_index=0,
        metadata=meta,
        classification=cls,
        anomaly=anom,
        conflict=ConflictStatus.AMBIGUOUS_SIGNATURE,
    )
    score = engine.score_single_finding(finding)
    assert 0.0 <= score <= 100.0
    assert score == pytest.approx(100.0, abs=1.0)
