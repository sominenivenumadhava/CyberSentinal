"""
Central Coordinator for CyberSentinel Multi-Agent Swarm.
Orchestrates synchronous and concurrent agent workflows, validates inter-agent envelopes,
tracks execution metrics, and persists investigation records to SQLite database.
"""
from typing import Dict, Any, List, Optional
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
import json
import logging
import uuid

from config.settings import settings
from src.core.database import SessionLocal, init_db
from src.core.models import Alert, Investigation, AgentAuditLog
from src.agents.protocols import (
    AgentRole,
    AgentStatus,
    AgentMessage,
    RiskReport,
)
from src.agents.data_agent import DataProcessingAgent
from src.agents.classification_agent import AttackClassificationAgent
from src.agents.anomaly_agent import AnomalyDetectionAgent
from src.agents.investigation_agent import ThreatInvestigationAgent
from src.agents.risk_agent import RiskAssessmentAgent

logger = logging.getLogger(__name__)


class CentralCoordinator:
    """
    Central orchestration engine for the CyberSentinel multi-agent cybersecurity swarm.
    """

    def __init__(
        self,
        data_agent: Optional[DataProcessingAgent] = None,
        classification_agent: Optional[AttackClassificationAgent] = None,
        anomaly_agent: Optional[AnomalyDetectionAgent] = None,
        investigation_agent: Optional[ThreatInvestigationAgent] = None,
        risk_agent: Optional[RiskAssessmentAgent] = None,
    ):
        init_db()

        # Initialize or inject specialized agents
        self.data_agent = data_agent or DataProcessingAgent()
        self.classification_agent = classification_agent or AttackClassificationAgent()
        self.anomaly_agent = anomaly_agent or AnomalyDetectionAgent()
        self.investigation_agent = investigation_agent or ThreatInvestigationAgent()
        self.risk_agent = risk_agent or RiskAssessmentAgent()

        self.agents_map = {
            AgentRole.DATA_PROCESSOR: self.data_agent,
            AgentRole.ATTACK_CLASSIFIER: self.classification_agent,
            AgentRole.ANOMALY_DETECTOR: self.anomaly_agent,
            AgentRole.THREAT_INVESTIGATOR: self.investigation_agent,
            AgentRole.RISK_ASSESSOR: self.risk_agent,
        }

    def _log_audit_step(
        self,
        db,
        agent_role: AgentRole,
        action: str,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        reasoning: Optional[str] = None,
    ):
        """Record immutable agent step in SQLite audit log."""
        try:
            log_entry = AgentAuditLog(
                agent_name=agent_role.value,
                action_type=action,
                target_id=target_id,
                details=details,
                reasoning=reasoning,
            )
            db.add(log_entry)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"[CentralCoordinator] Failed recording audit log: {e}")

    def run_investigation(
        self,
        telemetry_data: Any,
        task_id: Optional[str] = None,
        save_to_db: bool = True,
        output_report_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Execute end-to-end multi-agent threat investigation pipeline:
        1. Agent 1: Data Processing (Validation, schema check, identifier isolation, transformation)
        2. Agent 2 & Agent 3: CONCURRENT Execution (Classification + Anomaly Detection)
        3. Agent 4: Threat Investigation (Correlation, timeline reconstruction, evidence preservation)
        4. Agent 5: Risk Assessment (Multi-factor scoring, conflict handling, response recommendations)
        5. SQLite Persistence & Report Export
        """
        task_id = task_id or f"TASK-{uuid.uuid4().hex[:8].upper()}"
        logger.info("=" * 70)
        logger.info(f"   CENTRAL COORDINATOR: INITIATING INVESTIGATION WORKFLOW [{task_id}]")
        logger.info("=" * 70)

        db = SessionLocal()
        execution_trace = {}

        try:
            # -------------------------------------------------------------
            # STEP 1: Ingest & Preprocess (Agent 1: Data Processing Agent)
            # -------------------------------------------------------------
            step1_msg = AgentMessage(
                task_id=task_id,
                sender=AgentRole.COORDINATOR,
                recipient=AgentRole.DATA_PROCESSOR,
                payload={"data": telemetry_data} if not isinstance(telemetry_data, dict) else telemetry_data,
            )
            step1_res = self.data_agent.execute(step1_msg)
            execution_trace[AgentRole.DATA_PROCESSOR.value] = {
                "status": step1_res.status.value,
                "latency_ms": self.data_agent.last_execution_time_ms,
                "error": step1_res.error,
            }
            self._log_audit_step(
                db, AgentRole.DATA_PROCESSOR, "DATA_VALIDATION_AND_PREPROCESSING",
                target_id=task_id, details=step1_res.payload.get("validation_report"),
                reasoning="Validated raw flow schema, isolated identifiers into metadata store, and transformed features."
            )

            if step1_res.status == AgentStatus.FAILED:
                raise RuntimeError(f"Data Processing Agent failed: {step1_res.error}")

            feature_matrix = step1_res.payload["feature_matrix"]
            metadata_list = step1_res.payload["metadata"]
            feature_names = step1_res.payload["feature_names"]
            total_records = step1_res.payload["total_records"]

            # -------------------------------------------------------------
            # STEP 2: CONCURRENT DETECTION (Agent 2: TabNet & Agent 3: Autoencoder)
            # -------------------------------------------------------------
            logger.info("[CentralCoordinator] Launching concurrent model inference for Agent 2 and Agent 3...")

            cls_input = AgentMessage(
                task_id=task_id,
                sender=AgentRole.COORDINATOR,
                recipient=AgentRole.ATTACK_CLASSIFIER,
                payload={"feature_matrix": feature_matrix, "feature_names": feature_names},
            )
            anom_input = AgentMessage(
                task_id=task_id,
                sender=AgentRole.COORDINATOR,
                recipient=AgentRole.ANOMALY_DETECTOR,
                payload={"feature_matrix": feature_matrix},
            )

            # Execute concurrently via ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_cls = executor.submit(self.classification_agent.execute, cls_input)
                future_anom = executor.submit(self.anomaly_agent.execute, anom_input)

                cls_res = future_cls.result()
                anom_res = future_anom.result()

            execution_trace[AgentRole.ATTACK_CLASSIFIER.value] = {
                "status": cls_res.status.value,
                "latency_ms": self.classification_agent.last_execution_time_ms,
                "error": cls_res.error,
            }
            execution_trace[AgentRole.ANOMALY_DETECTOR.value] = {
                "status": anom_res.status.value,
                "latency_ms": self.anomaly_agent.last_execution_time_ms,
                "error": anom_res.error,
            }

            self._log_audit_step(
                db, AgentRole.ATTACK_CLASSIFIER, "TABNET_ATTACK_CLASSIFICATION",
                target_id=task_id, details={"malicious_count": cls_res.payload.get("malicious_count")},
                reasoning="Executed supervised deep tabular attention inference with class balancing."
            )
            self._log_audit_step(
                db, AgentRole.ANOMALY_DETECTOR, "AUTOENCODER_ANOMALY_DETECTION",
                target_id=task_id, details={"anomaly_count": anom_res.payload.get("anomaly_count")},
                reasoning="Computed per-flow reconstruction errors against validation-calibrated threshold."
            )

            if cls_res.status == AgentStatus.FAILED or anom_res.status == AgentStatus.FAILED:
                raise RuntimeError("Concurrent detection agents encountered an unrecoverable failure.")

            classifications = cls_res.payload["classifications"]
            anomalies = anom_res.payload["anomalies"]

            # -------------------------------------------------------------
            # STEP 3: Forensics & Timeline (Agent 4: Threat Investigation Agent)
            # -------------------------------------------------------------
            step4_msg = AgentMessage(
                task_id=task_id,
                sender=AgentRole.COORDINATOR,
                recipient=AgentRole.THREAT_INVESTIGATOR,
                payload={
                    "metadata": metadata_list,
                    "classifications": classifications,
                    "anomalies": anomalies,
                },
            )
            step4_res = self.investigation_agent.execute(step4_msg)
            execution_trace[AgentRole.THREAT_INVESTIGATOR.value] = {
                "status": step4_res.status.value,
                "latency_ms": self.investigation_agent.last_execution_time_ms,
                "error": step4_res.error,
            }
            self._log_audit_step(
                db, AgentRole.THREAT_INVESTIGATOR, "INCIDENT_CORRELATION_AND_TIMELINE",
                target_id=task_id, details={"incidents": step4_res.payload.get("total_incidents")},
                reasoning="Correlated detections with network metadata, reconstructed timelines, and preserved forensic evidence."
            )

            if step4_res.status == AgentStatus.FAILED:
                raise RuntimeError(f"Threat Investigation Agent failed: {step4_res.error}")

            incidents = step4_res.payload["incidents"]
            findings = step4_res.payload["findings"]

            # -------------------------------------------------------------
            # STEP 4: Risk Scoring & Playbooks (Agent 5: Risk Assessment Agent)
            # -------------------------------------------------------------
            step5_msg = AgentMessage(
                task_id=task_id,
                sender=AgentRole.COORDINATOR,
                recipient=AgentRole.RISK_ASSESSOR,
                payload={
                    "incidents": incidents,
                    "findings": findings,
                    "total_flows_evaluated": total_records,
                },
            )
            step5_res = self.risk_agent.execute(step5_msg)
            execution_trace[AgentRole.RISK_ASSESSOR.value] = {
                "status": step5_res.status.value,
                "latency_ms": self.risk_agent.last_execution_time_ms,
                "error": step5_res.error,
            }
            self._log_audit_step(
                db, AgentRole.RISK_ASSESSOR, "RISK_ASSESSMENT_AND_REPORTING",
                target_id=task_id, details={"score": step5_res.payload.get("overall_risk_score")},
                reasoning="Evaluated consensus, assigned composite risk scores, and generated human-in-the-loop response playbooks."
            )

            risk_report = step5_res.payload

            # -------------------------------------------------------------
            # STEP 5: Persistence to SQLite & JSON Export
            # -------------------------------------------------------------
            if save_to_db:
                # Save Investigation Case
                inv_case = Investigation(
                    title=f"Incident Analysis {task_id}",
                    severity=risk_report.get("severity", "MEDIUM"),
                    status="ACTIVE",
                    summary=risk_report.get("executive_summary"),
                    root_cause=f"Correlated {len(incidents)} distinct campaign patterns.",
                    recommended_mitigation=json.dumps(risk_report.get("recommended_actions", [])),
                )
                db.add(inv_case)
                db.commit()

                # Save individual alerts for suspicious findings
                for f in findings[:50]:  # Cap individual alert rows to top 50
                    meta = f.get("metadata", {})
                    cls_info = f.get("classification", {})
                    anom_info = f.get("anomaly", {})
                    alert_row = Alert(
                        source_ip=meta.get("source_ip"),
                        destination_ip=meta.get("destination_ip"),
                        source_port=meta.get("source_port"),
                        destination_port=meta.get("destination_port"),
                        protocol=meta.get("protocol"),
                        detection_label="ATTACK" if cls_info.get("predicted_label") == 1 else "ANOMALY",
                        is_attack=bool(cls_info.get("predicted_label") == 1),
                        confidence=float(cls_info.get("confidence", 0.0)),
                        model_name="TabNet+Autoencoder Ensemble",
                        top_features=cls_info.get("top_attention_features", []),
                        raw_flow_data={
                            "reconstruction_error": anom_info.get("reconstruction_error"),
                            "conflict_status": f.get("conflict"),
                        },
                        status="INVESTIGATING",
                    )
                    db.add(alert_row)
                db.commit()

            # Export Report File
            report_dir = output_report_dir or settings.REPORTS_DIR
            report_dir.mkdir(parents=True, exist_ok=True)
            report_file = report_dir / f"investigation_{task_id}.json"
            final_output = {
                "task_id": task_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_trace": execution_trace,
                "risk_report": risk_report,
            }
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(final_output, f, indent=2, default=str)

            logger.info(f"[CentralCoordinator] Workflow completed successfully! Report exported to: {report_file}")
            return final_output

        finally:
            db.close()
