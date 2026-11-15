"""
Agent 3: Anomaly Detection Agent for CyberSentinel.
Loads trained Deep Autoencoder, computes per-flow reconstruction errors,
and detects anomalous intrusions deviating from normal benign manifold.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import logging
import numpy as np

from config.settings import settings
from src.agents.base import BaseAgent
from src.agents.protocols import AgentRole, AgentStatus, AgentMessage, FlowAnomaly
from src.models.autoencoder_model import CyberSentinelAutoencoder

logger = logging.getLogger(__name__)


class AnomalyDetectionAgent(BaseAgent):
    """
    Unsupervised zero-day and anomaly detection agent using deep autoencoder reconstruction error.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
        agent_id: Optional[str] = None,
    ):
        super().__init__(role=AgentRole.ANOMALY_DETECTOR, agent_id=agent_id)
        self.model_path = model_path or (settings.ROOT_DIR / "models" / "autoencoder" / "autoencoder_best.pt")
        self.metadata_path = metadata_path or (settings.ROOT_DIR / "models" / "autoencoder" / "autoencoder_metadata.json")
        
        self.model: Optional[CyberSentinelAutoencoder] = None
        self.threshold: float = 0.185111
        self._load_model()

    def _load_model(self):
        """Load trained Autoencoder weights and calibrated threshold."""
        candidate_model_paths = [
            self.model_path,
            settings.ROOT_DIR / "models" / "checkpoints" / "autoencoder_best.pt",
        ]
        candidate_meta_paths = [
            self.metadata_path,
            settings.ROOT_DIR / "models" / "checkpoints" / "autoencoder_metadata.json",
        ]

        loaded = False
        for m_p in candidate_model_paths:
            for meta_p in candidate_meta_paths:
                if m_p.exists() and meta_p.exists():
                    try:
                        self.model = CyberSentinelAutoencoder.load(m_p, meta_p, device="cpu")
                        self.threshold = float(self.model.threshold_)
                        logger.info(f"[{self.role.value}] Successfully loaded Autoencoder from {m_p} (Threshold: {self.threshold:.6f})")
                        loaded = True
                        break
                    except Exception as e:
                        logger.warning(f"[{self.role.value}] Failed loading: {e}")
            if loaded:
                break

        if not loaded:
            logger.error(f"[{self.role.value}] Autoencoder model checkpoint could not be found.")

    def process(self, message: AgentMessage) -> AgentMessage:
        """
        Compute reconstruction errors for flow vectors and flag deviations exceeding threshold.
        """
        payload = message.payload
        raw_features = payload.get("feature_matrix")

        if raw_features is None or len(raw_features) == 0:
            raise ValueError("Payload missing 'feature_matrix' or empty batch.")

        X = np.array(raw_features, dtype=np.float32)

        if self.model is None or not self.model.is_fitted_:
            raise RuntimeError(f"[{self.role.value}] Autoencoder model is not loaded or fitted.")

        # 1. Compute reconstruction errors
        errors = self.model.calculate_reconstruction_errors(X)

        # 2. Flag anomalies using calibrated validation threshold
        anomalies: List[Dict[str, Any]] = []
        anomaly_count = 0

        for idx in range(len(X)):
            recon_err = float(errors[idx])
            is_anom = bool(recon_err >= self.threshold)
            deviation = float(recon_err / self.threshold) if self.threshold > 0 else 1.0

            if is_anom:
                anomaly_count += 1

            anom_obj = FlowAnomaly(
                flow_index=idx,
                is_anomaly=is_anom,
                reconstruction_error=round(recon_err, 6),
                threshold=round(self.threshold, 6),
                deviation_ratio=round(deviation, 3),
            )
            anomalies.append(anom_obj.model_dump(mode="json"))

        logger.info(f"[{self.role.value}] Evaluated {len(X)} flows: {anomaly_count} flagged as ANOMALOUS (Error >= {self.threshold:.4f}).")

        output_payload = {
            "total_flows": len(X),
            "anomaly_count": anomaly_count,
            "normal_count": len(X) - anomaly_count,
            "threshold_used": round(self.threshold, 6),
            "anomalies": anomalies,
        }

        return self.create_message(
            task_id=message.task_id,
            recipient=AgentRole.COORDINATOR,
            payload=output_payload,
            status=AgentStatus.SUCCESS,
        )
