"""
Agent 2: Attack Classification Agent for CyberSentinel.
Loads trained PyTorch TabNet classifier, performs supervised attack inference,
computes confidence intervals, and extracts sequential attention masks for explainability.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import logging
import numpy as np

from config.settings import settings
from src.agents.base import BaseAgent
from src.agents.protocols import AgentRole, AgentStatus, AgentMessage, FlowClassification
from src.models.tabnet_model import CyberSentinelTabNet

logger = logging.getLogger(__name__)


class AttackClassificationAgent(BaseAgent):
    """
    Supervised inference agent using PyTorch TabNet deep tabular architecture.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
        agent_id: Optional[str] = None,
    ):
        super().__init__(role=AgentRole.ATTACK_CLASSIFIER, agent_id=agent_id)
        self.model_path = model_path or (settings.ROOT_DIR / "models" / "tabnet" / "tabnet_classifier.zip")
        self.metadata_path = metadata_path or (settings.ROOT_DIR / "models" / "tabnet" / "tabnet_metadata.json")
        
        self.model: Optional[CyberSentinelTabNet] = None
        self.feature_names: List[str] = []
        self._load_model()

    def _load_model(self):
        """Load trained TabNet checkpoint and metadata."""
        # Try both .zip and .zip.zip if created by tabnet
        candidate_paths = [
            self.model_path,
            Path(str(self.model_path) + ".zip"),
            settings.ROOT_DIR / "models" / "checkpoints" / "tabnet_best.zip",
            settings.ROOT_DIR / "models" / "checkpoints" / "tabnet_best.zip.zip",
        ]
        loaded = False
        for p in candidate_paths:
            if p.exists():
                try:
                    self.model = CyberSentinelTabNet.load(p, device_name="cpu")
                    logger.info(f"[{self.role.value}] Successfully loaded TabNet model from {p}")
                    loaded = True
                    break
                except Exception as e:
                    logger.warning(f"[{self.role.value}] Failed loading from {p}: {e}")

        if not loaded:
            logger.error(f"[{self.role.value}] TabNet model checkpoint could not be found.")

        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    self.feature_names = meta.get("features", [])
            except Exception as e:
                logger.warning(f"[{self.role.value}] Could not read metadata: {e}")

    def process(self, message: AgentMessage) -> AgentMessage:
        """
        Classify input feature vectors as Benign (0) or Attack (1),
        extract attention importances, and calculate confidence metrics.
        """
        payload = message.payload
        raw_features = payload.get("feature_matrix")
        feature_names = payload.get("feature_names", self.feature_names)

        if raw_features is None or len(raw_features) == 0:
            raise ValueError("Payload missing 'feature_matrix' or empty batch.")

        X = np.array(raw_features, dtype=np.float32)

        if self.model is None or not self.model.is_fitted_:
            raise RuntimeError(f"[{self.role.value}] TabNet model is not loaded or fitted.")

        # 1. Supervised prediction & class probabilities
        probs = self.model.predict_proba(X)
        preds = np.argmax(probs, axis=1)

        # 2. Extract attention masks for local attribution
        top_features_per_flow: List[List[str]] = []
        try:
            explain_matrix, _ = self.model.explain(X)
            for i in range(len(X)):
                importances = explain_matrix[i]
                top_indices = np.argsort(importances)[::-1][:3]
                top_feats = [feature_names[idx] for idx in top_indices if idx < len(feature_names)]
                top_features_per_flow.append(top_feats)
        except Exception as e:
            logger.warning(f"[{self.role.value}] Attention explanation fallback: {e}")
            top_features_per_flow = [[] for _ in range(len(X))]

        # 3. Assemble structured classification results
        classifications: List[Dict[str, Any]] = []
        malicious_count = 0

        for idx in range(len(X)):
            p_benign = float(probs[idx, 0])
            p_attack = float(probs[idx, 1])
            pred_lbl = int(preds[idx])
            
            # Confidence defined as gap between highest and lowest probability
            confidence = float(abs(p_attack - p_benign))

            if pred_lbl == 1:
                malicious_count += 1

            cls_obj = FlowClassification(
                flow_index=idx,
                predicted_label=pred_lbl,
                confidence=round(confidence, 4),
                probability_benign=round(p_benign, 4),
                probability_attack=round(p_attack, 4),
                top_attention_features=top_features_per_flow[idx],
            )
            classifications.append(cls_obj.model_dump(mode="json"))

        logger.info(f"[{self.role.value}] Classified {len(X)} flows: {malicious_count} flagged as ATTACK.")

        output_payload = {
            "total_flows": len(X),
            "malicious_count": malicious_count,
            "benign_count": len(X) - malicious_count,
            "classifications": classifications,
        }

        return self.create_message(
            task_id=message.task_id,
            recipient=AgentRole.COORDINATOR,
            payload=output_payload,
            status=AgentStatus.SUCCESS,
        )
