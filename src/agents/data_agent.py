"""
Agent 1: Data Processing Agent for CyberSentinel.
Validates uploaded telemetry records, enforces feature schema constraints,
strips network topology identifiers for audit isolation, and applies saved preprocessor.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import logging
import numpy as np
import pandas as pd

from config.settings import settings
from src.agents.base import BaseAgent
from src.agents.protocols import AgentRole, AgentStatus, AgentMessage, FlowMetadata
from src.data.preprocessor import FlowPreprocessor
from src.data.schema import clean_column_name, IDENTIFIER_COLUMNS

logger = logging.getLogger(__name__)


class DataProcessingAgent(BaseAgent):
    """
    Validates and transforms raw incoming telemetry batches into sanitized invariant flow vectors.
    """

    def __init__(
        self,
        preprocessor_path: Optional[Path] = None,
        schema_path: Optional[Path] = None,
        agent_id: Optional[str] = None,
    ):
        super().__init__(role=AgentRole.DATA_PROCESSOR, agent_id=agent_id)
        self.preprocessor_path = preprocessor_path or (settings.DATA_METADATA_DIR / "preprocessor.joblib")
        self.schema_path = schema_path or (settings.DATA_METADATA_DIR / "feature_schema.json")
        
        self.preprocessor: Optional[FlowPreprocessor] = None
        self.expected_features: List[str] = []
        self._load_preprocessor_and_schema()

    def _load_preprocessor_and_schema(self):
        """Load fitted preprocessor and schema specification."""
        if self.preprocessor_path.exists():
            self.preprocessor = FlowPreprocessor.load(self.preprocessor_path)
            logger.info(f"[{self.role.value}] Loaded saved preprocessor from {self.preprocessor_path}")
        else:
            logger.warning(f"[{self.role.value}] Preprocessor file not found at {self.preprocessor_path}. Creating default.")
            self.preprocessor = FlowPreprocessor()

        if self.schema_path.exists():
            with open(self.schema_path, "r", encoding="utf-8") as f:
                schema_data = json.load(f)
                self.expected_features = schema_data.get("features", [])
            logger.info(f"[{self.role.value}] Loaded schema: {len(self.expected_features)} expected features.")

    def validate_flow_records(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Perform schema and data sanity verification."""
        if df.empty:
            raise ValueError("Input flow dataset is completely empty.")

        cleaned_cols = [clean_column_name(c) for c in df.columns]
        missing_critical = []
        
        # Check if flow duration or packet length columns exist
        has_flow_dynamics = any("flow" in c or "packet" in c for c in cleaned_cols)
        if not has_flow_dynamics:
            missing_critical.append("Network flow dynamics features (e.g. flow_duration, packet_lengths)")

        null_cells = int(df.isna().sum().sum())
        inf_cells = int(np.isinf(df.select_dtypes(include=[np.number])).sum().sum())

        return {
            "total_records": len(df),
            "input_columns": len(df.columns),
            "null_cells_detected": null_cells,
            "infinite_cells_detected": inf_cells,
            "has_flow_dynamics": has_flow_dynamics,
            "missing_critical": missing_critical,
        }

    def process(self, message: AgentMessage) -> AgentMessage:
        """
        Ingest raw flow records (JSON list, CSV path, or DataFrame dict)
        and produce sanitized feature vectors and isolated metadata.
        """
        payload = message.payload
        raw_data = payload.get("data")
        csv_path = payload.get("csv_path")

        # 1. Parse input into DataFrame
        if isinstance(raw_data, pd.DataFrame):
            df = raw_data.copy()
        elif isinstance(raw_data, list):
            df = pd.DataFrame(raw_data)
        elif isinstance(raw_data, dict):
            df = pd.DataFrame(raw_data)
        elif csv_path:
            df = pd.read_csv(csv_path)
        else:
            raise ValueError("Payload must contain 'data' (records/DataFrame) or 'csv_path'.")

        # 2. Validate input
        val_report = self.validate_flow_records(df)
        logger.info(f"[{self.role.value}] Validated {len(df)} records. Infs={val_report['infinite_cells_detected']}, NaNs={val_report['null_cells_detected']}")

        # 3. Standardize & separate identifiers and timestamps
        standardized_df = self.preprocessor.standardize_column_names(df)
        features_raw, meta_df, _, _ = self.preprocessor.separate_identifiers_and_labels(standardized_df)

        # 4. Extract structured metadata for audit/triage
        metadata_list: List[Dict[str, Any]] = []
        for idx in range(len(df)):
            row_meta = meta_df.iloc[idx] if not meta_df.empty else pd.Series()
            m = FlowMetadata(
                flow_id=str(row_meta.get("flow_id", f"FLOW-{idx}")),
                source_ip=str(row_meta.get("source_ip", row_meta.get("src_ip", "10.0.0.1"))),
                destination_ip=str(row_meta.get("destination_ip", row_meta.get("dst_ip", "192.168.1.1"))),
                source_port=int(row_meta.get("source_port", row_meta.get("src_port", 0))),
                destination_port=int(row_meta.get("destination_port", row_meta.get("dst_port", 80))),
                timestamp=str(row_meta.get("timestamp", "07/07/2017 08:30:00")),
                protocol=str(row_meta.get("protocol", "TCP")),
            )
            metadata_list.append(m.model_dump(mode="json"))

        # 5. Apply fitted preprocessing transformations (scaling & imputation)
        if self.preprocessor.is_fitted_:
            transformed_df = self.preprocessor.transform(features_raw)
        else:
            # Fallback fit
            self.preprocessor.fit(features_raw)
            transformed_df = self.preprocessor.transform(features_raw)

        feature_matrix = transformed_df.values.astype(np.float32)

        # 6. Verify feature dimension consistency
        if self.expected_features and transformed_df.shape[1] != len(self.expected_features):
            logger.warning(
                f"[{self.role.value}] Feature dimension mismatch: got {transformed_df.shape[1]}, expected {len(self.expected_features)}"
            )

        output_payload = {
            "feature_matrix": feature_matrix.tolist(),
            "metadata": metadata_list,
            "feature_names": list(transformed_df.columns),
            "num_features": transformed_df.shape[1],
            "total_records": len(df),
            "validation_report": val_report,
        }

        return self.create_message(
            task_id=message.task_id,
            recipient=AgentRole.COORDINATOR,
            payload=output_payload,
            status=AgentStatus.SUCCESS,
        )
