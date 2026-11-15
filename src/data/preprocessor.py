"""
FlowPreprocessor: Production-Grade Preprocessing Pipeline for CyberSentinel.
Guarantees training and inference preprocessing consistency, sanitizes infinite/NaN values,
eliminates zero-variance artifacts, and strictly separates metadata/identifiers from model features.
"""
from typing import Tuple, List, Dict, Optional, Any
from pathlib import Path
import json
import logging
import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import RobustScaler

from src.data.schema import (
    IDENTIFIER_COLUMNS,
    DUPLICATE_COLUMNS_TO_DROP,
    clean_column_name,
    normalize_label,
    get_attack_category,
)

logger = logging.getLogger(__name__)


class FlowPreprocessor(BaseEstimator, TransformerMixin):
    """
    Robust Feature Preprocessor for Network Flow Telemetry.
    Learns statistical parameters (imputation medians, scaling quantiles, active feature list)
    from training data and applies them identically to validation, test, and live inference feeds.
    """

    def __init__(
        self,
        scaler_type: str = "robust",
        variance_threshold: float = 0.0,
        handle_inf: bool = True,
        clip_quantiles: Optional[Tuple[float, float]] = (0.001, 0.999),
    ):
        self.scaler_type = scaler_type
        self.variance_threshold = variance_threshold
        self.handle_inf = handle_inf
        self.clip_quantiles = clip_quantiles

        # State learned during fit
        self.feature_names_: List[str] = []
        self.imputer_values_: Dict[str, float] = {}
        self.clip_bounds_: Dict[str, Tuple[float, float]] = {}
        self.scaler_: Optional[Any] = None
        self.is_fitted_: bool = False

    @staticmethod
    def standardize_column_names(df: pd.DataFrame) -> pd.DataFrame:
        """Strip whitespace, lowercase, and sanitize column headers."""
        renamed = {col: clean_column_name(col) for col in df.columns}
        df = df.rename(columns=renamed)
        # Drop duplicates if present
        df = df.loc[:, ~df.columns.duplicated()]
        return df

    def separate_identifiers_and_labels(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame, Optional[pd.Series], Optional[pd.Series]]:
        """
        Separate raw DataFrame into:
        1. features_raw_df (network flow behavioral features)
        2. identifiers_meta_df (IPs, ports, timestamps, flow_ids preserved for audit/triage)
        3. y_binary (0 for BENIGN, 1 for Attack)
        4. y_category (BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack, Bot, etc.)
        """
        df = self.standardize_column_names(df)

        # Drop known duplicate or corrupt columns
        for dup in DUPLICATE_COLUMNS_TO_DROP:
            if dup in df.columns:
                df = df.drop(columns=[dup])

        # Identify label column
        label_col = None
        for col in df.columns:
            if col in ("label", "labels", "attack_type", "class"):
                label_col = col
                break

        y_binary = None
        y_category = None
        if label_col is not None:
            raw_labels = df[label_col].astype(str).apply(normalize_label)
            y_binary = (raw_labels != "BENIGN").astype(int)
            y_category = raw_labels.apply(get_attack_category)
            feature_cols = [c for c in df.columns if c != label_col]
        else:
            feature_cols = list(df.columns)

        # Separate identifier columns
        found_identifiers = [
            c for c in feature_cols if c in IDENTIFIER_COLUMNS or "timestamp" in c or "ip" in c
        ]
        meta_df = df[found_identifiers].copy() if found_identifiers else pd.DataFrame(index=df.index)

        # Retained flow features for ML
        model_feature_cols = [c for c in feature_cols if c not in found_identifiers]
        features_df = df[model_feature_cols].copy()

        return features_df, meta_df, y_binary, y_category

    def clean_inf_and_nan(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace inf, -inf with NaN and ensure all data is numeric float64."""
        df_clean = df.copy()
        for col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce")
            if self.handle_inf:
                df_clean[col] = df_clean[col].replace([np.inf, -np.inf], np.nan)
        return df_clean

    def fit(self, X: pd.DataFrame, y=None):
        """Fit statistical imputers, variance filters, and scalers on training data."""
        # Sanitize columns
        X_std = self.standardize_column_names(X)
        X_clean = self.clean_inf_and_nan(X_std)

        # 1. Feature selection: drop constant features (zero variance)
        selected_cols = []
        for col in X_clean.columns:
            valid_vals = X_clean[col].dropna()
            if len(valid_vals) > 0 and valid_vals.std() > self.variance_threshold:
                selected_cols.append(col)
            elif len(valid_vals) > 0 and valid_vals.std() == 0:
                logger.debug(f"Dropping constant feature with zero variance: {col}")

        self.feature_names_ = selected_cols
        X_selected = X_clean[selected_cols]

        # 2. Learn median imputation values and clipping bounds
        for col in selected_cols:
            col_series = X_selected[col].dropna()
            if len(col_series) > 0:
                med_val = float(col_series.median())
                self.imputer_values_[col] = med_val
                if self.clip_quantiles:
                    q_low, q_high = self.clip_quantiles
                    low_bound = float(col_series.quantile(q_low))
                    high_bound = float(col_series.quantile(q_high))
                    self.clip_bounds_[col] = (low_bound, high_bound)
            else:
                self.imputer_values_[col] = 0.0

        # Impute missing values for scaler fitting
        X_imputed = X_selected.copy()
        for col in selected_cols:
            X_imputed[col] = X_imputed[col].fillna(self.imputer_values_[col])
            if col in self.clip_bounds_:
                low_b, high_b = self.clip_bounds_[col]
                X_imputed[col] = X_imputed[col].clip(lower=low_b, upper=high_b)

        # 3. Fit Scaler
        if self.scaler_type == "robust":
            self.scaler_ = RobustScaler()
            self.scaler_.fit(X_imputed.values)
        else:
            self.scaler_ = None

        self.is_fitted_ = True
        logger.info(f"FlowPreprocessor fitted with {len(self.feature_names_)} active features.")
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Transform network flow data using learned statistics (consistent for train/test/inference)."""
        if not self.is_fitted_:
            raise RuntimeError("FlowPreprocessor must be fitted before calling transform().")

        X_std = self.standardize_column_names(X)
        X_clean = self.clean_inf_and_nan(X_std)

        # Align columns to learned features (fill missing with 0, drop unknown)
        X_aligned = pd.DataFrame(index=X_clean.index)
        for col in self.feature_names_:
            if col in X_clean.columns:
                X_aligned[col] = X_clean[col]
            else:
                X_aligned[col] = self.imputer_values_.get(col, 0.0)

        # Impute missing and clip extreme outliers
        for col in self.feature_names_:
            X_aligned[col] = X_aligned[col].fillna(self.imputer_values_.get(col, 0.0))
            if col in self.clip_bounds_:
                low_b, high_b = self.clip_bounds_[col]
                X_aligned[col] = X_aligned[col].clip(lower=low_b, upper=high_b)

        # Scale features
        if self.scaler_ is not None:
            scaled_vals = self.scaler_.transform(X_aligned.values)
            return pd.DataFrame(scaled_vals, columns=self.feature_names_, index=X.index)

        return X_aligned

    def save(self, file_path: Path, metadata_path: Optional[Path] = None):
        """Serialize preprocessor state and export schema JSON."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, file_path)

        if metadata_path is not None:
            metadata_path = Path(metadata_path)
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            schema_data = {
                "num_features": len(self.feature_names_),
                "features": self.feature_names_,
                "scaler_type": self.scaler_type,
                "clip_quantiles": self.clip_quantiles,
                "imputer_medians": self.imputer_values_,
            }
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(schema_data, f, indent=2)

    @classmethod
    def load(cls, file_path: Path) -> "FlowPreprocessor":
        """Deserialize trained preprocessor."""
        return joblib.load(file_path)

