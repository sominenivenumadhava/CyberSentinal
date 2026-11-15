"""
Unit and integration tests for CyberSentinel FlowPreprocessor.
Verifies identifier isolation, inf/nan sanitization, zero-variance pruning,
and train/inference consistency.
"""
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from src.data.preprocessor import FlowPreprocessor
from src.data.schema import IDENTIFIER_COLUMNS


def test_standardize_column_names(sample_raw_flow_data):
    """Verify whitespace stripping and special character replacement."""
    df_clean = FlowPreprocessor.standardize_column_names(sample_raw_flow_data)
    
    assert "flow_duration" in df_clean.columns
    assert " Flow Duration" not in df_clean.columns
    assert "total_fwd_packets" in df_clean.columns
    assert "flow_bytes_s" in df_clean.columns
    assert "label" in df_clean.columns


def test_separate_identifiers_and_labels(sample_raw_flow_data):
    """
    CRITICAL TEST: Ensure IP addresses, ports, and timestamps are strictly
    separated into metadata and NEVER present in feature DataFrame X.
    """
    preprocessor = FlowPreprocessor()
    features_df, meta_df, y_binary, y_category = (
        preprocessor.separate_identifiers_and_labels(sample_raw_flow_data)
    )

    # 1. Feature DF must not contain any identifier or label columns
    for col in features_df.columns:
        assert col not in IDENTIFIER_COLUMNS, f"Leaked identifier column in features: {col}"
        assert "ip" not in col, f"Leaked IP column in features: {col}"
        assert "timestamp" not in col, f"Leaked timestamp in features: {col}"
        assert col != "label", "Leaked label column in features"

    # 2. Metadata DF should capture identifiers
    assert "source_ip" in meta_df.columns
    assert "destination_ip" in meta_df.columns
    assert "timestamp" in meta_df.columns

    # 3. Target labels check
    assert len(y_binary) == len(features_df)
    assert y_binary.isin([0, 1]).all()
    assert "DDoS" in y_category.values
    assert "BENIGN" in y_category.values


def test_handle_infinite_and_nan_values(sample_raw_flow_data):
    """Verify that inf and -inf values are sanitized and imputed."""
    preprocessor = FlowPreprocessor(handle_inf=True)
    features_df, _, _, _ = preprocessor.separate_identifiers_and_labels(sample_raw_flow_data)

    # Features should have inf initially
    clean_before_impute = preprocessor.clean_inf_and_nan(features_df)
    assert not np.isinf(clean_before_impute.values).any()

    # Fit and transform
    preprocessor.fit(features_df)
    transformed = preprocessor.transform(features_df)

    # After transform, there should be zero NaNs and zero Infs
    assert not transformed.isna().any().any()
    assert not np.isinf(transformed.values).any()


def test_zero_variance_feature_removal(sample_raw_flow_data):
    """Verify that constant features with zero variance are pruned."""
    preprocessor = FlowPreprocessor(variance_threshold=0.0)
    features_df, _, _, _ = preprocessor.separate_identifiers_and_labels(sample_raw_flow_data)

    preprocessor.fit(features_df)
    
    # In conftest, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags are all 0
    assert "bwd_psh_flags" not in preprocessor.feature_names_
    assert "fwd_urg_flags" not in preprocessor.feature_names_
    assert "bwd_urg_flags" not in preprocessor.feature_names_


def test_train_inference_preprocessing_consistency(sample_raw_flow_data, tmp_path):
    """
    Verify that fitted preprocessor transforms novel inference data consistently,
    preserving exact feature dimensions and column alignment.
    """
    preprocessor = FlowPreprocessor()
    features_df, _, _, _ = preprocessor.separate_identifiers_and_labels(sample_raw_flow_data)

    # Train partition
    train_df = features_df.iloc[:70]
    inference_df = features_df.iloc[70:]

    preprocessor.fit(train_df)
    X_train_transformed = preprocessor.transform(train_df)
    X_infer_transformed = preprocessor.transform(inference_df)

    assert X_train_transformed.shape[1] == X_infer_transformed.shape[1]
    assert list(X_train_transformed.columns) == list(X_infer_transformed.columns)

    # Serialization test
    model_file = tmp_path / "preprocessor.joblib"
    meta_file = tmp_path / "feature_schema.json"
    preprocessor.save(model_file, meta_file)

    loaded_preprocessor = FlowPreprocessor.load(model_file)
    X_loaded_transformed = loaded_preprocessor.transform(inference_df)

    np.testing.assert_allclose(
        X_infer_transformed.values, X_loaded_transformed.values, rtol=1e-5
    )
