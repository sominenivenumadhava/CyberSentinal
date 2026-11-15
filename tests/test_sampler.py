"""
Unit tests for reproducible stratified sampling.
"""
import pytest
import pandas as pd
import numpy as np
from src.data.preprocessor import FlowPreprocessor
from src.data.sampler import StratifiedFlowSampler


def test_stratified_dev_sample_preserves_rare_classes(sample_raw_flow_data):
    """Verify that rare classes (e.g. Infiltration) are kept even when downsampling."""
    preprocessor = FlowPreprocessor()
    features_df, meta_df, y_binary, y_category = (
        preprocessor.separate_identifiers_and_labels(sample_raw_flow_data)
    )

    sampler = StratifiedFlowSampler(random_seed=42)
    sub_feat, sub_meta, sub_y_bin, sub_y_cat = sampler.create_stratified_dev_sample(
        features_df, meta_df, y_binary, y_category, target_size=40, min_samples_per_class=2
    )

    assert len(sub_feat) <= 60
    # Infiltration must be preserved
    assert "Infiltration" in sub_y_cat.values
    assert "DDoS" in sub_y_cat.values
    assert "BENIGN" in sub_y_cat.values


def test_reproducibility():
    """Verify that identical random seeds produce byte-identical samples."""
    sampler1 = StratifiedFlowSampler(random_seed=42)
    sampler2 = StratifiedFlowSampler(random_seed=42)

    X = pd.DataFrame({"feat1": np.arange(100), "feat2": np.random.randn(100)})
    meta = pd.DataFrame({"ip": [f"10.0.0.{i}" for i in range(100)]})
    y_bin = pd.Series([0 if i < 80 else 1 for i in range(100)])
    y_cat = pd.Series(["BENIGN" if i < 80 else "Attack" for i in range(100)])

    res1 = sampler1.create_stratified_dev_sample(X, meta, y_bin, y_cat, target_size=30)
    res2 = sampler2.create_stratified_dev_sample(X, meta, y_bin, y_cat, target_size=30)

    pd.testing.assert_frame_equal(res1[0], res2[0])
    pd.testing.assert_series_equal(res1[2], res2[2])

