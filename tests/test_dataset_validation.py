"""
Dataset Integrity and Partition Validation Test Suite for CyberSentinel.
Verifies schema invariants, zero identifier leakage, NaN/infinite absence,
and label distribution consistency across train, val, and test splits.
"""
import pytest
import numpy as np
import pandas as pd
from config.settings import settings
from src.data.schema import IDENTIFIER_COLUMNS


def test_processed_partitions_exist():
    """Verify that all required processed partitions exist."""
    assert (settings.DATA_PROCESSED_DIR / "train.parquet").exists()
    assert (settings.DATA_PROCESSED_DIR / "val.parquet").exists()
    assert (settings.DATA_PROCESSED_DIR / "test.parquet").exists()


def test_feature_columns_invariance_and_alignment():
    """Verify identical 65 feature columns across train, val, and test partitions."""
    train_df = pd.read_parquet(settings.DATA_PROCESSED_DIR / "train.parquet")
    val_df = pd.read_parquet(settings.DATA_PROCESSED_DIR / "val.parquet")
    test_df = pd.read_parquet(settings.DATA_PROCESSED_DIR / "test.parquet")

    train_feats = [c for c in train_df.columns if c not in ("is_attack", "attack_category")]
    val_feats = [c for c in val_df.columns if c not in ("is_attack", "attack_category")]
    test_feats = [c for c in test_df.columns if c not in ("is_attack", "attack_category")]

    assert len(train_feats) == 65
    assert train_feats == val_feats
    assert train_feats == test_feats


def test_zero_identifier_leakage():
    """Verify that network identifiers (IPs, ports, timestamps) are strictly excluded."""
    for split_name in ["train.parquet", "val.parquet", "test.parquet"]:
        df = pd.read_parquet(settings.DATA_PROCESSED_DIR / split_name)
        for col in df.columns:
            assert col.lower() not in [i.lower() for i in IDENTIFIER_COLUMNS]


def test_absence_of_nan_and_infinite_values():
    """Verify that all feature columns are clean, finite real numbers."""
    for split_name in ["train.parquet", "val.parquet", "test.parquet"]:
        df = pd.read_parquet(settings.DATA_PROCESSED_DIR / split_name)
        num_cols = df.select_dtypes(include=[np.number])
        assert not num_cols.isna().any().any(), f"NaN found in {split_name}"
        assert not np.isinf(num_cols.values).any(), f"Infinite value found in {split_name}"


def test_binary_labels_validity_and_balance():
    """Verify that labels are strictly binary and present in reasonable proportions."""
    for split_name in ["train.parquet", "val.parquet", "test.parquet"]:
        df = pd.read_parquet(settings.DATA_PROCESSED_DIR / split_name)
        assert "is_attack" in df.columns
        unique_labels = set(df["is_attack"].unique())
        assert unique_labels == {0, 1}
        # Check both benign and attack samples exist
        counts = df["is_attack"].value_counts().to_dict()
        assert counts[0] > 0
        assert counts[1] > 0
