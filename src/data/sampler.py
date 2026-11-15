"""
Reproducible Stratified Sampling for Network Flow Telemetry.
Safeguards rare attack representation (e.g. Infiltration, Web Attacks, Heartbleed)
and produces standardized train/val/test splits for CyberSentinel.
"""
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

from config.settings import settings
from src.data.preprocessor import FlowPreprocessor

logger = logging.getLogger(__name__)


class StratifiedFlowSampler:
    """
    Extracts reproducible stratified subsets from preprocessed flow data,
    guaranteeing that rare attack classes are preserved for model training and evaluation.
    """

    def __init__(self, random_seed: int = settings.RANDOM_SEED):
        self.random_seed = random_seed

    def create_stratified_dev_sample(
        self,
        features_df: pd.DataFrame,
        meta_df: pd.DataFrame,
        y_binary: pd.Series,
        y_category: pd.Series,
        target_size: int = settings.DEV_SAMPLE_SIZE,
        min_samples_per_class: int = 50,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Sample dataset with stratification on attack category.
        If a rare class has fewer instances than min_samples_per_class, keep 100% of its instances.
        """
        np.random.seed(self.random_seed)
        total_rows = len(features_df)
        if total_rows <= target_size:
            logger.info(f"Dataset has {total_rows} rows <= target size {target_size}. Using all rows.")
            return features_df, meta_df, y_binary, y_category

        # Group indices by attack category
        category_indices: Dict[str, np.ndarray] = {}
        for cat in y_category.unique():
            idx = np.where(y_category.values == cat)[0]
            category_indices[cat] = idx

        selected_indices = []
        fraction = target_size / total_rows

        for cat, indices in category_indices.items():
            n_class = len(indices)
            if n_class <= min_samples_per_class:
                # Keep all instances of rare attacks
                selected_indices.extend(indices)
            else:
                n_take = max(min_samples_per_class, int(np.round(n_class * fraction)))
                chosen = np.random.choice(indices, size=min(n_take, n_class), replace=False)
                selected_indices.extend(chosen)

        selected_indices = np.array(selected_indices)
        np.random.shuffle(selected_indices)

        # Slice DataFrames
        sub_features = features_df.iloc[selected_indices].reset_index(drop=True)
        sub_meta = meta_df.iloc[selected_indices].reset_index(drop=True)
        sub_y_bin = y_binary.iloc[selected_indices].reset_index(drop=True)
        sub_y_cat = y_category.iloc[selected_indices].reset_index(drop=True)

        logger.info(
            f"Created stratified dev sample: {len(sub_features)} rows across {len(category_indices)} categories."
        )
        return sub_features, sub_meta, sub_y_bin, sub_y_cat

    def train_val_test_split(
        self,
        X: pd.DataFrame,
        y_binary: pd.Series,
        y_category: Optional[pd.Series] = None,
        test_size: float = settings.TEST_SPLIT,
        val_size: float = settings.VALIDATION_SPLIT,
    ) -> Dict[str, Any]:
        """
        Split dataset into train, validation, and test partitions
        with stratification on category (or binary label if category is homogeneous).
        """
        strat_target = y_category if y_category is not None and y_category.nunique() > 1 else y_binary

        # Filter out classes with single sample for safe stratification
        class_counts = strat_target.value_counts()
        single_sample_classes = class_counts[class_counts < 2].index
        
        if len(single_sample_classes) > 0:
            logger.warning(f"Classes with single sample detected: {list(single_sample_classes)}. Reverting strat to binary.")
            strat_target = y_binary

        # 1. Split off test set
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X,
            y_binary,
            test_size=test_size,
            random_state=self.random_seed,
            stratify=strat_target,
        )

        # 2. Split train into train and val
        val_fraction_adjusted = val_size / (1.0 - test_size)
        strat_sub = (
            y_category.iloc[X_train_val.index]
            if y_category is not None and y_category.nunique() > 1
            else y_train_val
        )
        # Check single samples again
        sub_counts = strat_sub.value_counts()
        if (sub_counts < 2).any():
            strat_sub = y_train_val

        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val,
            y_train_val,
            test_size=val_fraction_adjusted,
            random_state=self.random_seed,
            stratify=strat_sub,
        )

        logger.info(
            f"Dataset split: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}"
        )

        return {
            "X_train": X_train.reset_index(drop=True),
            "X_val": X_val.reset_index(drop=True),
            "X_test": X_test.reset_index(drop=True),
            "y_train": y_train.reset_index(drop=True),
            "y_val": y_val.reset_index(drop=True),
            "y_test": y_test.reset_index(drop=True),
        }
