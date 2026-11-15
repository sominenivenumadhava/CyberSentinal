"""
TabNet Architecture Wrapper for Network Intrusion Detection in CyberSentinel.
Implements self-supervised masked tabular pretraining and attention-based classification
with class imbalance compensation, early stopping, and CPU optimization.
"""
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
import os
import json
import logging
import numpy as np
import torch
from sklearn.utils.class_weight import compute_class_weight
from pytorch_tabnet.tab_model import TabNetClassifier
from pytorch_tabnet.pretraining import TabNetPretrainer

logger = logging.getLogger(__name__)


class CyberSentinelTabNet:
    """
    Attention-based Deep Tabular Classifier for Network Telemetry.
    """

    def __init__(
        self,
        n_d: int = 16,
        n_a: int = 16,
        n_steps: int = 3,
        gamma: float = 1.3,
        lambda_sparse: float = 1e-4,
        momentum: float = 0.02,
        learning_rate: float = 2e-2,
        seed: int = 42,
        device_name: str = "cpu",
    ):
        self.n_d = n_d
        self.n_a = n_a
        self.n_steps = n_steps
        self.gamma = gamma
        self.lambda_sparse = lambda_sparse
        self.momentum = momentum
        self.learning_rate = learning_rate
        self.seed = seed
        self.device_name = device_name

        self.pretrainer_: Optional[TabNetPretrainer] = None
        self.classifier_: Optional[TabNetClassifier] = None
        self.feature_names_: List[str] = []
        self.is_fitted_: bool = False
        self.pretraining_history_: List[float] = []
        self.training_history_: Dict[str, list] = {"train_loss": [], "val_loss": [], "val_auc": []}

    def build_pretrainer(self) -> TabNetPretrainer:
        """Instantiate self-supervised masked autoencoder pretrainer."""
        return TabNetPretrainer(
            n_d=self.n_d,
            n_a=self.n_a,
            n_steps=self.n_steps,
            gamma=self.gamma,
            lambda_sparse=self.lambda_sparse,
            momentum=self.momentum,
            optimizer_fn=torch.optim.Adam,
            optimizer_params=dict(lr=self.learning_rate),
            mask_type="entmax",
            seed=self.seed,
            device_name=self.device_name,
            verbose=1,
        )

    def build_classifier(self) -> TabNetClassifier:
        """Instantiate supervised TabNet classifier."""
        return TabNetClassifier(
            n_d=self.n_d,
            n_a=self.n_a,
            n_steps=self.n_steps,
            gamma=self.gamma,
            lambda_sparse=self.lambda_sparse,
            momentum=self.momentum,
            optimizer_fn=torch.optim.Adam,
            optimizer_params=dict(lr=self.learning_rate),
            scheduler_fn=torch.optim.lr_scheduler.StepLR,
            scheduler_params=dict(step_size=10, gamma=0.85),
            mask_type="entmax",
            seed=self.seed,
            device_name=self.device_name,
            verbose=1,
        )

    def pretrain(
        self,
        X_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        max_epochs: int = 15,
        batch_size: int = 256,
        patience: int = 5,
        pretraining_ratio: float = 0.2,
    ) -> TabNetPretrainer:
        """
        Self-supervised pretraining on unlabelled network flow telemetry.
        Learns feature correlations via masked autoencoding.
        """
        logger.info(f"Starting TabNet self-supervised pretraining (max_epochs={max_epochs})...")
        self.pretrainer_ = self.build_pretrainer()

        eval_set = [X_val] if X_val is not None else None
        self.pretrainer_.fit(
            X_train=X_train,
            eval_set=eval_set,
            max_epochs=max_epochs,
            patience=patience,
            batch_size=batch_size,
            virtual_batch_size=64,
            num_workers=0,
            drop_last=False,
            pin_memory=False,
            pretraining_ratio=pretraining_ratio,
        )
        self.pretraining_history_ = [float(v) for v in self.pretrainer_.history["loss"]]
        logger.info("TabNet self-supervised pretraining completed.")
        return self.pretrainer_

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        feature_names: Optional[List[str]] = None,
        use_pretrainer: bool = True,
        use_class_weights: bool = True,
        max_epochs: int = 30,
        batch_size: int = 256,
        patience: int = 10,
    ):
        """
        Fine-tune TabNet on labelled network flow data with early stopping.
        """
        self.feature_names_ = feature_names or [f"feature_{i}" for i in range(X_train.shape[1])]

        self.classifier_ = self.build_classifier()

        # Class weights: TabNet supports weights=1 for automated class balancing
        # or a custom dictionary mapping class_id -> weight
        weights_arg = 0
        if use_class_weights:
            classes = np.unique(y_train)
            computed_weights = compute_class_weight("balanced", classes=classes, y=y_train)
            weights_arg = {cls_idx: float(w) for cls_idx, w in zip(classes, computed_weights)}
            logger.info(f"Applied balanced class weights dict: {weights_arg}")

        from_unsupervised = self.pretrainer_ if (use_pretrainer and self.pretrainer_ is not None) else None
        if from_unsupervised is not None:
            logger.info("Initializing TabNet classifier weights from self-supervised pretrainer.")

        logger.info(f"Training TabNetClassifier (max_epochs={max_epochs}, patience={patience})...")
        self.classifier_.fit(
            X_train=X_train,
            y_train=y_train,
            eval_set=[(X_train, y_train), (X_val, y_val)],
            eval_name=["train", "val"],
            eval_metric=["auc", "accuracy", "balanced_accuracy"],
            weights=weights_arg,
            max_epochs=max_epochs,
            patience=patience,
            batch_size=batch_size,
            virtual_batch_size=64,
            num_workers=0,
            drop_last=False,
            pin_memory=False,
            from_unsupervised=from_unsupervised,
        )

        self.is_fitted_ = True
        hist = getattr(self.classifier_.history, "history", {})
        self.training_history_["train_loss"] = [float(v) for v in hist.get("loss", [])]
        self.training_history_["val_loss"] = [float(v) for v in hist.get("val_loss", hist.get("loss", []))]
        self.training_history_["val_auc"] = [float(v) for v in hist.get("val_auc", [])]
        logger.info(f"TabNet fine-tuning finished at epoch {len(self.training_history_['train_loss'])}.")

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted_:
            raise RuntimeError("Model must be fitted before predict().")
        return self.classifier_.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted_:
            raise RuntimeError("Model must be fitted before predict_proba().")
        return self.classifier_.predict_proba(X)

    def explain(self, X: np.ndarray) -> Tuple[np.ndarray, Dict[int, np.ndarray]]:
        """Extract attention masks and feature importances."""
        if not self.is_fitted_:
            raise RuntimeError("Model must be fitted before explain().")
        return self.classifier_.explain(X)

    def save(self, filepath: Path, metadata_path: Optional[Path] = None):
        """Save TabNet weights and configuration metadata."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        # Note: pytorch-tabnet saves as a zip archive and appends .zip automatically if not present
        saved_path = self.classifier_.save_model(str(filepath))

        if metadata_path is not None:
            metadata_path = Path(metadata_path)
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            meta = {
                "model_type": "TabNetClassifier",
                "n_d": self.n_d,
                "n_a": self.n_a,
                "n_steps": self.n_steps,
                "features": self.feature_names_,
                "num_features": len(self.feature_names_),
                "best_epoch": int(self.classifier_.best_epoch) if hasattr(self.classifier_, "best_epoch") else None,
                "best_cost": float(self.classifier_.best_cost) if hasattr(self.classifier_, "best_cost") else None,
            }
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        return saved_path

    @classmethod
    def load(cls, filepath: Path, device_name: str = "cpu") -> "CyberSentinelTabNet":
        """Load trained TabNet model."""
        wrapper = cls(device_name=device_name)
        wrapper.classifier_ = TabNetClassifier(device_name=device_name)
        wrapper.classifier_.load_model(str(filepath))
        wrapper.is_fitted_ = True
        return wrapper
