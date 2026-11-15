"""
Training and Evaluation Pipeline for TabNet Classifier on CICIDS2017.
Performs self-supervised pretraining, supervised fine-tuning with class weighting,
early stopping, checkpointing, and comprehensive CPU performance benchmarking.
"""
import time
import os
from pathlib import Path
import json
import logging
import pandas as pd
import numpy as np

# Configure matplotlib cache
mpl_cache = Path("./.cache/matplotlib").resolve()
mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ["MPLCONFIGDIR"] = str(mpl_cache)

from config.settings import settings
from config.logging_config import logger
from src.models.tabnet_model import CyberSentinelTabNet
from src.utils.metrics import (
    evaluate_classifier_performance,
    benchmark_inference_latency,
    plot_confusion_matrix_and_curves,
    plot_training_loss_curves,
)


def load_dataset_partitions():
    """Load train, val, and test splits from processed data."""
    train_path = settings.DATA_PROCESSED_DIR / "train.parquet"
    val_path = settings.DATA_PROCESSED_DIR / "val.parquet"
    test_path = settings.DATA_PROCESSED_DIR / "test.parquet"

    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path)

    feature_cols = [c for c in train_df.columns if c not in ("is_attack", "attack_category")]

    X_train = train_df[feature_cols].values.astype(np.float32)
    y_train = train_df["is_attack"].values.astype(np.int64)

    X_val = val_df[feature_cols].values.astype(np.float32)
    y_val = val_df["is_attack"].values.astype(np.int64)

    X_test = test_df[feature_cols].values.astype(np.float32)
    y_test = test_df["is_attack"].values.astype(np.int64)

    logger.info(f"Loaded partitions: Train={X_train.shape}, Val={X_val.shape}, Test={X_test.shape}")
    return X_train, y_train, X_val, y_val, X_test, y_test, feature_cols


def run_tabnet_training():
    logger.info("=" * 70)
    logger.info("             STARTING TABNET CLASSIFIER TRAINING")
    logger.info("=" * 70)

    X_train, y_train, X_val, y_val, X_test, y_test, feature_cols = load_dataset_partitions()

    model = CyberSentinelTabNet(
        n_d=16,
        n_a=16,
        n_steps=3,
        gamma=1.3,
        lambda_sparse=1e-4,
        learning_rate=2e-2,
        seed=settings.RANDOM_SEED,
        device_name="cpu",
    )

    # 1. TabNet Self-Supervised Pretraining
    pretrain_start = time.perf_counter()
    pretrain_success = False
    try:
        logger.info("[*] Phase 1: Self-Supervised Masked Tabular Pretraining...")
        model.pretrain(
            X_train=X_train,
            X_val=X_val,
            max_epochs=15,
            batch_size=256,
            patience=5,
            pretraining_ratio=0.2,
        )
        pretrain_success = True
    except Exception as e:
        logger.warning(f"Self-supervised pretraining encountered issue: {e}. Falling back to direct supervised training.")

    pretrain_duration = time.perf_counter() - pretrain_start
    logger.info(f"[+] Pretraining duration: {pretrain_duration:.2f}s (Success: {pretrain_success})")

    # 2. Supervised Fine-Tuning with Class Weights & Early Stopping
    train_start = time.perf_counter()
    logger.info("[*] Phase 2: Supervised Fine-Tuning with Class Imbalance Weighting...")
    model.fit(
        X_train=X_train,
        y_train=y_train,
        X_val=X_val,
        y_val=y_val,
        feature_names=feature_cols,
        use_pretrainer=pretrain_success,
        use_class_weights=True,
        max_epochs=30,
        batch_size=256,
        patience=10,
    )
    train_duration = time.perf_counter() - train_start
    logger.info(f"[+] Fine-tuning duration: {train_duration:.2f}s")

    # 3. Model Checkpointing
    out_dir = settings.ROOT_DIR / "models" / "tabnet"
    chk_dir = settings.ROOT_DIR / "models" / "checkpoints"
    out_dir.mkdir(parents=True, exist_ok=True)
    chk_dir.mkdir(parents=True, exist_ok=True)

    saved_path = model.save(
        out_dir / "tabnet_classifier.zip",
        metadata_path=out_dir / "tabnet_metadata.json",
    )
    # Also save checkpoint
    model.save(chk_dir / "tabnet_best.zip")
    logger.info(f"[+] Saved TabNet model checkpoints: {saved_path}")

    # 4. Evaluation on Held-Out Test Data (Never seen during training/validation)
    logger.info("[*] Phase 3: Evaluating on Held-Out Test Data...")
    y_test_pred = model.predict(X_test)
    y_test_prob = model.predict_proba(X_test)

    eval_metrics = evaluate_classifier_performance(
        y_true=y_test,
        y_pred=y_test_pred,
        y_prob=y_test_prob,
        model_name="TabNet Classifier",
    )

    # 5. Benchmark Latency & Throughput
    logger.info("[*] Benchmarking CPU inference latency...")
    benchmarks = benchmark_inference_latency(model, X_test, predict_fn_name="predict", num_iterations=50)

    eval_metrics["timing"] = {
        "pretraining_duration_seconds": round(pretrain_duration, 2),
        "fine_tuning_duration_seconds": round(train_duration, 2),
        "total_training_duration_seconds": round(pretrain_duration + train_duration, 2),
        "single_sample_latency_ms": benchmarks["single_sample_latency_ms"],
        "batch_throughput_samples_per_sec": benchmarks["batch_throughput_samples_per_sec"],
    }

    # Save metrics JSON
    with open(out_dir / "tabnet_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(eval_metrics, f, indent=2)

    # 6. Generate Figures
    fig_dir = settings.FIGURES_DIR
    plot_confusion_matrix_and_curves(
        y_true=y_test,
        y_pred=y_test_pred,
        y_prob=y_test_prob,
        model_name="TabNet Classifier",
        output_dir=fig_dir,
    )
    plot_training_loss_curves(
        train_losses=model.training_history_["train_loss"],
        val_losses=model.training_history_["val_loss"],
        model_name="TabNet Classifier",
        output_dir=fig_dir,
    )
    logger.info("[+] Generated TabNet evaluation plots in reports/figures/")

    logger.info(f"[+] TabNet Results: Accuracy={eval_metrics['accuracy']:.4f}, F1={eval_metrics['f1_score']:.4f}, ROC-AUC={eval_metrics['roc_auc']:.4f}, PR-AUC={eval_metrics['pr_auc']:.4f}")
    return eval_metrics


if __name__ == "__main__":
    run_tabnet_training()
