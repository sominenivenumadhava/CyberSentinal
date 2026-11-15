"""
Training and Evaluation Pipeline for Deep Autoencoder Anomaly Detector on CICIDS2017.
Trains strictly on benign network flow telemetry, establishes a calibrated anomaly threshold
using validation data, and evaluates intrusion detection performance on held-out test telemetry.
"""
import time
import os
from pathlib import Path
import json
import logging
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Configure matplotlib cache
mpl_cache = Path("./.cache/matplotlib").resolve()
mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ["MPLCONFIGDIR"] = str(mpl_cache)

from config.settings import settings
from config.logging_config import logger
from src.models.autoencoder_model import CyberSentinelAutoencoder
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

    # Extract benign-only flows for unsupervised autoencoder training
    train_benign = train_df[train_df["is_attack"] == 0]
    val_benign = val_df[val_df["is_attack"] == 0]

    X_train_benign = train_benign[feature_cols].values.astype(np.float32)
    X_val_benign = val_benign[feature_cols].values.astype(np.float32)

    # Full validation set for threshold determination (contains both benign & attacks)
    X_val_full = val_df[feature_cols].values.astype(np.float32)
    y_val_full = val_df["is_attack"].values.astype(np.int64)

    # Full test set for evaluation
    X_test = test_df[feature_cols].values.astype(np.float32)
    y_test = test_df["is_attack"].values.astype(np.int64)

    logger.info(f"Autoencoder Data: Train Benign={X_train_benign.shape}, Val Full={X_val_full.shape}, Test={X_test.shape}")
    return X_train_benign, X_val_benign, X_val_full, y_val_full, X_test, y_test, feature_cols


def plot_reconstruction_error_distribution(
    errors: np.ndarray,
    labels: np.ndarray,
    threshold: float,
    output_path: Path,
):
    """
    Plot reconstruction error distributions for Benign vs Attack flows
    showing the validation-calibrated decision threshold.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    benign_errors = errors[labels == 0]
    attack_errors = errors[labels == 1]

    # Clip for clean visual representation
    clip_val = float(np.percentile(errors, 99))
    b_clipped = np.clip(benign_errors, 0, clip_val)
    a_clipped = np.clip(attack_errors, 0, clip_val)

    sns.kdeplot(b_clipped, ax=ax, label="Normal Flows (Benign)", color="#2ecc71", fill=True, alpha=0.35, lw=2)
    sns.kdeplot(a_clipped, ax=ax, label="Intrusion Flows (Attacks)", color="#e74c3c", fill=True, alpha=0.35, lw=2)

    ax.axvline(threshold, color="#e67e22", linestyle="--", lw=2.5, label=f"Anomaly Threshold (τ = {threshold:.4f})")
    ax.set_title("Autoencoder Reconstruction Error Density (Benign vs Attack)", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Reconstruction MSE Error", fontsize=11, fontweight="bold")
    ax.set_ylabel("Density", fontsize=11, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_path, dpi=300)
    plt.close(fig)
    logger.info(f"Saved reconstruction error distribution plot: {output_path}")


def run_autoencoder_training():
    logger.info("=" * 70)
    logger.info("           STARTING DEEP AUTOENCODER TRAINING")
    logger.info("=" * 70)

    X_train_benign, X_val_benign, X_val_full, y_val_full, X_test, y_test, feature_cols = (
        load_dataset_partitions()
    )

    model = CyberSentinelAutoencoder(
        latent_dim=12,
        learning_rate=1e-3,
        weight_decay=1e-5,
        device="cpu",
        random_seed=settings.RANDOM_SEED,
    )

    # 1. Train Autoencoder strictly on benign traffic
    train_start = time.perf_counter()
    model.fit(
        X_train_benign=X_train_benign,
        X_val_benign=X_val_benign,
        batch_size=128,
        max_epochs=35,
        patience=8,
    )
    train_duration = time.perf_counter() - train_start
    logger.info(f"[+] Autoencoder training duration: {train_duration:.2f}s")

    # 2. Determine Anomaly Threshold using VALIDATION data ONLY
    logger.info("[*] Phase 2: Determining Anomaly Threshold on Validation Data (Leakage-Free)...")
    threshold = model.determine_anomaly_threshold(
        X_val=X_val_full,
        y_val=y_val_full,
        strategy="val_f1_optimal",
    )

    # 3. Model Checkpointing
    out_dir = settings.ROOT_DIR / "models" / "autoencoder"
    chk_dir = settings.ROOT_DIR / "models" / "checkpoints"
    out_dir.mkdir(parents=True, exist_ok=True)
    chk_dir.mkdir(parents=True, exist_ok=True)

    model_pt = out_dir / "autoencoder_best.pt"
    meta_json = out_dir / "autoencoder_metadata.json"
    model.save(model_pt, meta_json)

    # Also save checkpoint
    model.save(chk_dir / "autoencoder_best.pt", chk_dir / "autoencoder_metadata.json")
    logger.info(f"[+] Saved Autoencoder checkpoint to: {model_pt}")

    # 4. Evaluation on Held-Out Test Data
    logger.info("[*] Phase 3: Evaluating Anomaly Detection on Test Data...")
    y_test_pred = model.predict(X_test)
    y_test_prob = model.predict_proba(X_test)
    test_recon_errors = model.calculate_reconstruction_errors(X_test)

    eval_metrics = evaluate_classifier_performance(
        y_true=y_test,
        y_pred=y_test_pred,
        y_prob=y_test_prob,
        model_name="Flow Autoencoder",
    )

    # 5. Benchmark Latency & Throughput
    logger.info("[*] Benchmarking CPU inference latency...")
    benchmarks = benchmark_inference_latency(model, X_test, predict_fn_name="predict", num_iterations=50)

    eval_metrics["timing"] = {
        "training_duration_seconds": round(train_duration, 2),
        "single_sample_latency_ms": benchmarks["single_sample_latency_ms"],
        "batch_throughput_samples_per_sec": benchmarks["batch_throughput_samples_per_sec"],
    }
    eval_metrics["anomaly_threshold"] = round(float(threshold), 6)
    eval_metrics["threshold_strategy"] = model.threshold_strategy_

    # Save metrics JSON
    with open(out_dir / "autoencoder_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(eval_metrics, f, indent=2)

    # 6. Generate Figures
    fig_dir = settings.FIGURES_DIR
    plot_confusion_matrix_and_curves(
        y_true=y_test,
        y_pred=y_test_pred,
        y_prob=y_test_prob,
        model_name="Flow Autoencoder",
        output_dir=fig_dir,
    )
    plot_training_loss_curves(
        train_losses=model.training_losses_,
        val_losses=model.validation_losses_,
        model_name="Flow Autoencoder",
        output_dir=fig_dir,
        metric_name="MSE Loss",
    )
    plot_reconstruction_error_distribution(
        errors=test_recon_errors,
        labels=y_test,
        threshold=threshold,
        output_path=fig_dir / "autoencoder_reconstruction_distribution.png",
    )
    logger.info("[+] Generated Autoencoder evaluation plots in reports/figures/")

    logger.info(f"[+] Autoencoder Results: Accuracy={eval_metrics['accuracy']:.4f}, F1={eval_metrics['f1_score']:.4f}, ROC-AUC={eval_metrics['roc_auc']:.4f}, PR-AUC={eval_metrics['pr_auc']:.4f}")
    return eval_metrics


if __name__ == "__main__":
    run_autoencoder_training()
