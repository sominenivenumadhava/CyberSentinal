"""
Model Evaluation, Metrics Computation, and Diagnostic Visualization for CyberSentinel.
Calculates Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix,
inference latency benchmarks, and generates publication-grade evaluation charts.
"""
import time
from typing import Dict, Any, Tuple, Optional
from pathlib import Path
import json
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)

from config.settings import settings

logger = logging.getLogger(__name__)


def evaluate_classifier_performance(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    model_name: str = "Classifier",
) -> Dict[str, Any]:
    """
    Compute comprehensive classification metrics.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    roc_auc = None
    pr_auc = None
    if y_prob is not None:
        y_prob = np.asarray(y_prob)
        # Handle 2D probability output if passed
        if y_prob.ndim == 2:
            y_prob = y_prob[:, 1]
        try:
            roc_auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            roc_auc = None
        try:
            pr_auc = float(average_precision_score(y_true, y_prob))
        except Exception:
            pr_auc = None

    metrics = {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "total_test_samples": len(y_true),
    }

    return metrics


def benchmark_inference_latency(
    model: Any,
    X_sample: np.ndarray,
    predict_fn_name: str = "predict",
    num_iterations: int = 100,
) -> Dict[str, float]:
    """
    Measure single-sample latency and batch throughput on CPU.
    """
    # Warmup
    fn = getattr(model, predict_fn_name)
    _ = fn(X_sample[:5])

    # 1. Single sample latency test
    single_sample = X_sample[:1]
    times = []
    for _ in range(num_iterations):
        t0 = time.perf_counter()
        _ = fn(single_sample)
        times.append((time.perf_counter() - t0) * 1000.0)  # ms

    single_latency_ms = float(np.median(times))

    # 2. Batch throughput test (samples / second)
    batch_size = len(X_sample)
    t0 = time.perf_counter()
    _ = fn(X_sample)
    total_batch_time = time.perf_counter() - t0
    throughput_samples_per_sec = float(batch_size / total_batch_time) if total_batch_time > 0 else 0.0

    return {
        "single_sample_latency_ms": round(single_latency_ms, 3),
        "batch_throughput_samples_per_sec": round(throughput_samples_per_sec, 1),
    }


def plot_confusion_matrix_and_curves(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    model_name: str,
    output_dir: Path,
) -> Tuple[Path, Path]:
    """
    Generate and save confusion matrix heatmap and ROC/PR curves.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if y_prob.ndim == 2:
        y_prob = y_prob[:, 1]

    # 1. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Benign (0)", "Attack (1)"],
        yticklabels=["Benign (0)", "Attack (1)"],
        cbar=False,
        ax=ax,
        annot_kws={"size": 13, "weight": "bold"},
    )
    ax.set_title(f"{model_name} Confusion Matrix", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Predicted Class", fontsize=11, fontweight="bold")
    ax.set_ylabel("True Class", fontsize=11, fontweight="bold")
    plt.tight_layout()
    cm_path = output_dir / f"{model_name.lower().replace(' ', '_')}_confusion_matrix.png"
    fig.savefig(cm_path, dpi=300)
    plt.close(fig)

    # 2. ROC and Precision-Recall Curves
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = roc_auc_score(y_true, y_prob)
    ax1.plot(fpr, tpr, color="#2980b9", lw=2.5, label=f"ROC (AUC = {roc_auc:.4f})")
    ax1.plot([0, 1], [0, 1], color="grey", lw=1.5, linestyle="--")
    ax1.set_xlim([0.0, 1.0])
    ax1.set_ylim([0.0, 1.05])
    ax1.set_xlabel("False Positive Rate", fontsize=11)
    ax1.set_ylabel("True Positive Rate", fontsize=11)
    ax1.set_title(f"{model_name} ROC Curve", fontsize=12, fontweight="bold")
    ax1.legend(loc="lower right", fontsize=10)
    ax1.grid(True, alpha=0.3)

    prec_curve, rec_curve, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = average_precision_score(y_true, y_prob)
    ax2.plot(rec_curve, prec_curve, color="#27ae60", lw=2.5, label=f"PR (AUC = {pr_auc:.4f})")
    ax2.set_xlim([0.0, 1.0])
    ax2.set_ylim([0.0, 1.05])
    ax2.set_xlabel("Recall", fontsize=11)
    ax2.set_ylabel("Precision", fontsize=11)
    ax2.set_title(f"{model_name} Precision-Recall Curve", fontsize=12, fontweight="bold")
    ax2.legend(loc="lower left", fontsize=10)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    curves_path = output_dir / f"{model_name.lower().replace(' ', '_')}_roc_pr_curves.png"
    fig.savefig(curves_path, dpi=300)
    plt.close(fig)

    return cm_path, curves_path


def plot_training_loss_curves(
    train_losses: list,
    val_losses: list,
    model_name: str,
    output_dir: Path,
    metric_name: str = "Loss",
) -> Path:
    """
    Generate and save training vs validation learning curves.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 5))
    epochs = range(1, len(train_losses) + 1)
    ax.plot(epochs, train_losses, "b-", lw=2, label=f"Train {metric_name}")
    if val_losses and len(val_losses) == len(train_losses):
        ax.plot(epochs, val_losses, "r--", lw=2, label=f"Validation {metric_name}")
    ax.set_title(f"{model_name} Training Dynamics ({metric_name})", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Epochs", fontsize=11)
    ax.set_ylabel(metric_name, fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    save_path = output_dir / f"{model_name.lower().replace(' ', '_')}_loss_curves.png"
    fig.savefig(save_path, dpi=300)
    plt.close(fig)
    return save_path

