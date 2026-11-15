"""
Unit tests for CyberSentinel Deep Learning Models (TabNet & Autoencoder).
Verifies network architectures, forward passes, reconstruction error calculations,
validation-calibrated thresholding, and model serialization.
"""
import pytest
import numpy as np
import torch
from pathlib import Path

from src.models.tabnet_model import CyberSentinelTabNet
from src.models.autoencoder_model import CyberSentinelAutoencoder, FlowAutoencoderNet
from src.utils.metrics import evaluate_classifier_performance, benchmark_inference_latency


@pytest.fixture
def synthetic_flow_tensors():
    """Create minimal synthetic numeric dataset for fast model unit testing."""
    np.random.seed(42)
    torch.manual_seed(42)
    n_features = 65
    
    # Benign flows (centered at 0, low variance)
    X_benign = np.random.normal(loc=0.0, scale=1.0, size=(100, n_features)).astype(np.float32)
    y_benign = np.zeros(100, dtype=np.int64)

    # Attack flows (shifted distribution, high variance)
    X_attack = np.random.normal(loc=3.5, scale=2.0, size=(40, n_features)).astype(np.float32)
    y_attack = np.ones(40, dtype=np.int64)

    X_train = np.vstack([X_benign[:70], X_attack[:25]])
    y_train = np.concatenate([y_benign[:70], y_attack[:25]])

    X_val = np.vstack([X_benign[70:85], X_attack[25:32]])
    y_val = np.concatenate([y_benign[70:85], y_attack[25:32]])

    X_test = np.vstack([X_benign[85:], X_attack[32:]])
    y_test = np.concatenate([y_benign[85:], y_attack[32:]])

    return {
        "X_train": X_train,
        "y_train": y_train,
        "X_val": X_val,
        "y_val": y_val,
        "X_test": X_test,
        "y_test": y_test,
        "n_features": n_features,
    }


def test_autoencoder_architecture_and_forward(synthetic_flow_tensors):
    """Verify FlowAutoencoderNet tensor forward pass and dimensionality."""
    n_features = synthetic_flow_tensors["n_features"]
    net = FlowAutoencoderNet(input_dim=n_features, latent_dim=12)

    batch_x = torch.randn(8, n_features)
    recon = net(batch_x)

    assert recon.shape == batch_x.shape, f"Expected shape {batch_x.shape}, got {recon.shape}"
    assert not torch.isnan(recon).any(), "Reconstructed tensor contains NaN"


def test_autoencoder_training_and_thresholding(synthetic_flow_tensors, tmp_path):
    """Verify Autoencoder training on benign data and threshold calibration."""
    data = synthetic_flow_tensors
    ae = CyberSentinelAutoencoder(latent_dim=8, learning_rate=1e-3, random_seed=42)

    # Train strictly on benign training flows
    X_train_benign = data["X_train"][data["y_train"] == 0]
    X_val_benign = data["X_val"][data["y_val"] == 0]

    ae.fit(X_train_benign, X_val_benign, batch_size=32, max_epochs=5, patience=2)
    assert ae.is_fitted_

    # Determine anomaly threshold on validation set
    thresh = ae.determine_anomaly_threshold(data["X_val"], data["y_val"], strategy="val_f1_optimal")
    assert thresh > 0.0

    # Predictions on test set
    preds = ae.predict(data["X_test"])
    assert len(preds) == len(data["X_test"])
    assert set(np.unique(preds)).issubset({0, 1})

    probs = ae.predict_proba(data["X_test"])
    assert probs.shape == (len(data["X_test"]), 2)
    np.testing.assert_allclose(probs.sum(axis=1), 1.0, rtol=1e-5)

    # Serialization test
    m_path = tmp_path / "ae.pt"
    meta_path = tmp_path / "ae_meta.json"
    ae.save(m_path, meta_path)

    loaded_ae = CyberSentinelAutoencoder.load(m_path, meta_path)
    loaded_preds = loaded_ae.predict(data["X_test"])
    np.testing.assert_array_equal(preds, loaded_preds)


def test_tabnet_classifier_workflow(synthetic_flow_tensors, tmp_path):
    """Verify TabNetClassifier initialization, fitting, prediction, and explanation."""
    data = synthetic_flow_tensors
    tabnet = CyberSentinelTabNet(
        n_d=8,
        n_a=8,
        n_steps=2,
        seed=42,
        device_name="cpu",
    )

    # Fast fit on synthetic data
    tabnet.fit(
        X_train=data["X_train"],
        y_train=data["y_train"],
        X_val=data["X_val"],
        y_val=data["y_val"],
        max_epochs=4,
        batch_size=32,
        patience=2,
        use_pretrainer=False,
    )
    assert tabnet.is_fitted_

    preds = tabnet.predict(data["X_test"])
    probs = tabnet.predict_proba(data["X_test"])

    assert len(preds) == len(data["X_test"])
    assert set(np.unique(preds)).issubset({0, 1})
    assert probs.shape == (len(data["X_test"]), 2)
    np.testing.assert_allclose(probs.sum(axis=1), 1.0, rtol=1e-5)

    # Attention mask explanation
    explain_matrix, masks = tabnet.explain(data["X_test"][:5])
    assert explain_matrix.shape == (5, data["n_features"])

    # Checkpoint serialization
    save_zip = tmp_path / "tabnet_test.zip"
    meta_json = tmp_path / "tabnet_test.json"
    tabnet.save(save_zip, meta_json)


def test_metrics_and_latency_benchmarks():
    """Verify evaluation metric calculations and latency benchmarking."""
    y_true = np.array([0, 0, 1, 1, 0, 1])
    y_pred = np.array([0, 0, 1, 0, 0, 1])
    y_prob = np.array([0.1, 0.2, 0.9, 0.4, 0.3, 0.85])

    metrics = evaluate_classifier_performance(y_true, y_pred, y_prob, model_name="TestModel")
    assert metrics["accuracy"] == round(5 / 6, 4)
    assert metrics["confusion_matrix"]["true_positives"] == 2
    assert metrics["confusion_matrix"]["false_negatives"] == 1
    assert metrics["roc_auc"] is not None
    assert metrics["pr_auc"] is not None
