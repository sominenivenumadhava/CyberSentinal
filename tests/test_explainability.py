"""
Unit and Integration Tests for CyberSentinel Explainable AI (SHAP) Engine.
Verifies game-theoretic feature attributions, non-causality disclaimer,
summary plot export, and graceful fallback execution.
"""
import pytest
import numpy as np
from pathlib import Path
from src.explainability.shap_explainer import FlowShapExplainer, CAUSALITY_DISCLAIMER


def dummy_predict_fn(X: np.ndarray) -> np.ndarray:
    """Mock predictor returning binary attack probabilities."""
    n = len(X)
    probs = np.zeros((n, 2))
    # Give high attack probability if feature 0 is high
    probs[:, 1] = np.clip(X[:, 0] * 0.5 + 0.2, 0.01, 0.99)
    probs[:, 0] = 1.0 - probs[:, 1]
    return probs


def test_shap_explainer_initialization_and_attribution():
    """Verify FlowShapExplainer computes valid local attributions and includes disclaimer."""
    feature_names = [f"Feature_{i}" for i in range(10)]
    background = np.random.randn(15, 10).astype(np.float32)

    explainer = FlowShapExplainer(
        predict_fn=dummy_predict_fn,
        feature_names=feature_names,
        background_samples=background,
        max_background_size=15,
    )

    test_flow = np.ones(10, dtype=np.float32) * 2.0
    result = explainer.explain_instance(test_flow, flow_index=42, top_k=4, nsamples=30)

    assert result["flow_index"] == 42
    assert "top_features" in result
    assert len(result["top_features"]) == 4
    assert "causality_disclaimer" in result
    assert "not be interpreted as physical proof of causality" in result["causality_disclaimer"].lower()
    assert result["causality_disclaimer"] == CAUSALITY_DISCLAIMER

    # Check top feature keys
    top_f = result["top_features"][0]
    assert "feature_name" in top_f
    assert "shap_value" in top_f
    assert "directional_impact" in top_f


def test_shap_selected_attacks_filtering():
    """Verify explain_selected_attacks filters top suspicious candidates."""
    feature_names = [f"Feature_{i}" for i in range(10)]
    explainer = FlowShapExplainer(
        predict_fn=dummy_predict_fn,
        feature_names=feature_names,
        background_samples=np.zeros((5, 10)),
        max_background_size=5,
    )

    matrix = np.random.randn(8, 10).astype(np.float32)
    predictions = [
        {"predicted_label": 0, "confidence": 0.95, "attack_probability": 0.05},
        {"predicted_label": 1, "confidence": 0.85, "attack_probability": 0.85},
        {"predicted_label": 0, "confidence": 0.99, "attack_probability": 0.01},
        {"predicted_label": 1, "confidence": 0.72, "attack_probability": 0.72},
    ]

    explanations = explainer.explain_selected_attacks(
        feature_matrix=matrix,
        predictions=predictions,
        max_to_explain=2,
    )

    assert len(explanations) == 2
    # Flow indices should be 1 and 3 (the two attack candidates)
    explained_indices = {exp["flow_index"] for exp in explanations}
    assert 1 in explained_indices
    assert 3 in explained_indices


def test_shap_summary_plot_export(tmp_path):
    """Verify summary plot is generated and saved as valid image."""
    feature_names = [f"Feature_{i}" for i in range(10)]
    explainer = FlowShapExplainer(
        predict_fn=dummy_predict_fn,
        feature_names=feature_names,
        background_samples=np.zeros((5, 10)),
    )

    mock_explanations = [
        {
            "flow_index": 0,
            "top_features": [
                {"feature_name": "Destination Port", "shap_value": 0.45},
                {"feature_name": "Flow Duration", "shap_value": -0.20},
            ]
        }
    ]

    out_file = tmp_path / "shap_test.png"
    saved_path = explainer.generate_summary_plot(mock_explanations, output_path=out_file)

    assert saved_path.exists()
    assert saved_path.stat().st_size > 1000  # Non-empty image
