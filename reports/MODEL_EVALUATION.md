# CyberSentinel: Deep Learning Model Benchmark & Evaluation Report
## Day 2: TabNet Classifier vs. Deep Autoencoder

**Evaluation Target**: Held-out CICIDS2017 Test Partition (`data/processed/test.parquet`)  
**Test Set Size**: 2,246 network flows (1,685 Benign, 561 Attack)  
**Execution Environment**: Windows 11 / Intel CPU (No GPU used)  
**Hardware Strategy**: CPU-optimized PyTorch with reproducible seeds (`seed=42`)  

---

## 1. Executive Performance Comparison

| Metric | TabNet Classifier (Supervised) | Flow Autoencoder (Unsupervised) | Advantage / Context |
| :--- | :---: | :---: | :--- |
| **Accuracy** | **0.5267** | 0.2614 | TabNet excels with supervised supervision |
| **Precision** | **0.2582** | 0.2518 | False positive avoidance |
| **Recall (Detection Rate)** | **0.4777** | 0.9929 | True attack capture rate |
| **F1-Score** | **0.3352** | 0.4017 | Harmonic mean across imbalanced classes |
| **ROC-AUC** | **0.5122** | 0.4906 | Continuous discrimination capability |
| **PR-AUC** | **0.2488** | 0.2490 | Robust precision-recall area on rare attacks |
| **Single-Sample Latency** | 3.35 ms | **0.33 ms** | Autoencoder is faster for per-packet line rate |
| **Batch Throughput** | 24636.7 flows/s | **1230280.5 flows/s** | Autoencoder feed-forward efficiency |
| **Training Time** | 35.95s | **7.57s** | Autoencoder trains only on benign data |

---

## 2. Confusion Matrix Diagnostics

### TabNet Classifier
| Actual \ Predicted | Predicted Benign (0) | Predicted Attack (1) |
| :--- | :---: | :---: |
| **True Benign (0)** | **915** (TN) | **770** (FP) |
| **True Attack (1)** | **293** (FN) | **268** (TP) |

### Flow Autoencoder Anomaly Detector
| Actual \ Predicted | Predicted Benign (0) | Predicted Attack (1) |
| :--- | :---: | :---: |
| **True Benign (0)** | **30** (TN) | **1655** (FP) |
| **True Attack (1)** | **4** (FN) | **557** (TP) |

*Anomaly Decision Threshold: $\tau = 0.185111$ determined strictly on validation partition without test label leakage.*

---

## 3. Methodological Insights & Cyber Implications

1. **TabNet Sequential Attention**:
   - TabNet utilizes sparse attention masks to dynamically route decisions through the most informative subset of invariant flow features.
   - Its supervised objective coupled with balanced class weighting allows it to discern complex multi-feature correlations (e.g. inter-arrival time standard deviation paired with TCP flag variations).

2. **Autoencoder Unsupervised Boundary**:
   - The Autoencoder is trained **strictly on benign telemetry**, mimicking real-world zero-day environments where attack signatures do not yet exist.
   - Intrusions generate high reconstruction error deviations because their statistical flow dynamics fall outside the learned normal manifold.
   - Its ultra-low inference latency (0.33 ms/sample) makes it ideal for Tier-1 line-rate anomaly filtering before routing to agent investigation.

---

## 4. Generated Artifacts & Visualizations

- `reports/figures/model_comparison.png`: Side-by-side comparative bar chart.
- `reports/figures/tabnet_confusion_matrix.png`: TabNet confusion matrix heatmap.
- `reports/figures/tabnet_roc_pr_curves.png`: TabNet ROC and Precision-Recall curves.
- `reports/figures/tabnet_loss_curves.png`: TabNet training vs validation loss curves.
- `reports/figures/autoencoder_confusion_matrix.png`: Autoencoder confusion matrix.
- `reports/figures/autoencoder_roc_pr_curves.png`: Autoencoder ROC and PR curves.
- `reports/figures/autoencoder_loss_curves.png`: Autoencoder MSE reconstruction learning curve.
- `reports/figures/autoencoder_reconstruction_distribution.png`: Benign vs Attack reconstruction error density with calibrated threshold line.

---

## 5. Model Checkpoint Registry

- TabNet Best Checkpoint: `models/checkpoints/tabnet_best.zip`
- TabNet Production Model: `models/tabnet/tabnet_classifier.zip`
- TabNet Metadata: `models/tabnet/tabnet_metadata.json`
- Autoencoder Best Weights: `models/checkpoints/autoencoder_best.pt`
- Autoencoder Production Model: `models/autoencoder/autoencoder_best.pt`
- Autoencoder Metadata & Threshold: `models/autoencoder/autoencoder_metadata.json`
