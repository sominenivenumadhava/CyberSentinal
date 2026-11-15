# CyberSentinel: Dataset Profiling & Telemetry Analysis Report

**Analysis Timestamp**: Generated during Day 1 Pipeline Verification  
**Total Records Analyzed**: 14,970  
**Total Behavioral Features**: 76  

---

## 1. Class & Label Distribution

| Metric | Flow Count | Percentage |
| :--- | :--- | :--- |
| **BENIGN (Normal Traffic)** | 11,228 | 75.0% |
| **ATTACK (Malicious Telemetry)** | 3,742 | 25.0% |
| **Total Ingested Telemetry** | 14,970 | 100.0% |

---

## 2. Attack Category Breakdown

| Attack Taxonomy | Flow Count | Relative Share (%) |
| :--- | :--- | :--- |
| **BENIGN** | 11,228 | 75.003% |
| **DoS** | 1,451 | 9.693% |
| **PortScan** | 896 | 5.985% |
| **DDoS** | 750 | 5.010% |
| **BruteForce** | 525 | 3.507% |
| **WebAttack** | 60 | 0.401% |
| **Bot** | 45 | 0.301% |
| **Infiltration** | 15 | 0.100% |

---

## 3. Data Quality & Numerical Integrity

- **Total Missing / NaN Cells**: 35
- **Total Infinite (Inf / -Inf) Cells**: 0
- **Sanitization Strategy**: Median imputation and percentile quantile bounding (0.1% to 99.9%) fitted strictly on training distributions.

### Features Requiring Cleaning:
- `flow_bytes_s`: NaN count = 20, Inf count = 0
- `flow_packets_s`: NaN count = 15, Inf count = 0

---

## 4. Analytical Visualizations Generated

1. `reports/figures/label_distribution.png`: Binary flow classification breakdown.
2. `reports/figures/attack_category_distribution.png`: Multi-class taxonomy frequencies on log scale.
3. `reports/figures/missing_values_report.png`: Missing and infinite value diagnostic bars.
4. `reports/figures/feature_correlation_heatmap.png`: High-resolution Pearson correlation matrix.
