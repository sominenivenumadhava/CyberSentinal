"""
Dataset Profiling, Analysis and Visualization Engine for CyberSentinel.
Generates comprehensive empirical summaries, label distributions, missing value diagnostics,
and correlation heatmaps for CICIDS2017 network flow telemetry.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import logging
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend suitable for headless and server environments
import matplotlib.pyplot as plt
import seaborn as sns

from config.settings import settings

logger = logging.getLogger(__name__)


class DatasetAnalyzer:
    """
    Computes statistical diagnostics and visualization reports for network flow telemetry.
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or settings.FIGURES_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Apply standard style
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    def analyze_dataset(
        self,
        features_df: pd.DataFrame,
        y_binary: pd.Series,
        y_category: pd.Series,
        meta_df: Optional[pd.DataFrame] = None,
        save_plots: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate complete analytical report and visualizations.
        """
        total_records = len(features_df)
        num_features = features_df.shape[1]

        # 1. Label distribution
        binary_counts = y_binary.value_counts().to_dict()
        benign_count = binary_counts.get(0, 0)
        attack_count = binary_counts.get(1, 0)
        benign_pct = (benign_count / total_records * 100) if total_records > 0 else 0
        attack_pct = (attack_count / total_records * 100) if total_records > 0 else 0

        # 2. Attack category distribution
        cat_counts = y_category.value_counts().to_dict()
        cat_percentages = {
            k: (v / total_records * 100) for k, v in cat_counts.items()
        }

        # 3. Missing and infinite value analysis
        missing_per_col = features_df.isna().sum()
        cols_with_missing = missing_per_col[missing_per_col > 0].to_dict()
        total_missing_cells = int(missing_per_col.sum())

        inf_per_col = np.isinf(features_df.select_dtypes(include=[np.number])).sum()
        cols_with_inf = inf_per_col[inf_per_col > 0].to_dict()
        total_inf_cells = int(inf_per_col.sum())

        # 4. Statistical properties of numeric features
        numeric_df = features_df.select_dtypes(include=[np.number])
        summary_stats = numeric_df.describe().to_dict()

        report = {
            "total_records": total_records,
            "num_features": num_features,
            "benign_count": benign_count,
            "benign_percentage": round(benign_pct, 2),
            "attack_count": attack_count,
            "attack_percentage": round(attack_pct, 2),
            "category_distribution": cat_counts,
            "category_percentages": {k: round(v, 3) for k, v in cat_percentages.items()},
            "missing_values": {
                "total_missing_cells": total_missing_cells,
                "columns_affected": cols_with_missing,
            },
            "infinite_values": {
                "total_infinite_cells": total_inf_cells,
                "columns_affected": cols_with_inf,
            },
        }

        if save_plots:
            self.plot_label_distribution(benign_count, attack_count)
            self.plot_category_distribution(cat_counts)
            self.plot_missing_values(cols_with_missing, cols_with_inf)
            self.plot_correlation_matrix(numeric_df)
            self.export_markdown_report(report)

        return report

    def plot_label_distribution(self, benign: int, attack: int):
        """Generate binary label breakdown pie and bar chart."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Bar chart
        labels = ["Benign (0)", "Attack (1)"]
        counts = [benign, attack]
        colors = ["#2ecc71", "#e74c3c"]
        bars = ax1.bar(labels, counts, color=colors, edgecolor="black", alpha=0.85)
        ax1.set_title("Binary Flow Classification Distribution", fontsize=13, fontweight="bold")
        ax1.set_ylabel("Flow Count", fontsize=11)
        for bar in bars:
            yval = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2.0, yval + (max(counts) * 0.01), f"{yval:,}", ha="center", va="bottom", fontsize=10)

        # Donut chart
        total = benign + attack
        pcts = [benign/total, attack/total] if total > 0 else [0.5, 0.5]
        ax2.pie(pcts, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140,
                wedgeprops=dict(width=0.4, edgecolor='white', linewidth=2))
        ax2.set_title("Proportion of Malicious vs Normal Telemetry", fontsize=13, fontweight="bold")

        plt.tight_layout()
        save_path = self.output_dir / "label_distribution.png"
        fig.savefig(save_path, dpi=300)
        plt.close(fig)
        logger.info(f"Saved label distribution plot: {save_path}")

    def plot_category_distribution(self, cat_counts: Dict[str, int]):
        """Generate attack category frequency chart with log-scale support for rare classes."""
        fig, ax = plt.subplots(figsize=(12, 6))
        sorted_items = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        categories = [x[0] for x in sorted_items]
        counts = [x[1] for x in sorted_items]

        palette = sns.color_palette("viridis", len(categories))
        bars = ax.barh(categories[::-1], counts[::-1], color=palette, edgecolor="black", alpha=0.85)
        ax.set_xscale("log")
        ax.set_xlabel("Number of Network Flows (Log Scale)", fontsize=11, fontweight="bold")
        ax.set_title("Attack Category Distribution Across Ingested Telemetry", fontsize=13, fontweight="bold")

        for bar in bars:
            val = bar.get_width()
            ax.text(val * 1.08, bar.get_y() + bar.get_height()/2.0, f"{val:,}", ha="left", va="center", fontsize=9)

        plt.tight_layout()
        save_path = self.output_dir / "attack_category_distribution.png"
        fig.savefig(save_path, dpi=300)
        plt.close(fig)
        logger.info(f"Saved attack category plot: {save_path}")

    def plot_missing_values(self, cols_missing: Dict[str, int], cols_inf: Dict[str, int]):
        """Generate visual diagnostics for missing and infinite telemetry entries."""
        combined = {}
        for col, c in cols_missing.items():
            combined[col] = combined.get(col, 0) + c
        for col, c in cols_inf.items():
            combined[col] = combined.get(col, 0) + c

        fig, ax = plt.subplots(figsize=(10, 5))
        if combined:
            sorted_items = sorted(combined.items(), key=lambda x: x[1], reverse=True)[:15]
            cols = [x[0] for x in sorted_items]
            vals = [x[1] for x in sorted_items]
            bars = ax.bar(cols, vals, color="#f39c12", edgecolor="black", alpha=0.85)
            ax.set_xticks(range(len(cols)))
            ax.set_xticklabels(cols, rotation=45, ha="right", fontsize=9)
            ax.set_ylabel("Occurrence Count", fontsize=11)
            ax.set_title("Top Network Flow Attributes with NaN / Inf Values", fontsize=13, fontweight="bold")
            for bar in bars:
                yval = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, f"{yval:,}", ha="center", va="bottom", fontsize=8)
        else:
            ax.text(0.5, 0.5, "Zero Missing or Infinite Values Detected", ha="center", va="center", fontsize=14, color="green")
            ax.set_axis_off()

        plt.tight_layout()
        save_path = self.output_dir / "missing_values_report.png"
        fig.savefig(save_path, dpi=300)
        plt.close(fig)
        logger.info(f"Saved missing value report plot: {save_path}")

    def plot_correlation_matrix(self, numeric_df: pd.DataFrame, top_k: int = 18):
        """Generate high-resolution correlation matrix heatmap of top salient flow features."""
        # Select top features by variance
        variances = numeric_df.var().sort_values(ascending=False)
        top_cols = variances.head(top_k).index.tolist()
        
        subset_df = numeric_df[top_cols]
        corr_matrix = subset_df.corr().fillna(0.0)

        fig, ax = plt.subplots(figsize=(14, 12))
        mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
        sns.heatmap(
            corr_matrix,
            mask=mask,
            cmap="coolwarm",
            vmax=1.0,
            vmin=-1.0,
            center=0,
            annot=True,
            fmt=".2f",
            square=True,
            linewidths=0.5,
            cbar_kws={"shrink": 0.8},
            ax=ax,
            annot_kws={"size": 8}
        )
        ax.set_title(f"Feature Correlation Matrix (Top {top_k} Variational Flow Telemetry Features)", fontsize=14, fontweight="bold", pad=15)
        plt.xticks(rotation=45, ha="right", fontsize=9)
        plt.yticks(rotation=0, fontsize=9)

        plt.tight_layout()
        save_path = self.output_dir / "feature_correlation_heatmap.png"
        fig.savefig(save_path, dpi=300)
        plt.close(fig)
        logger.info(f"Saved feature correlation heatmap: {save_path}")

    def export_markdown_report(self, report_data: Dict[str, Any], file_path: Optional[Path] = None):
        """Save statistical breakdown as a clean Markdown report."""
        dest = file_path or (settings.REPORTS_DIR / "DATASET_ANALYSIS.md")
        dest.parent.mkdir(parents=True, exist_ok=True)

        md = f"""# CyberSentinel: Dataset Profiling & Telemetry Analysis Report

**Analysis Timestamp**: Generated during Day 1 Pipeline Verification  
**Total Records Analyzed**: {report_data['total_records']:,}  
**Total Behavioral Features**: {report_data['num_features']}  

---

## 1. Class & Label Distribution

| Metric | Flow Count | Percentage |
| :--- | :--- | :--- |
| **BENIGN (Normal Traffic)** | {report_data['benign_count']:,} | {report_data['benign_percentage']}% |
| **ATTACK (Malicious Telemetry)** | {report_data['attack_count']:,} | {report_data['attack_percentage']}% |
| **Total Ingested Telemetry** | {report_data['total_records']:,} | 100.0% |

---

## 2. Attack Category Breakdown

| Attack Taxonomy | Flow Count | Relative Share (%) |
| :--- | :--- | :--- |
"""
        for cat, cnt in sorted(report_data['category_distribution'].items(), key=lambda x: x[1], reverse=True):
            pct = report_data['category_percentages'].get(cat, 0.0)
            md += f"| **{cat}** | {cnt:,} | {pct:.3f}% |\n"

        md += f"""
---

## 3. Data Quality & Numerical Integrity

- **Total Missing / NaN Cells**: {report_data['missing_values']['total_missing_cells']:,}
- **Total Infinite (Inf / -Inf) Cells**: {report_data['infinite_values']['total_infinite_cells']:,}
- **Sanitization Strategy**: Median imputation and percentile quantile bounding (0.1% to 99.9%) fitted strictly on training distributions.

### Features Requiring Cleaning:
"""
        aff_missing = report_data['missing_values']['columns_affected']
        aff_inf = report_data['infinite_values']['columns_affected']
        all_aff = set(list(aff_missing.keys()) + list(aff_inf.keys()))
        if all_aff:
            for col in all_aff:
                m_cnt = aff_missing.get(col, 0)
                i_cnt = aff_inf.get(col, 0)
                md += f"- `{col}`: NaN count = {m_cnt}, Inf count = {i_cnt}\n"
        else:
            md += "- None. All features fully finite and non-null.\n"

        md += """
---

## 4. Analytical Visualizations Generated

1. `reports/figures/label_distribution.png`: Binary flow classification breakdown.
2. `reports/figures/attack_category_distribution.png`: Multi-class taxonomy frequencies on log scale.
3. `reports/figures/missing_values_report.png`: Missing and infinite value diagnostic bars.
4. `reports/figures/feature_correlation_heatmap.png`: High-resolution Pearson correlation matrix.
"""
        with open(dest, "w", encoding="utf-8") as f:
            f.write(md)
        logger.info(f"Exported dataset analysis report to {dest}")
