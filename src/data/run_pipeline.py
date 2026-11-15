"""
End-to-End Data Pipeline Execution Script for CyberSentinel.
Runs chunked ingestion, preprocessing, metadata isolation, stratified sampling,
exploratory data analysis, and database lineage registration.
"""
import os
import sys
import hashlib
from pathlib import Path
import pandas as pd
import numpy as np

# Configure Matplotlib cache directory
mpl_cache = Path("./.cache/matplotlib").resolve()
mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ["MPLCONFIGDIR"] = str(mpl_cache)

from config.settings import settings
from config.logging_config import logger
from src.core.database import SessionLocal, init_db
from src.core.models import DatasetRegistry
from src.data.downloader import check_existing_raw_files
from src.data.ingestion import ChunkedCSVIngestor
from src.data.preprocessor import FlowPreprocessor
from src.data.sampler import StratifiedFlowSampler
from src.utils.analysis import DatasetAnalyzer


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 checksum of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_pipeline():
    logger.info("=" * 70)
    logger.info("       STARTING CYBERSENTINEL DATA INGESTION & PREPROCESSING")
    logger.info("=" * 70)

    # 1. Initialize SQLite Database
    init_db()
    db = SessionLocal()

    # 2. Check for raw data files
    raw_files = check_existing_raw_files(settings.DATA_RAW_DIR)
    if not raw_files:
        logger.error(f"No CSV files found in {settings.DATA_RAW_DIR}.")
        sys.exit(1)

    logger.info(f"[+] Found {len(raw_files)} raw CSV file(s) for ingestion.")
    for f in raw_files:
        logger.info(f"    - {f.name} ({f.stat().st_size / (1024*1024):.2f} MB)")

    # 3. Chunked Ingestion & Aggregation
    ingestor = ChunkedCSVIngestor(
        chunk_size=settings.CHUNK_SIZE,
        remove_duplicates=True,
        handle_inf=True,
    )
    
    logger.info("[*] Running multi-file chunked scanner and quality profiler...")
    scan_summary = ingestor.scan_and_summarize(raw_files)
    logger.info(f"[+] Ingestion scan complete. Total records scanned: {scan_summary['total_rows']:,}")
    logger.info(f"[+] Duplicates detected & handled: {scan_summary['total_duplicates']:,}")

    # 4. Stream and process full dataset through chunks
    all_features = []
    all_meta = []
    all_y_bin = []
    all_y_cat = []

    for fpath in raw_files:
        logger.info(f"[*] Processing chunks for: {fpath.name}")
        for feat_chunk, meta_chunk, y_bin_chunk, y_cat_chunk in ingestor.process_file_chunks(fpath):
            all_features.append(feat_chunk)
            all_meta.append(meta_chunk)
            all_y_bin.append(y_bin_chunk)
            all_y_cat.append(y_cat_chunk)

    full_features = pd.concat(all_features, ignore_index=True)
    full_meta = pd.concat(all_meta, ignore_index=True)
    full_y_bin = pd.concat(all_y_bin, ignore_index=True)
    full_y_cat = pd.concat(all_y_cat, ignore_index=True)

    logger.info(f"[+] Combined extracted telemetry: {len(full_features):,} rows, {full_features.shape[1]} flow features.")
    logger.info(f"[+] Isolated metadata (IPs/Ports/Timestamps): {full_meta.shape[1]} columns.")

    # 5. Fit Preprocessor (learn imputations, scalers, and drop zero-variance features)
    logger.info("[*] Fitting FlowPreprocessor on telemetry...")
    preprocessor = FlowPreprocessor(scaler_type="robust", variance_threshold=0.0)
    preprocessor.fit(full_features)

    # Save fitted preprocessor
    prep_path = settings.DATA_METADATA_DIR / "preprocessor.joblib"
    schema_path = settings.DATA_METADATA_DIR / "feature_schema.json"
    preprocessor.save(prep_path, schema_path)
    logger.info(f"[+] Preprocessor serialized to: {prep_path}")
    logger.info(f"[+] Feature schema exported to: {schema_path} ({len(preprocessor.feature_names_)} active features)")

    # 6. Transform Telemetry
    logger.info("[*] Transforming flow features with learned statistics...")
    transformed_features = preprocessor.transform(full_features)

    # 7. Stratified Sampling & Splitting
    logger.info("[*] Creating reproducible stratified development sample (seed=42)...")
    sampler = StratifiedFlowSampler(random_seed=settings.RANDOM_SEED)
    
    sub_X, sub_meta, sub_y_bin, sub_y_cat = sampler.create_stratified_dev_sample(
        transformed_features,
        full_meta,
        full_y_bin,
        full_y_cat,
        target_size=settings.DEV_SAMPLE_SIZE,
        min_samples_per_class=50,
    )

    # Save development samples
    dev_sample_parquet = settings.DATA_SAMPLES_DIR / "dev_sample.parquet"
    dev_sample_csv = settings.DATA_SAMPLES_DIR / "dev_sample.csv"
    dev_meta_csv = settings.DATA_SAMPLES_DIR / "dev_sample_meta.csv"

    # Merge features with labels for development dataset
    dev_df = sub_X.copy()
    dev_df["is_attack"] = sub_y_bin.values
    dev_df["attack_category"] = sub_y_cat.values

    dev_df.to_parquet(dev_sample_parquet, index=False)
    dev_df.to_csv(dev_sample_csv, index=False)
    sub_meta.to_csv(dev_meta_csv, index=False)

    logger.info(f"[+] Saved development sample: {dev_sample_parquet} ({len(dev_df):,} rows)")
    logger.info(f"[+] Saved companion metadata: {dev_meta_csv}")

    # Generate Train/Val/Test partitions
    logger.info("[*] Generating train/validation/test partitions...")
    splits = sampler.train_val_test_split(sub_X, sub_y_bin, sub_y_cat)
    
    for split_name in ("train", "val", "test"):
        split_df = splits[f"X_{split_name}"].copy()
        split_df["is_attack"] = splits[f"y_{split_name}"].values
        split_file = settings.DATA_PROCESSED_DIR / f"{split_name}.parquet"
        split_df.to_parquet(split_file, index=False)
        logger.info(f"[+] Saved {split_name} partition: {split_file} ({len(split_df):,} rows)")

    # 8. Analytical Visualizations and Reports
    logger.info("[*] Running DatasetAnalyzer for statistical profiling and charts...")
    analyzer = DatasetAnalyzer(output_dir=settings.FIGURES_DIR)
    report = analyzer.analyze_dataset(
        features_df=full_features,
        y_binary=full_y_bin,
        y_category=full_y_cat,
        meta_df=full_meta,
        save_plots=True,
    )
    logger.info("[+] Visualizations generated successfully in reports/figures/:")
    logger.info("    - label_distribution.png")
    logger.info("    - attack_category_distribution.png")
    logger.info("    - missing_values_report.png")
    logger.info("    - feature_correlation_heatmap.png")
    logger.info(f"[+] Markdown report generated: {settings.REPORTS_DIR / 'DATASET_ANALYSIS.md'}")

    # 9. Register in SQLite Database Lineage
    for f in raw_files:
        rec = DatasetRegistry(
            dataset_name=f.stem,
            source_path=str(f.resolve()),
            total_records=len(dev_df),
            benign_count=int((sub_y_bin == 0).sum()),
            attack_count=int((sub_y_bin == 1).sum()),
            file_hash_sha256=calculate_sha256(f),
            metadata_json={
                "features": preprocessor.feature_names_,
                "num_features": len(preprocessor.feature_names_),
                "categories": sub_y_cat.value_counts().to_dict(),
            }
        )
        db.add(rec)
    db.commit()
    db.close()
    logger.info("[+] Dataset registered in SQLite database: cybersentinel.db")

    logger.info("=" * 70)
    logger.info("       DATA INGESTION & PREPROCESSING PIPELINE COMPLETED!")
    logger.info("=" * 70)


if __name__ == "__main__":
    run_pipeline()

