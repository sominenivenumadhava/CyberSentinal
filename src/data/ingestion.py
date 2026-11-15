"""
Chunked CSV Ingestion Engine for CyberSentinel.
Scalably processes large network flow datasets (e.g. CICIDS2017) using streaming chunks,
preventing memory overflow, separating identifiers, handling inf/nan, and tracking dataset lineage.
"""
from typing import Generator, Dict, Any, List, Optional, Tuple
from pathlib import Path
import logging
import pandas as pd
import numpy as np
from tqdm import tqdm

from config.settings import settings
from src.data.schema import clean_column_name, normalize_label, get_attack_category, IDENTIFIER_COLUMNS
from src.data.preprocessor import FlowPreprocessor

logger = logging.getLogger(__name__)


class ChunkedCSVIngestor:
    """
    High-throughput, memory-efficient CSV stream processor for network telemetry.
    """

    def __init__(
        self,
        chunk_size: int = settings.CHUNK_SIZE,
        handle_inf: bool = True,
        remove_duplicates: bool = True,
    ):
        self.chunk_size = chunk_size
        self.handle_inf = handle_inf
        self.remove_duplicates = remove_duplicates
        self.preprocessor = FlowPreprocessor(handle_inf=handle_inf)

    def process_file_chunks(
        self, file_path: Path
    ) -> Generator[Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series], None, None]:
        """
        Yield processed chunks from a single CSV file:
        Yields (features_df, meta_df, y_binary, y_category) per chunk.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"CSV file not found: {file_path}")

        logger.info(f"Ingesting file in chunks ({self.chunk_size} rows/chunk): {file_path.name}")
        
        # Ingest in chunks
        chunk_iter = pd.read_csv(
            file_path,
            chunksize=self.chunk_size,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace"
        )

        for chunk_idx, raw_chunk in enumerate(chunk_iter):
            # 1. Clean column headers
            chunk = self.preprocessor.standardize_column_names(raw_chunk)

            # 2. Duplicate removal
            if self.remove_duplicates:
                chunk = chunk.drop_duplicates()

            # 3. Separate features, identifiers, and labels
            features_df, meta_df, y_binary, y_category = (
                self.preprocessor.separate_identifiers_and_labels(chunk)
            )

            # 4. Clean inf and nan in features
            features_df = self.preprocessor.clean_inf_and_nan(features_df)

            yield features_df, meta_df, y_binary, y_category

    def scan_and_summarize(self, file_paths: List[Path]) -> Dict[str, Any]:
        """
        Scan multiple CSV files using chunk processing and compute dataset-wide statistics
        without loading the full dataset into RAM.
        """
        total_rows = 0
        total_duplicates = 0
        label_counts = {}
        category_counts = {}
        missing_counts = {}
        inf_counts = {}
        detected_features = set()

        for fpath in file_paths:
            logger.info(f"Scanning {fpath.name}...")
            chunk_iter = pd.read_csv(
                fpath,
                chunksize=self.chunk_size,
                low_memory=False,
                encoding="utf-8",
                encoding_errors="replace"
            )
            for raw_chunk in chunk_iter:
                raw_len = len(raw_chunk)
                total_rows += raw_len

                cleaned = self.preprocessor.standardize_column_names(raw_chunk)
                dup_count = raw_len - len(cleaned.drop_duplicates())
                total_duplicates += dup_count

                features_df, meta_df, y_bin, y_cat = (
                    self.preprocessor.separate_identifiers_and_labels(cleaned)
                )

                detected_features.update(features_df.columns)

                # Count labels
                if y_cat is not None:
                    for cat, count in y_cat.value_counts().items():
                        category_counts[cat] = category_counts.get(cat, 0) + int(count)

                # Count nulls and infs
                for col in features_df.columns:
                    numeric_col = pd.to_numeric(features_df[col], errors="coerce")
                    null_count = int(numeric_col.isna().sum())
                    inf_count = int(np.isinf(numeric_col).sum())
                    missing_counts[col] = missing_counts.get(col, 0) + null_count
                    inf_counts[col] = inf_counts.get(col, 0) + inf_count

        return {
            "total_rows": total_rows,
            "total_duplicates": total_duplicates,
            "category_counts": category_counts,
            "missing_value_counts": missing_counts,
            "infinite_value_counts": inf_counts,
            "total_flow_features": len(detected_features),
            "features": sorted(list(detected_features)),
        }

