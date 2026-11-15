"""
Unit tests for chunked CSV ingestion engine.
"""
import pytest
import pandas as pd
from pathlib import Path
from src.data.ingestion import ChunkedCSVIngestor


def test_chunked_ingestion_streaming(sample_raw_flow_data, tmp_path):
    """Verify that ChunkedCSVIngestor processes data in small streaming chunks."""
    csv_file = tmp_path / "test_flow.csv"
    sample_raw_flow_data.to_csv(csv_file, index=False)

    chunk_size = 25
    ingestor = ChunkedCSVIngestor(chunk_size=chunk_size, remove_duplicates=True)
    
    chunks = list(ingestor.process_file_chunks(csv_file))
    
    # 100 rows / 25 rows = 4 chunks
    assert len(chunks) == 4
    for features_df, meta_df, y_bin, y_cat in chunks:
        assert len(features_df) <= chunk_size
        assert "flow_duration" in features_df.columns
        assert "source_ip" in meta_df.columns
        assert len(y_bin) == len(features_df)


def test_scan_and_summarize(sample_raw_flow_data, tmp_path):
    """Verify multi-file chunked scanner and aggregator."""
    csv1 = tmp_path / "test1.csv"
    csv2 = tmp_path / "test2.csv"
    sample_raw_flow_data.to_csv(csv1, index=False)
    sample_raw_flow_data.to_csv(csv2, index=False)

    ingestor = ChunkedCSVIngestor(chunk_size=50)
    summary = ingestor.scan_and_summarize([csv1, csv2])

    assert summary["total_rows"] == 200
    assert "BENIGN" in summary["category_counts"]
    assert "DDoS" in summary["category_counts"]
    assert summary["total_flow_features"] > 0

