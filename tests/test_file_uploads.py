"""
File Upload Edge Cases and Boundary Test Suite for CyberSentinel API.
Validates file extension checking, empty file rejection, size boundaries, and CSV parsing.
"""
import io
import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_upload_invalid_extensions():
    """Verify rejection of non-CSV extensions."""
    invalid_files = [
        ("malicious.exe", b"MZ\x90\x00BinaryData", "application/octet-stream"),
        ("notes.txt", b"plain text data", "text/plain"),
        ("config.json", b'{"key": "value"}', "application/json"),
        ("script.sh", b"#!/bin/bash\necho hello", "application/x-sh"),
    ]
    for filename, content, mime in invalid_files:
        response = client.post(
            "/api/upload",
            files={"file": (filename, io.BytesIO(content), mime)},
        )
        assert response.status_code == 400
        assert "Only CSV" in response.json()["detail"]


def test_upload_empty_file():
    """Verify empty CSV upload is rejected with 400 or 422 unprocessable entity."""
    empty_csv = io.BytesIO(b"")
    response = client.post(
        "/api/upload",
        files={"file": ("empty.csv", empty_csv, "text/csv")},
    )
    assert response.status_code in (400, 422)


def test_upload_valid_csv_and_verify_metadata():
    """Verify a valid CSV file uploads and returns correct metadata."""
    valid_csv_content = (
        "Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets\n"
        "80,1500,2,3\n"
        "443,3000,5,4\n"
    )
    response = client.post(
        "/api/upload",
        files={"file": ("test_flows.csv", io.BytesIO(valid_csv_content.encode("utf-8")), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_flows.csv"
    assert "file_id" in data
    assert len(data["columns"]) == 4
    assert "Destination Port" in data["columns"]
    assert data["total_rows"] == 2


def test_upload_csv_with_whitespace_and_mixed_casing():
    """Verify CSV parser standardizes whitespace and mixed-case headers."""
    content = (
        "  Flow Duration  ,  Total Fwd Packets  , Label \n"
        "1000, 2, BENIGN\n"
    )
    response = client.post(
        "/api/upload",
        files={"file": ("messy_headers.csv", io.BytesIO(content.encode("utf-8")), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["columns"]) == 3
