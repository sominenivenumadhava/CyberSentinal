"""
Integration tests for CyberSentinel FastAPI endpoints:
- System Health & Root
- Dataset CSV Upload & Validation
- Multi-Agent Swarm Analysis Trigger
- Forensic Results Retrieval
- Live Agent Status & Telemetry
- Model Performance Metrics
- Security Incident Report
"""
import io
import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify system health endpoint returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CyberSentinel"
    assert data["database"] == "sqlite_connected"


def test_root_endpoint():
    """Verify API root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert "CyberSentinel" in response.json()["message"]


def test_dashboard_ui_endpoint():
    """Verify SOC Dashboard UI endpoint serves HTML with the 3 required colors."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "CyberSentinel" in html
    # Check strictly required colors in CSS/Tailwind
    assert "14213d" in html
    assert "f4eded" in html
    assert "ff6b5b" in html



def test_get_agents_status():
    """Verify live status endpoint reports all 5 specialized agents."""
    response = client.get("/api/agents/status")
    assert response.status_code == 200
    data = response.json()
    assert data["coordinator_status"] == "ACTIVE"
    assert data["active_agents_count"] == 5
    assert "DataProcessingAgent" in data["agents"]
    assert "AttackClassificationAgent" in data["agents"]
    assert "AnomalyDetectionAgent" in data["agents"]
    assert "ThreatInvestigationAgent" in data["agents"]
    assert "RiskAssessmentAgent" in data["agents"]
    assert data["system_resources"]["sqlite_connected"] is True


def test_get_models_metrics():
    """Verify genuine model benchmarks endpoint for TabNet and Autoencoder."""
    response = client.get("/api/models/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "tabnet" in data
    assert "autoencoder" in data

    # Verify genuine TabNet metrics
    tabnet = data["tabnet"]
    assert tabnet["metrics"]["accuracy"] == 0.5267
    assert tabnet["metrics"]["recall"] == 0.4777
    assert tabnet["performance_benchmarks"]["device"] == "CPU"

    # Verify genuine Autoencoder metrics
    autoencoder = data["autoencoder"]
    assert autoencoder["metrics"]["recall"] == 0.9929
    assert autoencoder["performance_benchmarks"]["calibrated_threshold"] == 0.185111


def test_get_sample_data():
    """Verify dev sample preview endpoint returns real flow records."""
    response = client.get("/api/sample-data?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert data["returned_count"] == 10
    assert len(data["records"]) == 10
    assert len(data["columns"]) > 60


def test_upload_invalid_file_extension():
    """Verify upload rejects non-CSV files with 400 Bad Request."""
    fake_file = io.BytesIO(b"This is not a CSV")
    response = client.post(
        "/api/upload",
        files={"file": ("malware.exe", fake_file, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Only CSV (.csv) network telemetry files are accepted" in response.json()["detail"]


def test_upload_valid_csv():
    """Verify upload accepts and parses valid CSV data."""
    csv_content = (
        "Source IP,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Total Fwd Packets\n"
        "192.168.1.10,10.0.0.1,80,6,2026-11-15 10:00:00,1000,5\n"
        "192.168.1.11,10.0.0.1,443,6,2026-11-15 10:01:00,2000,8\n"
    ).encode("utf-8")
    
    response = client.post(
        "/api/upload",
        files={"file": ("test_flows.csv", io.BytesIO(csv_content), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_flows.csv"
    assert data["total_rows"] == 2
    assert "Source IP" in data["columns"]
    assert data["file_id"].startswith("UPLOAD_")


def test_end_to_end_analyze_workflow():
    """
    Test complete user workflow:
    1. POST /api/analyze with sample_size=10
    2. GET /api/results/{analysis_id}
    3. GET /api/reports/{analysis_id}
    """
    # 1. Trigger analysis on dev sample
    analyze_res = client.post("/api/analyze", json={"sample_size": 10})
    assert analyze_res.status_code == 200
    job_data = analyze_res.json()
    analysis_id = job_data["analysis_id"]
    assert job_data["status"] == "COMPLETED"
    assert job_data["total_flows"] == 10
    assert job_data["risk_score"] is not None
    assert job_data["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # 2. Retrieve detailed results
    results_res = client.get(f"/api/results/{analysis_id}")
    assert results_res.status_code == 200
    results_data = results_res.json()
    assert results_data["analysis_id"] == analysis_id
    assert results_data["total_flows_evaluated"] == 10
    assert "DataProcessingAgent" in results_data["execution_trace"]
    assert "AttackClassificationAgent" in results_data["execution_trace"]
    assert "AnomalyDetectionAgent" in results_data["execution_trace"]
    assert isinstance(results_data["correlated_incidents"], list)
    assert isinstance(results_data["recommended_actions"], list)

    # 3. Retrieve security report
    report_res = client.get(f"/api/reports/{analysis_id}")
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert report_data["analysis_id"] == analysis_id
    assert "# CyberSentinel Security Investigation Report" in report_data["markdown_report"]
    assert "Executive Summary" in report_data["markdown_report"]
    assert "Explainable AI" in report_data["markdown_report"]

    # 4. Test download endpoints (Markdown & JSON)
    dl_md = client.get(f"/api/reports/{analysis_id}/download?format=markdown")
    assert dl_md.status_code == 200
    assert "text/markdown" in dl_md.headers["content-type"]
    assert "# CyberSentinel Security Investigation Report" in dl_md.text

    dl_json = client.get(f"/api/reports/{analysis_id}/download?format=json")
    assert dl_json.status_code == 200
    assert "application/json" in dl_json.headers["content-type"]
    assert dl_json.json()["task_id"] == analysis_id
