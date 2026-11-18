"""
Frontend SOC Analyst User Journey and Workflow Integration Tests.
Simulates all frontend React page transitions, API polling, and report export interactions.
"""
import io
import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_complete_frontend_soc_workflow():
    """
    Simulates the end-to-end user workflow across all 8 frontend pages:
    Dashboard Overview -> Dataset Upload -> Analysis Progress -> Threat Detection ->
    Investigation Details -> Agent Monitoring -> Model Performance -> Security Reports.
    """
    # 1. Page 1: Dashboard Overview (Health and System Readiness)
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200

    # 2. Page 2: Dataset Upload (Inspect Sample or Upload CSV)
    sample_resp = client.get("/api/sample-data?limit=5")
    assert sample_resp.status_code == 200
    assert len(sample_resp.json()["records"]) <= 5

    # 3. Page 3: Analysis Execution & Tracking
    analyze_resp = client.post(
        "/api/analyze",
        json={"sample_size": 20},
    )
    assert analyze_resp.status_code == 200
    analyze_data = analyze_resp.json()
    analysis_id = analyze_data["analysis_id"]
    assert analyze_data["status"] == "COMPLETED"

    # 4. Page 4 & 5: Threat Detection & Investigation Details
    results_resp = client.get(f"/api/results/{analysis_id}")
    assert results_resp.status_code == 200
    res_data = results_resp.json()
    assert res_data["analysis_id"] == analysis_id
    assert "risk_score" in res_data
    assert "severity" in res_data
    assert "flows_sample" in res_data
    assert "correlated_incidents" in res_data

    # 5. Page 6: Agent Monitoring (Swarm Diagnostics)
    agents_resp = client.get("/api/agents/status")
    assert agents_resp.status_code == 200
    agents_data = agents_resp.json()
    assert agents_data["active_agents_count"] == 5
    assert len(agents_data["agents"]) == 5

    # 6. Page 7: Model Performance
    metrics_resp = client.get("/api/models/metrics")
    assert metrics_resp.status_code == 200
    metrics_data = metrics_resp.json()
    assert "tabnet" in metrics_data
    assert "autoencoder" in metrics_data

    # 7. Page 8: Security Reports (View and Download)
    report_resp = client.get(f"/api/reports/{analysis_id}")
    assert report_resp.status_code == 200
    assert "markdown_report" in report_resp.json()

    # Download Markdown
    md_down = client.get(f"/api/reports/{analysis_id}/download?format=markdown")
    assert md_down.status_code == 200
    assert "# CyberSentinel Security Investigation Report" in md_down.text
    assert "text/markdown" in md_down.headers["content-type"]

    # Download JSON
    json_down = client.get(f"/api/reports/{analysis_id}/download?format=json")
    assert json_down.status_code == 200
    assert json_down.json()["task_id"] == analysis_id
