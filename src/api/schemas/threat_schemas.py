"""
Pydantic schemas for CyberSentinel API requests and responses.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    file_id: str
    filename: str
    total_rows: int
    columns: List[str]
    file_size_bytes: int
    message: str


class AnalyzeRequest(BaseModel):
    file_id: Optional[str] = Field(None, description="Uploaded file identifier or 'dev_sample'")
    sample_size: Optional[int] = Field(50, ge=1, le=1000, description="Number of flow records to analyze (1-1000)")
    raw_flows: Optional[List[Dict[str, Any]]] = Field(None, description="Inline list of flow feature dictionaries")


class AnalyzeResponse(BaseModel):
    analysis_id: str
    status: str
    total_flows: int
    attacks_detected: int
    anomalies_detected: int
    correlated_incidents_count: int
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    executive_summary: Optional[str] = None
    message: str


class AnalysisResultResponse(BaseModel):
    analysis_id: str
    status: str
    created_at: str
    filename: Optional[str] = None
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    total_flows_evaluated: int
    malicious_flows_count: int
    anomalous_flows_count: int
    conflict_resolution: Optional[str] = None
    execution_trace: Dict[str, Any] = Field(default_factory=dict)
    correlated_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)
    executive_summary: Optional[str] = None
    flows_sample: List[Dict[str, Any]] = Field(default_factory=list)
    shap_summary: Optional[Dict[str, Any]] = None


class AgentDetail(BaseModel):
    role: str
    name: str
    status: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class AgentsStatusResponse(BaseModel):
    coordinator_status: str
    active_agents_count: int
    agents: Dict[str, AgentDetail]
    system_resources: Dict[str, Any]


class ModelMetricDetail(BaseModel):
    model_name: str
    architecture: str
    type: str
    metrics: Dict[str, Any]
    confusion_matrix: Dict[str, int]
    performance_benchmarks: Dict[str, Any]
    artifacts: Dict[str, str]


class ModelMetricsResponse(BaseModel):
    tabnet: ModelMetricDetail
    autoencoder: ModelMetricDetail
    last_evaluated: str


class ReportResponse(BaseModel):
    analysis_id: str
    generated_at: str
    markdown_report: str
    json_report: Dict[str, Any]
