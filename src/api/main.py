"""
FastAPI Application Entrypoint for CyberSentinel.
High-throughput asynchronous API gateway for streaming telemetry,
threat detection alerts, explainability attributions, and agent triage.
"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config.settings import settings
from src.core.database import init_db, get_db
from src.api.routes import threat_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle events: initialize SQLite database on startup."""
    init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Multi-Agent Cyber Threat Investigation and Detection System",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for local React dashboard development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register threat detection & multi-agent swarm router
app.include_router(threat_router)


@app.get("/health", tags=["System Health"])
def health_check():
    """System health and operational readiness status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": "sqlite_connected",
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["SOC Dashboard UI"])
def get_dashboard_ui():
    """Interactive React SOC Dashboard UI."""
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>CyberSentinel Dashboard Loading...</h1>")


@app.get("/", tags=["Root"])
def root(request: Request):
    """API welcome, navigation, or direct browser dashboard view."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        template_path = Path(__file__).parent / "templates" / "dashboard.html"
        if template_path.exists():
            with open(template_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
        "dashboard": "/dashboard",
    }

