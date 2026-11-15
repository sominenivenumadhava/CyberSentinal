"""
FastAPI Application Entrypoint for CyberSentinel.
High-throughput asynchronous API gateway for streaming telemetry,
threat detection alerts, explainability attributions, and agent triage.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config.settings import settings
from src.core.database import init_db, get_db


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


@app.get("/", tags=["Root"])
def root():
    """API welcome and navigation."""
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
    }

