"""
CyberSentinel Application Settings and Configuration.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    """Centralized configuration for CyberSentinel system."""

    # Project metadata
    PROJECT_NAME: str = "CyberSentinel"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Directories
    ROOT_DIR: Path = PROJECT_ROOT
    DATA_DIR: Path = PROJECT_ROOT / "data"
    DATA_RAW_DIR: Path = PROJECT_ROOT / "data" / "raw"
    DATA_PROCESSED_DIR: Path = PROJECT_ROOT / "data" / "processed"
    DATA_SAMPLES_DIR: Path = PROJECT_ROOT / "data" / "samples"
    DATA_METADATA_DIR: Path = PROJECT_ROOT / "data" / "metadata"
    REPORTS_DIR: Path = PROJECT_ROOT / "reports"
    FIGURES_DIR: Path = PROJECT_ROOT / "reports" / "figures"
    MODELS_DIR: Path = PROJECT_ROOT / "models"

    # Ingestion & Preprocessing Parameters
    CHUNK_SIZE: int = 50_000
    RANDOM_SEED: int = 42
    DEV_SAMPLE_SIZE: int = 100_000
    VALIDATION_SPLIT: float = 0.15
    TEST_SPLIT: float = 0.15

    # Dataset Source
    CICIDS2017_URL: str = (
        "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
    )

    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    # SQLite Database Configuration
    DATABASE_URL: str = f"sqlite:///{PROJECT_ROOT / 'cybersentinel.db'}"

    # Logging
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
