"""
Structured logging configuration for CyberSentinel.
"""
import sys
import logging
from config.settings import settings

def setup_logging(log_level: str = None) -> logging.Logger:
    """Configure root logger with consistent formatting."""
    level = log_level or settings.LOG_LEVEL
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("CyberSentinel")
    return logger

logger = setup_logging()
