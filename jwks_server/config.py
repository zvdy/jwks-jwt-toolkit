"""
JWKS Server Configuration Module

This module defines the configuration options for the JWKS server.
"""

import os
from typing import Dict, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class Config:
    """Base configuration class for JWKS server."""

    # Server settings
    HOST = "0.0.0.0"
    PORT = 5000
    DEBUG = False

    # JWKS storage settings
    JWKS_FOLDER = os.path.join(os.getcwd(), "jwks")
    JWKS_FILE = os.path.join(JWKS_FOLDER, "current_jwks.json")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # Backup settings
    ENABLE_BACKUPS = True
    BACKUP_FORMAT = "jwks_%Y%m%d%H%M%S.json"

    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        """Get configuration as a dictionary."""
        return {key: value for key, value in cls.__dict__.items()
                if not key.startswith('_') and key.isupper()}


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    JWKS_FOLDER = os.path.join(os.getcwd(), "test_jwks")
    JWKS_FILE = os.path.join(JWKS_FOLDER, "test_current_jwks.json")


# Set the active configuration based on environment variable
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig
}

# Get environment or default to development
ENV = os.getenv("JWKS_ENV", "development")
active_config = config_map.get(ENV, DevelopmentConfig)

logger.info(f"Using {ENV} configuration")
