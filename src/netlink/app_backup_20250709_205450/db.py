"""
NetLink Database Configuration
Database engine, session management, and SQLModel setup with encryption support.
"""

import os
from sqlmodel import SQLModel, create_engine, Session
from netlink.app.logger_config import logger, settings

# Import encryption support
try:
    from netlink.app.security.database_encryption import setup_database_encryption
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    logger.warning("Database encryption not available")

# Database URL from environment or default to SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netlink.db")
ENCRYPTION_KEY = os.getenv("DATABASE_ENCRYPTION_KEY")

# Create engine with appropriate settings
if DATABASE_URL.startswith("sqlite"):
    # SQLite specific settings
    engine = create_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
        connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL/MySQL settings
    engine = create_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
        pool_pre_ping=True,
        pool_recycle=300
    )

# Setup database encryption if available
if ENCRYPTION_AVAILABLE:
    try:
        setup_database_encryption(engine, ENCRYPTION_KEY)
        logger.info("Database encryption enabled")
    except Exception as e:
        logger.error(f"Failed to setup database encryption: {e}")
else:
    logger.warning("Database encryption not available - running without encryption")

def get_session():
    """Get database session."""
    with Session(engine) as session:
        yield session

def create_db_and_tables():
    """Create database tables."""
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables created/verified")

# Database initialization is done manually when needed
# Don't initialize on import to avoid hanging
