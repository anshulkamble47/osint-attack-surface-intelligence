"""Database connection, engine configuration, and session management."""

import time
import socket
from urllib.parse import urlparse
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.app.core.config import settings
from backend.app.core.logging import logger

# SQLAlchemy Engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
    connect_args={"connect_timeout": 2},
    echo=False,
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for future models
Base = declarative_base()


def get_db() -> Generator:
    """FastAPI dependency yielding database sessions with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_connection() -> Dict[str, Any]:
    """
    Perform a live health probe against PostgreSQL.
    Uses an initial socket probe to avoid blocking timeouts when DB is offline,
    followed by an active SQLAlchemy query.
    """
    start_time = time.perf_counter()
    parsed_url = urlparse(settings.DATABASE_URL)
    host = parsed_url.hostname or "127.0.0.1"
    port = parsed_url.port or 5432

    # Fast socket pre-check (1.0s max timeout)
    try:
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as sock_err:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "connected": False,
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": f"PostgreSQL port unreachable at {host}:{port} ({sock_err})",
        }

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "connected": True,
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": None,
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Database connection check failed: {exc}")
        return {
            "connected": False,
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": str(exc),
        }
