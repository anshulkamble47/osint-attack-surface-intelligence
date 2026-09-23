"""Health check and readiness endpoints for the platform."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import APIRouter, status
from pydantic import BaseModel
from backend.app.core.config import settings
from backend.app.database.connection import check_database_connection

router = APIRouter(prefix="/health", tags=["Health & System Status"])


class DatabaseHealth(BaseModel):
    connected: bool
    dialect: str
    latency_ms: float
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: str
    database: DatabaseHealth


@router.get(
    "",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Platform & Database Health Check",
    description="Returns backend service status along with live PostgreSQL database connectivity probe.",
)
def get_health() -> HealthResponse:
    """Check overall service health including database availability."""
    db_status = check_database_connection()
    overall_status = "ok" if db_status["connected"] else "degraded"

    return HealthResponse(
        status=overall_status,
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc).isoformat(),
        database=DatabaseHealth(**db_status),
    )


@router.get(
    "/db",
    response_model=DatabaseHealth,
    status_code=status.HTTP_200_OK,
    summary="Dedicated Database Probe",
    description="Explicitly inspects database connection latency, driver, and error details.",
)
def get_db_health() -> DatabaseHealth:
    """Dedicated endpoint to check only the database connection."""
    db_status = check_database_connection()
    return DatabaseHealth(**db_status)
