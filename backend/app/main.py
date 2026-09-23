"""FastAPI Application Entry Point for OSINT Attack Surface Intelligence Platform."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.api.health import router as health_router
from backend.app.database.connection import check_database_connection


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown procedures."""
    logger.info("=" * 60)
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT} | Debug: {settings.DEBUG}")
    logger.info("=" * 60)

    # Initial DB connectivity probe
    db_check = check_database_connection()
    if db_check["connected"]:
        logger.info(
            f"PostgreSQL connection verified ({db_check['dialect']}) - Latency: {db_check['latency_ms']}ms"
        )
    else:
        logger.warning(
            f"PostgreSQL connection check failed during startup: {db_check['error']}"
        )

    yield

    logger.info(f"Shutting down {settings.PROJECT_NAME}")


# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "An automated OSINT-based platform that discovers, correlates, analyzes, "
        "monitors, and reports publicly observable attack-surface information for "
        "authorized organizations and infrastructure."
    ),
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root_endpoint():
    """Platform root information endpoint."""
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "stage": "Stage 0 - Project Foundation",
        "documentation": "/api/docs",
        "health_endpoint": f"{settings.API_V1_PREFIX}/health",
    }
