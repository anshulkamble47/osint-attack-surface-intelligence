"""Consolidated metadata base for SQLAlchemy models and Alembic migrations."""

from backend.app.database.connection import Base
import backend.app.models  # noqa: F401 - Register all models with Base.metadata

__all__ = ["Base"]
