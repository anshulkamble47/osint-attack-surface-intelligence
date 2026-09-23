# Stage 0: Project Foundation Specification & Verification

## 1. Overview

Stage 0 establishes the software foundation and architecture for the **OSINT-Based Attack Surface Intelligence & Risk Analysis Platform**.

This foundation comprises:
- **FastAPI Backend Server:** Modular Python application entrypoint with configuration management (`pydantic-settings`), structured logging, and health/readiness endpoints.
- **PostgreSQL 16 Engine:** Relational database service managed via Docker Compose (`docker-compose.yml`) using `psycopg3` driver with pre-ping connection pooling.
- **React + TypeScript Frontend:** Modern user interface powered by Vite with dark-mode cybersecurity aesthetics, auto-polling health checks, and responsive diagnostic panels.
- **Containerization & Testing:** Docker Compose service for PostgreSQL and automated Pytest test suite for backend health diagnostics.

---

## 2. API Endpoints (Stage 0)

| Method | Path | Description | Response Model |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Root service metadata, stage, and docs pointers | JSON |
| `GET` | `/api/health` | Comprehensive health check (FastAPI + PostgreSQL connection probe) | `HealthResponse` |
| `GET` | `/api/health/db` | Dedicated PostgreSQL connectivity latency and driver diagnostics | `DatabaseHealth` |
| `GET` | `/api/docs` | Interactive Swagger UI API documentation | HTML |
| `GET` | `/api/redoc` | ReDoc API documentation | HTML |

---

## 3. Database Connection Probe Logic

The database connection probe executes an active `SELECT 1` query to verify:
1. TCP connectivity to the PostgreSQL container.
2. Authentication validity with configured credentials (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`).
3. Connection pool readiness and round-trip query latency (in milliseconds).
4. Graceful degradation: if the database is unreachable or starting up, the API returns a status of `degraded` with the explicit error string, rather than crashing.

---

## 4. Verification Checklist

- [x] Python 3.13 virtual environment configured at `backend/.venv`
- [x] Backend dependencies installed (`fastapi`, `uvicorn`, `sqlalchemy`, `psycopg[binary]`, `pydantic-settings`, `pytest`)
- [x] PostgreSQL service defined in `docker-compose.yml` with health checks
- [x] Frontend created with React 18, TypeScript, and Vite
- [x] Frontend API proxy configured to forward `/api` requests to backend on port 8000
- [x] Frontend UI tested for real-time health polling and visual diagnostics
- [x] Automated test suite created in `tests/test_health.py`
