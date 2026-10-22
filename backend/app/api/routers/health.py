"""
Health check router.
"""

from fastapi import APIRouter
from backend.app.database.mongodb import mongodb_manager
from backend.app.models.api import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse, summary="System Health Check")
def health_check():
    """
    Checks the status of the FastAPI backend and MongoDB database connection.
    """
    is_db_connected = mongodb_manager.check_health()
    if is_db_connected:
        db_status = "connected"
        overall_status = "healthy"
    elif mongodb_manager.is_fallback:
        db_status = "in_memory_fallback"
        overall_status = "healthy"
    else:
        db_status = "disconnected"
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        database=db_status
    )
