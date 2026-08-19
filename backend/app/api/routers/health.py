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
    return HealthResponse(
        status="healthy" if is_db_connected else "degraded",
        database="connected" if is_db_connected else "disconnected"
    )
