"""
FastAPI Main Application Entrypoint.
Provides REST APIs and WebSocket streams for dashboard metrics, events, sessions, attacker profiling, alerts, and analytics.
"""

import asyncio
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routers import (
    alerts_router,
    analytics_router,
    attackers_router,
    dashboard_router,
    events_router,
    health_router,
    sessions_router,
)
from backend.app.api.routers.websocket import router as websocket_router
from backend.app.config import settings
from backend.app.database.mongodb import mongodb_manager
from backend.app.services.websocket_manager import websocket_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("backend.app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown lifecycle.
    """
    logger.info("Initializing Intent-Aware Deception System API...")
    try:
        mongodb_manager.connect()
    except Exception as e:
        logger.warning("MongoDB connection could not be established at startup: %s", e)

    # Register main event loop with websocket manager for thread-safe cross-thread broadcasting
    websocket_manager.set_event_loop(asyncio.get_running_loop())

    yield

    logger.info("Shutting down API server...")
    mongodb_manager.close()


app = FastAPI(
    title="Intent-Aware Deception System API",
    description="Real-Time Attacker Profiling and Intent Classification REST & WebSocket API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"^https?://.*$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"]
)

# Register REST API Routers under /api prefix
app.include_router(health_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(sessions_router, prefix="/api")
app.include_router(attackers_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(analytics_router, prefix="/api")

# Register WebSocket Routers
app.include_router(websocket_router)


@app.get("/api", include_in_schema=False)
@app.get("/", include_in_schema=False)
def root():
    return {
        "message": "Intent-Aware Deception System API is running",
        "docs": "/docs",
        "health": "/api/health",
        "ws_events": "/ws/events",
        "ws_alerts": "/ws/alerts"
    }
