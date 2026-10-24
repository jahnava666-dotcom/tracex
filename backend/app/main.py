from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import settings
from .db.init_db import init_db
from .api.routes import (
    health,
    analyze_email,
    threat_intel,
    geolocation,
    cases,
    evidence,
    reports,
    ai_assistant,
    chat
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB and ensure tables exist
    print(f"[TRACE-X] Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}")
    init_db()
    yield
    # Shutdown
    print(f"[TRACE-X] Backend server shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Backend API for TRACE-X: AI-Powered Email Threat Detection, Geolocation, and Forensic Intelligence Platform.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits all localhost ports in dev (5173, 3000, 8000, etc.)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"[TRACE-X Server Error] {request.method} {request.url}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal forensic processing exception occurred.", "error": str(exc)}
    )

# Register API Routers
app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(analyze_email.router, prefix=settings.API_V1_PREFIX)
app.include_router(threat_intel.router, prefix=settings.API_V1_PREFIX)
app.include_router(geolocation.router, prefix=settings.API_V1_PREFIX)
app.include_router(cases.router, prefix=settings.API_V1_PREFIX)
app.include_router(evidence.router, prefix=settings.API_V1_PREFIX)
app.include_router(reports.router, prefix=settings.API_V1_PREFIX)
app.include_router(ai_assistant.router, prefix=settings.API_V1_PREFIX)
app.include_router(chat.router, prefix=settings.API_V1_PREFIX)

@app.get("/")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "status": "online",
        "docs": "/docs",
        "apiPrefix": settings.API_V1_PREFIX
    }
