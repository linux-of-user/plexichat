#!/usr/bin/env python3
"""
PlexiChat - Minimal Working Application

A simple, working FastAPI application without complex dependencies.
"""

import time
from typing import Dict, Any

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    print("[ERROR] FastAPI not available. Install with: pip install fastapi uvicorn")
    FASTAPI_AVAILABLE = False
    FastAPI = None

# Create the application
if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="PlexiChat API",
        description="A working chat application",
        version="1.0.0"
    )
    
    # Add CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Basic middleware
    @app.middleware("http")
    async def basic_middleware(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Routes
    @app.get("/")
    async def root():
        return {
            "message": "PlexiChat API is running!",
            "version": "1.0.0",
            "status": "operational",
            "timestamp": time.time()
        }
    
    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "1.0.0"
        }
    
    @app.get("/api/v1/status")
    async def api_status():
        return {
            "api_version": "1.0.0",
            "status": "operational",
            "features": ["basic_api", "health_check", "cors"],
            "timestamp": time.time()
        }
    
    @app.get("/api/v1/test")
    async def test_endpoint():
        return {
            "message": "Test endpoint working",
            "data": {"test": True, "working": True},
            "timestamp": time.time()
        }
    
    print("[INFO] Minimal PlexiChat application created successfully")
    
else:
    app = None
    print("[ERROR] Cannot create application - FastAPI not available")

# Export
__all__ = ["app"]
