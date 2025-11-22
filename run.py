#!/usr/bin/env python3
"""
PlexiChat Runner
================

Main entry point for the PlexiChat application.
Provides commands to start the server, run setup, and manage the application.
"""

import os
import sys
import uvicorn
import typer
from typing import Optional
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

app = typer.Typer(help="PlexiChat Management CLI")

@app.command()
def start(
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
    workers: int = typer.Option(1, help="Number of worker processes"),
    env: str = typer.Option("development", help="Environment (development/production)"),
):
    """
    Start the PlexiChat server.
    """
    os.environ["PLEXICHAT_ENV"] = env
    
    print(f"Starting PlexiChat on {host}:{port} (env={env})")
    
    uvicorn.run(
        "plexichat.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info",
    )

@app.command()
def setup(
    level: str = typer.Option("minimal", help="Installation level (minimal/full/developer)"),
):
    """
    Run setup tasks (placeholder).
    """
    print(f"Running setup for level: {level}")
    # TODO: Implement actual setup logic (install deps, init db, etc.)
    print("Setup completed (placeholder).")

if __name__ == "__main__":
    app()
