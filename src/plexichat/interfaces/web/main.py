"""
PlexiChat WebUI Main Entry Point

This module provides the main entry point for the PlexiChat WebUI server.
"""

import logging
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import uvicorn
except ImportError:
    uvicorn = None

try:
    from plexichat.interfaces.web import app
except ImportError:
    try:
        # Try alternative import path
        import sys
        from pathlib import Path
        web_path = Path(__file__).parent
        sys.path.insert(0, str(web_path))
        from . import app
    except ImportError:
        app = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_webui_app():
    """Create and configure the WebUI application."""
    if app is None:
        logger.error("Failed to import WebUI app")
        return None
    
    logger.info("WebUI application created successfully")
    return app

def run_webui_server(host: str = "0.0.0.0", port: int = 8080, reload: bool = False):
    """Run the WebUI server."""
    if not uvicorn:
        logger.error("uvicorn not available - install with: pip install uvicorn")
        return False
    
    webui_app = create_webui_app()
    if not webui_app:
        logger.error("Failed to create WebUI application")
        return False
    
    logger.info(f"Starting PlexiChat WebUI server on {host}:{port}")
    
    try:
        uvicorn.run(
            webui_app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
        return True
    except Exception as e:
        logger.error(f"Failed to start WebUI server: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PlexiChat WebUI Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    success = run_webui_server(
        host=args.host,
        port=args.port,
        reload=args.reload
    )
    
    if not success:
        sys.exit(1)
