from .core_system.config import get_config
from .main import app


        import sys

import uvicorn


"""
PlexiChat Module Entry Point
Allows running PlexiChat as a module: python -m src.plexichat
"""

def main():
    """Main entry point for module execution."""
    try:
        config = get_config()
        
        uvicorn.run(
            app,
            host=getattr(config.server, 'host', '127.0.0.1'),
            port=getattr(config.server, 'port', 8000),
            reload=getattr(config.server, 'reload', False),
            workers=1 if getattr(config.server, 'reload', False) else getattr(config.server, 'workers', 1),
            log_level="info"
        )
    except Exception as e:
        print(f" Failed to start PlexiChat: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
