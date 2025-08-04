#!/usr/bin/env python3
"""
Simple PlexiChat Runner

A simple script to run the PlexiChat application.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Main function."""
    print("=" * 50)
    print("PlexiChat - Simple Runner")
    print("=" * 50)
    
    try:
        # Import and run
        import uvicorn
        from plexichat.app_minimal import app
        
        if app is None:
            print("[ERROR] Application not available")
            return 1
        
        print("[INFO] Starting PlexiChat server...")
        print("[INFO] Server will be available at: http://localhost:8000")
        print("[INFO] Health check: http://localhost:8000/health")
        print("[INFO] API test: http://localhost:8000/api/v1/test")
        print("[INFO] Press Ctrl+C to stop")
        print("-" * 50)
        
        # Run the server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
        
        return 0
        
    except ImportError as e:
        print(f"[ERROR] Import failed: {e}")
        print("[INFO] Install dependencies: pip install fastapi uvicorn")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")
        return 0
    except Exception as e:
        print(f"[ERROR] Server failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
