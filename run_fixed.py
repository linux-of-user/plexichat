#!/usr/bin/env python3
"""
PlexiChat Application Runner - Fixed Version

Simple, working version that actually starts the application.
"""

import argparse
import asyncio
import os
import sys
import subprocess
import time
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

def print_banner():
    """Print the PlexiChat banner."""
    banner = """
================================================================
                          PlexiChat                            
                   Advanced Chat Platform                     
                                                              
    Enterprise Security | High Performance | DDoS Protection   
================================================================
    """
    print(banner)

def check_dependencies():
    """Check if required dependencies are installed."""
    print("[INFO] Checking dependencies...")
    
    required_packages = [
        "fastapi",
        "uvicorn",
        "pydantic"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"[OK] {package}")
        except ImportError:
            print(f"[MISSING] {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n[ERROR] Missing packages: {', '.join(missing_packages)}")
        print("[INFO] Installing missing packages...")
        
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install"
            ] + missing_packages)
            print("[OK] Packages installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install packages: {e}")
            return False
    
    return True

def setup_environment():
    """Setup the application environment."""
    print("[INFO] Setting up environment...")
    
    # Create required directories
    required_dirs = [
        "data/config",
        "data/logs",
        "data/cache",
        "data/uploads"
    ]
    
    for directory in required_dirs:
        dir_path = Path(directory)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"[CREATED] {directory}")
    
    # Create basic config if it doesn't exist
    config_file = Path("data/config/config.json")
    if not config_file.exists():
        basic_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False
            },
            "logging": {
                "level": "INFO"
            },
            "rate_limiting": {
                "enabled": True,
                "per_ip_requests_per_minute": 60
            }
        }
        
        import json
        with open(config_file, 'w') as f:
            json.dump(basic_config, f, indent=2)
        print(f"[CREATED] {config_file}")
    
    print("[OK] Environment setup complete")
    return True

def test_application():
    """Test if the application can be imported and started."""
    print("[INFO] Testing application...")
    
    try:
        # Test core imports
        from plexichat.core.logging.unified_logger import get_logger
        from plexichat.core.config.simple_config import get_config
        print("[OK] Core systems import successfully")
        
        # Test main application
        from plexichat.main_fixed import app
        if app is not None:
            print("[OK] Main application created successfully")
            return True
        else:
            print("[ERROR] Main application is None")
            return False
            
    except ImportError as e:
        print(f"[ERROR] Import failed: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Application test failed: {e}")
        return False

def run_server(host="0.0.0.0", port=8000, reload=False, workers=1):
    """Run the PlexiChat server."""
    print(f"[INFO] Starting PlexiChat server on {host}:{port}")
    
    try:
        import uvicorn
        from plexichat.main_fixed import app
        
        if app is None:
            print("[ERROR] Application not available")
            return False
        
        # Configure uvicorn
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            reload=reload,
            workers=workers,
            log_level="info",
            access_log=True
        )
        
        server = uvicorn.Server(config)
        
        print(f"[INFO] Server starting...")
        print(f"[INFO] API will be available at: http://{host}:{port}")
        print(f"[INFO] Health check: http://{host}:{port}/health")
        print(f"[INFO] API status: http://{host}:{port}/api/v1/status")
        print(f"[INFO] Press Ctrl+C to stop")
        
        # Run the server
        asyncio.run(server.serve())
        
        return True
        
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")
        return True
    except Exception as e:
        print(f"[ERROR] Server failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_tests():
    """Run application tests."""
    print("[INFO] Running tests...")
    
    try:
        # Run the bug fix script first
        print("[INFO] Running bug fix script...")
        result = subprocess.run([sys.executable, "fix_all_bugs.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] Bug fix script completed successfully")
        else:
            print(f"[WARNING] Bug fix script had issues: {result.stderr}")
        
        # Test basic functionality
        if test_application():
            print("[OK] All tests passed")
            return True
        else:
            print("[ERROR] Tests failed")
            return False
            
    except Exception as e:
        print(f"[ERROR] Test execution failed: {e}")
        return False

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="PlexiChat Application Runner")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Setup the application environment")
    setup_parser.add_argument("--check-deps", action="store_true", help="Check and install dependencies")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run the application server")
    run_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    run_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    run_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    run_parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run tests")
    
    # Start command (default)
    start_parser = subparsers.add_parser("start", help="Start the application (setup + run)")
    start_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    start_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    start_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Handle commands
    if args.command == "setup":
        success = setup_environment()
        if args.check_deps:
            success = success and check_dependencies()
        
        if success:
            print("\n[SUCCESS] Setup completed successfully!")
            print("Run 'python run_fixed.py start' to start the application")
        else:
            print("\n[ERROR] Setup failed!")
            return 1
    
    elif args.command == "run":
        if not test_application():
            print("[ERROR] Application test failed - run setup first")
            return 1
        
        success = run_server(args.host, args.port, args.reload, args.workers)
        return 0 if success else 1
    
    elif args.command == "test":
        success = run_tests()
        return 0 if success else 1
    
    elif args.command == "start":
        # Full startup: setup + test + run
        print("[INFO] Starting full application startup...")
        
        if not setup_environment():
            print("[ERROR] Environment setup failed")
            return 1
        
        if not check_dependencies():
            print("[ERROR] Dependency check failed")
            return 1
        
        if not test_application():
            print("[ERROR] Application test failed")
            return 1
        
        success = run_server(args.host, args.port, args.reload)
        return 0 if success else 1
    
    else:
        # Default: show help and start
        parser.print_help()
        print("\n[INFO] No command specified, starting application...")
        
        # Quick start
        if setup_environment() and check_dependencies() and test_application():
            success = run_server()
            return 0 if success else 1
        else:
            print("[ERROR] Quick start failed - please run setup first")
            return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INFO] Application stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
