#!/usr/bin/env python3
"""
PlexiChat Advanced Entry Point
==============================

Handles environment setup, dependency management, and application startup.
"""

import sys
import os
import argparse
import subprocess
import shutil
from pathlib import Path

def setup_environment(install_level: str = "prod"):
    """
    Setup the Python environment using uv.
    """
    print(f"[+] Setting up environment (Level: {install_level})...")
    
    # Check if uv is installed
    if not shutil.which("uv"):
        print("[-] 'uv' not found. Installing uv...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "uv"])

    # Install dependencies
    req_file = "requirements.txt"
    if install_level == "dev":
        req_file = "requirements-dev.txt" # Assuming this exists or will exist
    
    if not Path(req_file).exists():
        print(f"[-] {req_file} not found. Skipping dependency installation.")
        return

    print(f"[+] Installing dependencies from {req_file}...")
    subprocess.check_call(["uv", "pip", "install", "-r", req_file, "--system"])
    print("[+] Environment setup complete.")

def main():
    parser = argparse.ArgumentParser(description="PlexiChat Server Runner")
    
    # Logging options
    parser.add_argument("--log", type=str, default="INFO", help="Set logging level (DEBUG, INFO, WARNING, ERROR)")
    
    # Installation options
    parser.add_argument("--install", type=str, choices=["prod", "dev", "minimal"], help="Install dependencies and exit")
    
    # Config options
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    
    # Run modes
    parser.add_argument("--apionly", action="store_true", help="Run only the API server")
    parser.add_argument("--webuionly", action="store_true", help="Run only the WebUI server")
    
    args = parser.parse_args()

    # Handle installation
    if args.install:
        setup_environment(args.install)
        return

    # Set environment variables for config
    os.environ["PLEXICHAT_CONFIG_PATH"] = args.config
    os.environ["PLEXICHAT_LOG_LEVEL"] = args.log

    # Lazy imports to avoid overhead/side-effects before setup
    try:
        # Add src to path
        src_path = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_path))
        
        from plexichat.core.config import config, load_config
        
        # Reload config if custom path provided
        if args.config != "config.yaml":
            load_config(args.config)
            
        # Update log level from CLI override
        if args.log:
            config.system.log_level = args.log
            # Re-configure logging
            from plexichat.core.logging import configure_logging
            configure_logging()
            
        from plexichat.core.logging import get_logger
        logger = get_logger("run")
        
        logger.info(f"Starting PlexiChat (Version: {config.system.version})")
        logger.info(f"Config loaded from: {args.config}")

        # Start Servers
        if args.apionly:
            logger.info("Starting API Server only...")
            # TODO: Import and run API server
            pass
        elif args.webuionly:
            logger.info("Starting WebUI Server only...")
            # TODO: Import and run WebUI server
            pass
        else:
            logger.info("Starting All Services...")
            # TODO: Start both
            pass
            
    except ImportError as e:
        print(f"[!] Critical Import Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
