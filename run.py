import argparse
import os
import sys
import subprocess
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def setup_environment():
    """Sets up the environment using uv if needed."""
    # This is a placeholder for actual uv setup if we were running from scratch
    # For now, we assume the environment is active or we are just running the script
    pass

def main():
    parser = argparse.ArgumentParser(description="PlexiChat Advanced Server Entry Point")
    
    # Logging Options
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level")
    
    # Config Options
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    
    # Modes
    parser.add_argument("--api-only", action="store_true", help="Run only the API server")
    parser.add_argument("--webui-only", action="store_true", help="Run only the WebUI")
    
    # Installation
    parser.add_argument("--install", choices=["minimal", "standard", "full"], help="Install dependencies")
    
    args = parser.parse_args()

    # Handle Installation
    if args.install:
        print(f"Installing {args.install} requirements...")
        req_file = "requirements.txt"
        if args.install == "minimal":
            req_file = "requirements-minimal.txt"
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
        print("Installation complete.")
        return

    # Set Config Path in Env for Config Loader to pick up
    if args.config:
        os.environ["PLEXICHAT_CONFIG"] = args.config

    # Set Log Level in Env (or update config in memory if we had that capability exposed easily)
    if args.log_level:
        # We would ideally update the config object here, but for now we can set an env var
        # that the config loader or logger might check, or just rely on the config file.
        # For this implementation, let's assume the logger checks config.
        pass

    from plexichat.core.config import config
    from plexichat.core.logging import get_logger
    
    # Override config with CLI args if needed (simple way)
    if args.log_level:
        config._config["logging"]["level"] = args.log_level

    logger = get_logger("plexichat")
    logger.info("Starting PlexiChat Server...")
    logger.info(f"Config loaded from {os.environ.get('PLEXICHAT_CONFIG', 'config.yaml')}")

    # Start Services
    if args.webui_only:
        logger.info("Starting WebUI only...")
        # Start WebUI logic here
    elif args.api_only:
        logger.info("Starting API only...")
        # Start API logic here
    else:
        logger.info("Starting all services...")
        # Start everything
        
    # Placeholder for actual server startup (e.g. uvicorn)
    # import uvicorn
    # uvicorn.run("plexichat.api.main:app", host=config.get("server.host"), port=config.get("server.port"))

if __name__ == "__main__":
    main()
