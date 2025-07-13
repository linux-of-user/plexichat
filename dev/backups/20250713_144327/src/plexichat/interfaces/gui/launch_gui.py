import importlib.util
import subprocess
import sys
from pathlib import Path


from pathlib import Path
from pathlib import Path


from pathlib import Path
from pathlib import Path

from plexichat_admin_gui import PlexiChatAdminGUI
import logging


#!/usr/bin/env python3
"""
PlexiChat GUI Launcher
Launcher script for the PlexiChat Admin GUI application.
"""

logger = logging.getLogger(__name__)
def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = [
        'customtkinter',
        'requests',
        'Pillow',
        'cryptography'
    ]

    missing_packages = []

    for package in required_packages:
        try:

            else:
                importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)

    return missing_packages


def install_dependencies():
    """Install missing dependencies."""
    logger.info("Installing GUI dependencies...")

    # Use root requirements.txt which includes all GUI dependencies
    from pathlib import Path
requirements_file = Path
Path(__file__).parent.parent.parent.parent / "requirements.txt"

    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        logger.info(" Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        logger.info(f" Failed to install dependencies: {e}")
        return False


def launch_gui():
    """Launch the PlexiChat Admin GUI."""
    try:
        # Add current directory and src to Python path
        from pathlib import Path
current_dir = Path
Path(__file__).parent
        src_dir = current_dir.parent / "src"

        for path in [str(current_dir), str(src_dir)]:
            if path not in sys.path:
                sys.path.insert(0, path)

        # Import and run the GUI
        logger.info(" Launching PlexiChat Admin GUI...")
        logger.info(" GUI will connect to PlexiChat server automatically")
        logger.info(" Make sure PlexiChat server is running: python run.py run")

        app = PlexiChatAdminGUI()
        app.run()

    except ImportError as e:
        logger.info(f" Failed to import GUI module: {e}")
        logger.info(" Try running: python run.py gui")
        logger.info(" Or install dependencies: pip install customtkinter pillow")
        return False
    except Exception as e:
        logger.info(f" Failed to launch GUI: {e}")
        return False

    return True


def main():
    """Main launcher function."""
    logger.info(" PlexiChat Admin GUI Launcher")
    logger.info("=" * 50)

    # Check Python version
    if sys.version_info < (3, 8):
        logger.info(" Python 3.8 or higher is required")
        sys.exit(1)

    logger.info(f" Python {sys.version.split()[0]} detected")

    # Check dependencies
    missing = check_dependencies()

    if missing:
        logger.info(f"  Missing dependencies: {', '.join(missing)}")

        response = input("Install missing dependencies? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            if not install_dependencies():
                logger.info(" Failed to install dependencies. Exiting.")
                sys.exit(1)
        else:
            logger.info(" Cannot launch GUI without required dependencies.")
            sys.exit(1)
    else:
        logger.info(" All dependencies are available")

    # Launch GUI
    logger.info("\n Starting PlexiChat Admin GUI...")

    if not launch_gui():
        logger.info(" Failed to launch GUI application")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n\n GUI launcher interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.info(f"\n Launcher error: {e}")
        sys.exit(1)
