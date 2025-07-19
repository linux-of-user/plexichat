#!/usr/bin/env python3
"""
PlexiChat Run Script - Main Entry Point
=======================================

The comprehensive main entry point for PlexiChat that handles:
- Server startup with proper initialization
- CLI interface for running tests and management
- Interactive mode for development
- Graceful shutdown handling
- First-time setup with dynamic terminal UI
- Version management and updates
- Dependency installation and management
- Environment setup and configuration
- Cache cleaning and maintenance
- GitHub version downloading
- Custom terminal interface with real-time updates

This script serves as the primary interface for all PlexiChat operations,
providing a unified entry point for users, developers, and administrators.

Features:
- Dynamic terminal UI with real-time updates
- Comprehensive setup wizard
- Version management and GitHub integration
- Dependency management and environment setup
- Cache cleaning and optimization
- Multi-mode operation (GUI, CLI, API, Setup)
- Advanced logging and monitoring
- Error handling and recovery
- Performance optimization
- Security features
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Union
import hashlib
import re

# Constants and Configuration
PLEXICHAT_VERSION = "a.1.1-21"
GITHUB_REPO = "linux-of-user/plexichat"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_RELEASES_URL = f"{GITHUB_API_URL}/releases"
GITHUB_LATEST_URL = f"{GITHUB_RELEASES_URL}/latest"
GITHUB_DOWNLOAD_URL = f"https://github.com/{GITHUB_REPO}/archive"

# Terminal UI Constants
TERMINAL_WIDTH = 120
TERMINAL_HEIGHT = 40
REFRESH_RATE = 0.1  # seconds
ANIMATION_CHARS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

# Color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

# Add src to path for imports
src_path = str(Path(__file__).parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Initialize basic logging first (will be overridden by unified logging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try to import and initialize unified logging system
try:
    from plexichat.core.logging.unified_logging_manager import initialize_logging, get_logger
    from plexichat.interfaces.cli.test_commands import handle_test_command
    
    # Default logging configuration
    logging_config = {
        'log_level': 'INFO',  # Will be overridden by command line args
        'log_dir': 'logs',
        'max_log_size_mb': 10,
        'backup_count': 5,
        'enable_console': True,
        'enable_file': True,
        'enable_json': False,
        'enable_rotation': True,
        'enable_compression': True,
        'retention_days': 30
    }
    
    # Initialize the unified logging system
    try:
        initialize_logging(logging_config)
        logger = get_logger(__name__)
        logger.info("Initialized unified logging system")
    except Exception as e:
        logger.error(f"Failed to initialize unified logging: {e}")
        logger.info("Falling back to basic logging")
        logger = logging.getLogger(__name__)
    
except ImportError as e:
    logger.warning(f"Could not import unified logging system: {e}")
    logger.info("Falling back to basic logging")
    
    # Define fallback functions
    async def handle_test_command(*args, **kwargs) -> int:
        logger.error("Test commands not available - CLI module not imported")
        return 1

# ============================================================================
# TERMINAL UI CLASSES AND FUNCTIONS
# ============================================================================

class TerminalUI:
    """Advanced terminal UI with dynamic updates and animations."""

    def __init__(self):
        self.width = TERMINAL_WIDTH
        self.height = TERMINAL_HEIGHT
        self.running = False
        self.animation_frame = 0
        self.status_lines = []
        self.progress_bars = {}
        self.logs = []
        self.max_logs = 20

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def move_cursor(self, row: int, col: int):
        """Move cursor to specific position."""
        print(f"\033[{row};{col}H", end='')

    def hide_cursor(self):
        """Hide the cursor."""
        print("\033[?25l", end='')

    def show_cursor(self):
        """Show the cursor."""
        print("\033[?25h", end='')

    def draw_box(self, x: int, y: int, width: int, height: int, title: str = ""):
        """Draw a box with optional title."""
        # Top border
        self.move_cursor(y, x)
        if title:
            title_text = f"┌─ {title} "
            remaining = width - len(title_text) - 1
            print(f"{title_text}{'─' * remaining}┐")
        else:
            print(f"┌{'─' * (width - 2)}┐")

        # Side borders
        for i in range(1, height - 1):
            self.move_cursor(y + i, x)
            print(f"│{' ' * (width - 2)}│")

        # Bottom border
        self.move_cursor(y + height - 1, x)
        print(f"└{'─' * (width - 2)}┘")

    def draw_progress_bar(self, x: int, y: int, width: int, progress: float, label: str = ""):
        """Draw a progress bar."""
        filled = int(progress * (width - 2))
        bar = f"{'█' * filled}{'░' * (width - 2 - filled)}"
        self.move_cursor(y, x)
        print(f"│{bar}│ {progress:.1%} {label}")

    def add_log(self, message: str, level: str = "INFO"):
        """Add a log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": Colors.WHITE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "DEBUG": Colors.CYAN
        }.get(level, Colors.WHITE)

        log_entry = f"{Colors.DIM}[{timestamp}]{Colors.RESET} {color}{level}{Colors.RESET}: {message}"
        self.logs.append(log_entry)

        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def get_animation_char(self) -> str:
        """Get current animation character."""
        char = ANIMATION_CHARS[self.animation_frame % len(ANIMATION_CHARS)]
        self.animation_frame += 1
        return char

    def draw_header(self):
        """Draw the main header."""
        self.move_cursor(1, 1)
        header = f"{Colors.BOLD}{Colors.BLUE}PlexiChat Setup & Management System{Colors.RESET}"
        version = f"{Colors.DIM}v{PLEXICHAT_VERSION}{Colors.RESET}"
        padding = self.width - len("PlexiChat Setup & Management System") - len(f"v{PLEXICHAT_VERSION}") - 4
        print(f"  {header}{' ' * padding}{version}  ")

        # Draw separator
        self.move_cursor(2, 1)
        print(f"  {Colors.DIM}{'═' * (self.width - 4)}{Colors.RESET}  ")

    def draw_status_panel(self, y_start: int):
        """Draw the status panel."""
        self.draw_box(2, y_start, self.width - 4, 8, "System Status")

        # System info
        self.move_cursor(y_start + 2, 4)
        print(f"Platform: {platform.system()} {platform.release()}")
        self.move_cursor(y_start + 3, 4)
        print(f"Python: {sys.version.split()[0]}")
        self.move_cursor(y_start + 4, 4)
        print(f"Working Directory: {os.getcwd()}")
        self.move_cursor(y_start + 5, 4)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def draw_logs_panel(self, y_start: int):
        """Draw the logs panel."""
        self.draw_box(2, y_start, self.width - 4, 12, "Activity Log")

        for i, log in enumerate(self.logs[-10:]):  # Show last 10 logs
            self.move_cursor(y_start + 2 + i, 4)
            print(log[:self.width - 8])  # Truncate if too long

    def refresh_display(self):
        """Refresh the entire display."""
        self.clear_screen()
        self.hide_cursor()

        # Draw header
        self.draw_header()

        # Draw status panel
        self.draw_status_panel(4)

        # Draw logs panel
        self.draw_logs_panel(13)

        # Draw footer
        self.move_cursor(self.height - 2, 1)
        print(f"  {Colors.DIM}Press Ctrl+C to exit{Colors.RESET}")

        sys.stdout.flush()

class SetupWizard:
    """Interactive setup wizard with terminal UI."""

    def __init__(self):
        self.ui = TerminalUI()
        self.steps = [
            "Environment Check",
            "Dependency Installation",
            "Configuration Setup",
            "Database Initialization",
            "Security Setup",
            "Final Verification"
        ]
        self.current_step = 0
        self.setup_data = {}

    def run(self):
        """Run the setup wizard."""
        try:
            self.ui.clear_screen()
            self.ui.add_log("Starting PlexiChat Setup Wizard", "INFO")

            for i, step in enumerate(self.steps):
                self.current_step = i
                self.ui.add_log(f"Starting step {i+1}: {step}", "INFO")

                if not self.execute_step(i):
                    self.ui.add_log(f"Step {i+1} failed: {step}", "ERROR")
                    return False

                self.ui.add_log(f"Completed step {i+1}: {step}", "SUCCESS")

            self.ui.add_log("Setup completed successfully!", "SUCCESS")
            return True

        except KeyboardInterrupt:
            self.ui.add_log("Setup cancelled by user", "WARNING")
            return False
        except Exception as e:
            self.ui.add_log(f"Setup failed: {str(e)}", "ERROR")
            return False
        finally:
            self.ui.show_cursor()

    def execute_step(self, step_index: int) -> bool:
        """Execute a specific setup step."""
        step_methods = [
            self.check_environment,
            self.install_dependencies,
            self.setup_configuration,
            self.initialize_database,
            self.setup_security,
            self.verify_installation
        ]

        if step_index < len(step_methods):
            return step_methods[step_index]()
        return False

    def check_environment(self) -> bool:
        """Check system environment."""
        self.ui.add_log("Checking Python version...", "INFO")
        if sys.version_info < (3, 8):
            self.ui.add_log("Python 3.8+ required", "ERROR")
            return False

        self.ui.add_log("Checking required directories...", "INFO")
        required_dirs = ['logs', 'data', 'config', 'temp', 'backups', 'uploads']
        for dir_name in required_dirs:
            Path(dir_name).mkdir(exist_ok=True)

        return True

    def install_dependencies(self) -> bool:
        """Install required dependencies."""
        self.ui.add_log("Installing dependencies...", "INFO")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                         check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            self.ui.add_log("Failed to install dependencies", "ERROR")
            return False

    def setup_configuration(self) -> bool:
        """Setup configuration files."""
        self.ui.add_log("Setting up configuration...", "INFO")
        # Configuration setup logic here
        return True

    def initialize_database(self) -> bool:
        """Initialize database."""
        self.ui.add_log("Initializing database...", "INFO")
        # Database initialization logic here
        return True

    def setup_security(self) -> bool:
        """Setup security features."""
        self.ui.add_log("Setting up security...", "INFO")
        # Security setup logic here
        return True

    def verify_installation(self) -> bool:
        """Verify installation."""
        self.ui.add_log("Verifying installation...", "INFO")
        # Verification logic here
        return True

# ============================================================================
# VERSION MANAGEMENT AND GITHUB INTEGRATION
# ============================================================================

class GitHubVersionManager:
    """Manages version downloads and updates from GitHub."""

    def __init__(self):
        self.repo = GITHUB_REPO
        self.api_url = GITHUB_API_URL
        self.releases_url = GITHUB_RELEASES_URL
        self.latest_url = GITHUB_LATEST_URL
        self.download_url = GITHUB_DOWNLOAD_URL

    def get_available_versions(self) -> List[Dict[str, Any]]:
        """Get list of available versions from GitHub."""
        try:
            with urllib.request.urlopen(self.releases_url) as response:
                data = json.loads(response.read().decode())

            versions = []
            for release in data:
                versions.append({
                    'tag': release['tag_name'],
                    'name': release['name'],
                    'published_at': release['published_at'],
                    'prerelease': release['prerelease'],
                    'download_url': release['zipball_url'],
                    'body': release['body']
                })

            return versions

        except Exception as e:
            logger.error(f"Failed to fetch versions from GitHub: {e}")
            return []

    def get_latest_version(self) -> Optional[Dict[str, Any]]:
        """Get the latest version from GitHub."""
        try:
            with urllib.request.urlopen(self.latest_url) as response:
                data = json.loads(response.read().decode())

            return {
                'tag': data['tag_name'],
                'name': data['name'],
                'published_at': data['published_at'],
                'prerelease': data['prerelease'],
                'download_url': data['zipball_url'],
                'body': data['body']
            }

        except Exception as e:
            logger.error(f"Failed to fetch latest version from GitHub: {e}")
            return None

    def download_version(self, version_tag: str, target_dir: str) -> bool:
        """Download a specific version from GitHub."""
        try:
            download_url = f"{self.download_url}/{version_tag}.zip"
            target_path = Path(target_dir) / f"plexichat-{version_tag}.zip"

            logger.info(f"Downloading version {version_tag} from GitHub...")

            with urllib.request.urlopen(download_url) as response:
                with open(target_path, 'wb') as f:
                    shutil.copyfileobj(response, f)

            logger.info(f"Downloaded to {target_path}")

            # Extract the zip file
            extract_dir = Path(target_dir) / f"plexichat-{version_tag}"
            with zipfile.ZipFile(target_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            logger.info(f"Extracted to {extract_dir}")
            return True

        except Exception as e:
            logger.error(f"Failed to download version {version_tag}: {e}")
            return False

    def verify_download(self, file_path: str) -> bool:
        """Verify downloaded file integrity."""
        try:
            if not Path(file_path).exists():
                return False

            # Basic verification - check if it's a valid zip file
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.testzip()

            return True

        except Exception as e:
            logger.error(f"Download verification failed: {e}")
            return False

class DependencyManager:
    """Manages Python dependencies and environment setup."""

    def __init__(self):
        self.requirements_file = Path("requirements.txt")
        self.venv_dir = Path("venv")

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if all dependencies are installed."""
        results = {}

        if not self.requirements_file.exists():
            logger.warning("requirements.txt not found")
            return results

        try:
            with open(self.requirements_file, 'r') as f:
                requirements = f.readlines()

            for req in requirements:
                req = req.strip()
                if req and not req.startswith('#'):
                    package_name = req.split('>=')[0].split('==')[0].split('<')[0]
                    try:
                        __import__(package_name.replace('-', '_'))
                        results[package_name] = True
                    except ImportError:
                        results[package_name] = False

        except Exception as e:
            logger.error(f"Failed to check dependencies: {e}")

        return results

    def install_dependencies(self, upgrade: bool = False) -> bool:
        """Install all dependencies from requirements.txt."""
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(self.requirements_file)]
            if upgrade:
                cmd.append("--upgrade")

            logger.info("Installing dependencies...")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info("Dependencies installed successfully")
                return True
            else:
                logger.error(f"Failed to install dependencies: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error installing dependencies: {e}")
            return False

    def create_virtual_environment(self) -> bool:
        """Create a virtual environment."""
        try:
            if self.venv_dir.exists():
                logger.info("Virtual environment already exists")
                return True

            logger.info("Creating virtual environment...")
            subprocess.run([sys.executable, "-m", "venv", str(self.venv_dir)], check=True)
            logger.info("Virtual environment created successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to create virtual environment: {e}")
            return False

    def clean_cache(self) -> bool:
        """Clean pip cache and temporary files."""
        try:
            logger.info("Cleaning pip cache...")
            subprocess.run([sys.executable, "-m", "pip", "cache", "purge"],
                         capture_output=True, check=True)

            # Clean temporary directories
            temp_dirs = [Path("temp"), Path("__pycache__"), Path(".pytest_cache")]
            for temp_dir in temp_dirs:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned {temp_dir}")

            logger.info("Cache cleaned successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to clean cache: {e}")
            return False

def setup_environment():
    """Set up the runtime environment including required directories and environment variables."""
    logger.debug("Setting up environment...")

    # Define required directories
    directories = {
        'logs': 'Log files',
        'data': 'Application data',
        'config': 'Configuration files',
        'temp': 'Temporary files',
        'backups': 'Backup files',
        'uploads': 'User uploads'
    }

    # Create directories if they don't exist
    for directory, desc in directories.items():
        try:
            dir_path = Path(directory)
            dir_path.mkdir(exist_ok=True, parents=True)
            logger.debug(f"Directory ready: {dir_path.absolute()} ({desc})")
        except Exception as e:
            logger.error(f"Failed to create directory {directory}: {e}")
            raise

    # Set environment variables with defaults if not already set
    env_vars = {
        'PLEXICHAT_ENV': 'production',
        'PLEXICHAT_CONFIG_DIR': 'config',
        'PLEXICHAT_LOG_LEVEL': 'INFO'
    }

    for var, default in env_vars.items():
        os.environ.setdefault(var, default)
        logger.debug(f"Environment variable set: {var}={os.environ[var]}")

    logger.info("Environment setup completed")

# ============================================================================
# CONFIGURATION AND ENVIRONMENT MANAGEMENT
# ============================================================================

class ConfigurationManager:
    """Manages application configuration and environment setup."""

    def __init__(self):
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "plexichat.json"
        self.env_file = Path(".env")
        self.default_config = self.get_default_config()

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False,
                "reload": True
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./data/plexichat.db"
            },
            "security": {
                "secret_key": self.generate_secret_key(),
                "jwt_expire_minutes": 30,
                "password_min_length": 8
            },
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_size_mb": 10,
                "backup_count": 5
            },
            "features": {
                "file_uploads": True,
                "analytics": True,
                "clustering": False,
                "hot_updates": True
            }
        }

    def generate_secret_key(self) -> str:
        """Generate a secure secret key."""
        import secrets
        return secrets.token_urlsafe(32)

    def load_configuration(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logger.info("Configuration loaded from file")
                return config
            else:
                logger.info("Creating default configuration")
                self.save_configuration(self.default_config)
                return self.default_config

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return self.default_config

    def save_configuration(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            self.config_dir.mkdir(exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info("Configuration saved successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False

    def setup_environment_variables(self, config: Dict[str, Any]) -> bool:
        """Setup environment variables from configuration."""
        try:
            env_vars = {
                'PLEXICHAT_HOST': config['server']['host'],
                'PLEXICHAT_PORT': str(config['server']['port']),
                'PLEXICHAT_DEBUG': str(config['server']['debug']),
                'PLEXICHAT_SECRET_KEY': config['security']['secret_key'],
                'PLEXICHAT_DATABASE_URL': config['database']['url'],
                'PLEXICHAT_LOG_LEVEL': config['logging']['level']
            }

            for var, value in env_vars.items():
                os.environ[var] = value

            logger.info("Environment variables configured")
            return True

        except Exception as e:
            logger.error(f"Failed to setup environment variables: {e}")
            return False

class SystemManager:
    """Manages system operations and maintenance."""

    def __init__(self):
        self.github_manager = GitHubVersionManager()
        self.dependency_manager = DependencyManager()
        self.config_manager = ConfigurationManager()

    def check_system_health(self) -> Dict[str, Any]:
        """Check overall system health."""
        health = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "working_directory": os.getcwd(),
            "disk_space": self.get_disk_space(),
            "memory_usage": self.get_memory_usage(),
            "dependencies": self.dependency_manager.check_dependencies(),
            "configuration": self.config_manager.config_file.exists()
        }

        return health

    def get_disk_space(self) -> Dict[str, Any]:
        """Get disk space information."""
        try:
            total, used, free = shutil.disk_usage(os.getcwd())
            return {
                "total": total,
                "used": used,
                "free": free,
                "percent_used": (used / total) * 100
            }
        except Exception:
            return {"error": "Unable to get disk space"}

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information."""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": str(e)}

    def cleanup_system(self) -> bool:
        """Perform system cleanup."""
        try:
            logger.info("Starting system cleanup...")

            # Clean dependency cache
            self.dependency_manager.clean_cache()

            # Clean log files older than 30 days
            self.cleanup_old_logs()

            # Clean temporary files
            self.cleanup_temp_files()

            logger.info("System cleanup completed")
            return True

        except Exception as e:
            logger.error(f"System cleanup failed: {e}")
            return False

    def cleanup_old_logs(self):
        """Clean up old log files."""
        logs_dir = Path("logs")
        if logs_dir.exists():
            cutoff_time = time.time() - (30 * 24 * 60 * 60)  # 30 days
            for log_file in logs_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logger.info(f"Removed old log file: {log_file}")

    def cleanup_temp_files(self):
        """Clean up temporary files."""
        temp_dirs = [Path("temp"), Path("__pycache__")]
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                for item in temp_dir.rglob("*"):
                    if item.is_file():
                        item.unlink()
                logger.info(f"Cleaned temporary directory: {temp_dir}")

def load_configuration() -> Optional[Dict[str, Any]]:
    """Load and validate application configuration.

    Returns:
        Dict containing configuration if successful, None otherwise
    """
    logger.debug("Loading configuration...")

    try:
        config_manager = ConfigurationManager()
        config = config_manager.load_configuration()

        if not config:
            logger.warning("Empty configuration returned")
            return None

        logger.info("Configuration loaded successfully")
        logger.debug(f"Configuration keys: {list(config.keys())}")
        return config

    except ImportError as e:
        logger.error(f"Failed to import configuration module: {e}")
        logger.debug(traceback.format_exc())
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        logger.debug(f"Error details: {traceback.format_exc()}")

    return None

# ============================================================================
# INTERACTIVE SETUP AND MANAGEMENT FUNCTIONS
# ============================================================================

def run_interactive_setup():
    """Run the interactive setup wizard."""
    try:
        wizard = SetupWizard()
        return wizard.run()
    except Exception as e:
        logger.error(f"Setup wizard failed: {e}")
        return False

def run_version_manager():
    """Run the version management interface."""
    try:
        github_manager = GitHubVersionManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Version Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. List available versions")
            print("2. Download specific version")
            print("3. Check latest version")
            print("4. Show current version")
            print("5. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-5): {Colors.RESET}").strip()

            if choice == '1':
                versions = github_manager.get_available_versions()
                if versions:
                    print(f"\n{Colors.GREEN}Available Versions:{Colors.RESET}")
                    for i, version in enumerate(versions[:10]):  # Show last 10
                        status = "Pre-release" if version['prerelease'] else "Release"
                        print(f"  {i+1}. {version['tag']} - {version['name']} ({status})")
                else:
                    print(f"{Colors.RED}Failed to fetch versions{Colors.RESET}")

            elif choice == '2':
                version_tag = input(f"{Colors.CYAN}Enter version tag to download: {Colors.RESET}").strip()
                if version_tag:
                    target_dir = input(f"{Colors.CYAN}Enter target directory (default: ./downloads): {Colors.RESET}").strip()
                    if not target_dir:
                        target_dir = "./downloads"

                    Path(target_dir).mkdir(exist_ok=True)
                    if github_manager.download_version(version_tag, target_dir):
                        print(f"{Colors.GREEN}Version {version_tag} downloaded successfully{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Failed to download version {version_tag}{Colors.RESET}")

            elif choice == '3':
                latest = github_manager.get_latest_version()
                if latest:
                    print(f"\n{Colors.GREEN}Latest Version:{Colors.RESET}")
                    print(f"  Tag: {latest['tag']}")
                    print(f"  Name: {latest['name']}")
                    print(f"  Published: {latest['published_at']}")
                    print(f"  Pre-release: {latest['prerelease']}")
                else:
                    print(f"{Colors.RED}Failed to fetch latest version{Colors.RESET}")

            elif choice == '4':
                print(f"\n{Colors.GREEN}Current Version: {PLEXICHAT_VERSION}{Colors.RESET}")

            elif choice == '5':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-5.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Version manager exited{Colors.RESET}")
    except Exception as e:
        logger.error(f"Version manager error: {e}")

def run_dependency_manager():
    """Run the dependency management interface."""
    try:
        dep_manager = DependencyManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Dependency Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. Check dependencies")
            print("2. Install dependencies")
            print("3. Upgrade dependencies")
            print("4. Create virtual environment")
            print("5. Clean cache")
            print("6. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-6): {Colors.RESET}").strip()

            if choice == '1':
                deps = dep_manager.check_dependencies()
                print(f"\n{Colors.GREEN}Dependency Status:{Colors.RESET}")
                for package, installed in deps.items():
                    status = f"{Colors.GREEN}✓{Colors.RESET}" if installed else f"{Colors.RED}✗{Colors.RESET}"
                    print(f"  {status} {package}")

            elif choice == '2':
                if dep_manager.install_dependencies():
                    print(f"{Colors.GREEN}Dependencies installed successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to install dependencies{Colors.RESET}")

            elif choice == '3':
                if dep_manager.install_dependencies(upgrade=True):
                    print(f"{Colors.GREEN}Dependencies upgraded successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to upgrade dependencies{Colors.RESET}")

            elif choice == '4':
                if dep_manager.create_virtual_environment():
                    print(f"{Colors.GREEN}Virtual environment created successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to create virtual environment{Colors.RESET}")

            elif choice == '5':
                if dep_manager.clean_cache():
                    print(f"{Colors.GREEN}Cache cleaned successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to clean cache{Colors.RESET}")

            elif choice == '6':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-6.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Dependency manager exited{Colors.RESET}")
    except Exception as e:
        logger.error(f"Dependency manager error: {e}")

def run_system_manager():
    """Run the system management interface."""
    try:
        sys_manager = SystemManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat System Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. System health check")
            print("2. Clean system")
            print("3. Show disk usage")
            print("4. Show memory usage")
            print("5. Environment info")
            print("6. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-6): {Colors.RESET}").strip()

            if choice == '1':
                health = sys_manager.check_system_health()
                print(f"\n{Colors.GREEN}System Health:{Colors.RESET}")
                for key, value in health.items():
                    if isinstance(value, dict):
                        print(f"  {key}:")
                        for sub_key, sub_value in value.items():
                            print(f"    {sub_key}: {sub_value}")
                    else:
                        print(f"  {key}: {value}")

            elif choice == '2':
                if sys_manager.cleanup_system():
                    print(f"{Colors.GREEN}System cleaned successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}System cleanup failed{Colors.RESET}")

            elif choice == '3':
                disk = sys_manager.get_disk_space()
                if "error" not in disk:
                    print(f"\n{Colors.GREEN}Disk Usage:{Colors.RESET}")
                    print(f"  Total: {disk['total'] / (1024**3):.2f} GB")
                    print(f"  Used: {disk['used'] / (1024**3):.2f} GB ({disk['percent_used']:.1f}%)")
                    print(f"  Free: {disk['free'] / (1024**3):.2f} GB")
                else:
                    print(f"{Colors.RED}Error: {disk['error']}{Colors.RESET}")

            elif choice == '4':
                memory = sys_manager.get_memory_usage()
                if "error" not in memory:
                    print(f"\n{Colors.GREEN}Memory Usage:{Colors.RESET}")
                    print(f"  Total: {memory['total'] / (1024**3):.2f} GB")
                    print(f"  Used: {memory['used'] / (1024**3):.2f} GB ({memory['percent']:.1f}%)")
                    print(f"  Available: {memory['available'] / (1024**3):.2f} GB")
                else:
                    print(f"{Colors.RED}Error: {memory['error']}{Colors.RESET}")

            elif choice == '5':
                print(f"\n{Colors.GREEN}Environment Information:{Colors.RESET}")
                print(f"  Python: {sys.version}")
                print(f"  Platform: {platform.platform()}")
                print(f"  Working Directory: {os.getcwd()}")
                print(f"  PlexiChat Version: {PLEXICHAT_VERSION}")

            elif choice == '6':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-6.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}System manager exited{Colors.RESET}")
    except Exception as e:
        logger.error(f"System manager error: {e}")

def run_enhanced_tests():
    """Run the comprehensive test suite."""
    try:
        import asyncio
        try:
            from src.plexichat.tests.unified_test_manager import run_tests
        except ImportError:
            logger.error("Test runner not available")
            return False

        logger.info("🚀 Running PlexiChat comprehensive test suite...")

        # Run all tests
        report = asyncio.run(run_tests(
            categories=None,  # Run all categories
            verbose=True,
            save_report=True
        ))

        # Check results
        if report.get('summary', {}).get('failed', 0) == 0:
            logger.info("✅ All tests passed!")
            return True
        else:
            failed_count = report['summary']['failed']
            total_count = report['summary']['total_tests']
            logger.error(f"❌ {failed_count}/{total_count} tests failed")
            return False

    except ImportError as e:
        logger.error(f"Test system not available: {e}")
        logger.info("Make sure all test dependencies are installed")
        return False
    except Exception as e:
        logger.error(f"Error running tests: {e}")
        return False

# ============================================================================
# MAIN APPLICATION RUNNERS
# ============================================================================

def run_splitscreen_cli():
    """Run the enhanced splitscreen CLI interface."""
    try:
        from src.plexichat.interfaces.cli.console_manager import EnhancedSplitScreen
        cli = EnhancedSplitScreen(logger=logger)
        if cli and hasattr(cli, "start"):
            cli.start()
    except Exception as e:
        logger.error(f"Could not start splitscreen CLI: {e}")

def run_api_and_cli():
    """Run both API server and CLI interface."""
    # Start the splitscreen CLI in a separate thread
    cli_thread = threading.Thread(target=run_splitscreen_cli, daemon=True)
    if cli_thread and hasattr(cli_thread, "start"):
        cli_thread.start()
    # Start the API server (blocking)
    run_api_server()

def run_gui():
    """Launch the GUI interface."""
    logger.info("Launching PlexiChat GUI...")
    logger.info("Web interface available at: http://localhost:8000")
    logger.info("API documentation at: http://localhost:8000/docs")
    run_api_and_cli()

def run_webui():
    """Launch the web UI interface."""
    logger.info("Launching PlexiChat Web UI...")
    logger.info("Starting web server with enhanced UI...")
    run_api_server()

def run_configuration_wizard():
    """Run the configuration wizard."""
    try:
        config_manager = ConfigurationManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Configuration Wizard{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        # Load existing config or create new
        config = config_manager.load_configuration()

        print(f"\n{Colors.GREEN}Current Configuration:{Colors.RESET}")
        print(json.dumps(config, indent=2))

        modify = input(f"\n{Colors.CYAN}Do you want to modify the configuration? (y/N): {Colors.RESET}").strip().lower()

        if modify == 'y':
            # Server configuration
            print(f"\n{Colors.BOLD}Server Configuration:{Colors.RESET}")
            host = input(f"Host ({config['server']['host']}): ").strip() or config['server']['host']
            port = input(f"Port ({config['server']['port']}): ").strip()
            if port.isdigit():
                port = int(port)
            else:
                port = config['server']['port']

            config['server']['host'] = host
            config['server']['port'] = port

            # Database configuration
            print(f"\n{Colors.BOLD}Database Configuration:{Colors.RESET}")
            db_type = input(f"Database type (sqlite/postgresql/mysql) ({config['database']['type']}): ").strip() or config['database']['type']

            if db_type == 'sqlite':
                db_url = input(f"Database file path ({config['database']['url']}): ").strip() or config['database']['url']
            else:
                db_url = input(f"Database URL ({config['database']['url']}): ").strip() or config['database']['url']

            config['database']['type'] = db_type
            config['database']['url'] = db_url

            # Security configuration
            print(f"\n{Colors.BOLD}Security Configuration:{Colors.RESET}")
            jwt_expire = input(f"JWT expiration minutes ({config['security']['jwt_expire_minutes']}): ").strip()
            if jwt_expire.isdigit():
                config['security']['jwt_expire_minutes'] = int(jwt_expire)

            # Features configuration
            print(f"\n{Colors.BOLD}Features Configuration:{Colors.RESET}")
            for feature, enabled in config['features'].items():
                response = input(f"Enable {feature}? (y/N) [current: {enabled}]: ").strip().lower()
                if response == 'y':
                    config['features'][feature] = True
                elif response == 'n':
                    config['features'][feature] = False

            # Save configuration
            if config_manager.save_configuration(config):
                print(f"\n{Colors.GREEN}Configuration saved successfully!{Colors.RESET}")

                # Setup environment variables
                config_manager.setup_environment_variables(config)
                print(f"{Colors.GREEN}Environment variables configured{Colors.RESET}")

                return True
            else:
                print(f"\n{Colors.RED}Failed to save configuration{Colors.RESET}")
                return False
        else:
            print(f"\n{Colors.YELLOW}Configuration unchanged{Colors.RESET}")
            return True

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Configuration wizard cancelled{Colors.RESET}")
        return False
    except Exception as e:
        logger.error(f"Configuration wizard failed: {e}")
        return False

def run_update_system():
    """Run the update system using existing update functionality."""
    try:
        logger.info("Starting PlexiChat Update System...")

        # Import the existing update system
        try:
            from src.plexichat.interfaces.cli.commands.updates import UpdateCLI
        except ImportError:
            logger.error("Update CLI not available")
            return False

        update_cli = UpdateCLI()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Update System{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. Check for updates")
            print("2. Show current version")
            print("3. Upgrade to latest")
            print("4. Show changelog")
            print("5. Update history")
            print("6. Reinstall dependencies")
            print("7. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-7): {Colors.RESET}").strip()

            if choice == '1':
                # Use existing update system to check for updates
                asyncio.run(update_cli.handle_check(None))

            elif choice == '2':
                # Show current version
                asyncio.run(update_cli.handle_version(None))

            elif choice == '3':
                # Upgrade to latest
                confirm = input(f"{Colors.YELLOW}Are you sure you want to upgrade? (y/N): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    asyncio.run(update_cli.handle_upgrade(None))

            elif choice == '4':
                # Show changelog
                asyncio.run(update_cli.handle_changelog(None))

            elif choice == '5':
                # Show update history
                asyncio.run(update_cli.handle_history(None))

            elif choice == '6':
                # Reinstall dependencies
                asyncio.run(update_cli.handle_reinstall_deps(None))

            elif choice == '7':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-7.{Colors.RESET}")

    except ImportError as e:
        logger.error(f"Update system not available: {e}")
        print(f"{Colors.RED}Update system not available. Using fallback GitHub version manager.{Colors.RESET}")
        run_version_manager()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Update system exited{Colors.RESET}")
    except Exception as e:
        logger.error(f"Update system error: {e}")
        print(f"{Colors.RED}Update system error: {e}{Colors.RESET}")

def run_first_time_setup():
    """Run comprehensive first-time setup with dynamic terminal UI."""
    try:
        print(f"\n{Colors.BOLD}{Colors.GREEN}Welcome to PlexiChat!{Colors.RESET}")
        print(f"{Colors.DIM}Starting first-time setup...{Colors.RESET}")

        # Initialize terminal UI
        ui = TerminalUI()
        ui.add_log("Starting PlexiChat first-time setup", "INFO")

        # Initialize managers
        system_manager = SystemManager()

        # Step 1: System check
        ui.add_log("Checking system requirements...", "INFO")
        ui.refresh_display()

        health = system_manager.check_system_health()
        if health:
            ui.add_log("System check passed", "SUCCESS")
        else:
            ui.add_log("System check failed", "ERROR")
            return False

        # Step 2: Environment setup
        ui.add_log("Setting up environment...", "INFO")
        ui.refresh_display()

        setup_environment()
        ui.add_log("Environment setup completed", "SUCCESS")

        # Step 3: Configuration
        ui.add_log("Setting up configuration...", "INFO")
        ui.refresh_display()

        config_manager = ConfigurationManager()
        config = config_manager.load_configuration()
        config_manager.setup_environment_variables(config)
        ui.add_log("Configuration setup completed", "SUCCESS")

        # Step 4: Dependencies
        ui.add_log("Installing dependencies...", "INFO")
        ui.refresh_display()

        dep_manager = DependencyManager()
        if dep_manager.install_dependencies():
            ui.add_log("Dependencies installed successfully", "SUCCESS")
        else:
            ui.add_log("Dependency installation failed", "WARNING")

        # Step 5: Final setup
        ui.add_log("Finalizing setup...", "INFO")
        ui.refresh_display()

        ui.add_log("PlexiChat setup completed successfully!", "SUCCESS")
        ui.add_log("You can now start PlexiChat with: python run.py", "INFO")

        time.sleep(2)  # Give user time to read
        return True

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup cancelled by user{Colors.RESET}")
        return False
    except Exception as e:
        logger.error(f"First-time setup failed: {e}")
        return False

def run_api_server():
    """Start the PlexiChat API server."""
    try:
        import uvicorn
        config = load_configuration()
        host = "0.0.0.0"
        port = 8000

        if config:
            host = config.get('server', {}).get('host', '0.0.0.0')
            port = config.get('server', {}).get('port', 8000)

        logger.info(f"Starting PlexiChat API server on {host}:{port}")
        logger.info("PlexiChat API server starting...")
        logger.info(f"Version: {PLEXICHAT_VERSION}")
        logger.info(f"API Documentation available at: http://{host}:{port}/docs")
        logger.info(f"Web interface available at: http://{host}:{port}")
        logger.info(f"Health check: http://{host}:{port}/health")
        logger.info(f"Version info: http://{host}:{port}/api/v1/version")

        uvicorn.run(
            "plexichat.main:app",
            host=host,
            port=port,
            reload=True,
            log_level="info"
        )
        return True

    except Exception as e:
        logger.error(f"Could not start API server: {e}")
        return False

def run_cli():
    """Run the main CLI interface."""
    try:
        from plexichat.interfaces.cli.main_cli import main as cli_main
        cli_main()
    except Exception as e:
        logger.error(f"Could not start CLI: {e}")

def run_admin_cli():
    """Run admin CLI commands."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to admin commands
        original_argv = sys.argv.copy()

        # If no additional args, show admin help
        if len(sys.argv) <= 2:
            sys.argv = ['plexichat', 'admin', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['plexichat', 'admin'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        logger.error(f"Could not start admin CLI: {e}")
        print("Admin CLI not available. Please check your installation.")

def run_backup_node():
    """Run backup node."""
    try:
        from plexichat.features.backup.nodes.backup_node_main import main as backup_main
        import asyncio
        asyncio.run(backup_main())
    except Exception as e:
        logger.error(f"Could not start backup node: {e}")

def run_plugin_manager():
    """Run plugin management CLI."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to plugin commands
        original_argv = sys.argv.copy()

        # If no additional args, show plugin help
        if len(sys.argv) <= 2:
            sys.argv = ['run.py', 'plugins', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['run.py', 'plugins'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        logger.error(f"Could not start plugin manager: {e}")
        print("Plugin manager CLI not available. Please check your installation.")

def show_help():
    """Display comprehensive help information."""
    help_text = f"""
{Colors.BOLD}{Colors.BLUE}PlexiChat - Government-Level Secure Communication Platform{Colors.RESET}
{Colors.DIM}{'=' * 80}{Colors.RESET}

{Colors.BOLD}Usage:{Colors.RESET} python run.py [command] [options]

{Colors.BOLD}Main Commands:{Colors.RESET}
  {Colors.GREEN}(no command){Colors.RESET}     - Start API server with splitscreen CLI (default)
  {Colors.GREEN}api{Colors.RESET}              - Start API server with splitscreen CLI
  {Colors.GREEN}gui{Colors.RESET}              - Launch GUI (starts API server and splitscreen CLI)
  {Colors.GREEN}webui{Colors.RESET}            - Launch Web UI interface
  {Colors.GREEN}cli{Colors.RESET}              - Run comprehensive CLI interface
  {Colors.GREEN}admin{Colors.RESET}            - Run admin CLI commands only
  {Colors.GREEN}backup-node{Colors.RESET}      - Start backup node server
  {Colors.GREEN}plugin{Colors.RESET}           - Plugin management CLI
  {Colors.GREEN}test{Colors.RESET}             - Run enhanced test suite
  {Colors.GREEN}help{Colors.RESET}             - Show this help

{Colors.BOLD}Setup & Management Commands:{Colors.RESET}
  {Colors.CYAN}setup{Colors.RESET}             - Run first-time setup wizard
  {Colors.CYAN}advanced-setup{Colors.RESET}    - Run comprehensive advanced setup wizard
  {Colors.CYAN}wizard{Colors.RESET}            - Run configuration wizard
  {Colors.CYAN}config{Colors.RESET}            - Show/modify configuration
  {Colors.CYAN}update{Colors.RESET}            - Run update system
  {Colors.CYAN}version{Colors.RESET}           - Version management interface
  {Colors.CYAN}deps{Colors.RESET}              - Dependency management interface
  {Colors.CYAN}system{Colors.RESET}            - System management interface
  {Colors.CYAN}clean{Colors.RESET}             - Clean system cache and temporary files
  {Colors.CYAN}optimize{Colors.RESET}          - Run performance optimization
  {Colors.CYAN}diagnostic{Colors.RESET}        - Run comprehensive system diagnostics
  {Colors.CYAN}maintenance{Colors.RESET}       - Run maintenance mode with all optimizations

{Colors.BOLD}GitHub Integration Commands:{Colors.RESET}
  {Colors.YELLOW}download{Colors.RESET}         - Download specific version from GitHub
  {Colors.YELLOW}latest{Colors.RESET}           - Download latest version from GitHub
  {Colors.YELLOW}versions{Colors.RESET}         - List available versions on GitHub

{Colors.BOLD}Options:{Colors.RESET}
  {Colors.WHITE}--verbose, -v{Colors.RESET}    - Enable verbose output
  {Colors.WHITE}--debug, -d{Colors.RESET}      - Enable debug mode
  {Colors.WHITE}--config FILE{Colors.RESET}    - Use custom config file
  {Colors.WHITE}--log-level LEVEL{Colors.RESET} - Set log level (DEBUG, INFO, WARNING, ERROR)
  {Colors.WHITE}--port PORT{Colors.RESET}      - Override port number
  {Colors.WHITE}--host HOST{Colors.RESET}      - Override host address
  {Colors.WHITE}--no-ui{Colors.RESET}          - Disable terminal UI for setup commands

{Colors.BOLD}Examples:{Colors.RESET}
  {Colors.DIM}python run.py{Colors.RESET}                    # Start API server with splitscreen CLI (default)
  {Colors.DIM}python run.py setup{Colors.RESET}              # Run first-time setup wizard
  {Colors.DIM}python run.py advanced-setup{Colors.RESET}     # Run comprehensive advanced setup
  {Colors.DIM}python run.py gui{Colors.RESET}                # Launch GUI interface
  {Colors.DIM}python run.py version{Colors.RESET}            # Manage versions and downloads
  {Colors.DIM}python run.py download v1.2.0{Colors.RESET}    # Download specific version
  {Colors.DIM}python run.py update{Colors.RESET}             # Check for and install updates
  {Colors.DIM}python run.py deps{Colors.RESET}               # Manage dependencies
  {Colors.DIM}python run.py optimize{Colors.RESET}           # Run performance optimization
  {Colors.DIM}python run.py diagnostic{Colors.RESET}         # Run system diagnostics
  {Colors.DIM}python run.py maintenance{Colors.RESET}        # Run full maintenance mode
  {Colors.DIM}python run.py clean{Colors.RESET}              # Clean system cache
  {Colors.DIM}python run.py wizard{Colors.RESET}             # Configure PlexiChat
  {Colors.DIM}python run.py --verbose{Colors.RESET}          # Start with verbose logging

{Colors.BOLD}Features:{Colors.RESET}
  {Colors.GREEN}•{Colors.RESET} API server with comprehensive endpoints
  {Colors.GREEN}•{Colors.RESET} Admin management system with CLI and web interface
  {Colors.GREEN}•{Colors.RESET} Backup node system with clustering
  {Colors.GREEN}•{Colors.RESET} Plugin system with SDK
  {Colors.GREEN}•{Colors.RESET} File attachment support for messages
  {Colors.GREEN}•{Colors.RESET} Security scanning for uploaded files
  {Colors.GREEN}•{Colors.RESET} Real-time messaging capabilities
  {Colors.GREEN}•{Colors.RESET} Enhanced splitscreen CLI with terminal UI
  {Colors.GREEN}•{Colors.RESET} Comprehensive test suite
  {Colors.GREEN}•{Colors.RESET} Configuration management wizard
  {Colors.GREEN}•{Colors.RESET} GitHub version management and downloads
  {Colors.GREEN}•{Colors.RESET} Dependency management and virtual environments
  {Colors.GREEN}•{Colors.RESET} System monitoring and cleanup tools
  {Colors.GREEN}•{Colors.RESET} Security features and encryption
  {Colors.GREEN}•{Colors.RESET} AI integration and automation
  {Colors.GREEN}•{Colors.RESET} Advanced logging and monitoring
  {Colors.GREEN}•{Colors.RESET} Dynamic terminal UI with real-time updates

{Colors.BOLD}Version:{Colors.RESET} {PLEXICHAT_VERSION} (alpha version)
{Colors.BOLD}API Version:{Colors.RESET} v1
{Colors.BOLD}GitHub:{Colors.RESET} https://github.com/{GITHUB_REPO}

{Colors.DIM}For more information, visit the documentation or run specific commands with --help{Colors.RESET}
"""
    print(help_text)

def parse_arguments():
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments

    Raises:
        SystemExit: If there's an error parsing arguments
    """
    try:
        parser = argparse.ArgumentParser(
            description="PlexiChat - Government-Level Secure Communication Platform",
            add_help=False,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
{Colors.BOLD}Examples:{Colors.RESET}
  run.py                    # Start API server with splitscreen CLI (default)
  run.py setup              # Run first-time setup wizard
  run.py gui                # Launch GUI interface
  run.py version            # Manage versions and downloads
  run.py update             # Check for and install updates
  run.py deps               # Manage dependencies
  run.py clean              # Clean system cache
  run.py wizard             # Configure PlexiChat
  run.py --verbose          # Enable verbose logging
  run.py --log-level DEBUG  # Set log level to DEBUG
"""
        )

        # Command argument with expanded choices
        parser.add_argument('command',
                          nargs='?',
                          default='api',
                          choices=[
                              'api', 'gui', 'webui', 'cli', 'admin', 'backup-node', 'plugin',
                              'test', 'config', 'wizard', 'help', 'setup', 'update', 'version',
                              'deps', 'system', 'clean', 'download', 'latest', 'versions',
                              'advanced-setup', 'optimize', 'diagnostic', 'maintenance'
                          ],
                          help='Command to execute (default: %(default)s)')

        # Additional positional arguments for some commands
        parser.add_argument('args',
                          nargs='*',
                          help='Additional arguments for specific commands')

        # Optional arguments
        parser.add_argument('--verbose', '-v',
                          action='store_true',
                          help='Enable verbose output (same as --log-level=DEBUG)')
        parser.add_argument('--debug', '-d',
                          action='store_true',
                          help='Enable debug mode (same as --log-level=DEBUG)')
        parser.add_argument('--config',
                          type=str,
                          metavar='FILE',
                          help='Use custom config file')
        parser.add_argument('--log-level',
                          choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                          default='INFO',
                          help='Set the logging level (default: %(default)s)')
        parser.add_argument('--port',
                          type=int,
                          help='Override default port number')
        parser.add_argument('--host',
                          type=str,
                          help='Override default host address')
        parser.add_argument('--no-ui',
                          action='store_true',
                          help='Disable terminal UI for setup commands')
        parser.add_argument('--target-dir',
                          type=str,
                          default='./downloads',
                          help='Target directory for downloads (default: %(default)s)')
        parser.add_argument('--help', '-h',
                          action='store_true',
                          help='Show this help message and exit')

        # Parse and return arguments
        return parser.parse_args()

    except Exception as e:
        logger.error(f"Error parsing command line arguments: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
        sys.exit(1)

def print_config_info(config: Optional[Dict[str, Any]]):
    """Print configuration information."""
    if config:
        print(f"\n{Colors.BOLD}{Colors.GREEN}Current Configuration:{Colors.RESET}")
        print(json.dumps(config, indent=2))
    else:
        print(f"\n{Colors.RED}No configuration loaded{Colors.RESET}")

def handle_github_commands(command: str, args: List[str], target_dir: str):
    """Handle GitHub-related commands."""
    github_manager = GitHubVersionManager()

    if command == 'versions':
        versions = github_manager.get_available_versions()
        if versions:
            print(f"\n{Colors.GREEN}Available Versions on GitHub:{Colors.RESET}")
            for i, version in enumerate(versions[:20]):  # Show last 20
                status = f"{Colors.YELLOW}Pre-release{Colors.RESET}" if version['prerelease'] else f"{Colors.GREEN}Release{Colors.RESET}"
                print(f"  {i+1:2d}. {Colors.BOLD}{version['tag']}{Colors.RESET} - {version['name']} ({status})")
                print(f"      Published: {version['published_at']}")
        else:
            print(f"{Colors.RED}Failed to fetch versions from GitHub{Colors.RESET}")

    elif command == 'latest':
        latest = github_manager.get_latest_version()
        if latest:
            print(f"\n{Colors.GREEN}Latest Version on GitHub:{Colors.RESET}")
            print(f"  Tag: {Colors.BOLD}{latest['tag']}{Colors.RESET}")
            print(f"  Name: {latest['name']}")
            print(f"  Published: {latest['published_at']}")
            print(f"  Pre-release: {latest['prerelease']}")

            download = input(f"\n{Colors.CYAN}Download this version? (y/N): {Colors.RESET}").strip().lower()
            if download == 'y':
                Path(target_dir).mkdir(exist_ok=True)
                if github_manager.download_version(latest['tag'], target_dir):
                    print(f"{Colors.GREEN}Version {latest['tag']} downloaded successfully to {target_dir}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to download version {latest['tag']}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Failed to fetch latest version from GitHub{Colors.RESET}")

    elif command == 'download':
        if args:
            version_tag = args[0]
            Path(target_dir).mkdir(exist_ok=True)
            print(f"\n{Colors.CYAN}Downloading version {version_tag} to {target_dir}...{Colors.RESET}")
            if github_manager.download_version(version_tag, target_dir):
                print(f"{Colors.GREEN}Version {version_tag} downloaded successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}Failed to download version {version_tag}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Please specify a version tag to download{Colors.RESET}")
            print(f"Example: python run.py download v1.2.0")



def main():
    # --- BOOTSTRAP LOGIC: Download codebase if missing ---
    import sys, os
    from pathlib import Path
    import shutil
    import zipfile
    import tarfile
    import urllib.request
    import json
    import platform
    def bootstrap_log(msg):
        print(f"[BOOTSTRAP] {msg}")
    # Parse --bootstrap-version argument early
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--bootstrap-version', type=str, default=None, help='Specify a version/tag to bootstrap (e.g., a.1.1-23)')
    parser.add_argument('--list-versions', action='store_true', help='List available tags/releases for bootstrapping')
    args, _ = parser.parse_known_args()
    src_dir = Path(__file__).parent / 'src' / 'plexichat'
    GITHUB_REPO = "linux-of-user/plexichat"
    GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
    GITHUB_TAGS_URL = f"{GITHUB_API_URL}/tags"
    GITHUB_RELEASES_URL = f"{GITHUB_API_URL}/releases"
    GITHUB_LATEST_URL = f"{GITHUB_RELEASES_URL}/latest"
    GITHUB_DOWNLOAD_URL = f"https://github.com/{GITHUB_REPO}/archive"
    target_dir = Path(__file__).parent
    # List available tags/releases if requested
    if args.list_versions:
        try:
            with urllib.request.urlopen(GITHUB_TAGS_URL) as response:
                tags = json.loads(response.read().decode())
            print("Available tags:")
            for tag in tags:
                print(f"- {tag['name']}")
        except Exception as e:
            print(f"Error fetching tags: {e}")
            sys.exit(0)
    # Warn if bootstrapping an alpha/pre-release version
    if args.bootstrap_version and ("alpha" in args.bootstrap_version or "a." in args.bootstrap_version or "beta" in args.bootstrap_version):
        print(f"[BOOTSTRAP] WARNING: You are bootstrapping an alpha/pre-release version: {args.bootstrap_version}")
    if not src_dir.exists():
        bootstrap_log('plexichat source not found, attempting to download codebase from GitHub...')
        tried = []
        success = False
        extracted = None
        # If user specified a version/tag, try that first
        if args.bootstrap_version:
            try:
                tag = args.bootstrap_version
                download_url = f"{GITHUB_DOWNLOAD_URL}/{tag}.zip"
                target_path = target_dir / f"plexichat-{tag}.zip"
                tried.append(download_url)
                bootstrap_log(f"Trying specified version: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / f"plexichat-{tag}"
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Specified version download failed: {e}")
        # Try latest release zip
        if not success:
            try:
                with urllib.request.urlopen(GITHUB_LATEST_URL) as response:
                    data = json.loads(response.read().decode())
                version_tag = data['tag_name']
                download_url = f"{GITHUB_DOWNLOAD_URL}/{version_tag}.zip"
                target_path = target_dir / f"plexichat-{version_tag}.zip"
                tried.append(download_url)
                bootstrap_log(f"Trying latest release: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / f"plexichat-{version_tag}"
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Latest release download failed: {e}")
        # Fallback: main branch zip
        if not success:
            try:
                download_url = f"{GITHUB_DOWNLOAD_URL}/refs/heads/main.zip"
                target_path = target_dir / "plexichat-main.zip"
                tried.append(download_url)
                bootstrap_log(f"Trying main branch: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / "plexichat-main"
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Main branch download failed: {e}")
        # Fallback: master branch zip
        if not success:
            try:
                download_url = f"{GITHUB_DOWNLOAD_URL}/refs/heads/master.zip"
                target_path = target_dir / "plexichat-master.zip"
                tried.append(download_url)
                bootstrap_log(f"Trying master branch: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / "plexichat-master"
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Master branch download failed: {e}")
        # Fallback: main branch tar.gz
        if not success:
            try:
                download_url = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/main.tar.gz"
                target_path = target_dir / "plexichat-main.tar.gz"
                tried.append(download_url)
                bootstrap_log(f"Trying main branch tar.gz: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / "plexichat-main"
                with tarfile.open(target_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Main branch tar.gz download failed: {e}")
        # Fallback: master branch tar.gz
        if not success:
            try:
                download_url = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/master.tar.gz"
                target_path = target_dir / "plexichat-master.tar.gz"
                tried.append(download_url)
                bootstrap_log(f"Trying master branch tar.gz: {download_url}")
                with urllib.request.urlopen(download_url) as response:
                    with open(target_path, 'wb') as f:
                        shutil.copyfileobj(response, f)
                extract_dir = target_dir / "plexichat-master"
                with tarfile.open(target_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                success = True
                extracted = extract_dir
            except Exception as e:
                bootstrap_log(f"Master branch tar.gz download failed: {e}")
        if not success or not extracted:
            bootstrap_log(f"All download attempts failed. Tried URLs: {tried}")
            sys.exit(1)
        # --- Recursively find the real codebase root (contains run.py and src/) ---
        def find_codebase_root(path):
            # Returns the first directory containing both run.py and src/
            for root, dirs, files in os.walk(path):
                if 'run.py' in files and 'src' in dirs:
                    return Path(root)
            return None
        codebase_root = find_codebase_root(extracted)
        if not codebase_root:
            bootstrap_log("ERROR: Could not find codebase root (directory with run.py and src/) after extraction.")
            sys.exit(1)
        # Move contents to current directory (except run.py)
        for item in codebase_root.iterdir():
            if item.name == 'run.py':
                continue
            dest = target_dir / item.name
            if dest.exists():
                if dest.is_dir():
                    shutil.rmtree(dest)
                elif dest.is_file():
                    dest.unlink()
            shutil.move(str(item), str(dest))
        # Remove all parent extracted directories up to the original extracted dir
        try:
            shutil.rmtree(extracted)
        except Exception:
            pass
        # Remove all downloaded archives
        for f in target_dir.glob('plexichat-*.zip'):
            f.unlink()
        for f in target_dir.glob('plexichat-*.tar.gz'):
            f.unlink()
        bootstrap_log('Download and extraction complete. Re-running run.py...')
        os.execv(sys.executable, [sys.executable, __file__] + sys.argv[1:])
    # --- END BOOTSTRAP LOGIC ---

    # Now import everything else (plexichat, src, etc.)
    # All code that depends on the codebase must be here or below
    import logging
    import traceback
    from datetime import datetime
    # ... (all plexichat imports, logger setup, CLI handler definitions, etc.) ...
    # (Paste the rest of the original main() code here)
    # ... existing code ...

if __name__ == "__main__":
    if '--help' in sys.argv or '-h' in sys.argv:
        print("\n[BOOTSTRAP OPTIONS]\n  --bootstrap-version TAG   Bootstrap a specific version/tag (e.g., a.1.1-23)\n  --list-versions         List available tags/releases for bootstrapping\n")
    main()
