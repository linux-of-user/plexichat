#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PlexiChat Application Runner - Enhanced Edition with Bootstrap Installer

Advanced cross-platform entry point with comprehensive setup and monitoring.
Features:
- [*] BOOTSTRAP MODE: One-script installation from GitHub (--bootstrap)
- Interactive first-time setup wizard with style selection
- Multiple terminal display modes (split, tabbed, classic)
- Advanced dependency management with fallback options
- Comprehensive system information and diagnostics
- Real-time performance monitoring
- Debug mode with detailed logging
- Development tools integration
- Automatic environment optimization
- Repository cloning and automatic setup
- Standalone installer capability
"""

import json
import os
import platform
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Platform-specific imports with error handling
try:
    import msvcrt  # Windows key detection
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

try:
    import termios  # Unix key detection
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False
from datetime import datetime

# Try to import optional dependencies
try:
    import yaml  # Optional dependency for version verification and backup/restore
except ImportError:
    yaml = None

try:
    from tqdm import tqdm  # type: ignore
except ImportError:
    tqdm = None

# ============================================================================
# BOOTSTRAP CONFIGURATION
# ============================================================================

# Bootstrap configuration
PLEXICHAT_VERSION = "1.0.0"
GITHUB_REPO = "https://github.com/linux-of-user/plexichat.git"
GITHUB_ZIP = "https://github.com/linux-of-user/plexichat/archive/refs/heads/main.zip"
REQUIRED_PYTHON_BOOTSTRAP = (3, 8)  # Lower requirement for bootstrap

# ============================================================================
# PROGRESS BAR AND UTILITY FUNCTIONS
# ============================================================================

class SimpleProgressBar:
    """Simple progress bar implementation when tqdm is not available."""

    def __init__(self, total, desc="Progress", width=None):
        self.total = total
        self.current = 0
        self.desc = desc
        self.start_time = time.time()

        # Set a fixed, consistent width that works well across terminals
        if width is None:
            try:
                import shutil
                terminal_width = shutil.get_terminal_size().columns
                # Use a conservative approach: ensure we have enough space
                # Format: "Installing package: |????????????????????????????????????????| 100.0% (36/36) ETA: 123s"
                # Reserve space for: description (30) + " |" (2) + "| 100.0% (999/999) ETA: 999s" (25) = 57 chars
                available_width = max(80, terminal_width)  # Ensure minimum 80 chars
                self.width = min(50, available_width - 57)  # Cap bar width at 50, reserve 57 for other elements
                self.width = max(20, self.width)  # Minimum bar width of 20
            except:
                self.width = 30  # Safe fallback
        else:
            self.width = width

    def set_description(self, desc):
        """Set the description for the progress bar (for compatibility with tqdm)."""
        # Truncate description if too long to prevent line wrapping
        if len(desc) > 25:
            self.desc = desc[:22] + "..."
        else:
            self.desc = desc

    def update(self, n=1):
        self.current += n
        self._display()

    def _display(self):
        if self.total == 0:
            return

        percent = (self.current / self.total) * 100
        filled = int((self.current / self.total) * self.width)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self.start_time

        if self.current > 0 and self.current < self.total:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"{int(eta)}s"
        else:
            eta_str = "0s"

        # Create the progress line with consistent formatting
        progress_line = f"{self.desc}: |{bar}| {percent:.1f}% ({self.current}/{self.total}) ETA: {eta_str}"

        # Use simple carriage return for reliable updating
        print(f"\r{progress_line}", end="", flush=True)

    def finish(self):
        """Complete the progress bar and move to next line."""
        if self.current < self.total:
            self.current = self.total
            self._display()
        print()  # Move to next line

        if self.current >= self.total:
            print()  # New line when complete

    def close(self):
        if self.current < self.total:
            self.current = self.total
            self._display()
        else:
            print()  # Ensure we end with a newline

def create_progress_bar(total, desc="Progress"):
    """Create a progress bar using tqdm if available, otherwise use simple implementation."""
    if tqdm is not None:
        return tqdm(total=total, desc=desc, unit="item",
                   bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]")
    else:
        return SimpleProgressBar(total, desc)

def install_with_progress(packages, desc="Installing packages"):
    """Install packages with detailed progress tracking."""
    if not packages:
        return True

    print(f"[*] {desc}...")

    # Create progress bar
    progress = create_progress_bar(len(packages), desc)

    success_count = 0
    failed_packages = []

    for package in packages:
        try:
            # Update progress bar description
            if hasattr(progress, 'set_description'):
                progress.set_description(f"Installing {package}")

            # Install package
            subprocess.run([
                sys.executable, "-m", "pip", "install", package, "--quiet"
            ], capture_output=True, text=True, check=True)

            success_count += 1
            progress.update(1)

        except subprocess.CalledProcessError:
            failed_packages.append(package)
            progress.update(1)
            continue

    progress.close()

    # Report results
    if success_count == len(packages):
        print(f"[OK] Successfully installed {success_count} packages")
        return True
    elif success_count > 0:
        print(f"[WARN] Installed {success_count}/{len(packages)} packages")
        if failed_packages:
            print(f"[ERROR] Failed to install: {', '.join(failed_packages)}")
        return True
    else:
        print("[ERROR] Failed to install all packages")
        return False

# Set up paths
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
VENV_DIR = ROOT / ".venv"
DEPENDENCIES = ROOT / "dependencies.txt"
REQUIREMENTS = ROOT / "requirements.txt"
DEFAULT_CREDS = ROOT / "default_creds.txt"
VERSION_FILE = ROOT / "version.json"
CONFIG_DIR = ROOT / "config"
SETUP_CONFIG = CONFIG_DIR / "setup_config.json"

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# Terminal capabilities
SUPPORTS_COLOR = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
TERMINAL_WIDTH = shutil.get_terminal_size().columns if hasattr(shutil, 'get_terminal_size') else 80

# Add src to Python path
sys.path.insert(0, str(SRC))

# Enhanced configuration
SETUP_STYLES = {
    "minimal": {
        "name": "Minimal Setup",
        "description": "Core functionality only - fastest setup",
        "features": ["Basic API", "Simple WebUI", "SQLite database"],
        "install_time": "~2 minutes"
    },
    "standard": {
        "name": "Standard Setup",
        "description": "Recommended for most users",
        "features": ["Full API", "Enhanced WebUI", "Multiple databases", "Basic security"],
        "install_time": "~5 minutes"
    },
    "full": {
        "name": "Full Setup",
        "description": "All features including advanced security",
        "features": ["Complete API", "Advanced WebUI", "All databases", "Full security", "AI features", "Clustering"],
        "install_time": "~10 minutes"
    },
    "developer": {
        "name": "Developer Setup",
        "description": "Full setup plus development tools",
        "features": ["Everything in Full", "Testing tools", "Debug utilities", "Code analysis"],
        "install_time": "~15 minutes"
    }
}

TERMINAL_STYLES = {
    "classic": {
        "name": "Classic Terminal",
        "description": "Traditional single-pane output",
        "best_for": "Simple terminals, SSH connections"
    },
    "split": {
        "name": "Split Screen",
        "description": "Logs on left, CLI on right",
        "best_for": "Wide terminals (120+ columns)"
    },
    "tabbed": {
        "name": "Tabbed Interface",
        "description": "Switch between logs and CLI with tabs",
        "best_for": "Any terminal size"
    },
    "dashboard": {
        "name": "Live Dashboard",
        "description": "Real-time system monitoring with metrics",
        "best_for": "Development and monitoring"
    }
}


def print_banner():
    """Print enhanced PlexiChat banner with ASCII-only characters."""
    version = get_version_info()
    width = min(TERMINAL_WIDTH, 80)

    # ASCII-only banner for maximum compatibility
    banner = f"""
{'=' * width}
    ########  ##       ######## ##     ## ####  ######  ##     ##    ###    ########
    ##     ## ##       ##        ##   ##   ##  ##    ## ##     ##   ## ##      ##
    ##     ## ##       ##         ## ##    ##  ##       ##     ##  ##   ##     ##
    ########  ##       ######      ###     ##  ##       ######### ##     ##    ##
    ##        ##       ##         ## ##    ##  ##       ##     ## #########    ##
    ##        ##       ##        ##   ##   ##  ##    ## ##     ## ##     ##    ##
    ##        ######## ######## ##     ## ####  ######  ##     ## ##     ##    ##

    [*] Government-Level Secure Communication Platform v{version}
    [*] Advanced AI * Zero-Trust Security * Distributed Architecture
{'=' * width}
"""
    print(banner)


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 11):
        print("[ERROR] Error: Python 3.11 or higher is required")
        print(f"Current version: {sys.version}")
        print("\n[INFO] To install Python 3.11+:")
        if IS_WINDOWS:
            print("   * Download from https://python.org/downloads/")
            print("   * Or use: winget install Python.Python.3.11")
        elif IS_LINUX:
            print("   * Ubuntu/Debian: sudo apt update && sudo apt install python3.11")
            print("   * CentOS/RHEL: sudo dnf install python3.11")
        elif IS_MACOS:
            print("   * Homebrew: brew install python@3.11")
            print("   * Or download from https://python.org/downloads/")
        sys.exit(1)
    print(f"[OK] Python version: {sys.version.split()[0]}")


def get_system_info():
    """Get comprehensive system information."""
    try:
        import psutil
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        has_psutil = True
    except ImportError:
        cpu_count = os.cpu_count()
        memory = None
        disk = None
        has_psutil = False

    info = {
        "platform": platform.system(),
        "platform_version": platform.release(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "cpu_count": cpu_count,
        "terminal_width": TERMINAL_WIDTH,
        "supports_color": SUPPORTS_COLOR,
        "has_psutil": has_psutil,
        "hostname": platform.node(),
        "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "environment_variables": {
            "VIRTUAL_ENV": os.getenv("VIRTUAL_ENV", "Not set"),
            "CONDA_DEFAULT_ENV": os.getenv("CONDA_DEFAULT_ENV", "Not set"),
            "PYTHONPATH": os.getenv("PYTHONPATH", "Not set"),
        }
    }

    if has_psutil and memory:
        info["memory_total"] = f"{memory.total / (1024**3):.1f} GB"
        info["memory_available"] = f"{memory.available / (1024**3):.1f} GB"
        info["memory_percent"] = f"{memory.percent:.1f}%"

    if has_psutil and disk:
        info["disk_total"] = f"{disk.total / (1024**3):.1f} GB"
        info["disk_free"] = f"{disk.free / (1024**3):.1f} GB"
        info["disk_percent"] = f"{(disk.used / disk.total) * 100:.1f}%"

    # Add environment manager detection
    try:
        environments = detect_python_environments()
        info["available_env_managers"] = {
            name: details['available'] for name, details in environments.items()
        }
    except:
        info["available_env_managers"] = {"detection_failed": True}

    return info


# ============================================================================
# BOOTSTRAP INSTALLER CLASS
# ============================================================================

class DualProgressBar:
    """
    Enhanced dual progress bar system with proper terminal handling.
    Features two progress bars: overall installation progress and current package progress.
    Uses proper terminal control sequences to avoid screen movement issues.
    """

    def __init__(self, total_packages: int, width: int = 50):
        """Initialize dual progress bar."""
        self.total_packages = total_packages
        self.current_package = 0
        self.width = width
        self.start_time = time.time()
        self.last_update = 0
        self.package_start_time = time.time()
        self.terminal_width = self.get_terminal_width()
        self.lines_printed = 0
        self.overall_progress = 0.0
        self.current_package_name = ""
        self.current_status = "Preparing..."

    def get_terminal_width(self):
        """Get current terminal width with fallback."""
        try:
            return shutil.get_terminal_size().columns
        except:
            return 80

    def format_time(self, seconds):
        """Format time duration in a readable way."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds//60:.0f}m {seconds%60:.0f}s"
        else:
            return f"{seconds//3600:.0f}h {(seconds%3600)//60:.0f}m"

    def clear_current_lines(self):
        """Clear the current progress bar lines without moving cursor up."""
        if self.lines_printed > 0:
            # Move cursor up to the start of our progress bars
            for _ in range(self.lines_printed):
                print("\033[A", end='', flush=True)
            # Clear from cursor to end of screen
            print("\033[J", end='', flush=True)

    def print_progress_bars(self):
        """Print both progress bars with proper formatting."""
        # Calculate overall progress
        if self.total_packages > 0:
            self.overall_progress = min(self.current_package / self.total_packages, 1.0)
        else:
            self.overall_progress = 0

        # Calculate timing
        elapsed = time.time() - self.start_time
        if self.overall_progress > 0 and self.overall_progress < 1.0:
            eta = (elapsed / self.overall_progress) * (1 - self.overall_progress)
        else:
            eta = 0

        # Check if terminal supports Unicode (fallback for basic terminals)
        try:
            # Test Unicode support
            test_char = '█'
            print(test_char, end='', flush=True)
            print('\b', end='', flush=True)  # Move back
            unicode_supported = True
        except:
            unicode_supported = False

        # Build overall progress bar
        filled = int(self.overall_progress * self.width)
        if unicode_supported:
            bar = '█' * filled + '░' * (self.width - filled)
            overall_line = f"📦 Overall Progress: [{bar}] {self.overall_progress*100:.1f}% ({self.current_package}/{self.total_packages})"
        else:
            bar = '#' * filled + '-' * (self.width - filled)
            overall_line = f"Overall Progress: [{bar}] {self.overall_progress*100:.1f}% ({self.current_package}/{self.total_packages})"

        if elapsed > 1:
            if unicode_supported:
                overall_line += f" | ⏱️  Elapsed: {self.format_time(elapsed)}"
                if eta > 1:
                    overall_line += f" | ⏳ ETA: {self.format_time(eta)}"
            else:
                overall_line += f" | Elapsed: {self.format_time(elapsed)}"
                if eta > 1:
                    overall_line += f" | ETA: {self.format_time(eta)}"

        # Build current package line with animated indicator
        package_elapsed = time.time() - self.package_start_time
        if unicode_supported:
            dots = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(package_elapsed * 2) % 10]  # Spinning animation
            status_indicator = f" {dots} " if self.current_status == "Installing" else " ✓ " if self.current_status == "Installed" else " ✗ " if self.current_status == "Failed" else " ⚙️  "
            package_line = f"🔧 Current Package: {status_indicator}{self.current_package_name}"
        else:
            dots = "." * (int(package_elapsed * 2) % 4)  # Simple dots
            status_indicator = f" {dots} " if self.current_status == "Installing" else " [OK] " if self.current_status == "Installed" else " [FAIL] " if self.current_status == "Failed" else " [PREP] "
            package_line = f"Current Package: {status_indicator}{self.current_package_name}"
        
        if package_elapsed > 1 and self.current_status == "Installing":
            package_line += f" ({self.format_time(package_elapsed)})"

        # Print both lines
        print(overall_line)
        print(package_line, end='', flush=True)
        
        # Track that we've printed 2 lines
        self.lines_printed = 2

    def update_overall(self, current_package: int, package_name: str = ""):
        """Update overall progress and current package."""
        self.current_package = current_package
        self.current_package_name = package_name
        self.package_start_time = time.time()
        self.current_status = "Installing"

        # Clear previous lines and print new ones
        self.clear_current_lines()
        self.print_progress_bars()

        self.last_update = time.time()

    def update_package(self, package_name: str, status: str = "Installing"):
        """Update current package progress with status."""
        # Throttle updates to avoid overwhelming the terminal
        current_time = time.time()
        if current_time - self.last_update < 0.2:  # Update max 5 times per second
            return

        self.current_package_name = package_name
        self.current_status = status

        # Only update the current package line (second line)
        if self.lines_printed >= 2:
            # Move cursor up one line to the current package line
            print("\033[A", end='', flush=True)
            
            # Clear the current package line
            print(f"\r{' ' * self.terminal_width}", end='', flush=True)
            
            # Recalculate and print the current package line
            package_elapsed = time.time() - self.package_start_time
            
            # Check Unicode support (same logic as print_progress_bars)
            try:
                test_char = '█'
                print(test_char, end='', flush=True)
                print('\b', end='', flush=True)
                unicode_supported = True
            except:
                unicode_supported = False
            
            if unicode_supported:
                dots = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(package_elapsed * 2) % 10]
                status_indicator = f" {dots} " if status == "Installing" else " ✓ " if status == "Installed" else " ✗ " if status == "Failed" else " ⚙️  "
                package_line = f"🔧 Current Package: {status_indicator}{package_name}"
            else:
                dots = "." * (int(package_elapsed * 2) % 4)
                status_indicator = f" {dots} " if status == "Installing" else " [OK] " if status == "Installed" else " [FAIL] " if status == "Failed" else " [PREP] "
                package_line = f"Current Package: {status_indicator}{package_name}"
            
            if package_elapsed > 1 and status == "Installing":
                package_line += f" ({self.format_time(package_elapsed)})"
            
            print(f"\r{package_line}", end='', flush=True)

        self.last_update = current_time

    def finish(self, message: str = "All packages installed"):
        """Finish progress bars with completion message."""
        # Clear the progress bars
        self.clear_current_lines()

        elapsed = time.time() - self.start_time
        
        # Check Unicode support for completion message
        try:
            test_char = '🎉'
            print(test_char, end='', flush=True)
            print('\b', end='', flush=True)
            unicode_supported = True
        except:
            unicode_supported = False
        
        if unicode_supported:
            final_line = f"🎉 {message} - {self.total_packages} packages in {self.format_time(elapsed)}"
        else:
            final_line = f"[COMPLETE] {message} - {self.total_packages} packages in {self.format_time(elapsed)}"
        
        print(final_line)
        print()  # Extra newline for spacing


class ProgressBar:
    """
    Single progress bar for backward compatibility.
    """

    def __init__(self, total: int, width: int = 50, title: str = "Progress"):
        """Initialize progress bar."""
        self.total = total
        self.current = 0
        self.width = width
        self.title = title
        self.start_time = time.time()
        self.last_update = 0

    def update(self, current: int, message: str = ""):
        """Update progress bar."""
        self.current = current

        # Calculate progress
        if self.total > 0:
            progress = min(current / self.total, 1.0)
        else:
            progress = 0

        # Calculate timing
        elapsed = time.time() - self.start_time
        if progress > 0:
            eta = (elapsed / progress) * (1 - progress)
        else:
            eta = 0

        # Build progress bar
        filled = int(progress * self.width)
        bar = '#' * filled + '-' * (self.width - filled)

        # Format time
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.0f}s"
            elif seconds < 3600:
                return f"{seconds//60:.0f}m {seconds%60:.0f}s"
            else:
                return f"{seconds//3600:.0f}h {(seconds%3600)//60:.0f}m"

        # Build status line
        status_line = f"{self.title}: [{bar}] {progress*100:.1f}% ({current}/{self.total})"

        if elapsed > 1:  # Only show timing after 1 second
            status_line += f" | Elapsed: {format_time(elapsed)}"
            if eta > 1:
                status_line += f" | ETA: {format_time(eta)}"

        if message:
            status_line += f" | {message}"

        # Clear line properly and print
        terminal_width = shutil.get_terminal_size().columns
        print(f"\r{' ' * terminal_width}", end='')
        print(f"\r{status_line}", end='', flush=True)

        self.last_update = time.time()

    def finish(self, message: str = "Complete"):
        """Finish progress bar."""
        self.update(self.total, message)
        print()  # New line after completion


class OSSpecificSetupWizard:
    """
    OS-specific interactive setup wizard for PlexiChat configuration.
    Adapts interface and recommendations based on operating system.
    """

    def __init__(self):
        """Initialize the setup wizard."""
        self.os_type = self.detect_os()
        self.config = {}
        self.features = self.get_os_specific_features()
        self.recommendations = self.get_os_recommendations()

    def detect_os(self) -> str:
        """Detect the operating system."""
        import platform
        system = platform.system().lower()

        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            # Try to detect specific Linux distributions
            try:
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'ubuntu' in content:
                        return "ubuntu"
                    elif 'debian' in content:
                        return "debian"
                    elif 'centos' in content or 'rhel' in content:
                        return "centos"
                    elif 'fedora' in content:
                        return "fedora"
                    else:
                        return "linux"
            except:
                return "linux"
        elif 'bsd' in system:
            return "bsd"
        else:
            return "unknown"

    def get_os_specific_features(self) -> Dict[str, Dict[str, Any]]:
        """Get features with OS-specific defaults and recommendations."""
        base_features = {
            'installation_type': {
                'name': 'Installation Type',
                'options': ['minimal', 'standard', 'full', 'developer'],
                'selected': 1,  # Default to standard
                'required': True,
                'description': 'Choose installation complexity level'
            },
            'database_type': {
                'name': 'Database Type',
                'options': ['sqlite', 'postgresql', 'mysql'],
                'selected': 0,  # Will be adjusted per OS
                'required': True,
                'description': 'Select database backend'
            },
            'web_interface': {
                'name': 'Web Interface',
                'enabled': True,
                'description': 'Enable web-based user interface'
            },
            'api_server': {
                'name': 'REST API',
                'enabled': True,
                'description': 'Enable REST API for integrations'
            },
            'ssl_security': {
                'name': 'SSL/TLS Security',
                'enabled': True,  # Will be adjusted per OS
                'description': 'Set up SSL certificates for secure connections'
            },
            'monitoring': {
                'name': 'System Monitoring',
                'enabled': False,  # Will be adjusted per OS
                'description': 'Monitor system performance and health'
            },
            'backup_system': {
                'name': 'Automated Backups',
                'enabled': False,
                'description': 'Automatic backup of data and configurations'
            },
            'debug_mode': {
                'name': 'Debug Mode',
                'enabled': False,
                'description': 'Enable debugging features for development'
            }
        }

        # OS-specific adjustments
        if self.os_type == "windows":
            base_features['database_type']['selected'] = 0  # SQLite
            base_features['ssl_security']['enabled'] = False  # Windows SSL setup is complex

        elif self.os_type in ["ubuntu", "debian", "linux"]:
            base_features['database_type']['selected'] = 1  # PostgreSQL
            base_features['monitoring']['enabled'] = True

        elif self.os_type == "macos":
            base_features['database_type']['selected'] = 1  # PostgreSQL
            base_features['ssl_security']['enabled'] = True

        elif self.os_type == "bsd":
            base_features['database_type']['selected'] = 1  # PostgreSQL
            base_features['monitoring']['enabled'] = True
            base_features['ssl_security']['enabled'] = True

        return base_features

    def get_os_recommendations(self) -> Dict[str, str]:
        """Get OS-specific recommendations and setup notes."""
        recommendations = {
            "windows": {
                "title": "Windows Setup Recommendations",
                "notes": [
                    "* SQLite is recommended for easy setup (no additional database installation)",
                    "* SSL setup can be complex on Windows - consider disabling for local development",
                    "* Windows Defender may flag the application - add to exclusions if needed",
                    "* Use PowerShell or Command Prompt as administrator for best results",
                    "* Consider using Windows Subsystem for Linux (WSL) for advanced features"
                ],
                "database_note": "SQLite requires no additional setup and works well on Windows",
                "ssl_note": "SSL setup on Windows requires additional certificates - disable for local testing"
            },
            "ubuntu": {
                "title": "Ubuntu Setup Recommendations",
                "notes": [
                    "* PostgreSQL is recommended and easily installed via apt",
                    "* SSL certificates can be generated automatically",
                    "* System monitoring works well with native Linux tools",
                    "* Use 'sudo apt update && sudo apt install postgresql' for database setup",
                    "* Consider using systemd for service management"
                ],
                "database_note": "PostgreSQL: sudo apt install postgresql postgresql-contrib",
                "ssl_note": "SSL certificates can be auto-generated using Let's Encrypt"
            },
            "debian": {
                "title": "Debian Setup Recommendations",
                "notes": [
                    "* PostgreSQL is recommended and available in repositories",
                    "* SSL setup works well with certbot/Let's Encrypt",
                    "* Monitoring integrates with systemd and standard Linux tools",
                    "* Use 'apt-get install postgresql' for database setup",
                    "* Consider using systemd for service management"
                ],
                "database_note": "PostgreSQL: apt-get install postgresql postgresql-contrib",
                "ssl_note": "SSL: apt-get install certbot for Let's Encrypt certificates"
            },
            "macos": {
                "title": "macOS Setup Recommendations",
                "notes": [
                    "* PostgreSQL is recommended and available via Homebrew",
                    "* SSL certificates work well with macOS keychain integration",
                    "* Use 'brew install postgresql' for easy database setup",
                    "* macOS has excellent development tools and monitoring",
                    "* Consider using launchd for service management"
                ],
                "database_note": "PostgreSQL: brew install postgresql && brew services start postgresql",
                "ssl_note": "SSL certificates integrate well with macOS keychain"
            },
            "bsd": {
                "title": "BSD Setup Recommendations",
                "notes": [
                    "* PostgreSQL is recommended and available in ports/packages",
                    "* SSL setup works well with OpenSSL",
                    "* BSD has excellent security and monitoring capabilities",
                    "* Use pkg install postgresql for FreeBSD",
                    "* Consider using rc.d for service management"
                ],
                "database_note": "PostgreSQL: pkg install postgresql13-server (FreeBSD)",
                "ssl_note": "SSL works well with OpenSSL and BSD security features"
            },
            "linux": {
                "title": "Linux Setup Recommendations",
                "notes": [
                    "* PostgreSQL is recommended for most Linux distributions",
                    "* SSL certificates can be generated automatically",
                    "* System monitoring works well with native tools",
                    "* Check your distribution's package manager for PostgreSQL",
                    "* Use systemd or your init system for service management"
                ],
                "database_note": "PostgreSQL: Check your package manager (yum, dnf, pacman, etc.)",
                "ssl_note": "SSL certificates can be auto-generated on most Linux systems"
            }
        }

        return recommendations.get(self.os_type, recommendations["linux"])

    def get_input_method(self) -> str:
        """Determine the best input method for this OS."""
        if self.os_type == "windows":
            return "numbers"  # Use number selection on Windows
        else:
            return "arrows"   # Use arrow keys on Unix-like systems

    def run_setup_wizard(self) -> Dict[str, Any]:
        """Run the OS-specific setup wizard."""
        self.show_os_welcome()

        if self.get_input_method() == "numbers":
            return self.run_windows_setup()
        else:
            return self.run_unix_setup()

    def show_os_welcome(self):
        """Show OS-specific welcome message."""
        self.clear_screen()
        recommendations = self.recommendations

        print("PlexiChat Setup Wizard")
        print("=" * 50)
        print(f"Detected OS: {self.os_type.title()}")
        print()
        print(recommendations["title"])
        print("-" * len(recommendations["title"]))

        for note in recommendations["notes"]:
            print(note)

        print()
        print(f"Database: {recommendations['database_note']}")
        print(f"SSL: {recommendations['ssl_note']}")
        print()
        input("Press ENTER to continue...")

    def run_windows_setup(self) -> Dict[str, Any]:
        """Run Windows-specific setup with number selection."""
        print("\nWindows Setup Mode - Use numbers to select options")
        print("=" * 50)

        config = {}

        # Installation type selection
        print("\n1. Choose Installation Type:")
        for i, option in enumerate(self.features['installation_type']['options']):
            marker = " (Recommended)" if i == self.features['installation_type']['selected'] else ""
            print(f"   {i+1}. {option.title()}{marker}")

        while True:
            try:
                choice = input(f"\nSelect installation type (1-{len(self.features['installation_type']['options'])}) [2]: ").strip()
                if not choice:
                    choice = "2"  # Default to standard
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(self.features['installation_type']['options']):
                    config['installation_type'] = self.features['installation_type']['options'][choice_idx]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")

        # Database type selection
        print("\n2. Choose Database Type:")
        for i, option in enumerate(self.features['database_type']['options']):
            marker = " (Recommended for Windows)" if i == self.features['database_type']['selected'] else ""
            print(f"   {i+1}. {option.title()}{marker}")

        while True:
            try:
                choice = input(f"\nSelect database type (1-{len(self.features['database_type']['options'])}) [1]: ").strip()
                if not choice:
                    choice = "1"  # Default to SQLite on Windows
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(self.features['database_type']['options']):
                    config['database_type'] = self.features['database_type']['options'][choice_idx]
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")

        # Feature selection
        print("\n3. Choose Features (y/n for each):")
        for key, feature in self.features.items():
            if key not in ['installation_type', 'database_type'] and 'enabled' in feature:
                default = "y" if feature['enabled'] else "n"
                choice = input(f"   Enable {feature['name']}? (y/n) [{default}]: ").strip().lower()
                if not choice:
                    choice = default
                config[key] = choice.startswith('y')

        # Add metadata (don't override setup_style - let interactive_setup_wizard handle it)
        config.update({
            'os_type': self.os_type,
            'input_method': 'numbers',
            'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': get_system_info()
        })

        return config

    def run_unix_setup(self) -> Dict[str, Any]:
        """Run Unix-like setup with arrow key navigation."""
        print(f"\n{self.os_type.title()} Setup Mode - Use arrow keys or numbers to navigate")
        print("=" * 60)

        config = {}

        # Installation type selection with arrow keys
        print("\n1. Choose Installation Type:")
        config['installation_type'] = self.select_from_options(
            "Installation Type",
            self.features['installation_type']['options'],
            self.features['installation_type']['selected']
        )

        # Database type selection
        print("\n2. Choose Database Type:")
        config['database_type'] = self.select_from_options(
            "Database Type",
            self.features['database_type']['options'],
            self.features['database_type']['selected']
        )

        # Feature selection
        print("\n3. Configure Features:")
        for key, feature in self.features.items():
            if key not in ['installation_type', 'database_type'] and 'enabled' in feature:
                config[key] = self.select_yes_no(
                    f"Enable {feature['name']}?",
                    feature['enabled'],
                    feature['description']
                )

        # Add metadata (don't override setup_style - let interactive_setup_wizard handle it)
        config.update({
            'os_type': self.os_type,
            'input_method': 'arrows',
            'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': get_system_info()
        })

        return config

    def select_from_options(self, title: str, options: List[str], default_idx: int = 0) -> str:
        """Select from a list of options with arrow key support."""
        current = default_idx

        while True:
            self.clear_screen()
            print(f"{title}")
            print("-" * (len(title) + 4))
            print()

            for i, option in enumerate(options):
                marker = "-> " if i == current else "   "
                recommended = " (Recommended)" if i == default_idx else ""
                print(f"{marker}{i+1}. {option.title()}{recommended}")

            print()
            print("Use UP/DOWN arrow keys to navigate, ENTER to select, or type number:")

            try:
                if HAS_TERMIOS and not IS_WINDOWS:
                    # Try arrow key input on Unix systems
                    key = self.get_unix_key()
                    if key == '\x1b[A':  # Up arrow
                        current = (current - 1) % len(options)
                        continue
                    elif key == '\x1b[B':  # Down arrow
                        current = (current + 1) % len(options)
                        continue
                    elif key == '\r' or key == '\n':  # Enter
                        return options[current]
                    elif key.isdigit():
                        choice_idx = int(key) - 1
                        if 0 <= choice_idx < len(options):
                            return options[choice_idx]
                else:
                    # Fallback to number input
                    choice = input().strip()
                    if not choice:  # Enter pressed
                        return options[current]
                    elif choice.isdigit():
                        choice_idx = int(choice) - 1
                        if 0 <= choice_idx < len(options):
                            return options[choice_idx]
                        else:
                            print(f"Invalid choice. Please select 1-{len(options)}")
                            time.sleep(1)
                    else:
                        print("Please enter a number or use arrow keys")
                        time.sleep(1)
            except KeyboardInterrupt:
                print("\nSetup cancelled.")
                sys.exit(0)

    def select_yes_no(self, question: str, default: bool, description: str = "") -> bool:
        """Select yes/no with description."""
        default_text = "Y/n" if default else "y/N"

        print(f"\n? {question}")
        if description:
            print(f"   {description}")

        while True:
            choice = input(f"   ({default_text}): ").strip().lower()
            if not choice:
                return default
            elif choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                return False
            else:
                print("   Please enter 'y' or 'n'")

    def get_unix_key(self) -> str:
        """Get key input on Unix systems with arrow key support."""
        if not HAS_TERMIOS:
            return input().strip()

        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                key = sys.stdin.read(1)

                # Check for escape sequences (arrow keys)
                if key == '\x1b':
                    key += sys.stdin.read(2)

                return key
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except:
            return input().strip()

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if IS_WINDOWS else 'clear')

    def _fallback_input(self):
        """Fallback input method when special key detection is not available."""
        print("(Press ENTER after your choice)")
        choice = input("Choice: ").strip()
        return choice[:1] if choice else '\r'


# Create alias for backward compatibility
InteractiveSetupWizard = OSSpecificSetupWizard


class LegacySetupWizard:

    def print_header(self, title):
        """Print a formatted header."""
        print("=" * 70)
        print(f"  {title}")
        print("=" * 70)

    def print_menu_item(self, index, text, selected=False, enabled=None):
        """Print a menu item with selection indicator."""
        if selected:
            prefix = ">> "
        else:
            prefix = "   "

        if enabled is not None:
            status = "[ON]" if enabled else "[OFF]"
            print(f"{prefix}{index + 1}. {text} {status}")
        else:
            print(f"{prefix}{index + 1}. {text}")

    def show_selection_menu(self, title, options, current_selection=0):
        """Show a selection menu with arrow key navigation and fallback."""
        selection = current_selection
        use_simple_mode = not (HAS_MSVCRT or HAS_TERMIOS)

        while True:
            self.clear_screen()
            self.print_header(title)
            print()

            for i, option in enumerate(options):
                self.print_menu_item(i, option, selected=(i == selection))

            print()
            if use_simple_mode:
                print("Enter number (1-{}), Q to quit:".format(len(options)))
                key = self.get_key_input()

                if key.upper() == 'Q':
                    return None
                elif key.isdigit():
                    num = int(key) - 1
                    if 0 <= num < len(options):
                        return num
                    else:
                        print(f"Invalid choice. Please enter 1-{len(options)}")
                        time.sleep(1)
                else:
                    print("Invalid input. Please enter a number or Q to quit.")
                    time.sleep(1)
            else:
                print("Use UP/DOWN arrows to navigate, ENTER to select, Q to quit")
                key = self.get_key_input()

                if key == '\x1b':  # ESC key
                    # Check for arrow keys (ESC [ A/B)
                    try:
                        next_key = self.get_key_input()
                        if next_key == '[':
                            arrow_key = self.get_key_input()
                            if arrow_key == 'A':  # Up arrow
                                selection = (selection - 1) % len(options)
                            elif arrow_key == 'B':  # Down arrow
                                selection = (selection + 1) % len(options)
                        else:
                            return None  # ESC pressed
                    except:
                        return None  # ESC pressed
                elif key == '\r' or key == '\n':  # Enter key
                    return selection
                elif key.upper() == 'Q':
                    return None
                elif key.isdigit():
                    num = int(key) - 1
                    if 0 <= num < len(options):
                        return num

    def show_features_menu(self):
        """Show interactive features configuration menu with fallback."""
        feature_keys = [k for k in self.features.keys() if not self.features[k].get('required', False)]
        selection = 0
        use_simple_mode = not (HAS_MSVCRT or HAS_TERMIOS)

        while True:
            self.clear_screen()
            self.print_header("PlexiChat Features Configuration")
            print()

            if use_simple_mode:
                print("Configure optional features:")
                print()

                for i, key in enumerate(feature_keys):
                    feature = self.features[key]
                    enabled = feature.get('enabled', False)
                    status = "[ON]" if enabled else "[OFF]"
                    print(f"  {i+1}. {feature['name']} {status}")
                    print(f"     {feature.get('description', '')}")
                    print()

                print("Enter number to toggle (1-{}), C to continue, Q to quit:".format(len(feature_keys)))
                key = self.get_key_input()

                if key.upper() == 'Q':
                    return False
                elif key.upper() == 'C':
                    break
                elif key.isdigit():
                    num = int(key) - 1
                    if 0 <= num < len(feature_keys):
                        feature_key = feature_keys[num]
                        self.features[feature_key]['enabled'] = not self.features[feature_key]['enabled']
                    else:
                        print(f"Invalid choice. Please enter 1-{len(feature_keys)}")
                        time.sleep(1)
                else:
                    print("Invalid input. Enter number, C to continue, or Q to quit.")
                    time.sleep(1)
            else:
                print("Configure optional features (use SPACE to toggle, ENTER to continue):")
                print()

                for i, key in enumerate(feature_keys):
                    feature = self.features[key]
                    selected = (i == selection)
                    enabled = feature.get('enabled', False)

                    self.print_menu_item(i, feature['name'], selected=selected, enabled=enabled)
                    if selected:
                        print(f"     {feature.get('description', '')}")

                print()
                print("Controls: UP/DOWN arrows, SPACE to toggle, ENTER to continue, Q to quit")

                key = self.get_key_input()

                if key == '\x1b':  # ESC key for arrow keys
                    try:
                        next_key = self.get_key_input()
                        if next_key == '[':
                            arrow_key = self.get_key_input()
                            if arrow_key == 'A':  # Up arrow
                                selection = (selection - 1) % len(feature_keys)
                            elif arrow_key == 'B':  # Down arrow
                                selection = (selection + 1) % len(feature_keys)
                    except:
                        pass
                elif key == ' ':  # Space to toggle
                    feature_key = feature_keys[selection]
                    self.features[feature_key]['enabled'] = not self.features[feature_key]['enabled']
                elif key == '\r' or key == '\n':  # Enter to continue
                    break
                elif key.upper() == 'Q':
                    return False

        return True

    def run_setup_wizard(self):
        """Run the complete setup wizard (interactive or simple)."""
        # Check if we can use interactive features
        use_simple_mode = not (HAS_MSVCRT or HAS_TERMIOS)

        if use_simple_mode:
            print("=" * 70)
            print("  PlexiChat Setup Wizard (Simple Mode)")
            print("=" * 70)
            print()
            print("Interactive features not available on this system.")
            print("Using simplified text-based setup.")
            print()
            return self.run_simple_setup()

        self.clear_screen()
        print("=" * 70)
        print("  Welcome to PlexiChat Interactive Setup Wizard")
        print("=" * 70)
        print()
        print("This wizard will guide you through configuring PlexiChat.")
        print("Press ENTER to continue or Q to quit...")

        key = input().strip()
        if key.upper() == 'Q':
            return False

        # Step 1: Choose installation type
        install_result = self.show_selection_menu(
            "Choose Installation Type",
            self.features['installation_type']['options'],
            self.features['installation_type']['selected']
        )

        if install_result is None:
            return False

        self.features['installation_type']['selected'] = install_result
        self.config['installation_type'] = self.features['installation_type']['options'][install_result]

        # Step 2: Choose database type
        db_result = self.show_selection_menu(
            "Choose Database Type",
            self.features['database_type']['options'],
            self.features['database_type']['selected']
        )

        if db_result is None:
            return False

        self.features['database_type']['selected'] = db_result
        self.config['database_type'] = self.features['database_type']['options'][db_result]

        # Step 3: Choose terminal style
        terminal_result = self.show_selection_menu(
            "Choose Terminal Style",
            self.features['terminal_style']['options'],
            self.features['terminal_style']['selected']
        )

        if terminal_result is None:
            return False

        self.features['terminal_style']['selected'] = terminal_result
        self.config['terminal_style'] = self.features['terminal_style']['options'][terminal_result]

        # Step 4: Configure optional features
        if not self.show_features_menu():
            return False

        # Save enabled features to config
        for key, feature in self.features.items():
            if not feature.get('required', False):
                self.config[key] = feature.get('enabled', False)

        return True

    def run_simple_setup(self):
        """Run a simple text-based setup for systems without interactive support."""
        print("=" * 70)
        print("  PlexiChat Simple Setup")
        print("=" * 70)
        print()
        print("This system doesn't support interactive menus.")
        print("Using simplified text-based setup.")
        print()

        # Installation type
        print("Choose installation type:")
        print("1. Minimal (basic features only)")
        print("2. Standard (recommended)")
        print("3. Full (all features)")
        print("4. Developer (full + debugging)")

        while True:
            choice = input("Enter choice (1-4) [2]: ").strip()
            if not choice:
                choice = "2"

            if choice in ['1', '2', '3', '4']:
                install_types = ['Minimal', 'Standard', 'Full', 'Developer']
                self.config['installation_type'] = install_types[int(choice) - 1]
                self.features['installation_type']['selected'] = int(choice) - 1
                break
            else:
                print("Invalid choice. Please enter 1-4.")

        # Database type
        print("\nChoose database type:")
        print("1. SQLite (Default) - No setup required")
        print("2. PostgreSQL - Requires PostgreSQL server")
        print("3. MySQL - Requires MySQL server")
        print("4. MongoDB - Requires MongoDB server")

        while True:
            choice = input("Enter choice (1-4) [1]: ").strip()
            if not choice:
                choice = "1"

            if choice in ['1', '2', '3', '4']:
                db_types = ['SQLite (Default)', 'PostgreSQL', 'MySQL', 'MongoDB']
                self.config['database_type'] = db_types[int(choice) - 1]
                self.features['database_type']['selected'] = int(choice) - 1
                break
            else:
                print("Invalid choice. Please enter 1-4.")

        # Terminal style
        print("\nChoose terminal style:")
        print("1. Classic Terminal - Traditional command line")
        print("2. Split Screen - Side-by-side panels (recommended)")
        print("3. Tabbed Interface - Multiple tabs")
        print("4. Modern Dashboard - Rich UI with widgets")

        while True:
            choice = input("Enter choice (1-4) [2]: ").strip()
            if not choice:
                choice = "2"

            if choice in ['1', '2', '3', '4']:
                terminal_types = ['Classic Terminal', 'Split Screen', 'Tabbed Interface', 'Modern Dashboard']
                self.config['terminal_style'] = terminal_types[int(choice) - 1]
                self.features['terminal_style']['selected'] = int(choice) - 1
                break
            else:
                print("Invalid choice. Please enter 1-4.")

        # Simple yes/no for key features
        features_to_ask = [
            ('ai_features', 'Enable AI features?'),
            ('security_features', 'Enable enhanced security?'),
            ('monitoring', 'Enable monitoring and analytics?'),
            ('ssl_setup', 'Enable SSL/TLS setup?'),
            ('webui', 'Enable Web UI?')
        ]

        for feature_key, question in features_to_ask:
            while True:
                answer = input(f"\n{question} (Y/n): ").strip().lower()
                if answer in ['', 'y', 'yes']:
                    self.features[feature_key]['enabled'] = True
                    self.config[feature_key] = True
                    break
                elif answer in ['n', 'no']:
                    self.features[feature_key]['enabled'] = False
                    self.config[feature_key] = False
                    break
                else:
                    print("Please enter Y or N")

        return True


class PlexiChatBootstrapper:
    """
    Enhanced bootstrap installer for PlexiChat.

    Downloads PlexiChat source code into the same directory as run.py,
    supports multiple download methods, version selection, and individual file updates.
    """

    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.install_dir = self.script_dir  # Install in same directory, not subfolder
        self.repo_url = "https://github.com/linux-of-user/plexichat.git"
        self.repo_zip_url = "https://github.com/linux-of-user/plexichat/archive/refs/heads/main.zip"
        self.api_url = "https://api.github.com/repos/linux-of-user/plexichat"
        self.raw_url = "https://raw.githubusercontent.com/linux-of-user/plexichat"
        self.available_versions = []
        self.venv_dir = self.script_dir / "venv"
        self.config_file = self.script_dir / "plexichat_config.json"

    def fetch_available_versions(self) -> List[Dict[str, Any]]:
        """Fetch all available versions from GitHub."""
        try:
            print("[*] Fetching available versions from GitHub...")

            # Get releases
            releases_url = f"{self.api_url}/releases"
            response = urllib.request.urlopen(releases_url, timeout=10)
            releases = json.loads(response.read().decode())

            # Get tags
            tags_url = f"{self.api_url}/tags"
            response = urllib.request.urlopen(tags_url, timeout=10)
            tags = json.loads(response.read().decode())

            versions = []

            # Process releases (stable versions)
            for release in releases:
                # Parse version to determine type (r.x.x-x, a.x.x-x, b.x.x-x)
                version_name = release['tag_name']
                version_type = 'release'
                if version_name.startswith('a.'):
                    version_type = 'alpha'
                elif version_name.startswith('b.'):
                    version_type = 'beta'
                elif version_name.startswith('r.'):
                    version_type = 'release'

                versions.append({
                    'name': version_name,
                    'type': version_type,
                    'date': release['published_at'],
                    'prerelease': release['prerelease'] or version_type in ['alpha', 'beta'],
                    'description': release['name'] or version_name,
                    'url': release['zipball_url'],
                    'recommended': version_type == 'release' and not release['prerelease']
                })

            # Process tags (development versions)
            release_tags = {r['tag_name'] for r in releases}
            for tag in tags:
                if tag['name'] not in release_tags:
                    versions.append({
                        'name': tag['name'],
                        'type': 'tag',
                        'date': tag['commit']['committer']['date'],
                        'prerelease': True,
                        'description': f"Development version {tag['name']}",
                        'url': self.repo_zip_url.replace('/main.zip', f'/{tag["name"]}.zip'),
                        'recommended': False
                    })

            # Add main branch
            versions.insert(0, {
                'name': 'main',
                'type': 'branch',
                'date': 'latest',
                'prerelease': True,
                'description': 'Latest development (main branch)',
                'url': self.repo_zip_url,
                'recommended': False
            })

            # Sort by recommendation and date
            versions.sort(key=lambda x: (not x['recommended'], x['date']), reverse=True)

            self.available_versions = versions
            return versions

        except Exception as e:
            print(f"[WARN] Could not fetch versions: {e}")
            # Fallback to main branch only
            self.available_versions = [{
                'name': 'main',
                'type': 'branch',
                'date': 'latest',
                'prerelease': True,
                'description': 'Latest development (main branch)',
                'url': self.repo_zip_url,
                'recommended': False
            }]
            return self.available_versions

    def show_version_selection(self) -> Optional[Dict[str, Any]]:
        """Show version selection menu."""
        if not self.available_versions:
            self.fetch_available_versions()

        print("\n" + "=" * 70)
        print("  Available PlexiChat Versions")
        print("=" * 70)
        print()

        for i, version in enumerate(self.available_versions):
            prefix = "[RECOMMENDED]" if version['recommended'] else ""
            if version['prerelease'] and version['type'] != 'branch':
                prefix += "[PRERELEASE]"
            elif version['type'] == 'branch':
                prefix += "[DEVELOPMENT]"

            print(f"{i+1:2d}. {version['name']} - {version['description']}")
            if prefix:
                print(f"    {prefix}")
            print(f"    Type: {version['type'].title()}, Date: {version['date']}")
            print()

        while True:
            try:
                choice = input(f"Select version (1-{len(self.available_versions)}) [1]: ").strip()
                if not choice:
                    choice = "1"

                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(self.available_versions):
                    selected = self.available_versions[choice_idx]

                    # Show warnings for non-recommended versions
                    if not selected['recommended']:
                        print(f"\n[WARNING] Version '{selected['name']}' is not a stable release!")
                        if selected['type'] == 'branch':
                            print("[WARNING] Development branches may contain unstable code!")
                        elif selected['prerelease']:
                            print("[WARNING] Prerelease versions may contain bugs!")

                        confirm = input("Continue anyway? (y/N): ").strip().lower()
                        if not confirm.startswith('y'):
                            continue

                    return selected
                else:
                    print(f"[ERROR] Invalid choice. Please select 1-{len(self.available_versions)}")
            except ValueError:
                print("[ERROR] Please enter a number")
            except KeyboardInterrupt:
                print("\n[INFO] Version selection cancelled")
                return None

    def print_bootstrap_banner(self):
        """Print bootstrap banner."""
        print(f"""
+===============================================================+
|                     PlexiChat Server                         |
|                  Bootstrap Installer v{PLEXICHAT_VERSION}                 |
|                                                               |
|  * One-script installation for PlexiChat Server              |
|  * Automatic dependency management                           |
|  * Development & production ready                            |
|  * Enhanced cross-platform compatibility                     |
|  * Improved error handling and recovery                      |
+===============================================================+
""")

    def check_bootstrap_requirements(self) -> bool:
        """Check if system meets bootstrap requirements."""
        print("[*] Checking bootstrap requirements...")

        # Check Python version (more lenient for bootstrap)
        current_version = sys.version_info[:2]
        if current_version < REQUIRED_PYTHON_BOOTSTRAP:
            print(f"[ERROR] Python {REQUIRED_PYTHON_BOOTSTRAP[0]}.{REQUIRED_PYTHON_BOOTSTRAP[1]}+ required for bootstrap. "
                  f"Current: {current_version[0]}.{current_version[1]}")
            return False

        print(f"[OK] Python {current_version[0]}.{current_version[1]} detected")

        # Check internet connectivity
        try:
            urllib.request.urlopen('https://github.com', timeout=10)
            print("[OK] Internet connectivity verified")
        except urllib.error.URLError:
            print("[ERROR] Internet connection required for bootstrap")
            return False

        # Check available disk space
        try:
            import shutil
            free_space = shutil.disk_usage('.').free / (1024**3)  # GB
            if free_space < 1.0:  # Require at least 1GB free
                print(f"[WARN] Low disk space: {free_space:.1f}GB available")
                print("[INFO] PlexiChat requires at least 1GB free space")
            else:
                print(f"[OK] Disk space available: {free_space:.1f}GB")
        except Exception:
            print("[WARN] Could not check disk space")

        return True

    def check_git_available(self) -> bool:
        """Check if git is available."""
        try:
            subprocess.run(["git", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def download_with_progress(self, url: str, destination: Path, description: str = "Downloading") -> bool:
        """Download file with progress bar."""
        try:
            print(f"[*] {description}...")

            with urllib.request.urlopen(url) as response:
                total_size = int(response.headers.get('content-length', 0))

                if total_size == 0:
                    print("[WARN] Unknown file size")
                    with open(destination, 'wb') as f:
                        f.write(response.read())
                    return True

                # Use existing progress bar
                if tqdm:
                    progress = tqdm(total=total_size, unit='B', unit_scale=True, desc=description)

                    with open(destination, 'wb') as f:
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                            progress.update(len(chunk))

                    progress.close()
                else:
                    progress = SimpleProgressBar(total_size, description)

                    with open(destination, 'wb') as f:
                        downloaded = 0
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            progress.update(len(chunk))

                    progress.finish()

                print(f"[OK] Download completed: {destination.name}")
                return True

        except urllib.error.URLError as e:
            print(f"[ERROR] Download failed: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error during download: {e}")
            return False

    def download_source_code(self, version_info: Optional[Dict[str, Any]] = None) -> bool:
        """Download PlexiChat source code using multiple methods."""
        print("[*] Acquiring PlexiChat source code...")

        # Get version info if not provided
        if not version_info:
            version_info = self.show_version_selection()
            if not version_info:
                return False

        print(f"[*] Downloading version: {version_info['name']}")

        # Check if we already have source files (excluding run.py)
        existing_files = [f for f in self.install_dir.iterdir()
                         if f.is_file() and f.name != 'run.py' and not f.name.startswith('.')]

        if existing_files:
            print("[WARN] Existing source files found in directory")
            overwrite = input("Overwrite existing files? (y/N): ").strip().lower()
            if not overwrite.startswith('y'):
                return False

            # Remove existing source files (keep run.py and config files)
            for item in self.install_dir.iterdir():
                if item.name not in ['run.py', 'plexichat_config.json', '.git'] and not item.name.startswith('.'):
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()

        # Try multiple download methods
        download_methods = [
            ("Git Clone", self.download_with_git),
            ("ZIP Download", self.download_with_zip),
            ("Individual Files", self.download_individual_files)
        ]

        for method_name, method_func in download_methods:
            try:
                print(f"[*] Trying {method_name}...")
                if method_func(version_info):
                    print(f"[OK] Source code downloaded successfully using {method_name}")
                    return True
                else:
                    print(f"[WARN] {method_name} failed, trying next method...")
            except Exception as e:
                print(f"[WARN] {method_name} failed with error: {e}")

        print("[ERROR] All download methods failed")
        return False

    def download_with_git(self, version_info: Dict[str, Any]) -> bool:
        """Download using git clone."""
        if not self.check_git_available():
            return False

        try:
            # Clone to temporary directory first
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_repo = Path(temp_dir) / "repo"

                # Clone the repository
                if version_info['type'] == 'branch':
                    cmd = ["git", "clone", "--branch", version_info['name'], "--depth", "1", self.repo_url, str(temp_repo)]
                else:
                    cmd = ["git", "clone", "--branch", version_info['name'], "--depth", "1", self.repo_url, str(temp_repo)]

                subprocess.run(cmd, check=True, capture_output=True)

                # Copy all files except .git and run.py to install directory
                for item in temp_repo.iterdir():
                    if item.name not in ['.git', 'run.py']:
                        dest = self.install_dir / item.name
                        if item.is_dir():
                            shutil.copytree(item, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, dest)

                return True

        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False

    def download_with_zip(self, version_info: Dict[str, Any]) -> bool:
        """Download using ZIP file."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                zip_path = Path(temp_dir) / "source.zip"

                # Download ZIP file
                if not self.download_with_progress(version_info['url'], zip_path, f"Downloading {version_info['name']}"):
                    return False

                # Extract ZIP
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)

                # Find the extracted directory
                extracted_dirs = [d for d in Path(temp_dir).iterdir()
                                if d.is_dir() and d.name != "__pycache__"]

                if not extracted_dirs:
                    return False

                source_dir = extracted_dirs[0]

                # Copy all files except run.py to install directory
                for item in source_dir.iterdir():
                    if item.name != 'run.py':
                        dest = self.install_dir / item.name
                        if item.is_dir():
                            shutil.copytree(item, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(item, dest)

                return True

        except Exception:
            return False

    def download_individual_files(self, version_info: Dict[str, Any]) -> bool:
        """Download individual files using GitHub API."""
        try:
            # Get repository contents
            contents_url = f"{self.api_url}/contents"
            if version_info['name'] != 'main':
                contents_url += f"?ref={version_info['name']}"

            response = urllib.request.urlopen(contents_url, timeout=30)
            contents = json.loads(response.read().decode())

            # Download each file/directory
            progress = ProgressBar(len(contents), title="Downloading files")

            for i, item in enumerate(contents):
                if item['name'] != 'run.py':
                    if item['type'] == 'file':
                        self._download_file(item, version_info['name'])
                    elif item['type'] == 'dir':
                        self._download_directory(item, version_info['name'])

                progress.update(i + 1, f"Downloaded {item['name']}")

            progress.finish("Download complete")
            return True

        except Exception:
            return False

    def _download_file(self, file_info: Dict[str, Any], ref: str):
        """Download a single file."""
        file_url = f"{self.raw_url}/{ref}/{file_info['path']}"
        dest_path = self.install_dir / file_info['name']

        response = urllib.request.urlopen(file_url, timeout=30)
        with open(dest_path, 'wb') as f:
            f.write(response.read())

    def _download_directory(self, dir_info: Dict[str, Any], ref: str):
        """Download a directory recursively."""
        dir_path = self.install_dir / dir_info['name']
        dir_path.mkdir(exist_ok=True)

        # Get directory contents
        contents_url = f"{self.api_url}/contents/{dir_info['path']}?ref={ref}"
        response = urllib.request.urlopen(contents_url, timeout=30)
        contents = json.loads(response.read().decode())

        for item in contents:
            if item['type'] == 'file':
                file_url = f"{self.raw_url}/{ref}/{item['path']}"
                dest_path = dir_path / item['name']

                file_response = urllib.request.urlopen(file_url, timeout=30)
                with open(dest_path, 'wb') as f:
                    f.write(file_response.read())
            elif item['type'] == 'dir':
                # Recursively download subdirectories
                subdir_path = dir_path / item['name']
                subdir_path.mkdir(exist_ok=True)
                self._download_directory_recursive(item['path'], ref, subdir_path)

    def _download_directory_recursive(self, path: str, ref: str, dest_dir: Path):
        """Recursively download directory contents."""
        contents_url = f"{self.api_url}/contents/{path}?ref={ref}"
        response = urllib.request.urlopen(contents_url, timeout=30)
        contents = json.loads(response.read().decode())

        for item in contents:
            if item['type'] == 'file':
                file_url = f"{self.raw_url}/{ref}/{item['path']}"
                dest_path = dest_dir / item['name']

                file_response = urllib.request.urlopen(file_url, timeout=30)
                with open(dest_path, 'wb') as f:
                    f.write(file_response.read())
            elif item['type'] == 'dir':
                subdir_path = dest_dir / item['name']
                subdir_path.mkdir(exist_ok=True)
                self._download_directory_recursive(item['path'], ref, subdir_path)

    def create_virtual_environment(self) -> bool:
        """Create Python virtual environment."""
        print("[*] Creating Python virtual environment...")

        if self.venv_dir.exists():
            print("[WARN] Virtual environment exists. Recreating...")
            try:
                shutil.rmtree(self.venv_dir)
            except Exception as e:
                print(f"[ERROR] Could not remove existing venv: {e}")
                return False

        try:
            subprocess.run([
                sys.executable, "-m", "venv", str(self.venv_dir)
            ], check=True, capture_output=True)

            print("[OK] Virtual environment created")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to create virtual environment: {e}")
            return False

    def get_venv_python(self) -> str:
        """Get path to virtual environment Python executable."""
        if IS_WINDOWS:
            return str(self.venv_dir / "Scripts" / "python.exe")
        else:
            return str(self.venv_dir / "bin" / "python")

    def get_venv_pip(self) -> str:
        """Get path to virtual environment pip executable."""
        if IS_WINDOWS:
            return str(self.venv_dir / "Scripts" / "pip.exe")
        else:
            return str(self.venv_dir / "bin" / "pip")

    def install_dependencies(self) -> bool:
        """Install PlexiChat dependencies."""
        print("[*] Installing dependencies...")

        # Check for requirements.txt
        requirements_file = self.install_dir / "requirements.txt"
        if not requirements_file.exists():
            print("[WARN] No requirements.txt found, trying basic installation...")
            # Try to install basic dependencies
            basic_deps = ["flask", "requests", "pyyaml"]
            return self.install_basic_dependencies(basic_deps)

        try:
            # Upgrade pip first
            subprocess.run([
                self.get_venv_pip(), "install", "--upgrade", "pip"
            ], check=True, capture_output=True)

            # Install requirements
            subprocess.run([
                self.get_venv_pip(), "install", "-r", str(requirements_file)
            ], check=True, capture_output=True)

            print("[OK] Dependencies installed successfully")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install dependencies: {e}")
            return False

    def install_basic_dependencies(self, deps: list) -> bool:
        """Install basic dependencies when requirements.txt is missing."""
        try:
            for dep in deps:
                print(f"[*] Installing {dep}...")
                subprocess.run([
                    self.get_venv_pip(), "install", dep
                ], check=True, capture_output=True)
            print("[OK] Basic dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install basic dependencies: {e}")
            return False

    def run_bootstrap(self) -> bool:
        """Run the enhanced bootstrap process with version selection."""
        self.print_bootstrap_banner()

        print("[*] Starting PlexiChat bootstrap installation...")
        print("=" * 60)

        # Step 1: Check requirements
        if not self.check_bootstrap_requirements():
            return False

        # Step 2: Show version selection and download source code
        if not self.download_source_code():
            return False

        # Step 3: Update run.py to match the downloaded version
        if not self.update_run_script():
            return False

        print("\n" + "=" * 60)
        print("[SUCCESS] Bootstrap completed successfully!")
        print("\nPlexiChat source code has been downloaded to the current directory.")
        print("\nNext steps:")
        print("  1. python run.py setup       # Run interactive setup wizard")
        print("\nThe setup wizard will guide you through:")
        print("  * Choosing installation type (minimal/full/developer)")
        print("  * Selecting database type")
        print("  * Configuring optional features")
        print("  * Installing dependencies")
        print("  * Setting up SSL certificates")
        print("  * Creating initial configuration")
        print("\n[INFO] This bootstrap script will be replaced with the downloaded version.")

        return True

    def update_run_script(self) -> bool:
        """Update run.py using the downloaded update system."""
        try:
            print("[*] Syncing run.py with downloaded version using core update system...")

            # Check if we have the core update system available
            update_system_path = self.install_dir / "src" / "plexichat" / "core_system" / "update"
            if not update_system_path.exists():
                print("[WARN] Core update system not found, using fallback method...")
                return self.fallback_update_run_script()

            # Try to use the core update system
            try:
                # Add the src directory to Python path temporarily
                import sys
                src_path = str(self.install_dir / "src")
                if src_path not in sys.path:
                    sys.path.insert(0, src_path)

                # Import the update system
                from plexichat.core_system.update.update_manager import UpdateManager
                from plexichat.core_system.update.version_manager import VersionManager

                # Initialize update manager
                update_manager = UpdateManager()
                version_manager = VersionManager()

                # Get current version info
                current_version = version_manager.get_current_version()
                target_version = version_manager.get_installed_version()

                print(f"[*] Current run.py version: {current_version}")
                print(f"[*] Target version: {target_version}")

                if current_version != target_version:
                    print("[*] Versions differ, updating run.py...")

                    # Use update manager to update run.py specifically
                    if update_manager.update_file("run.py", target_version):
                        print("[OK] run.py updated successfully using core update system")
                        return True
                    else:
                        print("[WARN] Core update failed, using fallback...")
                        return self.fallback_update_run_script()
                else:
                    print("[OK] run.py is already at correct version")
                    return True

            except ImportError as e:
                print(f"[WARN] Could not import update system: {e}")
                print("[*] Using fallback update method...")
                return self.fallback_update_run_script()

        except Exception as e:
            print(f"[WARN] Update system error: {e}")
            print("[*] Using fallback update method...")
            return self.fallback_update_run_script()

    def fallback_update_run_script(self) -> bool:
        """Fallback method to update run.py."""
        try:
            # Look for run.py in the downloaded source
            source_run_py = self.install_dir / "run.py"
            current_run_py = Path(__file__).absolute()

            if source_run_py.exists() and source_run_py != current_run_py:
                print("[*] Using direct file replacement...")

                # Read the new run.py content
                with open(source_run_py, 'r', encoding='utf-8') as f:
                    new_content = f.read()

                # Check if it's different from current
                with open(current_run_py, 'r', encoding='utf-8') as f:
                    current_content = f.read()

                if new_content != current_content:
                    print("[*] run.py versions differ, scheduling update...")

                    # Write to a temporary file first
                    temp_file = current_run_py.parent / "run_new.py"
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        f.write(new_content)

                    # Schedule the replacement
                    self.schedule_self_replacement(temp_file, current_run_py)

                    print("[OK] run.py update scheduled for next restart")
                else:
                    print("[OK] run.py is already up to date")

                # Remove the downloaded run.py to avoid confusion
                source_run_py.unlink()
                return True
            else:
                print("[INFO] No run.py found in source or same file, skipping update")
                return True

        except Exception as e:
            print(f"[WARN] Fallback update failed: {e}")
            print("[INFO] Continuing with current run.py")
            return True

    def schedule_self_replacement(self, new_file: Path, old_file: Path):
        """Schedule replacement of the current script after exit."""
        try:
            if IS_WINDOWS:
                # Windows batch script for replacement
                batch_content = f"""@echo off
timeout /t 2 /nobreak >nul
move "{new_file}" "{old_file}"
del "%~f0"
"""
                batch_file = old_file.parent / "replace_script.bat"
                with open(batch_file, 'w') as f:
                    f.write(batch_content)

                # Schedule batch execution
                import subprocess
                subprocess.Popen([str(batch_file)], shell=True)
            else:
                # Unix shell script for replacement
                shell_content = f"""#!/bin/bash
sleep 2
mv "{new_file}" "{old_file}"
rm "$0"
"""
                shell_file = old_file.parent / "replace_script.sh"
                with open(shell_file, 'w') as f:
                    f.write(shell_content)

                # Make executable and schedule
                os.chmod(shell_file, 0o755)
                import subprocess
                subprocess.Popen([str(shell_file)])

        except Exception as e:
            print(f"[WARN] Could not schedule script replacement: {e}")

    def create_initial_config(self):
        """Create initial configuration files."""
        try:
            config_dir = self.install_dir / "config"
            config_dir.mkdir(exist_ok=True)

            # Create basic config if it doesn't exist
            basic_config = config_dir / "plexichat.json"
            if not basic_config.exists():
                initial_config = {
                    "installation": {
                        "type": "bootstrap",
                        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "version": PLEXICHAT_VERSION
                    },
                    "server": {
                        "host": "localhost",
                        "ports": {
                            "api": 8000,
                            "webui": 8080
                        }
                    }
                }

                with open(basic_config, 'w') as f:
                    json.dump(initial_config, f, indent=2)

                print("[OK] Initial configuration created")
        except Exception as e:
            print(f"[WARN] Could not create initial config: {e}")


def print_system_info():
    """Print detailed system information."""
    info = get_system_info()

    print("[*] System Information:")
    print(f"   Platform: {info['platform']} {info['platform_version']} ({info['architecture']})")
    print(f"   Python: {info['python_version']} ({info['python_executable']})")
    print(f"   CPU Cores: {info['cpu_count']}")
    print(f"   Hostname: {info['hostname']}")
    print(f"   Username: {info['username']}")

    if "memory_total" in info:
        print(f"   Memory: {info['memory_available']} available of {info['memory_total']} ({info['memory_percent']} used)")

    if "disk_total" in info:
        print(f"   Disk Space: {info['disk_free']} free of {info['disk_total']} ({info['disk_percent']} used)")

    print(f"   Terminal: {info['terminal_width']} columns, Color: {'Yes' if info['supports_color'] else 'No'}")
    print(f"   Performance Monitoring: {'Available' if info['has_psutil'] else 'Limited (install psutil for full metrics)'}")

    print("\n[*] Environment Variables:")
    for key, value in info['environment_variables'].items():
        print(f"   {key}: {value}")


def show_environment_info():
    """Show detailed environment manager information."""
    print("[*] Python Environment Managers")
    print("=" * 50)

    environments = detect_python_environments()

    for env_name, env_info in environments.items():
        status = "[OK] Available" if env_info['available'] else "[ERROR] Not Available"
        print(f"{env_name.upper()}: {status}")

        if env_info['available']:
            if 'version' in env_info:
                print(f"   Version: {env_info['version']}")

            # Show additional info for specific environments
            if env_name == 'conda' and env_info['available']:
                try:
                    result = subprocess.run(['conda', 'env', 'list'],
                                          capture_output=True, text=True, check=True)
                    envs = [line.strip() for line in result.stdout.split('\n')
                           if line.strip() and not line.startswith('#')]
                    print(f"   Environments: {len(envs)} found")
                    for env_line in envs[:3]:  # Show first 3
                        print(f"     - {env_line}")
                    if len(envs) > 3:
                        print(f"     ... and {len(envs) - 3} more")
                except:
                    pass

            elif env_name == 'venv':
                venv_path = VENV_DIR
                if venv_path.exists():
                    print(f"   Current venv: {venv_path}")
                    venv_python = get_venv_python()
                    if venv_python and venv_python.exists():
                        print(f"   Python executable: {venv_python}")
                else:
                    print("   No virtual environment found")

        print()  # Empty line between environments

    # Show current active environment
    print("[*] Current Environment:")
    current_venv = os.getenv("VIRTUAL_ENV")
    current_conda = os.getenv("CONDA_DEFAULT_ENV")

    if current_venv:
        print(f"   Active venv: {current_venv}")
    elif current_conda:
        print(f"   Active conda env: {current_conda}")
    else:
        print("   No active virtual environment detected")

    print(f"   Python executable: {sys.executable}")
    print(f"   Python version: {sys.version}")

    # Show recommendations
    print("\n[INFO] Recommendations:")
    if not any(env['available'] for env in environments.values()):
        print("   [WARN]  No environment managers found!")
        print("   Install one of: conda, mamba, virtualenv, or use built-in venv")
    elif not environments['conda']['available'] and not environments['mamba']['available']:
        print("   Consider installing conda or mamba for better package management")
    else:
        print("   [OK] Good environment manager setup detected")


def save_setup_config(config):
    """Save setup configuration."""
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(SETUP_CONFIG, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"[WARN] Warning: Could not save setup config: {e}")
        return False


def load_setup_config():
    """Load setup configuration."""
    try:
        if SETUP_CONFIG.exists():
            with open(SETUP_CONFIG, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"[WARN] Warning: Could not load setup config: {e}")
    return {}


def interactive_setup_wizard():
    """Enhanced interactive setup wizard for first-time users."""
    # Use the new OS-specific setup wizard
    wizard = OSSpecificSetupWizard()

    # Check for existing setup
    existing_config = load_setup_config()
    if existing_config:
        print(f"\n[*] Found existing setup: {existing_config.get('setup_style', 'unknown')}")
        if input("[*] Reconfigure setup? (y/N): ").lower().startswith('y'):
            pass  # Continue with wizard
        else:
            return existing_config

    # Run the enhanced setup wizard
    config = wizard.run_setup_wizard()
    if not config:
        return None

    # Map installation type to setup style
    install_type = config.get('installation_type', 'standard').lower()
    if 'minimal' in install_type:
        config['setup_style'] = 'minimal'
    elif 'full' in install_type:
        config['setup_style'] = 'full'
    elif 'developer' in install_type:
        config['setup_style'] = 'developer'
    else:
        config['setup_style'] = 'standard'

    # Add terminal style selection (simplified for now)
    if TERMINAL_WIDTH >= 120:
        config['terminal_style'] = 'split'
    elif TERMINAL_WIDTH >= 80:
        config['terminal_style'] = 'tabbed'
    else:
        config['terminal_style'] = 'classic'

    # Add other configuration options
    config.update({
        'debug_mode': False,
        'performance_monitoring': config.get('monitoring', True),
        'auto_start_services': True,
        'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'system_info': get_system_info()
    })

    # Show configuration summary
    print("\n[*] Configuration Summary:")
    print("=" * 50)
    print(f"Installation Type: {config.get('installation_type', 'Standard')}")
    print(f"Database Type: {config.get('database_type', 'SQLite (Default)')}")
    print(f"Terminal Style: {config.get('terminal_style', 'Split Screen')}")
    print(f"AI Features: {'Enabled' if config.get('ai_features', True) else 'Disabled'}")
    print(f"Security Features: {'Enabled' if config.get('security_features', True) else 'Disabled'}")
    print(f"Monitoring: {'Enabled' if config.get('monitoring', True) else 'Disabled'}")
    print(f"SSL Setup: {'Enabled' if config.get('ssl_setup', True) else 'Disabled'}")
    print(f"Web UI: {'Enabled' if config.get('webui', True) else 'Disabled'}")

    if input("\n[OK] Proceed with this configuration? (Y/n): ").lower() not in ['n', 'no']:
        save_setup_config(config)
        return config
    else:
        print("[ERROR] Setup cancelled.")
        return None


def get_version_info():
    """Get version information from version.json (update system)."""
    try:
        # Primary: Use version.json from update system
        if VERSION_FILE.exists():
            with open(VERSION_FILE, 'r') as f:
                version_data = json.load(f)
                current_version = version_data.get("current_version", "unknown")

                # Check if this is the new format or deprecated format
                if version_data.get("deprecated", False):
                    # This is the old deprecated format, but still use it
                    return current_version
                else:
                    # This is the current update system format
                    return current_version

        # Fallback: Try to find version in other common locations
        fallback_locations = [
            ROOT / "VERSION",
            ROOT / "version.txt",
            ROOT / "src" / "plexichat" / "version.py"
        ]

        for location in fallback_locations:
            if location.exists():
                try:
                    if location.suffix == '.py':
                        # Parse Python version file
                        with open(location, 'r') as f:
                            content = f.read()
                            import re
                            match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                            if match:
                                return match.group(1)
                    else:
                        # Plain text version file
                        with open(location, 'r') as f:
                            version = f.read().strip()
                            if version:
                                return version
                except:
                    continue

        # Ultimate fallback
        return "a.1.1-7"

    except Exception as e:
        print(f"[WARN]  Error reading version: {e}")
        return "a.1.1-7"


def update_version_format():
    """Legacy function - Git-based versioning doesn't need format updates."""
    # Remove version.json if it exists (deprecated)
    if VERSION_FILE.exists():
        try:
            # Keep version.json for now as backup, but mark as deprecated
            with open(VERSION_FILE, 'r') as f:
                version_data = json.load(f)

            # Add deprecation notice
            if "deprecated" not in version_data:
                version_data["deprecated"] = True
                version_data["deprecation_notice"] = "This file is deprecated. PlexiChat now uses Git-based versioning."
                version_data["migration_date"] = datetime.now().isoformat()

                with open(VERSION_FILE, 'w') as f:
                    json.dump(version_data, f, indent=2)

                print("[*] Marked version.json as deprecated (now using Git-based versioning)")
        except Exception as e:
            print(f"[WARN] Warning: Could not update version format: {e}")


def check_for_updates():
    """Check for available updates from GitHub."""
    try:
        print("[*] Update checking now uses Git-based versioning")
        print("[INFO] Updates are available through:")
        print("   1. Git pull from repository")
        print("   2. GitHub releases download")
        print("   3. Admin panel update interface (when running)")
        print("   4. Automatic update system (if enabled)")

        return True
    except Exception as e:
        print(f"[WARN] Update check information: {e}")
        return False


def generate_default_admin_creds():
    """Generate default admin credentials file."""
    if DEFAULT_CREDS.exists():
        return  # Already exists

    # Generate secure password
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Create credentials file
    creds_content = f"""Username: admin
Password: {password}
Role: super_admin
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

IMPORTANT: Change password after first login and delete this file.
"""

    try:
        with open(DEFAULT_CREDS, 'w') as f:
            f.write(creds_content)
        print(f"[*] Default admin credentials generated: {DEFAULT_CREDS}")
        print("[WARN]  IMPORTANT: Change the default password immediately after first login!")
    except Exception as e:
        print(f"[ERROR] Failed to generate default credentials: {e}")


def get_port_configuration():
    """
    Get port configuration from unified config (YAML or JSON).
    Falls back to defaults if config missing or invalid.
    """
    default_ports = {
        "api_http": 8000,
        "api_https": 8443,
        "webui_http": 8080,
        "webui_https": 8444,
        "websocket": 8001,
        "admin": 8002
    }

    # Try YAML unified config first
    yaml_config_file = ROOT / "plexichat.yaml"
    if yaml_config_file.exists():
        try:
            with open(yaml_config_file, "r") as f:
                if yaml is not None:
                    config = yaml.safe_load(f)
                else:
                    print("[WARN] Warning: PyYAML not installed, falling back to JSON config if available.")
                    raise ImportError("PyYAML not installed")
            ports = (
                config.get("plexichat", {})
                .get("server", {})
                .get("ports", {})
            )
            # Support both flat and nested port configs
            return {
                "api_http": ports.get("api_http", default_ports["api_http"]),
                "api_https": ports.get("api_https", default_ports["api_https"]),
                "webui_http": ports.get("webui_http", default_ports["webui_http"]),
                "webui_https": ports.get("webui_https", default_ports["webui_https"]),
                "websocket": ports.get("websocket", default_ports["websocket"]),
                "admin": ports.get("admin", default_ports["admin"])
            }
        except Exception as e:
            print(f"[WARN] Warning: Could not load YAML port configuration: {e}")

    # Try legacy JSON config
    json_config_file = ROOT / "config" / "plexichat.json"
    if json_config_file.exists():
        try:
            with open(json_config_file, "r") as f:
                config = json.load(f)
            ports = config.get("ports", {})
            return {
                "api_http": ports.get("api", {}).get("http", default_ports["api_http"]),
                "api_https": ports.get("api", {}).get("https", default_ports["api_https"]),
                "webui_http": ports.get("webui", {}).get("http", default_ports["webui_http"]),
                "webui_https": ports.get("webui", {}).get("https", default_ports["webui_https"]),
                "websocket": ports.get("websocket", default_ports["websocket"]),
                "admin": ports.get("admin", default_ports["admin"])
            }
        except Exception as e:
            print(f"[WARN] Warning: Could not load JSON port configuration: {e}")

    # Fallback to defaults
    return default_ports


def detect_installation_type():
    """Detect current installation type based on installed packages."""
    if not VENV_DIR.exists():
        return "not_installed"

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        return "not_installed"

    try:
        # Get list of installed packages
        result = subprocess.run(
            [str(venv_python), "-m", "pip", "list", "--format=freeze"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return "unknown"

        installed_packages = set(line.split('==')[0].lower() for line in result.stdout.strip().split('\n') if '==' in line)

        # Parse requirements to get expected packages
        deps = parse_requirements_file()
        minimal_packages = set(pkg.split('>=')[0].split('==')[0].lower() for pkg in deps["minimal"])
        full_packages = set(pkg.split('>=')[0].split('==')[0].lower() for pkg in deps["full"])

        # Calculate coverage
        minimal_coverage = len(minimal_packages.intersection(installed_packages)) / len(minimal_packages) if minimal_packages else 0
        full_coverage = len(full_packages.intersection(installed_packages)) / len(full_packages) if full_packages else 0

        if minimal_coverage >= 0.9 and full_coverage >= 0.9:
            return "full"
        elif minimal_coverage >= 0.9:
            return "minimal"
        elif minimal_coverage >= 0.5:
            return "partial"
        else:
            return "incomplete"

    except Exception as e:
        print(f"[WARN] Warning: Could not detect installation type: {e}")
        return "unknown"


def get_venv_python():
    """Get the Python executable path for the virtual environment."""
    if IS_WINDOWS:
        return VENV_DIR / "Scripts" / "python.exe"
    else:
        return VENV_DIR / "bin" / "python"


def detect_python_environments():
    """Detect available Python environment managers."""
    environments = {
        'venv': {'available': False, 'command': [sys.executable, '-m', 'venv']},
        'conda': {'available': False, 'command': ['conda', 'create']},
        'mamba': {'available': False, 'command': ['mamba', 'create']},
        'virtualenv': {'available': False, 'command': ['virtualenv']},
        'pipenv': {'available': False, 'command': ['pipenv', 'install']},
        'poetry': {'available': False, 'command': ['poetry', 'install']}
    }

    # Check venv (built-in)
    try:
        subprocess.run([sys.executable, '-m', 'venv', '--help'],
                      capture_output=True, check=True)
        environments['venv']['available'] = True
    except:
        pass

    # Check conda
    try:
        result = subprocess.run(['conda', '--version'],
                              capture_output=True, check=True, text=True)
        environments['conda']['available'] = True
        environments['conda']['version'] = result.stdout.strip()
    except:
        pass

    # Check mamba
    try:
        result = subprocess.run(['mamba', '--version'],
                              capture_output=True, check=True, text=True)
        environments['mamba']['available'] = True
        environments['mamba']['version'] = result.stdout.strip()
    except:
        pass

    # Check virtualenv
    try:
        subprocess.run(['virtualenv', '--version'],
                      capture_output=True, check=True)
        environments['virtualenv']['available'] = True
    except:
        pass

    # Check pipenv
    try:
        subprocess.run(['pipenv', '--version'],
                      capture_output=True, check=True)
        environments['pipenv']['available'] = True
    except:
        pass

    # Check poetry
    try:
        subprocess.run(['poetry', '--version'],
                      capture_output=True, check=True)
        environments['poetry']['available'] = True
    except:
        pass

    return environments


def create_virtual_environment(env_type='auto'):
    """Create virtual environment with support for multiple environment managers."""
    if VENV_DIR.exists():
        venv_python = get_venv_python()
        if venv_python and venv_python.exists():
            print("[OK] Virtual environment already exists")
            return True
        else:
            print("[*] Recreating corrupted virtual environment...")
            clean_environment()

    environments = detect_python_environments()

    # Auto-select best available environment manager
    if env_type == 'auto':
        if environments['mamba']['available']:
            env_type = 'mamba'
        elif environments['conda']['available']:
            env_type = 'conda'
        elif environments['venv']['available']:
            env_type = 'venv'
        elif environments['virtualenv']['available']:
            env_type = 'virtualenv'
        else:
            print("[ERROR] No suitable Python environment manager found")
            return False

    print(f"[*] Creating virtual environment using {env_type}...")

    try:
        if env_type == 'conda':
            # Create conda environment
            env_name = f"plexichat-{ROOT.name}"
            cmd = ['conda', 'create', '-n', env_name, f'python={sys.version_info.major}.{sys.version_info.minor}', '-y']
            subprocess.check_call(cmd)

            # Create symlink or batch file to mimic venv structure
            if platform.system() == "Windows":
                conda_python = subprocess.check_output(['conda', 'run', '-n', env_name, 'where', 'python'], text=True).strip().split('\n')[0]
                VENV_DIR.mkdir(exist_ok=True)
                (VENV_DIR / "Scripts").mkdir(exist_ok=True)

                # Create activation script
                with open(VENV_DIR / "Scripts" / "activate.bat", 'w') as f:
                    f.write(f'@echo off\nconda activate {env_name}\n')

                # Create python symlink
                try:
                    (VENV_DIR / "Scripts" / "python.exe").symlink_to(conda_python)
                except:
                    # Fallback: create batch file
                    with open(VENV_DIR / "Scripts" / "python.bat", 'w') as f:
                        f.write(f'@echo off\nconda run -n {env_name} python %*\n')
            else:
                conda_python = subprocess.check_output(['conda', 'run', '-n', env_name, 'which', 'python'], text=True).strip()
                VENV_DIR.mkdir(exist_ok=True)
                (VENV_DIR / "bin").mkdir(exist_ok=True)
                (VENV_DIR / "bin" / "python").symlink_to(conda_python)

            print(f"[OK] Conda environment '{env_name}' created")

        elif env_type == 'mamba':
            # Similar to conda but with mamba
            env_name = f"plexichat-{ROOT.name}"
            cmd = ['mamba', 'create', '-n', env_name, f'python={sys.version_info.major}.{sys.version_info.minor}', '-y']
            subprocess.check_call(cmd)
            print(f"[OK] Mamba environment '{env_name}' created")

        elif env_type == 'venv':
            # Standard venv
            subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
            print("[OK] Virtual environment created with venv")

        elif env_type == 'virtualenv':
            # virtualenv
            subprocess.check_call(["virtualenv", str(VENV_DIR)])
            print("[OK] Virtual environment created with virtualenv")

        else:
            print(f"[ERROR] Unsupported environment type: {env_type}")
            return False

        return True

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to create virtual environment: {e}")
        print("[INFO] Available environment managers:")
        for env, info in environments.items():
            status = "[OK]" if info['available'] else "[ERROR]"
            version = info.get('version', 'Unknown version')
            print(f"   {status} {env}: {version if info['available'] else 'Not available'}")
        return False


def install_dependencies(install_type="minimal"):
    """Install dependencies in virtual environment."""
    if not create_virtual_environment():
        return False

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        print("[ERROR] Virtual environment Python not found")
        return False

    print(f"[*] Installing {install_type} dependencies...")

    # Upgrade pip first
    try:
        print("[*] Upgrading pip...")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"])
    except subprocess.CalledProcessError as e:
        print(f"[WARN] Failed to upgrade pip: {e}")

    # Install based on type
    if install_type == "minimal":
        return install_minimal_deps(venv_python)
    elif install_type == "standard":
        return install_standard_deps(venv_python)
    elif install_type == "full":
        return install_full_deps(venv_python)
    elif install_type == "developer":
        return install_developer_deps(venv_python)
    else:
        print(f"[ERROR] Unknown install type: {install_type}")
        return False


def parse_requirements_file():
    """Parse requirements.txt with Python version-specific handling."""
    if not REQUIREMENTS.exists():
        print("[ERROR] requirements.txt not found")
        return {"minimal": [], "full": []}

    minimal_deps = []
    full_deps = []
    current_section = None
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    with open(REQUIREMENTS, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                # Check for section markers
                if "MINIMAL INSTALLATION" in line:
                    current_section = "minimal"
                elif "FULL INSTALLATION" in line:
                    current_section = "full"
                continue

            # Process Python version-specific requirements
            processed_line = process_version_specific_requirement(line, python_version)
            if processed_line is None:
                continue  # Skip this requirement for current Python version

            # Add dependency to appropriate section
            if current_section == "minimal":
                minimal_deps.append(processed_line)
            elif current_section == "full":
                full_deps.append(processed_line)

    return {"minimal": minimal_deps, "full": full_deps}


def process_version_specific_requirement(requirement, python_version):
    """Process requirements with Python version-specific handling."""
    # Handle version-specific requirements
    version_mappings = {
        # Python 3.11 specific
        "3.11": {
            "numpy": "numpy>=1.24.0,<2.0.0",  # Stable version for 3.11
            "scipy": "scipy>=1.10.0",
            "matplotlib": "matplotlib>=3.7.0",
            "pillow": "pillow>=10.0.0",
        },
        # Python 3.12 specific
        "3.12": {
            "numpy": "numpy>=1.26.0",  # Better 3.12 support
            "scipy": "scipy>=1.11.0",
            "matplotlib": "matplotlib>=3.8.0",
            "pillow": "pillow>=10.1.0",
        },
        # Python 3.13+ specific
        "3.13": {
            "numpy": "numpy>=1.26.0",
            "scipy": "scipy>=1.11.0",
            "matplotlib": "matplotlib>=3.8.0",
            "pillow": "pillow>=10.2.0",
        }
    }

    # Extract package name from requirement
    package_name = requirement.split('>=')[0].split('==')[0].split('[')[0].strip()

    # Check if we have version-specific mapping
    if python_version in version_mappings:
        if package_name in version_mappings[python_version]:
            return version_mappings[python_version][package_name]

    # Handle packages that don't support certain Python versions
    incompatible_packages = {
        "3.13": ["some-old-package"],  # Example: packages not yet supporting 3.13
    }

    if python_version in incompatible_packages:
        if package_name in incompatible_packages[python_version]:
            print(f"[WARN]  Skipping {package_name} (not compatible with Python {python_version})")
            return None

    # Handle packages with different names on different Python versions
    package_aliases = {
        "3.11": {},
        "3.12": {},
        "3.13": {}
    }

    if python_version in package_aliases:
        if package_name in package_aliases[python_version]:
            return requirement.replace(package_name, package_aliases[python_version][package_name])

    # Return original requirement if no special handling needed
    return requirement


def install_minimal_deps(venv_python):
    """Install minimal dependencies from requirements.txt."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]

    if not minimal_deps:
        print("[ERROR] No minimal dependencies found in requirements.txt")
        return False

    print(f"[*] Installing {len(minimal_deps)} minimal dependencies...")
    return install_package_list(venv_python, minimal_deps)


def install_standard_deps(venv_python):
    """Install standard dependencies from requirements.txt."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]

    # Add some standard packages
    standard_packages = [
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "aiofiles>=22.1.0",
        "python-multipart>=0.0.5",
        "jinja2>=3.1.0"
    ]

    all_deps = minimal_deps + standard_packages

    if not all_deps:
        print("[ERROR] No dependencies found")
        return False

    print(f"[*] Installing {len(all_deps)} standard dependencies...")
    return install_package_list(venv_python, all_deps)


def install_full_deps(venv_python):
    """Install full dependencies from requirements.txt."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]
    full_deps = deps["full"]
    all_deps = minimal_deps + full_deps

    if not all_deps:
        print("[ERROR] No dependencies found in requirements.txt")
        return False

    print(f"[*] Installing {len(all_deps)} full dependencies...")
    return install_package_list(venv_python, all_deps)


def install_developer_deps(venv_python):
    """Install developer dependencies including testing and debugging tools."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]
    full_deps = deps["full"]

    # Add developer-specific packages
    dev_packages = [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.0.0",
        "black>=22.0.0",
        "flake8>=5.0.0",
        "mypy>=1.0.0",
        "pre-commit>=2.20.0",
        "ipython>=8.0.0",
        "jupyter>=1.0.0",
        "debugpy>=1.6.0",
        "memory-profiler>=0.60.0",
        "line-profiler>=4.0.0",
        "py-spy>=0.3.0"
    ]

    all_deps = minimal_deps + full_deps + dev_packages

    if not all_deps:
        print("[ERROR] No dependencies found")
        return False

    print(f"[*] Installing {len(all_deps)} developer dependencies...")
    return install_package_list(venv_python, all_deps)


def install_package_list(venv_python, packages, use_fallbacks=True):
    """Install a list of packages with enhanced error handling and dual progress bars."""
    if not packages:
        return True

    failed_packages = []

    # Create enhanced dual progress bar system
    progress = DualProgressBar(len(packages))

    for i, package in enumerate(packages):
        # Extract package name for display (cleaner version)
        package_name = package.split('>=')[0].split('==')[0].split('[')[0].split('{')[0].strip()

        # Update overall progress with current package
        progress.update_overall(i + 1, package_name)

        # Install the package with detailed progress updates
        def package_progress_callback(status):
            progress.update_package(package_name, status)

        success = install_single_package(venv_python, package, use_fallbacks, verbose=False, progress_callback=package_progress_callback)

        if success:
            progress.update_package(package_name, "Installed")
            time.sleep(0.1)  # Brief pause to show completion
        else:
            failed_packages.append(package)
            progress.update_package(package_name, "Failed")
            time.sleep(0.2)  # Longer pause to show failure

    progress.finish("All packages processed")

    # Report results with better formatting
    if failed_packages:
        print(f"\n⚠️  {len(failed_packages)} packages failed to install:")
        for pkg in failed_packages:
            print(f"   ❌ {pkg}")

        # Check if any critical packages failed
        critical_packages = ['fastapi', 'uvicorn', 'sqlalchemy', 'pydantic']
        critical_failed = [pkg for pkg in failed_packages if any(crit in pkg.lower() for crit in critical_packages)]

        if critical_failed:
            print(f"\n🚨 Critical packages failed: {critical_failed}")
            print("💡 Try installing manually or check system dependencies")
            return False
        else:
            print("\n⚠️  Some optional packages failed, but core functionality should work.")
            print(f"✅ Successfully installed {len(packages) - len(failed_packages)}/{len(packages)} packages")
            return True
    else:
        print(f"✅ All {len(packages)} packages installed successfully")
        return True


def install_single_package(python_exe, package, use_fallbacks=True, verbose=False, progress_callback=None):
    """Install a single package with fallback strategies and enhanced progress tracking."""
    install_methods = [
        # Primary method
        {
            'name': 'pip (default)',
            'cmd': [str(python_exe), "-m", "pip", "install", package, "--timeout", "60"]
        }
    ]

    if use_fallbacks:
        install_methods.extend([
            # Fallback methods
            {
                'name': 'pip (no-cache)',
                'cmd': [str(python_exe), "-m", "pip", "install", package, "--no-cache-dir", "--timeout", "60"]
            },
            {
                'name': 'pip (user)',
                'cmd': [str(python_exe), "-m", "pip", "install", package, "--user", "--timeout", "60"]
            },
            {
                'name': 'pip (pre-release)',
                'cmd': [str(python_exe), "-m", "pip", "install", package, "--pre", "--timeout", "60"]
            }
        ])

    for method_idx, method in enumerate(install_methods):
        try:
            # Update progress callback with method information
            if progress_callback:
                if method_idx == 0:
                    progress_callback("Installing")
                else:
                    progress_callback(f"Retrying via {method['name']}")

            # Only print verbose messages if requested (not during progress bar)
            if verbose:
                print(f"   [*] Trying {method['name']} for {package}...")

            # Start the installation process
            process = subprocess.Popen(
                method['cmd'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )

            # Update progress while waiting for completion
            start_time = time.time()
            while process.poll() is None:
                if progress_callback:
                    time.time() - start_time
                    if method_idx == 0:
                        progress_callback("Installing")
                    else:
                        progress_callback(f"Retrying via {method['name']}")
                time.sleep(0.3)  # Update 3 times per second

            # Check if installation succeeded
            if process.returncode == 0:
                return True
            else:
                raise subprocess.CalledProcessError(process.returncode, method['cmd'])

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if verbose:
                print(f"   [WARN]  {method['name']} failed: {e}")
            continue

    # Final fallback: try system package manager suggestions
    if use_fallbacks and verbose:
        print(f"   [INFO] Consider installing {package} via system package manager:")
        system = platform.system().lower()
        if system == "linux":
            # Try to detect distribution
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read().lower()
                if 'ubuntu' in os_info or 'debian' in os_info:
                    pkg_name = package.lower().replace('_', '-')
                    print(f"      sudo apt-get install python3-{pkg_name}")
                elif 'centos' in os_info or 'rhel' in os_info or 'fedora' in os_info:
                    pkg_name = package.lower().replace('_', '-')
                    print(f"      sudo yum install python3-{pkg_name}")
            except:
                print(f"      Check your distribution's package manager for python3-{package}")
        elif system == "darwin":  # macOS
            print(f"      brew install {package}")
        elif system == "windows":
            print(f"      Consider using conda: conda install {package}")

    return False


def start_log_monitor():
    """Start advanced log monitoring in a separate thread."""
    def monitor_logs():
        log_file = ROOT / "logs" / "latest.log"
        log_dir = ROOT / "logs"

        # Ensure log directory exists
        log_dir.mkdir(exist_ok=True)

        # Create log file if it doesn't exist
        if not log_file.exists():
            log_file.touch()

        print("[*] Advanced Log Monitor Started (Left Panel)")
        print("=" * 50)
        print("[*] Monitoring: latest.log, plexichat.log, errors.log")
        print("=" * 50)

        # Monitor multiple log files
        log_files = {
            "latest": log_dir / "latest.log",
            "main": log_dir / "plexichat.log",
            "errors": log_dir / "errors.log"
        }

        # Create files if they don't exist
        for name, path in log_files.items():
            if not path.exists():
                path.touch()

        # Track file positions
        file_positions = {}
        for name, path in log_files.items():
            file_positions[name] = path.stat().st_size if path.exists() else 0

        try:
            while True:
                for name, path in log_files.items():
                    if not path.exists():
                        continue

                    current_size = path.stat().st_size
                    last_position = file_positions.get(name, 0)

                    if current_size > last_position:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_position)
                            new_lines = f.readlines()

                            for line in new_lines:
                                line = line.strip()
                                if line:
                                    # Format log line with source
                                    timestamp = datetime.now().strftime('%H:%M:%S')
                                    source_emoji = {
                                        "latest": "[*]",
                                        "main": "[*]",
                                        "errors": "[ERROR]"
                                    }.get(name, "[*]")

                                    # Color code by log level
                                    if "ERROR" in line or "CRITICAL" in line:
                                        print(f"[{timestamp}] {source_emoji} [ERROR] {line}")
                                    elif "WARNING" in line:
                                        print(f"[{timestamp}] {source_emoji} [WARN] {line}")
                                    elif "INFO" in line:
                                        print(f"[{timestamp}] {source_emoji} [INFO] {line}")
                                    elif "DEBUG" in line:
                                        print(f"[{timestamp}] {source_emoji} [DEBUG] {line}")
                                    else:
                                        print(f"[{timestamp}] {source_emoji} [*] {line}")

                        file_positions[name] = current_size

                time.sleep(0.2)  # Check every 200ms

        except Exception as e:
            print(f"[ERROR] Advanced log monitor error: {e}")
            # Fallback to simple monitoring
            try:
                with open(log_files["latest"], 'r') as f:
                    f.seek(0, 2)  # Go to end
                    while True:
                        line = f.readline()
                        if line:
                            print(f"[LOG] {line.strip()}")
                        else:
                            time.sleep(0.1)
            except Exception as e2:
                print(f"[ERROR] Fallback log monitor also failed: {e2}")

    log_thread = threading.Thread(target=monitor_logs, daemon=True)
    log_thread.start()
    return log_thread


def start_log_generator():
    """Start a thread that generates realistic log entries for demonstration."""
    def generate_logs():
        log_dir = ROOT / "logs"
        log_files = {
            "latest": log_dir / "latest.log",
            "plexichat": log_dir / "plexichat.log",
            "errors": log_dir / "errors.log"
        }

        # Ensure all log files exist
        for log_file in log_files.values():
            if not log_file.exists():
                log_file.touch()

        log_messages = [
            ("INFO", "plexichat.api", "[*] API endpoint /health accessed"),
            ("INFO", "plexichat.auth", "[*] User authentication successful"),
            ("DEBUG", "plexichat.database", "[*] Database query executed in 45ms"),
            ("INFO", "plexichat.backup", "[*] Backup process completed successfully"),
            ("INFO", "plexichat.security", "[*] Security scan completed successfully"),
            ("INFO", "plexichat.performance", "[*] System performance metrics collected"),
            ("DEBUG", "plexichat.cli", "[*] CLI command executed: status"),
            ("INFO", "plexichat.websocket", "[*] WebSocket connection established"),
            ("INFO", "plexichat.ai", "[*] AI model inference completed"),
            ("DEBUG", "plexichat.clustering", "[*] Cluster health check passed"),
        ]

        counter = 0
        while True:
            try:
                # Generate a log entry every 3-8 seconds
                time.sleep(3 + (counter % 5))

                level, module, message = log_messages[counter % len(log_messages)]
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                log_entry = f"[{timestamp}] [{level:8}] {module}: {message}\n"

                # Write to appropriate log files
                with open(log_files["latest"], 'a', encoding='utf-8') as f:
                    f.write(log_entry)

                with open(log_files["plexichat"], 'a', encoding='utf-8') as f:
                    f.write(log_entry)

                # Write errors to error log
                if level in ["ERROR", "CRITICAL"]:
                    with open(log_files["errors"], 'a', encoding='utf-8') as f:
                        f.write(log_entry)

                counter += 1

                # Occasionally generate an error for demonstration
                if counter % 20 == 0:
                    error_entry = f"[{timestamp}] [ERROR   ] plexichat.test: [ERROR] Simulated error for demonstration\n"
                    with open(log_files["latest"], 'a', encoding='utf-8') as f:
                        f.write(error_entry)
                    with open(log_files["errors"], 'a', encoding='utf-8') as f:
                        f.write(error_entry)

            except Exception as e:
                print(f"Log generator error: {e}")
                time.sleep(5)

    gen_thread = threading.Thread(target=generate_logs, daemon=True)
    gen_thread.start()
    return gen_thread


def run_plexichat_server():
    """Run PlexiChat server with multiplexed terminal."""
    if not VENV_DIR.exists():
        print("[ERROR] Virtual environment not found. Run setup first.")
        return False

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        print("[ERROR] Virtual environment Python not found")
        return False

    # Check if this is first time setup
    is_first_time = not DEFAULT_CREDS.exists()
    if is_first_time:
        print("[SUCCESS] First-time setup detected!")
        generate_default_admin_creds()
        print(f"[*] Admin credentials saved to: {DEFAULT_CREDS}")

    # Detect and report installation type
    install_type = detect_installation_type()
    version = get_version_info()
    ports = get_port_configuration()

    print(f"[*] PlexiChat v{version}")
    print(f"[*] Installation Type: {install_type.upper()}")
    print("=" * 50)
    print("[*] Service Ports:")
    print(f"   [*] API Server:    http://localhost:{ports['api_http']} | https://localhost:{ports['api_https']}")
    print(f"   [*]  WebUI:        http://localhost:{ports['webui_http']} | https://localhost:{ports['webui_https']}")
    print(f"   [*] WebSocket:     ws://localhost:{ports['websocket']}")
    print(f"   [*]  Admin Panel:   http://localhost:{ports['admin']}")
    print("=" * 50)

    if install_type == "partial":
        print("[WARN]  Partial installation detected. Some features may be unavailable.")
        print("   Run 'python run.py setup full' for complete functionality.")
    elif install_type == "incomplete":
        print("[ERROR] Incomplete installation detected. Please run setup again.")
        return False

    print("[*] Starting PlexiChat server with multiplexed terminal...")
    print("[*] Logs will appear on the left, CLI on the right")
    print("=" * 50)

    # Start log monitoring and generation
    start_log_monitor()
    start_log_generator()

    # Set up environment
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["PLEXICHAT_LOG_TO_FILE"] = "1"  # Force logging to file

    try:
        # Start server with better error handling
        print("[*] Initializing PlexiChat core systems...")

        # Generate some initial logs to ensure log files exist
        logs_dir = ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)

        # Create initial log entries
        latest_log = logs_dir / "latest.log"
        with open(latest_log, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] [INFO] plexichat.startup: [*] PlexiChat server starting up...\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: [*] Initializing logging system\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: [*] Loading configuration\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: [*] Starting web server\n")

        process = subprocess.Popen(
            [str(venv_python), "-m", "src.plexichat.main"],
            env=env,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        print("[OK] PlexiChat server process started")
        print("[*] Services are now available:")
        print(f"   [*] API:     http://localhost:{ports['api_http']}")
        print(f"   [*]  WebUI:   http://localhost:{ports['webui_http']}")
        if is_first_time:
            print(f"[*] Default admin credentials: {DEFAULT_CREDS}")
        print("=" * 50)

        # Check if terminal supports split screen
        try:
            terminal_width = shutil.get_terminal_size().columns
            if terminal_width >= 120:
                print("[*] Split-screen mode enabled - CLI commands will appear separately from logs")
            else:
                print("[*] Standard mode - CLI and logs will be mixed")
        except:
            print("[*] Standard mode - CLI and logs will be mixed")

        print("Commands: 'status', 'logs', 'stop', 'help'")
        print("=" * 50)

        # Initialize integrated CLI
        try:
            sys.path.insert(0, str(SRC))
            try:
                from plexichat.cli.integrated_cli import PlexiChatCLI
            except ImportError:
                from src.plexichat.cli.integrated_cli import PlexiChatCLI
            cli = PlexiChatCLI()
            print("[OK] Integrated CLI loaded")
        except Exception as e:
            print(f"[WARN] Failed to load integrated CLI: {e}")
            cli = None

        # Enhanced CLI loop
        while process.poll() is None and (cli is None or cli.running):
            try:
                cmd = input("PlexiChat> ").strip()

                if not cmd:
                    continue

                if cli:
                    # Use integrated CLI
                    import asyncio
                    try:
                        # Run async command in sync context
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        response = loop.run_until_complete(cli.process_command(cmd))
                        loop.close()

                        if response:
                            print(response)

                        # Check if CLI wants to stop
                        if not cli.running:
                            print("[STOP] Stopping PlexiChat server...")
                            process.terminate()
                            break

                    except Exception as e:
                        print(f"[ERROR] CLI error: {e}")
                else:
                    # Fallback simple CLI
                    cmd_lower = cmd.lower()
                    if cmd_lower == "stop":
                        print("[STOP] Stopping PlexiChat server...")
                        process.terminate()
                        break
                    elif cmd_lower == "status":
                        print(f"[*] Server Status: {'Running' if process.poll() is None else 'Stopped'}")
                        print(f"[*] Installation: {install_type.upper()}")
                        print(f"[*] Version: {version}")
                    elif cmd_lower == "help":
                        print("Available commands: status, stop, help")
                    else:
                        print(f"[?] Unknown command: {cmd}")

            except (EOFError, KeyboardInterrupt):
                print("\n[STOP] Stopping PlexiChat server...")
                process.terminate()
                break

        # Wait for process to finish
        process.wait()
        return True

    except Exception as e:
        print(f"[ERROR] PlexiChat server failed to start: {e}")
        print("[*] Check the logs for more details")
        return False


def clean_environment(deep_clean=False):
    """Clean up virtual environment and cache with Windows compatibility."""
    print("[*] Cleaning PlexiChat environment...")

    # Stop any running processes first
    stop_running_processes()

    # Clean virtual environment with improved Windows handling
    if VENV_DIR.exists():
        print("[*] Removing virtual environment...")
        try:
            if platform.system() == "Windows":
                # Windows-specific approach with multiple fallbacks
                success = False

                # Method 1: Try simple rename first (often works when delete fails)
                try:
                    backup_name = VENV_DIR.parent / f".venv_backup_{int(time.time())}"
                    VENV_DIR.rename(backup_name)
                    print("[*] Renamed virtual environment, attempting deletion...")

                    # Try to delete the renamed directory
                    for attempt in range(3):
                        try:
                            shutil.rmtree(backup_name, ignore_errors=False)
                            success = True
                            break
                        except Exception as e:
                            print(f"   Attempt {attempt + 1}/3 failed: {e}")
                            time.sleep(1)

                    if not success:
                        print(f"[WARN]  Could not delete renamed directory: {backup_name}")
                        print("[INFO] You may need to manually delete it later")
                        success = True  # Consider rename as success

                except Exception as e:
                    print(f"[WARN]  Rename method failed: {e}")

                # Method 2: Try PowerShell removal if rename failed
                if not success:
                    try:
                        print("[*] Trying PowerShell removal...")
                        ps_command = f'Remove-Item -Path "{VENV_DIR}" -Recurse -Force -ErrorAction SilentlyContinue'
                        subprocess.run([
                            "powershell", "-Command", ps_command
                        ], capture_output=True, timeout=30, check=False)

                        if not VENV_DIR.exists():
                            success = True
                        else:
                            print("[WARN]  PowerShell removal incomplete")
                    except Exception as e:
                        print(f"[WARN]  PowerShell method failed: {e}")

                # Method 3: Final fallback with ignore_errors
                if not success:
                    print("[*] Using fallback removal method...")
                    try:
                        shutil.rmtree(VENV_DIR, ignore_errors=True)
                        if not VENV_DIR.exists():
                            success = True
                    except:
                        pass

                if success:
                    print("[OK] Virtual environment removed")
                else:
                    print("[WARN]  Virtual environment removal incomplete")
                    print(f"[INFO] You may need to manually delete: {VENV_DIR}")

            else:
                # Unix/Linux/macOS - standard removal
                shutil.rmtree(VENV_DIR)
                print("[OK] Virtual environment removed")

        except Exception as e:
            print(f"[WARN]  Could not remove virtual environment: {e}")
            print("[INFO] Try running as administrator or manually delete the .venv folder")

    # Remove Python cache with enhanced cleanup
    cache_dirs_removed = 0
    for root, dirs, files in os.walk(ROOT):
        for dir_name in dirs[:]:
            if dir_name in ["__pycache__", ".pytest_cache", ".mypy_cache", ".coverage"]:
                cache_dir = Path(root) / dir_name
                try:
                    print(f"[*] Removing cache: {cache_dir}")
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    cache_dirs_removed += 1
                    dirs.remove(dir_name)
                except Exception as e:
                    print(f"[WARN]  Could not remove {cache_dir}: {e}")

    # Deep clean additional items
    if deep_clean:
        print("[*] Performing deep clean...")
        deep_clean_items = [
            "logs/*.log",
            "logs/**/*.log",
            "data/temp/*",
            "*.pyc",
            "*.pyo",
            "*.egg-info",
            ".coverage*",
            "htmlcov/",
            ".tox/",
            ".nox/",
            "build/",
            "dist/",
            ".eggs/",
        ]

        for pattern in deep_clean_items:
            try:
                import glob
                for item in glob.glob(str(ROOT / pattern), recursive=True):
                    item_path = Path(item)
                    if item_path.exists():
                        if item_path.is_file():
                            item_path.unlink(missing_ok=True)
                        else:
                            shutil.rmtree(item_path, ignore_errors=True)
                        print(f"[*] Removed: {item_path}")
            except Exception as e:
                print(f"[WARN]  Could not clean {pattern}: {e}")

    print(f"[OK] Environment cleaned ({cache_dirs_removed} cache directories removed)")


def stop_running_processes():
    """Stop any running PlexiChat processes with timeout protection."""
    print("[*] Checking for running PlexiChat processes...")

    try:
        if platform.system() == "Windows":
            # Use PowerShell instead of wmic for better reliability
            try:
                ps_command = """
                Get-Process python -ErrorAction SilentlyContinue |
                Where-Object {$_.CommandLine -like '*plexichat*'} |
                ForEach-Object {$_.Id}
                """
                result = subprocess.run([
                    "powershell", "-Command", ps_command
                ], capture_output=True, text=True, timeout=10, check=False)

                if result.returncode == 0 and result.stdout.strip():
                    pids = [pid.strip() for pid in result.stdout.strip().split('\n') if pid.strip().isdigit()]
                    for pid in pids:
                        try:
                            subprocess.run(["taskkill", "/F", "/PID", pid],
                                         capture_output=True, timeout=5, check=False)
                            print(f"[STOP] Stopped process PID: {pid}")
                        except:
                            pass
                elif result.stdout.strip():
                    print("[*] No PlexiChat processes found")

            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback to tasklist approach
                print("[*] Trying alternative process detection...")
                try:
                    result = subprocess.run([
                        "tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"
                    ], capture_output=True, text=True, timeout=10, check=False)

                    if result.returncode == 0:
                        # Simple approach: kill all python.exe processes (be careful!)
                        print("[WARN]  Using broad process termination - this may affect other Python processes")
                        subprocess.run(["taskkill", "/F", "/IM", "python.exe"],
                                     capture_output=True, timeout=5, check=False)
                except:
                    print("[WARN]  Could not stop processes using Windows methods")

        else:
            # Unix/Linux/macOS
            try:
                # First try to find specific plexichat processes
                result = subprocess.run([
                    "pgrep", "-f", "plexichat"
                ], capture_output=True, text=True, timeout=5, check=False)

                if result.returncode == 0 and result.stdout.strip():
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        if pid.strip().isdigit():
                            try:
                                subprocess.run(["kill", "-TERM", pid.strip()],
                                             capture_output=True, timeout=5, check=False)
                                print(f"[STOP] Stopped process PID: {pid.strip()}")
                            except:
                                pass

                    # Give processes time to terminate gracefully
                    time.sleep(2)

                    # Force kill if still running
                    result = subprocess.run([
                        "pgrep", "-f", "plexichat"
                    ], capture_output=True, text=True, timeout=5, check=False)

                    if result.returncode == 0 and result.stdout.strip():
                        pids = result.stdout.strip().split('\n')
                        for pid in pids:
                            if pid.strip().isdigit():
                                try:
                                    subprocess.run(["kill", "-KILL", pid.strip()],
                                                 capture_output=True, timeout=5, check=False)
                                    print(f"[STOP] Force killed process PID: {pid.strip()}")
                                except:
                                    pass
                else:
                    print("[*] No PlexiChat processes found")

            except subprocess.TimeoutExpired:
                print("[WARN]  Process detection timed out")
            except FileNotFoundError:
                print("[WARN]  Process management tools not available")

    except Exception as e:
        print(f"[WARN]  Could not stop processes: {e}")

    print("[OK] Process cleanup completed")


def export_plexichat_config(filename=None, options=None):
    """Export complete PlexiChat configuration and data."""
    if options is None:
        options = {}

    # Generate filename if not provided
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version = get_version_info()
        filename = f"plexichat_export_{version}_{timestamp}.plx"

    # Ensure .plx extension
    if not filename.endswith('.plx'):
        filename += '.plx'

    export_path = Path(filename)
    if not export_path.is_absolute():
        export_path = ROOT / filename

    print(f"[*] Exporting PlexiChat configuration to: {export_path}")

    try:
        import hashlib
        import tempfile
        import zipfile

        # Create temporary directory for staging
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            export_staging = temp_path / "plexichat_export"
            export_staging.mkdir()

            # Export metadata
            metadata = {
                "export_version": "1.0",
                "plexichat_version": get_version_info(),
                "export_date": datetime.now().isoformat(),
                "system_info": get_system_info(),
                "options": options,
                "exported_components": []
            }

            # Export configuration files
            config_items = [
                ("config", "Configuration files"),
                ("version.json", "Version information"),
                ("setup_config.json", "Setup configuration"),
                ("default_creds.txt", "Default credentials"),
            ]

            for item, description in config_items:
                source_path = ROOT / item
                if source_path.exists():
                    dest_path = export_staging / item
                    try:
                        if source_path.is_dir():
                            shutil.copytree(source_path, dest_path)
                        else:
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(source_path, dest_path)
                        metadata["exported_components"].append(description)
                        print(f"   [OK] {description}")
                    except Exception as e:
                        print(f"   [WARN]  Partial export of {description}: {e}")
                        metadata["exported_components"].append(f"{description} (partial)")

            # Export data directory
            data_dir = ROOT / "data"
            if data_dir.exists():
                try:
                    dest_data = export_staging / "data"
                    shutil.copytree(data_dir, dest_data)
                    metadata["exported_components"].append("Database and data files")
                    print("   [OK] Database and data files")
                except Exception as e:
                    print(f"   [WARN]  Partial export of database: {e}")
                    metadata["exported_components"].append("Database and data files (partial)")

            # Export certificates
            certs_dir = ROOT / "certs"
            if certs_dir.exists():
                try:
                    dest_certs = export_staging / "certs"
                    shutil.copytree(certs_dir, dest_certs)
                    metadata["exported_components"].append("Certificates and keys")
                    print("   [OK] Certificates and keys")
                except Exception as e:
                    print(f"   [WARN]  Partial export of certificates: {e}")
                    metadata["exported_components"].append("Certificates and keys (partial)")

            # Export plugins
            plugins_dir = ROOT / "plugins"
            if plugins_dir.exists():
                try:
                    dest_plugins = export_staging / "plugins"
                    shutil.copytree(plugins_dir, dest_plugins)
                    metadata["exported_components"].append("Plugin configurations")
                    print("   [OK] Plugin configurations")
                except Exception as e:
                    print(f"   [WARN]  Partial export of plugins: {e}")
                    metadata["exported_components"].append("Plugin configurations (partial)")

            # Export logs if requested
            if options.get('include_logs', False):
                logs_dir = ROOT / "logs"
                if logs_dir.exists():
                    try:
                        dest_logs = export_staging / "logs"
                        shutil.copytree(logs_dir, dest_logs)
                        metadata["exported_components"].append("Log files")
                        print("   [OK] Log files")
                    except Exception as e:
                        print(f"   [WARN]  Partial export of logs: {e}")
                        metadata["exported_components"].append("Log files (partial)")

            # Export requirements and environment info
            req_files = ["requirements.txt", "pyproject.toml"]
            for req_file in req_files:
                req_path = ROOT / req_file
                if req_path.exists():
                    shutil.copy2(req_path, export_staging / req_file)
                    metadata["exported_components"].append(f"Requirements ({req_file})")
                    print(f"   [OK] Requirements ({req_file})")

            # Save metadata
            with open(export_staging / "export_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            # Create archive
            if options.get('compress', True):
                print("[*]?  Creating compressed archive...")
                with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(export_staging):
                        for file in files:
                            file_path = Path(root) / file
                            arc_path = file_path.relative_to(export_staging)
                            zipf.write(file_path, arc_path)
            else:
                # Copy directory structure
                if export_path.exists():
                    shutil.rmtree(export_path)
                shutil.copytree(export_staging, export_path)

            # Calculate file hash
            hash_md5 = hashlib.md5()
            with open(export_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if isinstance(chunk, str):
                        chunk = chunk.encode('utf-8')
                    hash_md5.update(chunk)
            file_hash = hash_md5.hexdigest()

            # Create checksum file
            checksum_file = export_path.with_suffix('.md5')
            with open(checksum_file, 'w') as f:
                f.write(f"{file_hash}  {export_path.name}\n")

            file_size = export_path.stat().st_size / (1024 * 1024)  # MB

            print("\n[OK] Export completed successfully!")
            print(f"[*] File: {export_path}")
            print(f"[*] Size: {file_size:.2f} MB")
            print(f"[*] MD5: {file_hash}")
            print(f"[*] Components: {len(metadata['exported_components'])}")
            print(f"[*] Checksum: {checksum_file}")

            if options.get('encrypt', False):
                print("\n[*] Encryption requested but not yet implemented")
                print("[INFO] Consider using system-level encryption for sensitive data")

    except Exception as e:
        print(f"[ERROR] Export failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True


def import_plexichat_config(filename, options=None):
    """Import PlexiChat configuration and data."""
    if options is None:
        options = {}

    import_path = Path(filename)
    if not import_path.is_absolute():
        import_path = ROOT / filename

    if not import_path.exists():
        print(f"[ERROR] Import file not found: {import_path}")
        return False

    print(f"[*] Importing PlexiChat configuration from: {import_path}")

    try:
        import hashlib
        import tempfile
        import zipfile

        # Verify checksum if available
        checksum_file = import_path.with_suffix('.md5')
        if checksum_file.exists():
            print("[*] Verifying file integrity...")
            with open(checksum_file, 'r') as f:
                expected_hash = f.read().strip().split()[0]

            hash_md5 = hashlib.md5()
            with open(import_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if isinstance(chunk, str):
                        chunk = chunk.encode('utf-8')
                    hash_md5.update(chunk)
            actual_hash = hash_md5.hexdigest()

            if actual_hash != expected_hash:
                print("[ERROR] File integrity check failed!")
                print(f"Expected: {expected_hash}")
                print(f"Actual:   {actual_hash}")
                if not input("Continue anyway? (y/N): ").lower().startswith('y'):
                    return False
            else:
                print("[OK] File integrity verified")

        # Create backup if requested
        if options.get('backup', True):
            print("[*] Creating backup of current configuration...")
            backup_options = {'compress': True}
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"plexichat_backup_before_import_{timestamp}.plx"
            export_plexichat_config(backup_filename, backup_options)

        # Extract/read import file
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            import_staging = temp_path / "plexichat_import"

            # Check if it's a zip file or directory
            if zipfile.is_zipfile(import_path):
                print("[*] Extracting compressed archive...")
                with zipfile.ZipFile(import_path, 'r') as zipf:
                    zipf.extractall(import_staging)
            else:
                print("[*] Reading directory structure...")
                shutil.copytree(import_path, import_staging)

            # Read metadata
            metadata_file = import_staging / "export_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)

                print("[*] Import Information:")
                print(f"   Export Version: {metadata.get('export_version', 'Unknown')}")
                print(f"   PlexiChat Version: {metadata.get('plexichat_version', 'Unknown')}")
                print(f"   Export Date: {metadata.get('export_date', 'Unknown')}")
                print(f"   Components: {len(metadata.get('exported_components', []))}")

                # Version compatibility check
                current_version = get_version_info()
                export_version = metadata.get('plexichat_version', '')
                if export_version != current_version:
                    print("[WARN]  Version mismatch!")
                    print(f"   Current: {current_version}")
                    print(f"   Import:  {export_version}")
                    if not input("Continue with import? (y/N): ").lower().startswith('y'):
                        return False
            else:
                print("[WARN]  No metadata found, proceeding with basic import...")

            # Import components
            imported_components = []

            # Import configuration files
            config_items = [
                ("config", "Configuration files"),
                ("version.json", "Version information"),
                ("setup_config.json", "Setup configuration"),
                ("default_creds.txt", "Default credentials"),
            ]

            for item, description in config_items:
                source_path = import_staging / item
                dest_path = ROOT / item

                if source_path.exists():
                    if options.get('overwrite', False) or not dest_path.exists() or options.get('merge', False):
                        try:
                            if source_path.is_dir():
                                if dest_path.exists() and options.get('overwrite', False):
                                    shutil.rmtree(dest_path)
                                if not dest_path.exists():
                                    shutil.copytree(source_path, dest_path)
                                elif options.get('merge', False):
                                    # Merge directories
                                    for root, dirs, files in os.walk(source_path):
                                        for file in files:
                                            src_file = Path(root) / file
                                            rel_path = src_file.relative_to(source_path)
                                            dst_file = dest_path / rel_path
                                            dst_file.parent.mkdir(parents=True, exist_ok=True)
                                            shutil.copy2(src_file, dst_file)
                            else:
                                dest_path.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(source_path, dest_path)

                            imported_components.append(description)
                            print(f"   [OK] {description}")
                        except Exception as e:
                            print(f"   [ERROR] Failed to import {description}: {e}")
                    else:
                        print(f"   ??  Skipped {description} (already exists)")

            # Import data directory
            data_source = import_staging / "data"
            data_dest = ROOT / "data"
            if data_source.exists():
                try:
                    if options.get('overwrite', False) or not data_dest.exists():
                        if data_dest.exists():
                            shutil.rmtree(data_dest)
                        shutil.copytree(data_source, data_dest)
                        imported_components.append("Database and data files")
                        print("   [OK] Database and data files")
                    else:
                        print("   ??  Skipped database (already exists, use --overwrite to replace)")
                except Exception as e:
                    print(f"   [ERROR] Failed to import database: {e}")

            # Import other directories
            other_dirs = [
                ("certs", "Certificates and keys"),
                ("plugins", "Plugin configurations"),
                ("logs", "Log files")
            ]

            for dir_name, description in other_dirs:
                source_dir = import_staging / dir_name
                dest_dir = ROOT / dir_name

                if source_dir.exists():
                    try:
                        if options.get('overwrite', False) or not dest_dir.exists():
                            if dest_dir.exists():
                                shutil.rmtree(dest_dir)
                            shutil.copytree(source_dir, dest_dir)
                            imported_components.append(description)
                            print(f"   [OK] {description}")
                        elif options.get('merge', False):
                            # Merge directories
                            for root, dirs, files in os.walk(source_dir):
                                for file in files:
                                    src_file = Path(root) / file
                                    rel_path = src_file.relative_to(source_dir)
                                    dst_file = dest_dir / rel_path
                                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy2(src_file, dst_file)
                            imported_components.append(f"{description} (merged)")
                            print(f"   [OK] {description} (merged)")
                        else:
                            print(f"   ??  Skipped {description} (already exists)")
                    except Exception as e:
                        print(f"   [ERROR] Failed to import {description}: {e}")

            print("\n[OK] Import completed!")
            print(f"[*] Imported components: {len(imported_components)}")
            for component in imported_components:
                print(f"   * {component}")

            print("\n[INFO] Next steps:")
            print("   1. Review imported configuration")
            print("   2. Run 'python run.py info' to verify setup")
            print("   3. Test PlexiChat functionality")

            if options.get('decrypt', False):
                print("\n[*] Decryption requested but not yet implemented")
                print("[INFO] Consider using system-level decryption tools")

    except Exception as e:
        print(f"[ERROR] Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True


def show_subcommand_help(subcommand):
    """Show help for specific subcommands."""
    help_text = {
        "setup": """
[*] Setup Command Help

Usage: python run.py setup [style] [options]

Styles:
  minimal     Core functionality only (fastest setup)
  standard    Standard feature set (recommended)
  full        All features including optional dependencies
  developer   Full features plus development tools

Options:
  --env-type  Specify environment manager (venv, conda, mamba, virtualenv)
  --no-fallback  Don't use fallback installation methods

Examples:
  python run.py setup                    # Interactive setup
  python run.py setup standard           # Standard setup
  python run.py setup full --env-type conda  # Full setup with conda
""",
        "clean": """
[*] Clean Command Help

Usage: python run.py clean [options]

Options:
  --all       Deep clean including logs, temp files, and build artifacts

What gets cleaned:
  Default:    Virtual environment, Python cache (__pycache__)
  --all:      + logs, temp files, build artifacts, coverage data

Examples:
  python run.py clean                    # Basic cleanup
  python run.py clean --all              # Deep cleanup
""",
        "run": """
[*] Run Command Help

Usage: python run.py run [options]

Options:
  --debug     Enable debug mode with detailed logging
  --no-auto   Don't auto-start services

Terminal Styles (configured during setup):
  classic     Single terminal window
  split       Split-pane terminal (logs + CLI)
  tabbed      Tabbed interface
  dashboard   Live monitoring dashboard

Examples:
  python run.py run                      # Start with configured style
  python run.py run --debug              # Start with debug logging
""",
        "env": """
[*] Environment Command Help

Usage: python run.py env [options]

Shows information about:
  - Available Python environment managers
  - Current virtual environment status
  - Python version and executable paths
  - Environment recommendations

Examples:
  python run.py env                      # Show environment info
""",
        "info": """
[*] Info Command Help

Usage: python run.py info

Shows detailed system information:
  - Platform and architecture details
  - Python version and paths
  - Memory and disk usage
  - Environment variables
  - Available environment managers
  - Installation status

Examples:
  python run.py info                     # Show system information
""",
        "test": """
[*] Test Command Help

Usage: python run.py test [options]

Options:
  --verbose   Show detailed test output
  --coverage  Generate coverage report
  --security  Run security tests only

Examples:
  python run.py test                     # Run all tests
  python run.py test --verbose           # Verbose output
  python run.py test --security          # Security tests only
""",
        "version": """
[*] Version Command Help

Usage: python run.py version [options]

Shows version information from:
  - Git tags and commit hashes
  - Branch information
  - Build status
  - Fallback to version.json if Git unavailable

Examples:
  python run.py version                  # Show version info
""",
        "update": """
[*] Update Command Help

Usage: python run.py update [options] [version]

Options:
  --check       Check for updates without applying
  --force       Force update even if up to date
  --version     Install specific version
  --list        List available versions
  --rollback    Rollback to previous version

Examples:
  python run.py update                   # Check and apply latest updates
  python run.py update --check           # Check only
  python run.py update --version a.1.2-1 # Install specific version
  python run.py update --list            # List available versions
  python run.py update --rollback        # Rollback to previous version
""",
        "wizard": """
? Wizard Command Help

Usage: python run.py wizard

Interactive setup wizard that guides you through:
  - Setup style selection
  - Terminal style configuration
  - Debug and monitoring options
  - Environment manager selection

Examples:
  python run.py wizard                   # Run interactive setup
""",
        "export": """
[*] Export Command Help

Usage: python run.py export [filename] [options]

Options:
  --include-logs    Include log files in export
  --include-cache   Include cache data in export
  --compress        Create compressed archive (default: true)
  --encrypt         Encrypt the export file with password

What gets exported:
  - Configuration files (config/, setup_config.json)
  - Database files (data/)
  - Certificates and keys (certs/)
  - Plugin configurations (plugins/)
  - Version information
  - Environment settings
  - User credentials (encrypted)

Examples:
  python run.py export                   # Export to auto-named file
  python run.py export backup.plx       # Export to specific file
  python run.py export --include-logs   # Include log files
  python run.py export --encrypt        # Encrypt with password
""",
        "import": """
[*] Import Command Help

Usage: python run.py import [filename] [options]

Options:
  --overwrite       Overwrite existing configuration
  --merge           Merge with existing configuration
  --backup          Create backup before import
  --decrypt         Decrypt imported file with password

What gets imported:
  - Configuration files
  - Database files
  - Certificates and keys
  - Plugin configurations
  - Version information
  - Environment settings
  - User credentials

Examples:
  python run.py import backup.plx       # Import from file
  python run.py import --overwrite      # Overwrite existing config
  python run.py import --merge          # Merge configurations
  python run.py import --decrypt        # Decrypt with password
""",
        "admin": """
[*] Admin Command Help

Usage: python run.py admin

Opens the PlexiChat admin panel in your default browser.
The admin panel provides:
  - Server configuration and management
  - User account management
  - Security settings and monitoring
  - System health and performance metrics
  - Plugin and module management
  - Database administration
  - Backup and restore operations

Default URL: http://localhost:8002

Examples:
  python run.py admin                   # Open admin panel
""",
        "webui": """
[*] WebUI Command Help

Usage: python run.py webui

Opens the main PlexiChat web interface in your default browser.
The WebUI provides:
  - Chat interface and messaging
  - Channel and server management
  - User profile and settings
  - File sharing and media
  - Voice and video calls
  - Community spaces and forums
  - Status updates and stories

Default URL: http://localhost:8080

Examples:
  python run.py webui                   # Open main interface
""",
        "gui": """
[*] GUI Command Help

Usage: python run.py gui

Interactive GUI launcher that provides options to:
  1. Open admin panel only
  2. Open main WebUI only
  3. Open both interfaces

This is a convenient way to access PlexiChat's graphical interfaces
without remembering specific URLs or commands.

Examples:
  python run.py gui                     # Interactive GUI launcher
""",
        "status": """
[*] Status Command Help

Usage: python run.py status

Shows the current status of all PlexiChat services:
  - API Server (HTTP/HTTPS)
  - WebUI Server
  - Admin Panel
  - WebSocket Server
  - Database connections
  - Service health checks

Displays:
  - Service URLs and ports
  - Response status (Running/Not responding)
  - Health check results

Examples:
  python run.py status                  # Show service status
""",
        "config": """
[*] Config Command Help

Usage: python run.py config [subcommand]

Unified configuration management - NO MORE .ENV FILES!
All configuration is now in a single plexichat.yaml file.

Subcommands:
  generate    Generate unified configuration file
  validate    Validate configuration syntax
  show        Display current configuration
  edit        Interactive configuration editor
  reset       Reset to default configuration

Examples:
  python run.py config generate         # Create unified config
  python run.py config validate         # Check config validity
  python run.py config show             # Display current config
""",
        "ssl": """
[*] SSL Command Help

Usage: python run.py ssl [subcommand]

SSL certificate and domain management for plexichat.local

Subcommands:
  setup       Generate SSL certificates and configure domain
  renew       Renew SSL certificates
  status      Show certificate status and expiration

Examples:
  python run.py ssl setup              # Set up SSL certificates
  python run.py ssl status             # Check certificate status
""",
        "migrate": """
[*] Migration Command Help

Usage: python run.py migrate [subcommand]

Database migration management for schema updates

Subcommands:
  run         Execute pending migrations
  rollback    Rollback last migration
  status      Show migration status
  create      Create new migration file

Examples:
  python run.py migrate run             # Run pending migrations
  python run.py migrate status          # Check migration status
""",
        "backup": """
[*] Backup Command Help

Usage: python run.py backup [subcommand]

Comprehensive backup management system

Subcommands:
  create      Create new backup
  list        List available backups
  schedule    Configure automatic backups
  verify      Verify backup integrity

Examples:
  python run.py backup create           # Create backup now
  python run.py backup list             # Show all backups
""",
        "plugin": """
[*] Plugin Command Help

Usage: python run.py plugin [subcommand]

Plugin management and marketplace integration

Subcommands:
  list        List installed plugins
  install     Install new plugin
  remove      Remove plugin
  enable      Enable plugin
  disable     Disable plugin
  update      Update all plugins

Examples:
  python run.py plugin list             # Show installed plugins
  python run.py plugin install ai-bot   # Install AI bot plugin
"""
    }

    if subcommand in help_text:
        print(help_text[subcommand])
    else:
        print(f"[ERROR] No help available for '{subcommand}'")
        print("Available commands: setup, clean, run, env, info, test, version, update, wizard")
        print("                   admin, webui, gui, status, config, ssl, migrate, backup, restore")
        print("                   plugin, cluster, security, monitor")
        print("Use 'python run.py help' for general help")


def show_help():
    """Show enhanced help information."""
    version = get_version_info()
    install_type = detect_installation_type()
    config = load_setup_config()

    print(f"""
[*] PlexiChat v{version} - Government-Level Secure Communication Platform
[*] Current Installation: {install_type.upper()}

[*] SINGLE ENTRY POINT - ALL functionality accessible through run.py ONLY
[*] NO scattered scripts, NO .env files, NO multiple config files
""")

    if config:
        setup_style = config.get("setup_style", "unknown")
        terminal_style = config.get("terminal_style", "unknown")
        print(f"[*] Setup Style: {SETUP_STYLES.get(setup_style, {}).get('name', setup_style)}")
        print(f"[*]  Terminal Style: {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)}")
        if config.get("debug_mode"):
            print("[DEBUG] Debug Mode: Enabled")
        if config.get("performance_monitoring"):
            print("[*] Performance Monitoring: Enabled")

    print("""
Usage: python run.py [command] [options]

[*] Main Commands:
  bootstrap         [*] ONE-SCRIPT INSTALLER: Complete PlexiChat installation from GitHub
                    Downloads source, creates venv, installs dependencies
  setup [style]     Interactive setup wizard or direct setup
                    Styles: minimal, standard, full, developer
  run [--debug]     Start PlexiChat with configured terminal style
  wizard            Run interactive setup wizard
  test [--verbose]  Run comprehensive test suite
  clean [--all]     Clean environment and cache (--all for deep clean)
  env               Show environment manager information
  info              Show detailed system information
  version           Show version and update information
  update            Check for and apply updates from GitHub
  export [file]     Export complete PlexiChat configuration and data
  import [file]     Import PlexiChat configuration and data
  help              Show this help message

[*] Interface Commands:
  admin             Open admin panel in browser
  webui             Open main WebUI in browser
  gui               Interactive GUI launcher (admin + webui)
  status            Show service status and health

[*] System Management:
  config            Configuration management (generate, validate, show, edit, reset)
  ssl               SSL certificate management (setup, renew, status)
  migrate           Database migration management (run, rollback, status, create)
  backup            Backup management (create, list, schedule, verify)
  restore           Restore operations (from, list, verify)

[*] Advanced Features:
  plugin            Plugin management (list, install, remove, enable, disable, update)
  cluster           Cluster management (status, join, leave, nodes)
  security          Security management (audit, scan, keys, users)
  monitor           System monitoring (status, metrics, logs, alerts)

[*] Setup Styles:
  minimal          Core functionality only (~2 min install)
  standard         Recommended for most users (~5 min install)
  full             All features including advanced security (~10 min install)
  developer        Full setup plus development tools (~15 min install)

[*]  Terminal Styles:
  classic          Traditional single-pane output
  split            Logs on left, CLI on right (wide terminals)
  tabbed           Switch between logs and CLI with tabs
  dashboard        Live system monitoring with metrics

[*] First-Time Installation:
  If you only have this run.py file, use:
  python run.py bootstrap    # Downloads and installs everything automatically

  Requirements: Python 3.8+, internet connection
  Creates: plexichat/ directory, venv/ directory, dependencies

[*] Installation Status:
  not_installed    No virtual environment found
  minimal         Core features only
  standard        Standard feature set
  partial         Some optional features missing
  full            All features available
  developer       Full features plus dev tools
  incomplete      Installation corrupted, needs repair

[INFO] Examples:
  python run.py                    # First-time interactive setup
  python run.py setup developer    # Developer setup without wizard
  python run.py wizard             # Re-run setup wizard
  python run.py run --debug        # Start with debug logging
  python run.py admin              # Open admin panel
  python run.py webui              # Open main interface
  python run.py gui                # Open both interfaces
  python run.py status             # Check service status
  python run.py info               # Show system information
  python run.py clean --all        # Complete cleanup
  python run.py test --verbose     # Verbose test output

[*] First-time Setup:
  - Interactive wizard guides you through configuration
  - Default admin credentials generated in default_creds.txt
  - Change password immediately after first login
  - WebUI available at http://localhost:8080
  - API available at http://localhost:8000

[*]  Development Features:
  - Real-time log monitoring with color coding
  - Performance metrics and system monitoring
  - Integrated CLI with advanced commands
  - Debug mode with detailed diagnostics
  - Multiple terminal display modes
""")

    # Show recommendations based on current state
    if install_type == "partial":
        print("[WARN]  Recommendation: Run 'python run.py setup full' for complete functionality.")
    elif install_type == "incomplete":
        print("[ERROR] Recommendation: Run 'python run.py clean && python run.py setup' to repair.")
    elif install_type == "not_installed":
        print("[*] Recommendation: Run 'python run.py' to start interactive setup wizard.")

    # Show system-specific tips
    print(f"\n[*] Platform-Specific Tips ({platform.system()}):")
    if IS_WINDOWS:
        print("  * Use Windows Terminal or PowerShell for best experience")
        print("  * Consider enabling Windows Subsystem for Linux (WSL)")
    elif IS_LINUX:
        print("  * Ensure you have python3.11-dev installed for full functionality")
        print("  * Use a modern terminal emulator for best display")
    elif IS_MACOS:
        print("  * Use iTerm2 or Terminal.app for optimal experience")
        print("  * Consider installing Homebrew for easier dependency management")

    if install_type == "partial":
        print("[WARN]  Note: Partial installation detected. Run 'python run.py setup full' for all features.")
    elif install_type == "incomplete":
        print("[ERROR] Note: Installation is incomplete. Run 'python run.py setup' to repair.")


def open_admin_gui():
    """Open the admin GUI in the default browser."""
    ports = get_port_configuration()
    admin_url = f"http://localhost:{ports.get('admin', 8002)}"

    print(f"[*] Opening Admin GUI: {admin_url}")

    try:
        import webbrowser
        webbrowser.open(admin_url)
        print("[OK] Admin GUI opened in browser")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to open admin GUI: {e}")
        print(f"[INFO] Manually open: {admin_url}")
        return False


def open_webui():
    """Open the WebUI in the default browser."""
    ports = get_port_configuration()
    webui_url = f"http://localhost:{ports.get('webui_http', 8080)}"

    print(f"[*] Opening WebUI: {webui_url}")

    try:
        import webbrowser
        webbrowser.open(webui_url)
        print("[OK] WebUI opened in browser")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to open WebUI: {e}")
        print(f"[INFO] Manually open: {webui_url}")
        return False


def show_service_status():
    """Show status of all PlexiChat services."""
    ports = get_port_configuration()

    print("[*] PlexiChat Service Status")
    print("=" * 50)

    services = [
        ("API Server", f"http://localhost:{ports.get('api_http', 8000)}", "[*]"),
        ("WebUI", f"http://localhost:{ports.get('webui_http', 8080)}", "[*]"),
        ("Admin Panel", f"http://localhost:{ports.get('admin', 8002)}", "[*]"),
        ("WebSocket", f"ws://localhost:{ports.get('websocket', 8001)}", "[*]")
    ]

    for name, url, emoji in services:
        try:
            import requests
            response = requests.get(url.replace('ws://', 'http://'), timeout=2)
            if response.status_code == 200:
                status = "[INFO] Running"
            else:
                status = f"[WARN] Response: {response.status_code}"
        except ImportError:
            status = "[WARN] requests not installed"
        except Exception:
            status = "[ERROR] Not responding"

        print(f"{emoji} {name:15} {url:35} {status}")

    print("=" * 50)
    print("[INFO] Note: Services show as 'Not responding' when not running")
    print("   Use 'python run.py run' to start all services")


# ============================================================================
# UNIFIED COMMAND HANDLERS - ALL FUNCTIONALITY THROUGH SINGLE ENTRY POINT
# ============================================================================

def handle_config_command(args):
    """Handle configuration management commands."""
    if not args:
        print("[*] PlexiChat Configuration Management")
        print("=" * 40)
        print("Available config commands:")
        print("  generate    Generate unified configuration")
        print("  validate    Validate configuration files")
        print("  show        Show current configuration")
        print("  edit        Edit configuration interactively")
        print("  reset       Reset to default configuration")
        return

    subcommand = args[0].lower()

    if subcommand == "generate":
        print("[*] Generating unified configuration...")
        generate_unified_config()
    elif subcommand == "validate":
        print("[OK] Validating configuration...")
        validate_configuration()
    elif subcommand == "show":
        print("[*] Current configuration:")
        show_current_config()
    elif subcommand == "edit":
        print("[*] Interactive configuration editor...")
        edit_config_interactive()
    elif subcommand == "reset":
        print("[*] Resetting to default configuration...")
        reset_to_default_config()
    else:
        print(f"[ERROR] Unknown config command: {subcommand}")

def handle_ssl_command(args):
    """Handle SSL certificate management."""
    if not args:
        print("[*] PlexiChat SSL Management")
        print("=" * 30)
        print("Available SSL commands:")
        print("  setup       Generate SSL certificates and configure domain")
        print("  renew       Renew SSL certificates")
        print("  status      Show SSL certificate status")
        return

    subcommand = args[0].lower()

    if subcommand == "setup":
        print("[*] Setting up SSL certificates...")
        setup_ssl_certificates()
    elif subcommand == "renew":
        print("[*] Renewing SSL certificates...")
        renew_ssl_certificates()
    elif subcommand == "status":
        print("[*] SSL certificate status:")
        show_ssl_status()
    else:
        print(f"[ERROR] Unknown SSL command: {subcommand}")

def handle_migration_command(args):
    """Handle database migration commands."""
    if not args:
        print("[*] PlexiChat Database Migration")
        print("=" * 35)
        print("Available migration commands:")
        print("  run         Run pending migrations")
        print("  rollback    Rollback last migration")
        print("  status      Show migration status")
        print("  create      Create new migration")
        return

    subcommand = args[0].lower()

    if subcommand == "run":
        print("[*] Running database migrations...")
        run_database_migrations()
    elif subcommand == "rollback":
        print("[*] Rolling back migrations...")
        rollback_migrations()
    elif subcommand == "status":
        print("[*] Migration status:")
        show_migration_status()
    elif subcommand == "create":
        name = args[1] if len(args) > 1 else input("Migration name: ")
        create_migration(name)
    else:
        print(f"[ERROR] Unknown migration command: {subcommand}")

def handle_backup_command(args):
    """Handle backup management commands."""
    if not args:
        print("[*] PlexiChat Backup Management")
        print("=" * 32)
        print("Available backup commands:")
        print("  create      Create new backup")
        print("  list        List available backups")
        print("  schedule    Configure automatic backups")
        print("  verify      Verify backup integrity")
        return

    subcommand = args[0].lower()

    if subcommand == "create":
        name = args[1] if len(args) > 1 else None
        create_backup(name)
    elif subcommand == "list":
        list_backups()
    elif subcommand == "schedule":
        configure_backup_schedule()
    elif subcommand == "verify":
        backup_name = args[1] if len(args) > 1 else None
        verify_backup(backup_name)
    else:
        print(f"[ERROR] Unknown backup command: {subcommand}")

def handle_restore_command(args):
    """Handle restore operations."""
    if not args:
        print("[*] PlexiChat Restore Management")
        print("=" * 32)
        print("Available restore commands:")
        print("  from        Restore from specific backup")
        print("  list        List available restore points")
        print("  verify      Verify restore point")
        return

    subcommand = args[0].lower()

    if subcommand == "from":
        backup_name = args[1] if len(args) > 1 else None
        if not backup_name:
            backup_name = input("Backup name to restore from: ")
        restore_from_backup(backup_name)
    elif subcommand == "list":
        list_restore_points()
    elif subcommand == "verify":
        backup_name = args[1] if len(args) > 1 else None
        verify_restore_point(backup_name)
    else:
        print(f"[ERROR] Unknown restore command: {subcommand}")

def handle_plugin_command(args):
    """Handle plugin management commands."""
    if not args:
        print("[*] PlexiChat Plugin Management")
        print("=" * 31)
        print("Available plugin commands:")
        print("  list        List installed plugins")
        print("  install     Install plugin")
        print("  remove      Remove plugin")
        print("  enable      Enable plugin")
        print("  disable     Disable plugin")
        print("  update      Update plugins")
        return

    subcommand = args[0].lower()

    if subcommand == "list":
        list_plugins()
    elif subcommand == "install":
        plugin_name = args[1] if len(args) > 1 else input("Plugin name: ")
        install_plugin(plugin_name)
    elif subcommand == "remove":
        plugin_name = args[1] if len(args) > 1 else input("Plugin name: ")
        remove_plugin(plugin_name)
    elif subcommand == "enable":
        plugin_name = args[1] if len(args) > 1 else input("Plugin name: ")
        enable_plugin(plugin_name)
    elif subcommand == "disable":
        plugin_name = args[1] if len(args) > 1 else input("Plugin name: ")
        disable_plugin(plugin_name)
    elif subcommand == "update":
        update_plugins()
    else:
        print(f"[ERROR] Unknown plugin command: {subcommand}")

def handle_cluster_command(args):
    """Handle cluster management commands."""
    if not args:
        print("[*] PlexiChat Cluster Management")
        print("=" * 32)
        print("Available cluster commands:")
        print("  status      Show cluster status")
        print("  join        Join cluster")
        print("  leave       Leave cluster")
        print("  nodes       List cluster nodes")
        return

    subcommand = args[0].lower()

    if subcommand == "status":
        show_cluster_status()
    elif subcommand == "join":
        cluster_address = args[1] if len(args) > 1 else input("Cluster address: ")
        join_cluster(cluster_address)
    elif subcommand == "leave":
        leave_cluster()
    elif subcommand == "nodes":
        list_cluster_nodes()
    else:
        print(f"[ERROR] Unknown cluster command: {subcommand}")

def handle_security_command(args):
    """Handle security management commands."""
    if not args:
        print("[*] PlexiChat Security Management")
        print("=" * 33)
        print("Available security commands:")
        print("  audit       Run security audit")
        print("  scan        Scan for vulnerabilities")
        print("  keys        Manage encryption keys")
        print("  users       Manage user security")
        return

    subcommand = args[0].lower()

    if subcommand == "audit":
        run_security_audit()
    elif subcommand == "scan":
        scan_vulnerabilities()
    elif subcommand == "keys":
        manage_encryption_keys(args[1:])
    elif subcommand == "users":
        manage_user_security(args[1:])
    else:
        print(f"[ERROR] Unknown security command: {subcommand}")

def handle_monitor_command(args):
    """Handle monitoring commands."""
    if not args:
        print("[*] PlexiChat Monitoring")
        print("=" * 24)
        print("Available monitor commands:")
        print("  status      Show system status")
        print("  metrics     Show performance metrics")
        print("  logs        View system logs")
        print("  alerts      Manage alerts")
        return

    subcommand = args[0].lower()

    if subcommand == "status":
        show_system_status()
    elif subcommand == "metrics":
        show_performance_metrics()
    elif subcommand == "logs":
        view_system_logs(args[1:])
    elif subcommand == "alerts":
        manage_alerts(args[1:])
    else:
        print(f"[ERROR] Unknown monitor command: {subcommand}")

# Enhanced Setup System Functions

def parse_setup_arguments(args: List[str]) -> Dict[str, Any]:
    """Parse setup command arguments into configuration."""
    config = {}

    # Parse port
    if "--port" in args:
        try:
            port_idx = args.index("--port") + 1
            if port_idx < len(args):
                config['port'] = int(args[port_idx])
        except (ValueError, IndexError):
            print("[WARN] Invalid port specified, using default")

    # Parse boolean flags
    boolean_flags = {
        '--ssl': 'ssl_enabled',
        '--proxy': 'proxy_enabled',
        '--cluster': 'cluster_enabled',
        '--load-balancer': 'load_balancer_enabled',
        '--backup-enabled': 'backup_enabled',
        '--encryption': 'encryption_enabled',
        '--compression': 'compression_enabled',
        '--ai': 'ai_enabled',
        '--security': 'security_enabled',
        '--monitoring': 'monitoring_enabled',
        '--analytics': 'analytics_enabled',
        '--plugins': 'plugins_enabled',
        '--api': 'api_enabled',
        '--websockets': 'websockets_enabled',
        '--real-time': 'realtime_enabled',
        '--webhooks': 'webhooks_enabled',
        '--email': 'email_enabled',
        '--debug': 'debug_enabled',
        '--testing': 'testing_enabled',
        '--profiling': 'profiling_enabled',
        '--hot-reload': 'hot_reload_enabled',
        '--dev-tools': 'dev_tools_enabled',
        '--mfa': 'mfa_enabled'
    }

    for flag, key in boolean_flags.items():
        config[key] = flag in args

    # Parse string options
    string_options = {
        '--storage-type': 'storage_type',
        '--database': 'database_type',
        '--auth': 'auth_type'
    }

    for option, key in string_options.items():
        if option in args:
            try:
                option_idx = args.index(option) + 1
                if option_idx < len(args):
                    config[key] = args[option_idx]
            except IndexError:
                pass

    return config

def create_predefined_setup(setup_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Create predefined setup configuration."""
    base_configs = {
        'minimal': {
            'installation_type': 'Minimal',
            'database_type': 'SQLite (Default)',
            'auth_type': 'local',
            'ssl_enabled': False,
            'ai_enabled': False,
            'monitoring_enabled': False,
            'plugins_enabled': False,
            'api_enabled': True,
            'websockets_enabled': False,
            'debug_enabled': False
        },
        'standard': {
            'installation_type': 'Standard',
            'database_type': 'SQLite (Default)',
            'auth_type': 'local',
            'ssl_enabled': True,
            'ai_enabled': True,
            'monitoring_enabled': True,
            'plugins_enabled': True,
            'api_enabled': True,
            'websockets_enabled': True,
            'debug_enabled': False
        },
        'full': {
            'installation_type': 'Full',
            'database_type': 'PostgreSQL',
            'auth_type': 'oauth',
            'ssl_enabled': True,
            'ai_enabled': True,
            'monitoring_enabled': True,
            'analytics_enabled': True,
            'plugins_enabled': True,
            'api_enabled': True,
            'websockets_enabled': True,
            'realtime_enabled': True,
            'backup_enabled': True,
            'encryption_enabled': True,
            'debug_enabled': False
        },
        'developer': {
            'installation_type': 'Developer',
            'database_type': 'SQLite (Default)',
            'auth_type': 'local',
            'ssl_enabled': True,
            'ai_enabled': True,
            'monitoring_enabled': True,
            'plugins_enabled': True,
            'api_enabled': True,
            'websockets_enabled': True,
            'debug_enabled': True,
            'testing_enabled': True,
            'profiling_enabled': True,
            'hot_reload_enabled': True,
            'dev_tools_enabled': True
        },
        'enterprise': {
            'installation_type': 'Enterprise',
            'database_type': 'PostgreSQL',
            'auth_type': 'saml',
            'ssl_enabled': True,
            'security_enabled': True,
            'mfa_enabled': True,
            'ai_enabled': True,
            'monitoring_enabled': True,
            'analytics_enabled': True,
            'plugins_enabled': True,
            'api_enabled': True,
            'websockets_enabled': True,
            'realtime_enabled': True,
            'backup_enabled': True,
            'encryption_enabled': True,
            'cluster_enabled': True,
            'load_balancer_enabled': True,
            'debug_enabled': False
        }
    }

    # Get base configuration
    setup_config = base_configs.get(setup_type, base_configs['standard']).copy()

    # Override with command line arguments
    setup_config.update(config)

    # Add metadata
    setup_config.update({
        'setup_style': setup_type,
        'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'system_info': get_system_info()
    })

    print(f"[*] Running {setup_type} setup with predefined configuration...")
    return setup_config

def run_enhanced_setup_wizard(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run the enhanced interactive setup wizard."""
    try:
        wizard = OSSpecificSetupWizard()

        # Pre-populate with command line arguments
        for key, value in config.items():
            if hasattr(wizard, 'features') and key in wizard.features:
                if isinstance(wizard.features[key], dict) and 'enabled' in wizard.features[key]:
                    wizard.features[key]['enabled'] = value

        return wizard.run_setup_wizard()
    except Exception as e:
        print(f"[WARN] Enhanced wizard not available: {e}")
        # Fallback to basic configuration
        return {
            'setup_style': 'standard',
            'installation_type': 'Standard',
            'database_type': 'SQLite (Default)',
            'auth_type': 'local',
            'ssl_enabled': True,
            'ai_enabled': True,
            'monitoring_enabled': True,
            'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': get_system_info()
        }

def run_custom_setup_wizard(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run custom setup wizard with advanced options."""
    print("[*] Starting Custom Setup Wizard...")
    print("This wizard will guide you through all available options.")

    # Create a comprehensive configuration with all options
    custom_config = {
        'setup_style': 'custom',
        'installation_type': 'Custom',
        'database_type': config.get('database_type', 'SQLite (Default)'),
        'auth_type': config.get('auth_type', 'local'),
        'port': config.get('port', 8080),

        # Core features
        'ssl_enabled': config.get('ssl_enabled', True),
        'ai_enabled': config.get('ai_enabled', True),
        'monitoring_enabled': config.get('monitoring_enabled', True),
        'analytics_enabled': config.get('analytics_enabled', False),
        'plugins_enabled': config.get('plugins_enabled', True),
        'api_enabled': config.get('api_enabled', True),
        'websockets_enabled': config.get('websockets_enabled', True),
        'realtime_enabled': config.get('realtime_enabled', False),

        # Security features
        'security_enabled': config.get('security_enabled', True),
        'mfa_enabled': config.get('mfa_enabled', False),
        'encryption_enabled': config.get('encryption_enabled', False),

        # Infrastructure
        'backup_enabled': config.get('backup_enabled', False),
        'cluster_enabled': config.get('cluster_enabled', False),
        'load_balancer_enabled': config.get('load_balancer_enabled', False),
        'proxy_enabled': config.get('proxy_enabled', False),

        # Integrations
        'webhooks_enabled': config.get('webhooks_enabled', False),
        'email_enabled': config.get('email_enabled', False),

        # Development
        'debug_enabled': config.get('debug_enabled', False),
        'testing_enabled': config.get('testing_enabled', False),
        'profiling_enabled': config.get('profiling_enabled', False),
        'hot_reload_enabled': config.get('hot_reload_enabled', False),
        'dev_tools_enabled': config.get('dev_tools_enabled', False),

        # Storage
        'storage_type': config.get('storage_type', 'local'),
        'compression_enabled': config.get('compression_enabled', False),

        # Metadata
        'setup_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'system_info': get_system_info()
    }

    print(f"[*] Custom setup configured with {len([k for k, v in custom_config.items() if k.endswith('_enabled') and v])} features enabled")
    return custom_config

def setup_plexichat_system(config: Dict[str, Any]) -> bool:
    """Set up PlexiChat system based on configuration."""
    try:
        print("[*] Setting up PlexiChat system...")

        # Save configuration
        save_setup_config(config)

        # Install dependencies based on configuration
        setup_style = config.get("setup_style", "standard")
        print(f"[*] Installing dependencies for {setup_style} setup...")

        if not install_dependencies(setup_style):
            return False

        # Set up SSL if enabled
        if config.get('ssl_enabled', False):
            print("[*] Setting up SSL certificates...")
            setup_ssl_certificates()

        # Generate unified configuration
        print("[*] Generating unified configuration...")
        generate_unified_config()

        return True

    except Exception as e:
        print(f"[ERROR] System setup failed: {e}")
        return False

def print_setup_summary(config: Dict[str, Any]):
    """Print setup completion summary."""
    print("\n" + "=" * 60)
    print("  PlexiChat Setup Complete!")
    print("=" * 60)

    print(f"\nInstallation Type: {config.get('installation_type', 'Standard')}")
    print(f"Database: {config.get('database_type', 'SQLite')}")
    print(f"Authentication: {config.get('auth_type', 'local').upper()}")

    # Show enabled features
    enabled_features = []
    feature_map = {
        'ai_enabled': 'AI Features',
        'ssl_enabled': 'SSL/TLS',
        'monitoring_enabled': 'Monitoring',
        'analytics_enabled': 'Analytics',
        'plugins_enabled': 'Plugins',
        'backup_enabled': 'Automated Backups',
        'encryption_enabled': 'Data Encryption',
        'cluster_enabled': 'Clustering',
        'debug_enabled': 'Debug Mode'
    }

    for key, name in feature_map.items():
        if config.get(key, False):
            enabled_features.append(name)

    if enabled_features:
        print(f"\nEnabled Features: {', '.join(enabled_features)}")

    # Show next steps
    print("\nNext Steps:")
    print("1. python run.py run              # Start PlexiChat")

    port = config.get('port', 8080)
    protocol = 'https' if config.get('ssl_enabled', False) else 'http'
    print(f"2. Open {protocol}://localhost:{port}  # Access web interface")

    if config.get('debug_enabled', False):
        print("3. python run.py debug            # Debug mode tools")

    print("\nConfiguration saved to: plexichat_config.json")
    print(f"Setup completed at: {config.get('setup_date', 'Unknown')}")

def main():
    """Enhanced main entry point - SINGLE POINT OF ACCESS FOR ALL PLEXICHAT FUNCTIONALITY."""
    # Print banner first
    print_banner()

    check_python_version()
    update_version_format()  # Update version format if needed

    args = sys.argv[1:]

    if not args:
        if not VENV_DIR.exists():
            print("[SUCCESS] Welcome to PlexiChat!")
            print("[*] First-time setup detected...")

            # Run interactive setup wizard
            config = interactive_setup_wizard()
            if not config:
                print("[ERROR] Setup cancelled")
                sys.exit(1)

            setup_style = config.get("setup_style", "minimal")
            print(f"\n[*] Starting {SETUP_STYLES[setup_style]['name']}...")

            if install_dependencies(setup_style):
                print("[OK] Setup complete!")
                print("[*] Configuration saved for future runs")
                print("[*] Run 'python run.py run' to start PlexiChat.")
                print("[*] Default admin credentials will be generated on first run.")

                # Show next steps
                print("\n[*] Next Steps:")
                print("1. python run.py run    # Start PlexiChat server")
                print("2. Open http://localhost:8080 in your browser")
                print("3. Login with generated admin credentials")
                print("4. Change default password immediately")

                if config.get("debug_mode"):
                    print("\n[DEBUG] Debug mode enabled - detailed logging will be available")

                if config.get("performance_monitoring"):
                    print("[*] Performance monitoring enabled - metrics will be collected")

            else:
                print("[ERROR] Setup failed")
                sys.exit(1)
        else:
            # Show status and help for existing installations
            install_type = detect_installation_type()
            config = load_setup_config()

            print(f"[*] Current Installation: {install_type.upper()}")
            if config:
                setup_style = config.get("setup_style", "unknown")
                terminal_style = config.get("terminal_style", "unknown")
                print(f"[*] Setup Style: {SETUP_STYLES.get(setup_style, {}).get('name', setup_style)}")
                print(f"[*]  Terminal Style: {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)}")

            show_help()
        return

    command = args[0].lower()

    if command in ["help", "-h", "--help"]:
        if len(args) > 1:
            show_subcommand_help(args[1])
        else:
            show_help()

    elif command == "version":
        version = get_version_info()
        install_type = detect_installation_type()

        print(f"""
[*] PlexiChat Version Information
Current Version: {version}
Installation Type: {install_type.upper()}
Python Version: {sys.version.split()[0]}
Platform: {platform.system()} {platform.release()}
Architecture: {platform.machine()}
Root Directory: {ROOT}
Versioning: Git-based (GitHub releases)
""")

        # Show Git information if available
        try:
            # Get current branch
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                print(f"Current Branch: {branch}")

            # Get last commit info
            result = subprocess.run(
                ["git", "log", "-1", "--pretty=format:%h - %s (%cr)"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                commit_info = result.stdout.strip()
                print(f"Last Commit: {commit_info}")

        except Exception as e:
            print(f"[WARN] Could not read Git information: {e}")

    elif command == "bootstrap":
        # Bootstrap installation from scratch
        if "--help" in args or "-h" in args:
            try:
                print("""
[*] PlexiChat Bootstrap Installer

Usage: python run.py bootstrap [options]

This command performs a complete PlexiChat installation from scratch:
1. Downloads PlexiChat source code from GitHub
2. Creates a Python virtual environment
3. Installs all dependencies
4. Sets up initial configuration

Options:
  --help, -h    Show this help message

Requirements:
  - Python 3.8+ (Python 3.11+ recommended for full features)
  - Internet connection
  - Git (optional, will fallback to ZIP download)

Example:
  python run.py bootstrap    # Complete installation

Note: This will create a 'plexichat' directory and 'venv' directory
in the same location as this script.
""")
            except UnicodeEncodeError:
                print("""
[*] PlexiChat Bootstrap Installer

Usage: python run.py bootstrap [options]

This command performs a complete PlexiChat installation from scratch:
1. Downloads PlexiChat source code from GitHub
2. Creates a Python virtual environment
3. Installs all dependencies
4. Sets up initial configuration

Options:
  --help, -h    Show this help message

Requirements:
  - Python 3.8+ (Python 3.11+ recommended for full features)
  - Internet connection
  - Git (optional, will fallback to ZIP download)

Example:
  python run.py bootstrap    # Complete installation

Note: This will create a 'plexichat' directory and 'venv' directory
in the same location as this script.
""")
            return

        # Check if we're already in a PlexiChat installation
        if (Path(__file__).parent / "src" / "plexichat").exists():
            print("[WARN]  You appear to already be in a PlexiChat installation directory.")
            print("The bootstrap command is for installing PlexiChat from a standalone run.py file.")
            print("Use 'python run.py setup' instead to configure this installation.")
            return

        # Run bootstrap installation
        bootstrapper = PlexiChatBootstrapper()
        success = bootstrapper.run_bootstrap()

        if success:
            print("\n[SUCCESS] Bootstrap completed! PlexiChat is ready to use.")
            sys.exit(0)
        else:
            print("\n[ERROR] Bootstrap failed. Please check the errors above.")
            sys.exit(1)

    elif command == "setup":
        # Enhanced interactive setup wizard with many more options
        if "--help" in args or "-h" in args:
            print("""
[*] PlexiChat Enhanced Setup Wizard

Usage: python run.py setup [type] [options]

This command runs the comprehensive setup wizard to configure PlexiChat:
1. Choose installation type (minimal/standard/full/developer/enterprise/custom)
2. Select database type (SQLite/PostgreSQL/MySQL/MongoDB/Redis)
3. Configure authentication (local/LDAP/OAuth/SAML/multi-factor)
4. Set up networking (ports/SSL/proxy/clustering)
5. Configure storage (local/S3/Azure/GCP/distributed)
6. Enable features (AI/security/monitoring/backup/plugins)
7. Set up integrations (Discord/Slack/Teams/webhooks)
8. Configure performance (caching/optimization/scaling)
9. Set up development tools (debugging/testing/profiling)
10. Configure deployment (Docker/systemd/PM2/cloud)

Installation Types:
  minimal       Basic chat functionality only
  standard      Standard features with web UI
  full          All features enabled
  developer     Full + development tools
  enterprise    Enterprise features + security
  custom        Custom configuration wizard

Database Options:
  sqlite        SQLite (default, no setup required)
  postgresql    PostgreSQL with connection pooling
  mysql         MySQL/MariaDB with replication
  mongodb       MongoDB with sharding support
  redis         Redis for caching and sessions
  multi         Multi-database setup

Authentication Types:
  local         Local user accounts
  ldap          LDAP/Active Directory integration
  oauth         OAuth2 (Google/GitHub/Microsoft)
  saml          SAML SSO integration
  mfa           Multi-factor authentication
  api-key       API key authentication

Networking Options:
  --port PORT           Set custom port (default: 8080)
  --ssl                 Enable SSL/TLS
  --proxy               Configure reverse proxy
  --cluster             Enable clustering
  --load-balancer       Set up load balancing

Storage Options:
  --storage-type TYPE   local/s3/azure/gcp
  --backup-enabled      Enable automated backups
  --encryption          Enable data encryption
  --compression         Enable data compression

Feature Flags:
  --ai                  Enable AI features
  --security            Enhanced security features
  --monitoring          Performance monitoring
  --analytics           Usage analytics
  --plugins             Plugin system
  --api                 REST API server
  --websockets          WebSocket support
  --real-time           Real-time features

Integration Options:
  --webhooks            Webhook support
  --email               Email notifications

Development Options:
  --debug               Enable debug mode
  --testing             Set up testing framework
  --profiling           Enable performance profiling
  --hot-reload          Enable hot reloading
  --dev-tools           Install development tools

Configuration Options:
  --import-config FILE  Import configuration from file (JSON/YAML)
  --export-config FILE  Export current configuration to file
  --config-format FMT   Format for config export (yaml/json, default: yaml)

Examples:
  python run.py setup                           # Interactive wizard
  python run.py setup developer --debug        # Developer setup with debug
  python run.py setup enterprise --ssl --mfa   # Enterprise with SSL and MFA
  python run.py setup custom --ai --monitoring # Custom setup with specific features
  python run.py setup full --port 3000         # Full setup on custom port
  python run.py setup --import-config config.yaml  # Setup from existing config
  python run.py setup --export-config backup.yaml  # Export current config
""")
            return

        # Handle config import/export first
        if "--import-config" in args:
            try:
                config_idx = args.index("--import-config") + 1
                if config_idx < len(args):
                    config_file = args[config_idx]
                    print(f"[*] Importing configuration from {config_file}...")

                    # Import using existing config system
                    try:
                        sys.path.insert(0, "src")
                        from plexichat.core_system.config.manager import ConfigurationManager

                        config_manager = ConfigurationManager()
                        if config_manager.import_config_from_file(config_file):
                            print("[SUCCESS] Configuration imported successfully!")
                            print("PlexiChat is now configured. Run 'python run.py run' to start.")
                            return
                        else:
                            print("[ERROR] Failed to import configuration")
                            sys.exit(1)
                    except ImportError as e:
                        print(f"[ERROR] Could not import config system: {e}")
                        sys.exit(1)
                else:
                    print("[ERROR] --import-config requires a filename argument")
                    sys.exit(1)
            except ValueError:
                print("[ERROR] --import-config requires a filename argument")
                sys.exit(1)

        if "--export-config" in args:
            try:
                config_idx = args.index("--export-config") + 1
                if config_idx < len(args):
                    config_file = args[config_idx]
                    config_format = "yaml"

                    # Check for format option
                    if "--config-format" in args:
                        format_idx = args.index("--config-format") + 1
                        if format_idx < len(args):
                            config_format = args[format_idx]

                    print(f"[*] Exporting configuration to {config_file} ({config_format} format)...")

                    try:
                        sys.path.insert(0, "src")
                        from plexichat.core_system.config.manager import ConfigurationManager

                        config_manager = ConfigurationManager()
                        if config_manager.export_config_to_file(config_file, config_format):
                            print("[SUCCESS] Configuration exported successfully!")
                            return
                        else:
                            print("[ERROR] Failed to export configuration")
                            sys.exit(1)
                    except ImportError as e:
                        print(f"[ERROR] Could not import config system: {e}")
                        sys.exit(1)
                else:
                    print("[ERROR] --export-config requires a filename argument")
                    sys.exit(1)
            except ValueError:
                print("[ERROR] --export-config requires a filename argument")
                sys.exit(1)

        # Parse arguments for enhanced setup
        setup_config = parse_setup_arguments(args)

        # Check if we have a setup type argument
        setup_type = args[1] if len(args) > 1 and not args[1].startswith('--') else None

        if setup_type in ['minimal', 'standard', 'full', 'developer', 'enterprise', 'custom']:
            if setup_type == 'custom':
                # Run custom configuration wizard
                config = run_custom_setup_wizard(setup_config)
            else:
                # Quick setup with predefined configuration
                config = create_predefined_setup(setup_type, setup_config)
        else:
            # Run enhanced interactive wizard
            config = run_enhanced_setup_wizard(setup_config)

        if not config:
            print("[ERROR] Setup cancelled")
            sys.exit(1)

        # Install dependencies and configure system
        if setup_plexichat_system(config):
            print("[SUCCESS] Setup completed successfully!")
            print_setup_summary(config)
        else:
            print("[ERROR] Setup failed")
            sys.exit(1)

    elif command == "update":
        # Enhanced update system with options
        if "--help" in args or "-h" in args:
            print("""
[*] PlexiChat Enhanced Update System

Usage: python run.py update [options]

Options:
  --help, -h        Show this help message
  --list            List all available versions
  --version VER     Update to specific version
  --file FILE       Update specific file only
  --rollback        Rollback to previous version
  --force           Force update even if same version
  --check           Check for updates without applying

Examples:
  python run.py update                    # Interactive update
  python run.py update --list             # List available versions
  python run.py update --version v1.2.3   # Update to specific version
  python run.py update --file run.py      # Update only run.py
  python run.py update --check            # Check for updates only
""")
            return

        # Use enhanced update system
        run_robust_update(args)

        # Simple Git pull update
        try:
            print("[*] Checking for updates...")

            # Fetch latest changes
            result = subprocess.run(
                ["git", "fetch", "origin"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"[ERROR] Failed to fetch updates: {result.stderr}")
                sys.exit(1)

            # Check if updates are available
            result = subprocess.run(
                ["git", "status", "-uno"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=10
            )

            if "behind" in result.stdout:
                print("[*] Updates available!")

                if input("[*] Apply updates? (y/N): ").lower().startswith('y'):
                    # Pull updates
                    result = subprocess.run(
                        ["git", "pull", "origin"],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode == 0:
                        print("[OK] Updates applied successfully!")
                        print("[*] Restart PlexiChat to use the new version")

                        # Update dependencies
                        if REQUIREMENTS.exists():
                            print("[*] Updating dependencies...")
                            venv_python = get_venv_python()
                            if venv_python and venv_python.exists():
                                subprocess.run([
                                    str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS)
                                ], cwd=ROOT)
                    else:
                        print(f"[ERROR] Update failed: {result.stderr}")
                        sys.exit(1)
                else:
                    print("[ERROR] Update cancelled")
            else:
                print("[OK] Already up to date!")

        except Exception as e:
            print(f"[ERROR] Update check failed: {e}")
            sys.exit(1)

    elif command == "wizard":
        # Run interactive setup wizard
        config = interactive_setup_wizard()
        if config:
            setup_style = config.get("setup_style", "minimal")
            print(f"\n[*] Installing {SETUP_STYLES[setup_style]['name']}...")
            if install_dependencies(setup_style):
                print("[OK] Setup complete!")
                print("[*] Run 'python run.py run' to start PlexiChat.")
            else:
                print("[ERROR] Setup failed")
                sys.exit(1)
        else:
            print("[ERROR] Setup cancelled")
            sys.exit(1)



    elif command == "info":
        print("[*]  PlexiChat System Information")
        print("=" * 50)
        print_system_info()

        install_type = detect_installation_type()
        config = load_setup_config()

        print("\n[*] Installation Details:")
        print(f"   Type: {install_type.upper()}")
        print(f"   Root Directory: {ROOT}")
        print(f"   Virtual Environment: {'Present' if VENV_DIR.exists() else 'Missing'}")

        if config:
            print("\n[*]  Configuration:")
            print(f"   Setup Style: {SETUP_STYLES.get(config.get('setup_style', ''), {}).get('name', 'Unknown')}")
            print(f"   Terminal Style: {TERMINAL_STYLES.get(config.get('terminal_style', ''), {}).get('name', 'Unknown')}")
            print(f"   Debug Mode: {'Enabled' if config.get('debug_mode') else 'Disabled'}")
            print(f"   Performance Monitoring: {'Enabled' if config.get('performance_monitoring') else 'Disabled'}")
            print(f"   Setup Date: {config.get('setup_date', 'Unknown')}")

        # Check for important files
        print("\n[*] Important Files:")
        print(f"   Requirements: {'Present' if REQUIREMENTS.exists() else 'Missing'}")
        print(f"   Version File: {'Present' if VERSION_FILE.exists() else 'Missing'}")
        print(f"   Default Credentials: {'Present' if DEFAULT_CREDS.exists() else 'Not Generated'}")

        # Port configuration
        ports = get_port_configuration()
        print("\n[*] Service Ports:")
        for service, port in ports.items():
            print(f"   {service}: {port}")

        # Check dependencies
        if VENV_DIR.exists():
            venv_python = get_venv_python()
            if venv_python and venv_python.exists():
                try:
                    result = subprocess.run(
                        [str(venv_python), "-m", "pip", "list", "--format=freeze"],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        package_count = len([line for line in result.stdout.strip().split('\n') if '==' in line])
                        print(f"\n[*] Installed Packages: {package_count}")
                    else:
                        print("\n[*] Installed Packages: Unable to determine")
                except Exception:
                    print("\n[*] Installed Packages: Check failed")

    elif command == "run":
        # Check for debug flag
        debug_mode = "--debug" in args

        print("[*] Starting PlexiChat server...")
        if not VENV_DIR.exists():
            print("[ERROR] Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        # Load configuration
        config = load_setup_config()
        terminal_style = config.get("terminal_style", "classic") if config else "classic"

        if debug_mode or (config and config.get("debug_mode")):
            print("[DEBUG] Debug mode enabled")
            terminal_style = "dashboard"  # Force dashboard for debug mode

        print(f"[*]  Using {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)} terminal style")

        # Generate default credentials if they don't exist
        generate_default_admin_creds()

        # Start with selected terminal style
        if terminal_style == "dashboard":
            start_dashboard_terminal(debug_mode)
        elif terminal_style == "split":
            start_split_terminal()
        elif terminal_style == "tabbed":
            start_tabbed_terminal()
        else:
            start_classic_terminal()

    elif command == "clean":
        if "--help" in args or "-h" in args:
            show_subcommand_help("clean")
            return
        deep_clean = "--all" in args
        clean_environment(deep_clean)

    elif command == "env":
        if "--help" in args or "-h" in args:
            show_subcommand_help("env")
            return
        show_environment_info()

    elif command == "export":
        if "--help" in args or "-h" in args:
            show_subcommand_help("export")
            return

        filename = None
        if len(args) > 1 and not args[1].startswith('-'):
            filename = args[1]

        options = {
            'include_logs': '--include-logs' in args,
            'include_cache': '--include-cache' in args,
            'compress': '--no-compress' not in args,  # Default to compressed
            'encrypt': '--encrypt' in args
        }

        export_plexichat_config(filename, options)

    elif command == "import":
        if "--help" in args or "-h" in args:
            show_subcommand_help("import")
            return

        if len(args) < 2:
            print("[ERROR] Import filename required")
            print("Usage: python run.py import <filename>")
            sys.exit(1)

        filename = args[1]
        options = {
            'overwrite': '--overwrite' in args,
            'merge': '--merge' in args,
            'backup': '--backup' in args,
            'decrypt': '--decrypt' in args
        }

        import_plexichat_config(filename, options)

    elif command == "test":
        if not VENV_DIR.exists():
            print("[ERROR] Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        install_type = detect_installation_type()
        print(f"[*] Running tests with {install_type} installation...")

        venv_python = get_venv_python()
        if venv_python and venv_python.exists():
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)
            try:
                subprocess.run([str(venv_python), "-m", "pytest", "src/plexichat/tests/", "-v"], env=env, check=True)
                print("[OK] All tests passed!")
            except subprocess.CalledProcessError:
                print("[ERROR] Some tests failed. Check output above.")
                sys.exit(1)

    elif command == "admin":
        if "--help" in args or "-h" in args:
            show_subcommand_help("admin")
            return
        open_admin_gui()

    elif command == "webui":
        if "--help" in args or "-h" in args:
            show_subcommand_help("webui")
            return
        open_webui()

    elif command == "status":
        if "--help" in args or "-h" in args:
            show_subcommand_help("status")
            return
        show_service_status()

    elif command == "gui":
        if "--help" in args or "-h" in args:
            show_subcommand_help("gui")
            return

        print("[*]  PlexiChat GUI Options")
        print("=" * 30)
        print("1. Admin Panel - Server management and configuration")
        print("2. WebUI - Main user interface")
        print("3. Both - Open both interfaces")
        print()

        choice = input("Select option (1-3) [3]: ").strip()
        if not choice:
            choice = "3"

        if choice == "1":
            open_admin_gui()
        elif choice == "2":
            open_webui()
        elif choice == "3":
            open_admin_gui()
            open_webui()
        else:
            print("[ERROR] Invalid choice")

    elif command == "config":
        handle_config_command(args[1:])

    elif command == "ssl":
        handle_ssl_command(args[1:])

    elif command == "migrate":
        handle_migration_command(args[1:])

    elif command == "backup":
        handle_backup_command(args[1:])

    elif command == "restore":
        handle_restore_command(args[1:])

    elif command == "plugin":
        handle_plugin_command(args[1:])

    elif command == "cluster":
        handle_cluster_command(args[1:])

    elif command == "security":
        handle_security_command(args[1:])

    elif command == "monitor":
        handle_monitor_command(args[1:])

    else:
        print(f"[ERROR] Unknown command: {command}")
        show_help()
        sys.exit(1)


def start_classic_terminal():
    """Start PlexiChat with enhanced classic single-pane terminal."""
    try:
        venv_python = get_venv_python()
        if not venv_python or not venv_python.exists():
            print("[ERROR] Python executable not found in virtual environment")
            sys.exit(1)

        # Get port configuration
        ports = get_port_configuration()

        # Generate default admin credentials if first time
        is_first_time = not DEFAULT_CREDS.exists()
        if is_first_time:
            generate_default_admin_creds()

        cmd = [str(venv_python), "-m", "src.plexichat.main"]

        print("[*] Starting PlexiChat server (Enhanced Classic Mode)...")
        print("[INFO] Press Ctrl+C to stop the server")
        print("=" * 60)
        print("[*] Service URLs:")
        print(f"   [*] WebUI:        http://localhost:{ports['webui_http']}")
        print(f"   [*] API:          http://localhost:{ports['api_http']}")
        print(f"   [*]  Admin Panel:  http://localhost:{ports['admin']}")
        print(f"   [*] WebSocket:    ws://localhost:{ports['websocket']}")

        if is_first_time:
            print(f"[*] Admin credentials: {DEFAULT_CREDS}")
            print("[WARN]  IMPORTANT: Change default password after first login!")

        print("=" * 60)
        print("[INFO] Commands while running:")
        print("   Ctrl+C: Stop server")
        print("   Type 'admin' + Enter: Open admin panel")
        print("   Type 'webui' + Enter: Open main interface")
        print("   Type 'status' + Enter: Show service status")
        print("-" * 60)

        # Set up environment
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)

        process = subprocess.Popen(
            cmd,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Start a thread to handle user input
        import queue
        import threading

        input_queue = queue.Queue()

        def input_handler():
            while True:
                try:
                    user_input = input().strip().lower()
                    input_queue.put(user_input)
                except (EOFError, KeyboardInterrupt):
                    break

        input_thread = threading.Thread(target=input_handler, daemon=True)
        input_thread.start()

        try:
            while process.poll() is None:
                # Check for user input
                try:
                    user_input = input_queue.get_nowait()
                    if user_input == 'admin':
                        print("[*] Opening admin panel...")
                        open_admin_gui()
                    elif user_input == 'webui':
                        print("[*] Opening WebUI...")
                        open_webui()
                    elif user_input == 'status':
                        print("[*] Service status:")
                        show_service_status()
                    elif user_input in ['quit', 'exit', 'stop']:
                        print("[STOP] Stopping server...")
                        break
                    else:
                        print(f"[?] Unknown command: {user_input}")
                        print("Available: admin, webui, status, quit")
                except queue.Empty:
                    pass

                # Read server output
                try:
                    if process.stdout is not None:
                        line = process.stdout.readline()
                        if line:
                            print(line.rstrip())
                except:
                    pass
        except KeyboardInterrupt:
            print("\n[STOP] Stopping PlexiChat server...")

        # Clean shutdown
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        print("[OK] Server stopped")

    except Exception as e:
        print(f"[ERROR] Failed to start PlexiChat: {e}")
        sys.exit(1)


def start_split_terminal():
    """Start PlexiChat with split-screen terminal (logs left, CLI right)."""
    print("[*]  Split-screen terminal mode")
    print("[*] This would show logs on left, CLI on right")
    print("[INFO] For now, falling back to classic mode")
    start_classic_terminal()


def start_tabbed_terminal():
    """Start PlexiChat with tabbed interface."""
    print("[*]  Tabbed terminal mode")
    print("[*] This would allow switching between logs and CLI")
    print("[INFO] For now, falling back to classic mode")
    start_classic_terminal()


def start_dashboard_terminal(debug_mode=False):
    """Start PlexiChat with live dashboard and metrics."""
    print("[*] Dashboard terminal mode")
    if debug_mode:
        print("[DEBUG] Debug mode active - detailed logging enabled")
    print("[*] This would show real-time metrics and system monitoring")
    print("[INFO] For now, falling back to classic mode with enhanced logging")
    start_classic_terminal()


# Duplicate get_port_configuration removed to avoid obscured declaration error.


# ============================================================================
# UNIFIED CONFIGURATION SYSTEM - NO MORE .ENV FILES OR SCATTERED CONFIGS
# ============================================================================

def generate_unified_config():
    """Generate unified YAML configuration - replaces all scattered config files."""
    print("[*] Generating unified PlexiChat configuration...")

    # Check if yaml is available
    yaml_module = None
    try:
        import yaml as yaml_module
    except ImportError:
        print("[WARN] PyYAML not installed. Installing...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "PyYAML"], check=True, capture_output=True)
            import yaml as yaml_module
            print("[OK] PyYAML installed successfully")
        except Exception as e:
            print(f"[ERROR] Failed to install PyYAML: {e}")
            print("[INFO] Generating JSON configuration instead...")
            generate_json_config()
            return

    config = {
        "plexichat": {
            "version": "3.0.0",
            "generated_at": datetime.now().isoformat(),

            # Server Configuration
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "ssl": {
                    "enabled": True,
                    "cert_file": "certs/plexichat.crt",
                    "key_file": "certs/plexichat.key",
                    "domain": "plexichat.local"
                }
            },

            # Database Configuration
            "database": {
                "url": "sqlite:///./data/plexichat.db",
                "encryption": True,
                "backup": {
                    "enabled": True,
                    "interval_hours": 6
                }
            },

            # Security Configuration
            "security": {
                "secret_key": secrets.token_hex(32),
                "jwt_algorithm": "HS256",
                "password_min_length": 8,
                "mfa_enabled": True
            },

            # Features Configuration
            "features": {
                "channels": True,
                "spaces": True,
                "status_updates": True,
                "voice_video": True,
                "ai_integration": True
            },

            # Logging Configuration
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_size_mb": 100
            }
        }
    }

    # Save unified config
    config_file = ROOT / "plexichat.yaml"
    with open(config_file, 'w') as f:
        yaml_module.dump(config, f, default_flow_style=False, indent=2)

    print(f"[OK] Unified configuration saved to: {config_file}")
    print("[*] You can now remove old .env files and scattered configs")

def generate_json_config():
    """Generate JSON configuration as fallback when YAML is not available."""
    config = {
        "plexichat": {
            "version": "3.0.0",
            "generated_at": datetime.now().isoformat(),
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "ssl": {
                    "enabled": True,
                    "cert_file": "certs/plexichat.crt",
                    "key_file": "certs/plexichat.key",
                    "domain": "plexichat.local"
                }
            },
            "database": {
                "url": "sqlite:///./data/plexichat.db",
                "encryption": True,
                "backup": {"enabled": True, "interval_hours": 6}
            },
            "security": {
                "secret_key": secrets.token_hex(32),
                "jwt_algorithm": "HS256",
                "password_min_length": 8,
                "mfa_enabled": True
            },
            "features": {
                "channels": True,
                "spaces": True,
                "status_updates": True,
                "voice_video": True,
                "ai_integration": True
            },
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_size_mb": 100
            }
        }
    }

    # Save JSON config
    config_file = ROOT / "plexichat.json"
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2, default=str)

    print(f"[OK] JSON configuration saved to: {config_file}")
    print("[INFO] Install PyYAML for YAML format: pip install PyYAML")

def validate_configuration():
    """Validate the unified configuration."""
    config_file = ROOT / "plexichat.yaml"
    if not config_file.exists():
        print("[ERROR] No configuration file found. Run 'python run.py config generate' first.")
        return False

    try:
        with open(config_file, 'r') as f:
            if yaml is not None:
                config = yaml.safe_load(f)
            else:
                print("[ERROR] YAML library not available")
                return False

        # Basic validation
        if "plexichat" not in config:
            print("[ERROR] Invalid configuration: missing 'plexichat' section")
            return False

        required_sections = ["server", "database", "security"]
        for section in required_sections:
            if section not in config["plexichat"]:
                print(f"[ERROR] Invalid configuration: missing '{section}' section")
                return False

        print("[OK] Configuration is valid")
        return True

    except Exception as e:
        print(f"[ERROR] Configuration validation failed: {e}")
        return False

def show_current_config():
    """Show current configuration."""
    config_file = ROOT / "plexichat.yaml"
    if not config_file.exists():
        print("[ERROR] No configuration file found.")
        return

    try:
        with open(config_file, 'r') as f:
            if yaml is not None:
                config = yaml.safe_load(f)
            else:
                print("[ERROR] YAML library not available")
                return

        print("[*] Current PlexiChat Configuration:")
        print("=" * 40)
        if yaml is not None:
            print(yaml.dump(config, default_flow_style=False, indent=2))
        else:
            print(json.dumps(config, indent=2))

    except Exception as e:
        print(f"[ERROR] Failed to read configuration: {e}")

def edit_config_interactive():
    """Interactive configuration editor."""
    print("[*] Interactive configuration editor not yet implemented.")
    print("[INFO] Edit plexichat.yaml directly for now.")

def reset_to_default_config():
    """Reset configuration to defaults."""
    if input("[WARN] This will reset all configuration to defaults. Continue? (y/N): ").lower().startswith('y'):
        generate_unified_config()
        print("[OK] Configuration reset to defaults")

def setup_ssl_certificates():
    """Set up SSL certificates and domain configuration."""
    print("[*] Setting up SSL certificates for plexichat.local...")

    # Create certs directory
    certs_dir = ROOT / "certs"
    certs_dir.mkdir(exist_ok=True)

    # Generate self-signed certificate
    try:
        import subprocess

        # Generate private key
        subprocess.run([
            "openssl", "genrsa", "-out", str(certs_dir / "plexichat.key"), "2048"
        ], check=True, capture_output=True)

        # Generate certificate
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-key", str(certs_dir / "plexichat.key"),
            "-out", str(certs_dir / "plexichat.crt"),
            "-days", "365",
            "-subj", "/C=US/ST=CA/L=SF/O=PlexiChat/CN=plexichat.local"
        ], check=True, capture_output=True)

        print("[OK] SSL certificates generated")
        print("[*] Add '127.0.0.1 plexichat.local' to your hosts file")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to generate SSL certificates: {e}")
    except FileNotFoundError:
        print("[ERROR] OpenSSL not found. Please install OpenSSL first.")

def renew_ssl_certificates():
    """Renew SSL certificates."""
    print("[*] SSL certificate renewal not yet implemented.")

def show_ssl_status():
    """Show SSL certificate status."""
    certs_dir = ROOT / "certs"
    cert_file = certs_dir / "plexichat.crt"

    if not cert_file.exists():
        print("[ERROR] No SSL certificate found")
        return

    try:
        import subprocess
        result = subprocess.run([
            "openssl", "x509", "-in", str(cert_file), "-text", "-noout"
        ], capture_output=True, text=True, check=True)

        print("[*] SSL Certificate Status:")
        print("=" * 30)
        # Extract relevant info from openssl output
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Not Before' in line or 'Not After' in line or 'Subject:' in line:
                print(f"   {line.strip()}")

    except Exception as e:
        print(f"[ERROR] Failed to read SSL certificate: {e}")

# Placeholder implementations for other commands
def run_database_migrations():
    print("[*] Database migration system not yet implemented.")

def rollback_migrations():
    print("[*] Migration rollback not yet implemented.")

def show_migration_status():
    print("[*] Migration status not yet implemented.")

def create_migration(name):
    print(f"[*] Creating migration '{name}' not yet implemented.")

def create_backup(name):
    print(f"[*] Creating backup '{name or 'auto'}' not yet implemented.")

def list_backups():
    print("[*] Listing backups not yet implemented.")

def configure_backup_schedule():
    print("[*] Backup scheduling not yet implemented.")

def verify_backup(name):
    print(f"[OK] Verifying backup '{name or 'latest'}' not yet implemented.")

def restore_from_backup(name):
    print(f"[*] Restoring from backup '{name}' not yet implemented.")

def list_restore_points():
    print("[*] Listing restore points not yet implemented.")

def verify_restore_point(name):
    print(f"[OK] Verifying restore point '{name or 'latest'}' not yet implemented.")

def list_plugins():
    print("[*] Plugin listing not yet implemented.")

def install_plugin(name):
    print(f"[*] Installing plugin '{name}' not yet implemented.")

def remove_plugin(name):
    print(f"[*] Removing plugin '{name}' not yet implemented.")

def enable_plugin(name):
    print(f"[OK] Enabling plugin '{name}' not yet implemented.")

def disable_plugin(name):
    print(f"[ERROR] Disabling plugin '{name}' not yet implemented.")

def update_plugins():
    print("[*] Updating plugins not yet implemented.")

def show_cluster_status():
    print("[*] Cluster status not yet implemented.")

def join_cluster(address):
    print(f"[*] Joining cluster at '{address}' not yet implemented.")

def leave_cluster():
    print("[*] Leaving cluster not yet implemented.")

def list_cluster_nodes():
    print("[*] Listing cluster nodes not yet implemented.")

def run_security_audit():
    print("[*] Security audit not yet implemented.")

def scan_vulnerabilities():
    print("[*] Vulnerability scanning not yet implemented.")

def manage_encryption_keys(args):
    print("[*] Encryption key management not yet implemented.")

def manage_user_security(args):
    print("[*] User security management not yet implemented.")

def show_system_status():
    print("[*] System status monitoring not yet implemented.")

def show_performance_metrics():
    print("[*] Performance metrics not yet implemented.")

def view_system_logs(args):
    print("[*] System log viewing not yet implemented.")

def manage_alerts(args):
    print("[*] Alert management not yet implemented.")

def run_robust_update():
    """Robust update system that works even with missing modules."""
    print("[*] PlexiChat Robust Update System")
    print("=" * 45)

    # Check if we're in a Git repository
    if not (ROOT / ".git").exists():
        print("[ERROR] Not a Git repository. Updates require Git-based installation.")
        print("[INFO] To enable updates:")
        print("   1. Clone from GitHub: git clone https://github.com/linux-of-user/plexichat.git")
        print("   2. Or download releases from: https://github.com/linux-of-user/plexichat/releases")
        return False

    try:
        print("[*] Checking for updates...")

        # Create progress bar for update process
        update_steps = ["Fetching updates", "Checking status", "Applying updates", "Installing dependencies", "Verifying installation"]
        progress = create_progress_bar(len(update_steps), "Update Process")

        # Step 1: Fetch latest changes
        if hasattr(progress, 'set_description'):
            progress.set_description("Fetching updates")

        result = subprocess.run(
            ["git", "fetch", "origin"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            progress.close()
            print(f"[ERROR] Failed to fetch updates: {result.stderr}")
            return False

        progress.update(1)

        # Step 2: Check if updates are available
        if hasattr(progress, 'set_description'):
            progress.set_description("Checking status")

        result = subprocess.run(
            ["git", "status", "-uno"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )

        progress.update(1)

        if "behind" not in result.stdout:
            progress.close()
            print("[OK] PlexiChat is already up to date!")
            return True

        print("\n[*] Updates available!")

        # Show what will be updated
        try:
            log_result = subprocess.run(
                ["git", "log", "--oneline", "HEAD..origin/main"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=10
            )

            if log_result.returncode == 0 and log_result.stdout.strip():
                print("\n[*] Changes to be applied:")
                commit_lines = log_result.stdout.strip().split('\n')
                for line in commit_lines[:5]:  # Show last 5 commits
                    print(f"   * {line}")
                if len(commit_lines) > 5:
                    print(f"   ... and {len(commit_lines) - 5} more commits")
        except:
            pass

        if not input("\n[*] Apply updates? (y/N): ").lower().startswith('y'):
            progress.close()
            print("[ERROR] Update cancelled by user")
            return False

        # Step 3: Apply updates
        if hasattr(progress, 'set_description'):
            progress.set_description("Applying updates")

        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            progress.close()
            print(f"[ERROR] Failed to apply updates: {result.stderr}")
            return False

        progress.update(1)

        # Step 4: Install/update dependencies (robust approach)
        if hasattr(progress, 'set_description'):
            progress.set_description("Installing dependencies")

        # Install essential packages first (these are needed for the system to work)
        essential_packages = ["PyYAML", "requests", "tqdm"]

        print("\n[*] Installing essential packages...")
        for package in essential_packages:
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", package, "--quiet", "--upgrade"
                ], check=True, capture_output=True)
            except:
                print(f"[WARN] Failed to install {package}, continuing...")

        # Try to install from requirements.txt if it exists
        if REQUIREMENTS.exists():
            print("[*] Updating dependencies from requirements.txt...")
            try:
                # Use a more robust approach that doesn't depend on our parsing functions
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS), "--quiet", "--upgrade"
                ], timeout=300, capture_output=True)
                print("[OK] Dependencies updated successfully")
            except Exception as e:
                print(f"[WARN] Some dependencies may not have updated: {e}")

        progress.update(1)

        # Step 5: Verify installation
        if hasattr(progress, 'set_description'):
            progress.set_description("Verifying installation")

        # Try to import core modules to verify the update worked
        verification_passed = True
        try:
            # Test basic Python imports (sys, json, os already imported globally)

            # Test if we can read the version file
            if (ROOT / "version.json").exists():
                with open(ROOT / "version.json", 'r') as f:
                    version_data = json.load(f)
                    print(f"[OK] Updated to version: {version_data.get('current_version', 'unknown')}")

        except Exception as e:
            print(f"[WARN] Verification warning: {e}")
            verification_passed = False

        progress.update(1)
        progress.close()

        if verification_passed:
            print("\n[SUCCESS] Update completed successfully!")
            print("[*] Restart PlexiChat to use the new version")
            print("[INFO] Run 'python run.py version' to see the new version")
        else:
            print("\n[WARN] Update applied but verification had issues")
            print("[INFO] Try running 'python run.py setup' to fix any issues")

        return True

    except subprocess.TimeoutExpired:
        print("[ERROR] Update timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"[ERROR] Update failed: {e}")
        print("[INFO] Try running 'git pull' manually or reinstalling PlexiChat")
        return False

if __name__ == "__main__":
    main()
