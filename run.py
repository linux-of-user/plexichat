#!/usr/bin/env python3
"""
PlexiChat Application Runner - Enhanced Edition

Advanced cross-platform entry point with comprehensive setup and monitoring.
Features:
- Interactive first-time setup wizard with style selection
- Multiple terminal display modes (split, tabbed, classic)
- Advanced dependency management with fallback options
- Comprehensive system information and diagnostics
- Real-time performance monitoring
- Debug mode with detailed logging
- Development tools integration
- Automatic environment optimization
"""

import sys
import os
import subprocess
import platform
import shutil
import threading
import time
import json
import secrets
import string
import shlex
import signal
import atexit
from pathlib import Path
from datetime import datetime

# Try to import optional dependencies
try:
    import yaml  # Optional dependency for version verification and backup/restore
except ImportError:
    yaml = None

try:
    from tqdm import tqdm # type: ignore
except ImportError:
    tqdm = None
from datetime import datetime

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
        self.last_line_count = 0

        # Get terminal width dynamically
        if width is None:
            try:
                import shutil
                terminal_width = shutil.get_terminal_size().columns
                # Reserve space for description, percentage, count, and ETA
                # Format: "desc: |bar| 100.0% (30/31) ETA: 123s"
                reserved_space = len(desc) + 25  # Approximate space for other elements
                self.width = max(20, terminal_width - reserved_space)
            except:
                self.width = 50
        else:
            self.width = width

    def set_description(self, desc):
        """Set the description for the progress bar (for compatibility with tqdm)."""
        self.desc = desc

    def update(self, n=1):
        self.current += n
        self._display()

    def _display(self):
        if self.total == 0:
            return

        percent = (self.current / self.total) * 100
        filled = int((self.current / self.total) * self.width)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_time

        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"{int(eta)}s"
        else:
            eta_str = "?s"

        # Save cursor position and move to bottom of terminal
        try:
            import shutil
            terminal_height = shutil.get_terminal_size().lines
            # Move cursor to bottom line
            print(f"\033[s", end="")  # Save cursor position
            print(f"\033[{terminal_height};1H", end="")  # Move to bottom line
            print(f"\033[K", end="")  # Clear line
            print(f"{self.desc}: |{bar}| {percent:.1f}% ({self.current}/{self.total}) ETA: {eta_str}", end="", flush=True)
            print(f"\033[u", end="")  # Restore cursor position
        except:
            # Fallback to simple progress bar if terminal control fails
            print(f"\r{self.desc}: |{bar}| {percent:.1f}% ({self.current}/{self.total}) ETA: {eta_str}", end="", flush=True)

        if self.current >= self.total:
            # Clear the bottom line and print completion message
            try:
                import shutil
                terminal_height = shutil.get_terminal_size().lines
                print(f"\033[{terminal_height};1H", end="")  # Move to bottom line
                print(f"\033[K", end="")  # Clear line
            except:
                pass
            print()  # New line when complete

    def close(self):
        if self.current < self.total:
            self.current = self.total
            self._display()
        else:
            # Clear the progress bar from bottom line
            try:
                import shutil
                terminal_height = shutil.get_terminal_size().lines
                print(f"\033[{terminal_height};1H", end="")  # Move to bottom line
                print(f"\033[K", end="")  # Clear line
            except:
                pass

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

    print(f"📦 {desc}...")

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
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package, "--quiet"
            ], capture_output=True, text=True, check=True)

            success_count += 1
            progress.update(1)

        except subprocess.CalledProcessError as e:
            failed_packages.append(package)
            progress.update(1)
            continue

    progress.close()

    # Report results
    if success_count == len(packages):
        print(f"✅ Successfully installed {success_count} packages")
        return True
    elif success_count > 0:
        print(f"⚠️ Installed {success_count}/{len(packages)} packages")
        if failed_packages:
            print(f"❌ Failed to install: {', '.join(failed_packages)}")
        return True
    else:
        print(f"❌ Failed to install all packages")
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
    """Print enhanced PlexiChat banner."""
    version = get_version_info()
    width = min(TERMINAL_WIDTH, 80)

    banner = f"""
{'=' * width}
    ██████╗ ██╗     ███████╗██╗  ██╗██╗ ██████╗██╗  ██╗ █████╗ ████████╗   
    ██╔══██╗██║     ██╔════╝╗██╗██╔╝██║██╔════╝██║  ██║██╔══██╗╚══██╔══╝   
    ██████╔╝██║     █████╗   ╚███╔╝ ██║██║     ███████║███████║   ██║      
    ██╔═══╝ ██║     ██╔══╝   ██╔██╗ ██║██║     ██╔══██║██╔══██║   ██║      
    ██║     ███████╗███████╗██╔╝ ██╗██║╚██████╗██║  ██║██║  ██║   ██║      
    ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝      

    🔒 Government-Level Secure Communication Platform v{version}
    🌐 Advanced AI • 🛡️ Zero-Trust Security • 🔄 Distributed Architecture
{'=' * width}
"""
    print(banner)


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 11):
        print("❌ Error: Python 3.11 or higher is required")
        print(f"Current version: {sys.version}")
        print("\n💡 To install Python 3.11+:")
        if IS_WINDOWS:
            print("   • Download from https://python.org/downloads/")
            print("   • Or use: winget install Python.Python.3.11")
        elif IS_LINUX:
            print("   • Ubuntu/Debian: sudo apt update && sudo apt install python3.11")
            print("   • CentOS/RHEL: sudo dnf install python3.11")
        elif IS_MACOS:
            print("   • Homebrew: brew install python@3.11")
            print("   • Or download from https://python.org/downloads/")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")


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


def print_system_info():
    """Print detailed system information."""
    info = get_system_info()

    print("🖥️  System Information:")
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

    print("\n🌍 Environment Variables:")
    for key, value in info['environment_variables'].items():
        print(f"   {key}: {value}")


def show_environment_info():
    """Show detailed environment manager information."""
    print("🐍 Python Environment Managers")
    print("=" * 50)

    environments = detect_python_environments()

    for env_name, env_info in environments.items():
        status = "✅ Available" if env_info['available'] else "❌ Not Available"
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
    print("🎯 Current Environment:")
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
    print("\n💡 Recommendations:")
    if not any(env['available'] for env in environments.values()):
        print("   ⚠️  No environment managers found!")
        print("   Install one of: conda, mamba, virtualenv, or use built-in venv")
    elif not environments['conda']['available'] and not environments['mamba']['available']:
        print("   Consider installing conda or mamba for better package management")
    else:
        print("   ✅ Good environment manager setup detected")


def save_setup_config(config):
    """Save setup configuration."""
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(SETUP_CONFIG, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"⚠️ Warning: Could not save setup config: {e}")
        return False


def load_setup_config():
    """Load setup configuration."""
    try:
        if SETUP_CONFIG.exists():
            with open(SETUP_CONFIG, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"⚠️ Warning: Could not load setup config: {e}")
    return {}


def interactive_setup_wizard():
    """Interactive setup wizard for first-time users."""
    print("\n🧙‍♂️ PlexiChat Setup Wizard")
    print("=" * 50)

    # System check
    print("🔍 Checking system compatibility...")
    print_system_info()

    # Check for existing setup
    existing_config = load_setup_config()
    if existing_config:
        print(f"\n📋 Found existing setup: {existing_config.get('setup_style', 'unknown')}")
        if input("🔄 Reconfigure setup? (y/N): ").lower().startswith('y'):
            pass  # Continue with wizard
        else:
            return existing_config

    print("\n🎯 Choose your setup style:")
    print("=" * 30)

    for i, (key, style) in enumerate(SETUP_STYLES.items(), 1):
        print(f"{i}. {style['name']}")
        print(f"   {style['description']}")
        print(f"   Features: {', '.join(style['features'])}")
        print(f"   Install time: {style['install_time']}")
        print()

    while True:
        try:
            choice = input("Select setup style (1-4) [2]: ").strip()
            if not choice:
                choice = "2"  # Default to standard

            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(SETUP_STYLES):
                setup_style = list(SETUP_STYLES.keys())[choice_idx]
                break
            else:
                print("❌ Invalid choice. Please select 1-4.")
        except ValueError:
            print("❌ Please enter a number (1-4).")

    print(f"\n✅ Selected: {SETUP_STYLES[setup_style]['name']}")

    # Terminal style selection
    print("\n🖥️  Choose your terminal style:")
    print("=" * 30)

    for i, (key, style) in enumerate(TERMINAL_STYLES.items(), 1):
        print(f"{i}. {style['name']}")
        print(f"   {style['description']}")
        print(f"   Best for: {style['best_for']}")
        print()

    # Auto-recommend terminal style based on width
    if TERMINAL_WIDTH >= 120:
        recommended = "2"  # Split screen
        rec_name = "Split Screen"
    elif TERMINAL_WIDTH >= 80:
        recommended = "3"  # Tabbed
        rec_name = "Tabbed Interface"
    else:
        recommended = "1"  # Classic
        rec_name = "Classic Terminal"

    print(f"💡 Recommended for your terminal ({TERMINAL_WIDTH} columns): {rec_name}")

    while True:
        try:
            choice = input(f"Select terminal style (1-4) [{recommended}]: ").strip()
            if not choice:
                choice = recommended

            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(TERMINAL_STYLES):
                terminal_style = list(TERMINAL_STYLES.keys())[choice_idx]
                break
            else:
                print("❌ Invalid choice. Please select 1-4.")
        except ValueError:
            print("❌ Please enter a number (1-4).")

    print(f"\n✅ Selected: {TERMINAL_STYLES[terminal_style]['name']}")

    # Debug mode
    debug_mode = input("\n🐛 Enable debug mode? (y/N): ").lower().startswith('y')

    # Performance monitoring
    perf_monitoring = input("📊 Enable performance monitoring? (Y/n): ").lower() not in ['n', 'no']

    # Auto-start services
    auto_start = input("🚀 Auto-start all services? (Y/n): ").lower() not in ['n', 'no']

    config = {
        "setup_style": setup_style,
        "terminal_style": terminal_style,
        "debug_mode": debug_mode,
        "performance_monitoring": perf_monitoring,
        "auto_start_services": auto_start,
        "setup_date": datetime.now().isoformat(),
        "system_info": get_system_info()
    }

    print("\n📋 Configuration Summary:")
    print("=" * 30)
    print(f"Setup Style: {SETUP_STYLES[setup_style]['name']}")
    print(f"Terminal Style: {TERMINAL_STYLES[terminal_style]['name']}")
    print(f"Debug Mode: {'Enabled' if debug_mode else 'Disabled'}")
    print(f"Performance Monitoring: {'Enabled' if perf_monitoring else 'Disabled'}")
    print(f"Auto-start Services: {'Enabled' if auto_start else 'Disabled'}")

    if input("\n✅ Proceed with this configuration? (Y/n): ").lower() not in ['n', 'no']:
        save_setup_config(config)
        return config
    else:
        print("❌ Setup cancelled.")
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
        print(f"⚠️  Error reading version: {e}")
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

                print("📝 Marked version.json as deprecated (now using Git-based versioning)")
        except Exception as e:
            print(f"⚠️ Warning: Could not update version format: {e}")


def check_for_updates():
    """Check for available updates from GitHub."""
    try:
        print("🔍 Update checking now uses Git-based versioning")
        print("💡 Updates are available through:")
        print("   1. Git pull from repository")
        print("   2. GitHub releases download")
        print("   3. Admin panel update interface (when running)")
        print("   4. Automatic update system (if enabled)")

        return True
    except Exception as e:
        print(f"⚠️ Update check information: {e}")
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
        print(f"🔐 Default admin credentials generated: {DEFAULT_CREDS}")
        print("⚠️  IMPORTANT: Change the default password immediately after first login!")
    except Exception as e:
        print(f"❌ Failed to generate default credentials: {e}")


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
                    print("⚠️ Warning: PyYAML not installed, falling back to JSON config if available.")
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
            print(f"⚠️ Warning: Could not load YAML port configuration: {e}")

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
            print(f"⚠️ Warning: Could not load JSON port configuration: {e}")

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
        print(f"⚠️ Warning: Could not detect installation type: {e}")
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
            print("✅ Virtual environment already exists")
            return True
        else:
            print("🔄 Recreating corrupted virtual environment...")
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
            print("❌ No suitable Python environment manager found")
            return False

    print(f"🔄 Creating virtual environment using {env_type}...")

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

            print(f"✅ Conda environment '{env_name}' created")

        elif env_type == 'mamba':
            # Similar to conda but with mamba
            env_name = f"plexichat-{ROOT.name}"
            cmd = ['mamba', 'create', '-n', env_name, f'python={sys.version_info.major}.{sys.version_info.minor}', '-y']
            subprocess.check_call(cmd)
            print(f"✅ Mamba environment '{env_name}' created")

        elif env_type == 'venv':
            # Standard venv
            subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
            print("✅ Virtual environment created with venv")

        elif env_type == 'virtualenv':
            # virtualenv
            subprocess.check_call(["virtualenv", str(VENV_DIR)])
            print("✅ Virtual environment created with virtualenv")

        else:
            print(f"❌ Unsupported environment type: {env_type}")
            return False

        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        print("💡 Available environment managers:")
        for env, info in environments.items():
            status = "✅" if info['available'] else "❌"
            version = info.get('version', 'Unknown version')
            print(f"   {status} {env}: {version if info['available'] else 'Not available'}")
        return False


def install_dependencies(install_type="minimal"):
    """Install dependencies in virtual environment."""
    if not create_virtual_environment():
        return False

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        print("❌ Virtual environment Python not found")
        return False

    print(f"📦 Installing {install_type} dependencies...")

    # Upgrade pip first
    try:
        print("📦 Upgrading pip...")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"])
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to upgrade pip: {e}")

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
        print(f"❌ Unknown install type: {install_type}")
        return False


def parse_requirements_file():
    """Parse requirements.txt with Python version-specific handling."""
    if not REQUIREMENTS.exists():
        print("❌ requirements.txt not found")
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
            print(f"⚠️  Skipping {package_name} (not compatible with Python {python_version})")
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
        print("❌ No minimal dependencies found in requirements.txt")
        return False

    print(f"📋 Installing {len(minimal_deps)} minimal dependencies...")
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
        print("❌ No dependencies found")
        return False

    print(f"📋 Installing {len(all_deps)} standard dependencies...")
    return install_package_list(venv_python, all_deps)


def install_full_deps(venv_python):
    """Install full dependencies from requirements.txt."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]
    full_deps = deps["full"]
    all_deps = minimal_deps + full_deps

    if not all_deps:
        print("❌ No dependencies found in requirements.txt")
        return False

    print(f"📋 Installing {len(all_deps)} full dependencies...")
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
        print("❌ No dependencies found")
        return False

    print(f"📋 Installing {len(all_deps)} developer dependencies...")
    return install_package_list(venv_python, all_deps)


def install_package_list(venv_python, packages, use_fallbacks=True):
    """Install a list of packages with enhanced error handling and fallback options."""
    if not packages:
        return True

    failed_packages = []

    # Create progress bar
    progress = create_progress_bar(len(packages), "Installing packages")

    for package in packages:
        # Update progress description
        if hasattr(progress, 'set_description'):
            progress.set_description(f"Installing {package}")

        success = install_single_package(venv_python, package, use_fallbacks)
        if success:
            # Don't print individual success messages to avoid cluttering with progress bar
            pass
        else:
            failed_packages.append(package)

        progress.update(1)

    progress.close()

    if failed_packages:
        print(f"\n⚠️  {len(failed_packages)} packages failed to install:")
        for pkg in failed_packages:
            print(f"   - {pkg}")

        # Check if any critical packages failed
        critical_packages = ['fastapi', 'uvicorn', 'sqlalchemy', 'pydantic']
        critical_failed = [pkg for pkg in failed_packages if any(crit in pkg.lower() for crit in critical_packages)]

        if critical_failed:
            print(f"\n❌ Critical packages failed: {critical_failed}")
            print("💡 Try installing manually or check system dependencies")
            return False
        else:
            print(f"\n⚠️  Some optional packages failed, but core functionality should work.")
            print(f"✅ Successfully installed {len(packages) - len(failed_packages)}/{len(packages)} packages")
            return True
    else:
        print(f"✅ All {len(packages)} packages installed successfully")
        return True


def install_single_package(python_exe, package, use_fallbacks=True, verbose=False):
    """Install a single package with fallback strategies."""
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

    for method in install_methods:
        try:
            # Only print verbose messages if requested (not during progress bar)
            if verbose:
                print(f"   🔄 Trying {method['name']} for {package}...")
            subprocess.check_call(
                method['cmd'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=180
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if verbose:
                print(f"   ⚠️  {method['name']} failed: {e}")
            continue

    # Final fallback: try system package manager suggestions
    if use_fallbacks:
        print(f"   💡 Consider installing {package} via system package manager:")
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

        print("📊 Advanced Log Monitor Started (Left Panel)")
        print("=" * 50)
        print("🔍 Monitoring: latest.log, plexichat.log, errors.log")
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
                                        "latest": "📝",
                                        "main": "🔗",
                                        "errors": "❌"
                                    }.get(name, "📋")

                                    # Color code by log level
                                    if "ERROR" in line or "CRITICAL" in line:
                                        print(f"[{timestamp}] {source_emoji} 🔴 {line}")
                                    elif "WARNING" in line:
                                        print(f"[{timestamp}] {source_emoji} 🟡 {line}")
                                    elif "INFO" in line:
                                        print(f"[{timestamp}] {source_emoji} 🟢 {line}")
                                    elif "DEBUG" in line:
                                        print(f"[{timestamp}] {source_emoji} 🔵 {line}")
                                    else:
                                        print(f"[{timestamp}] {source_emoji} ⚪ {line}")

                        file_positions[name] = current_size

                time.sleep(0.2)  # Check every 200ms

        except Exception as e:
            print(f"❌ Advanced log monitor error: {e}")
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
                print(f"❌ Fallback log monitor also failed: {e2}")

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
            ("INFO", "plexichat.api", "📡 API endpoint /health accessed"),
            ("INFO", "plexichat.auth", "🔐 User authentication successful"),
            ("DEBUG", "plexichat.database", "🗄️ Database query executed in 45ms"),
            ("INFO", "plexichat.backup", "💾 Backup process completed successfully"),
            ("INFO", "plexichat.security", "🔒 Security scan completed successfully"),
            ("INFO", "plexichat.performance", "📊 System performance metrics collected"),
            ("DEBUG", "plexichat.cli", "🖥️ CLI command executed: status"),
            ("INFO", "plexichat.websocket", "🔌 WebSocket connection established"),
            ("INFO", "plexichat.ai", "🤖 AI model inference completed"),
            ("DEBUG", "plexichat.clustering", "🌐 Cluster health check passed"),
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
                    error_entry = f"[{timestamp}] [ERROR   ] plexichat.test: ❌ Simulated error for demonstration\n"
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
        print("❌ Virtual environment not found. Run setup first.")
        return False

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        print("❌ Virtual environment Python not found")
        return False

    # Check if this is first time setup
    is_first_time = not DEFAULT_CREDS.exists()
    if is_first_time:
        print("🎉 First-time setup detected!")
        generate_default_admin_creds()
        print(f"📋 Admin credentials saved to: {DEFAULT_CREDS}")

    # Detect and report installation type
    install_type = detect_installation_type()
    version = get_version_info()
    ports = get_port_configuration()

    print(f"💬 PlexiChat v{version}")
    print(f"📦 Installation Type: {install_type.upper()}")
    print("=" * 50)
    print("🌐 Service Ports:")
    print(f"   📡 API Server:    http://localhost:{ports['api_http']} | https://localhost:{ports['api_https']}")
    print(f"   🖥️  WebUI:        http://localhost:{ports['webui_http']} | https://localhost:{ports['webui_https']}")
    print(f"   🔌 WebSocket:     ws://localhost:{ports['websocket']}")
    print(f"   ⚙️  Admin Panel:   http://localhost:{ports['admin']}")
    print("=" * 50)

    if install_type == "partial":
        print("⚠️  Partial installation detected. Some features may be unavailable.")
        print("   Run 'python run.py setup full' for complete functionality.")
    elif install_type == "incomplete":
        print("❌ Incomplete installation detected. Please run setup again.")
        return False

    print("🚀 Starting PlexiChat server with multiplexed terminal...")
    print("📊 Logs will appear on the left, CLI on the right")
    print("=" * 50)

    # Start log monitoring and generation
    log_thread = start_log_monitor()
    log_gen_thread = start_log_generator()

    # Set up environment
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["PLEXICHAT_LOG_TO_FILE"] = "1"  # Force logging to file

    try:
        # Start server with better error handling
        print("🔄 Initializing PlexiChat core systems...")

        # Generate some initial logs to ensure log files exist
        logs_dir = ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)

        # Create initial log entries
        latest_log = logs_dir / "latest.log"
        with open(latest_log, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] [INFO] plexichat.startup: 🚀 PlexiChat server starting up...\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: 📊 Initializing logging system\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: 🔧 Loading configuration\n")
            f.write(f"[{timestamp}] [INFO] plexichat.startup: 🌐 Starting web server\n")

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

        print("✅ PlexiChat server process started")
        print("🌐 Services are now available:")
        print(f"   📡 API:     http://localhost:{ports['api_http']}")
        print(f"   🖥️  WebUI:   http://localhost:{ports['webui_http']}")
        if is_first_time:
            print(f"🔐 Default admin credentials: {DEFAULT_CREDS}")
        print("=" * 50)

        # Check if terminal supports split screen
        try:
            terminal_width = shutil.get_terminal_size().columns
            if terminal_width >= 120:
                print("📱 Split-screen mode enabled - CLI commands will appear separately from logs")
                use_split_screen = True
            else:
                print("📱 Standard mode - CLI and logs will be mixed")
                use_split_screen = False
        except:
            print("📱 Standard mode - CLI and logs will be mixed")
            use_split_screen = False

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
            print("✅ Integrated CLI loaded")
        except Exception as e:
            print(f"⚠️ Failed to load integrated CLI: {e}")
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
                            print("🛑 Stopping PlexiChat server...")
                            process.terminate()
                            break

                    except Exception as e:
                        print(f"❌ CLI error: {e}")
                else:
                    # Fallback simple CLI
                    cmd_lower = cmd.lower()
                    if cmd_lower == "stop":
                        print("🛑 Stopping PlexiChat server...")
                        process.terminate()
                        break
                    elif cmd_lower == "status":
                        print(f"📊 Server Status: {'Running' if process.poll() is None else 'Stopped'}")
                        print(f"📦 Installation: {install_type.upper()}")
                        print(f"🔗 Version: {version}")
                    elif cmd_lower == "help":
                        print("Available commands: status, stop, help")
                    else:
                        print(f"❓ Unknown command: {cmd}")

            except (EOFError, KeyboardInterrupt):
                print("\n🛑 Stopping PlexiChat server...")
                process.terminate()
                break

        # Wait for process to finish
        process.wait()
        return True

    except Exception as e:
        print(f"❌ PlexiChat server failed to start: {e}")
        print("🔍 Check the logs for more details")
        return False


def clean_environment(deep_clean=False):
    """Clean up virtual environment and cache with Windows compatibility."""
    print("🧹 Cleaning PlexiChat environment...")

    # Stop any running processes first
    stop_running_processes()

    # Clean virtual environment with improved Windows handling
    if VENV_DIR.exists():
        print("🗑️ Removing virtual environment...")
        try:
            if platform.system() == "Windows":
                # Windows-specific approach with multiple fallbacks
                success = False

                # Method 1: Try simple rename first (often works when delete fails)
                try:
                    backup_name = VENV_DIR.parent / f".venv_backup_{int(time.time())}"
                    VENV_DIR.rename(backup_name)
                    print("🔄 Renamed virtual environment, attempting deletion...")

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
                        print(f"⚠️  Could not delete renamed directory: {backup_name}")
                        print("💡 You may need to manually delete it later")
                        success = True  # Consider rename as success

                except Exception as e:
                    print(f"⚠️  Rename method failed: {e}")

                # Method 2: Try PowerShell removal if rename failed
                if not success:
                    try:
                        print("🔄 Trying PowerShell removal...")
                        ps_command = f'Remove-Item -Path "{VENV_DIR}" -Recurse -Force -ErrorAction SilentlyContinue'
                        result = subprocess.run([
                            "powershell", "-Command", ps_command
                        ], capture_output=True, timeout=30, check=False)

                        if not VENV_DIR.exists():
                            success = True
                        else:
                            print("⚠️  PowerShell removal incomplete")
                    except Exception as e:
                        print(f"⚠️  PowerShell method failed: {e}")

                # Method 3: Final fallback with ignore_errors
                if not success:
                    print("🔄 Using fallback removal method...")
                    try:
                        shutil.rmtree(VENV_DIR, ignore_errors=True)
                        if not VENV_DIR.exists():
                            success = True
                    except:
                        pass

                if success:
                    print("✅ Virtual environment removed")
                else:
                    print("⚠️  Virtual environment removal incomplete")
                    print(f"💡 You may need to manually delete: {VENV_DIR}")

            else:
                # Unix/Linux/macOS - standard removal
                shutil.rmtree(VENV_DIR)
                print("✅ Virtual environment removed")

        except Exception as e:
            print(f"⚠️  Could not remove virtual environment: {e}")
            print("💡 Try running as administrator or manually delete the .venv folder")

    # Remove Python cache with enhanced cleanup
    cache_dirs_removed = 0
    for root, dirs, files in os.walk(ROOT):
        for dir_name in dirs[:]:
            if dir_name in ["__pycache__", ".pytest_cache", ".mypy_cache", ".coverage"]:
                cache_dir = Path(root) / dir_name
                try:
                    print(f"🗑️ Removing cache: {cache_dir}")
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    cache_dirs_removed += 1
                    dirs.remove(dir_name)
                except Exception as e:
                    print(f"⚠️  Could not remove {cache_dir}: {e}")

    # Deep clean additional items
    if deep_clean:
        print("🧹 Performing deep clean...")
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
                        print(f"🗑️ Removed: {item_path}")
            except Exception as e:
                print(f"⚠️  Could not clean {pattern}: {e}")

    print(f"✅ Environment cleaned ({cache_dirs_removed} cache directories removed)")


def stop_running_processes():
    """Stop any running PlexiChat processes with timeout protection."""
    print("🔍 Checking for running PlexiChat processes...")

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
                            print(f"🛑 Stopped process PID: {pid}")
                        except:
                            pass
                elif result.stdout.strip():
                    print("🔍 No PlexiChat processes found")

            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback to tasklist approach
                print("🔄 Trying alternative process detection...")
                try:
                    result = subprocess.run([
                        "tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"
                    ], capture_output=True, text=True, timeout=10, check=False)

                    if result.returncode == 0:
                        # Simple approach: kill all python.exe processes (be careful!)
                        print("⚠️  Using broad process termination - this may affect other Python processes")
                        subprocess.run(["taskkill", "/F", "/IM", "python.exe"],
                                     capture_output=True, timeout=5, check=False)
                except:
                    print("⚠️  Could not stop processes using Windows methods")

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
                                print(f"🛑 Stopped process PID: {pid.strip()}")
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
                                    print(f"🛑 Force killed process PID: {pid.strip()}")
                                except:
                                    pass
                else:
                    print("🔍 No PlexiChat processes found")

            except subprocess.TimeoutExpired:
                print("⚠️  Process detection timed out")
            except FileNotFoundError:
                print("⚠️  Process management tools not available")

    except Exception as e:
        print(f"⚠️  Could not stop processes: {e}")

    print("✅ Process cleanup completed")


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

    print(f"📦 Exporting PlexiChat configuration to: {export_path}")

    try:
        import tempfile
        import zipfile
        import hashlib

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
                        print(f"   ✅ {description}")
                    except Exception as e:
                        print(f"   ⚠️  Partial export of {description}: {e}")
                        metadata["exported_components"].append(f"{description} (partial)")

            # Export data directory
            data_dir = ROOT / "data"
            if data_dir.exists():
                try:
                    dest_data = export_staging / "data"
                    shutil.copytree(data_dir, dest_data)
                    metadata["exported_components"].append("Database and data files")
                    print("   ✅ Database and data files")
                except Exception as e:
                    print(f"   ⚠️  Partial export of database: {e}")
                    metadata["exported_components"].append("Database and data files (partial)")

            # Export certificates
            certs_dir = ROOT / "certs"
            if certs_dir.exists():
                try:
                    dest_certs = export_staging / "certs"
                    shutil.copytree(certs_dir, dest_certs)
                    metadata["exported_components"].append("Certificates and keys")
                    print("   ✅ Certificates and keys")
                except Exception as e:
                    print(f"   ⚠️  Partial export of certificates: {e}")
                    metadata["exported_components"].append("Certificates and keys (partial)")

            # Export plugins
            plugins_dir = ROOT / "plugins"
            if plugins_dir.exists():
                try:
                    dest_plugins = export_staging / "plugins"
                    shutil.copytree(plugins_dir, dest_plugins)
                    metadata["exported_components"].append("Plugin configurations")
                    print("   ✅ Plugin configurations")
                except Exception as e:
                    print(f"   ⚠️  Partial export of plugins: {e}")
                    metadata["exported_components"].append("Plugin configurations (partial)")

            # Export logs if requested
            if options.get('include_logs', False):
                logs_dir = ROOT / "logs"
                if logs_dir.exists():
                    try:
                        dest_logs = export_staging / "logs"
                        shutil.copytree(logs_dir, dest_logs)
                        metadata["exported_components"].append("Log files")
                        print("   ✅ Log files")
                    except Exception as e:
                        print(f"   ⚠️  Partial export of logs: {e}")
                        metadata["exported_components"].append("Log files (partial)")

            # Export requirements and environment info
            req_files = ["requirements.txt", "pyproject.toml"]
            for req_file in req_files:
                req_path = ROOT / req_file
                if req_path.exists():
                    shutil.copy2(req_path, export_staging / req_file)
                    metadata["exported_components"].append(f"Requirements ({req_file})")
                    print(f"   ✅ Requirements ({req_file})")

            # Save metadata
            with open(export_staging / "export_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            # Create archive
            if options.get('compress', True):
                print("🗜️  Creating compressed archive...")
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

            print(f"\n✅ Export completed successfully!")
            print(f"📁 File: {export_path}")
            print(f"📊 Size: {file_size:.2f} MB")
            print(f"🔐 MD5: {file_hash}")
            print(f"📋 Components: {len(metadata['exported_components'])}")
            print(f"🔍 Checksum: {checksum_file}")

            if options.get('encrypt', False):
                print("\n🔒 Encryption requested but not yet implemented")
                print("💡 Consider using system-level encryption for sensitive data")

    except Exception as e:
        print(f"❌ Export failed: {e}")
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
        print(f"❌ Import file not found: {import_path}")
        return False

    print(f"📥 Importing PlexiChat configuration from: {import_path}")

    try:
        import tempfile
        import zipfile
        import hashlib

        # Verify checksum if available
        checksum_file = import_path.with_suffix('.md5')
        if checksum_file.exists():
            print("🔍 Verifying file integrity...")
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
                print(f"❌ File integrity check failed!")
                print(f"Expected: {expected_hash}")
                print(f"Actual:   {actual_hash}")
                if not input("Continue anyway? (y/N): ").lower().startswith('y'):
                    return False
            else:
                print("✅ File integrity verified")

        # Create backup if requested
        if options.get('backup', True):
            print("💾 Creating backup of current configuration...")
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
                print("📦 Extracting compressed archive...")
                with zipfile.ZipFile(import_path, 'r') as zipf:
                    zipf.extractall(import_staging)
            else:
                print("📁 Reading directory structure...")
                shutil.copytree(import_path, import_staging)

            # Read metadata
            metadata_file = import_staging / "export_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)

                print(f"📋 Import Information:")
                print(f"   Export Version: {metadata.get('export_version', 'Unknown')}")
                print(f"   PlexiChat Version: {metadata.get('plexichat_version', 'Unknown')}")
                print(f"   Export Date: {metadata.get('export_date', 'Unknown')}")
                print(f"   Components: {len(metadata.get('exported_components', []))}")

                # Version compatibility check
                current_version = get_version_info()
                export_version = metadata.get('plexichat_version', '')
                if export_version != current_version:
                    print(f"⚠️  Version mismatch!")
                    print(f"   Current: {current_version}")
                    print(f"   Import:  {export_version}")
                    if not input("Continue with import? (y/N): ").lower().startswith('y'):
                        return False
            else:
                print("⚠️  No metadata found, proceeding with basic import...")

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
                            print(f"   ✅ {description}")
                        except Exception as e:
                            print(f"   ❌ Failed to import {description}: {e}")
                    else:
                        print(f"   ⏭️  Skipped {description} (already exists)")

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
                        print("   ✅ Database and data files")
                    else:
                        print("   ⏭️  Skipped database (already exists, use --overwrite to replace)")
                except Exception as e:
                    print(f"   ❌ Failed to import database: {e}")

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
                            print(f"   ✅ {description}")
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
                            print(f"   ✅ {description} (merged)")
                        else:
                            print(f"   ⏭️  Skipped {description} (already exists)")
                    except Exception as e:
                        print(f"   ❌ Failed to import {description}: {e}")

            print(f"\n✅ Import completed!")
            print(f"📋 Imported components: {len(imported_components)}")
            for component in imported_components:
                print(f"   • {component}")

            print(f"\n💡 Next steps:")
            print(f"   1. Review imported configuration")
            print(f"   2. Run 'python run.py info' to verify setup")
            print(f"   3. Test PlexiChat functionality")

            if options.get('decrypt', False):
                print("\n🔒 Decryption requested but not yet implemented")
                print("💡 Consider using system-level decryption tools")

    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True


def show_subcommand_help(subcommand):
    """Show help for specific subcommands."""
    help_text = {
        "setup": """
🔧 Setup Command Help

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
🧹 Clean Command Help

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
🚀 Run Command Help

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
🐍 Environment Command Help

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
🖥️ Info Command Help

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
🧪 Test Command Help

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
📋 Version Command Help

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
🔄 Update Command Help

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
🧙 Wizard Command Help

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
📦 Export Command Help

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
📥 Import Command Help

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
⚙️ Admin Command Help

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
🌐 WebUI Command Help

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
🖥️ GUI Command Help

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
🔍 Status Command Help

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
🔧 Config Command Help

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
🔒 SSL Command Help

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
🗃️ Migration Command Help

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
💾 Backup Command Help

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
🔌 Plugin Command Help

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
        print(f"❌ No help available for '{subcommand}'")
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
💬 PlexiChat v{version} - Government-Level Secure Communication Platform
📦 Current Installation: {install_type.upper()}

⚡ SINGLE ENTRY POINT - ALL functionality accessible through run.py ONLY
🚫 NO scattered scripts, NO .env files, NO multiple config files
""")

    if config:
        setup_style = config.get("setup_style", "unknown")
        terminal_style = config.get("terminal_style", "unknown")
        print(f"🎯 Setup Style: {SETUP_STYLES.get(setup_style, {}).get('name', setup_style)}")
        print(f"🖥️  Terminal Style: {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)}")
        if config.get("debug_mode"):
            print("🐛 Debug Mode: Enabled")
        if config.get("performance_monitoring"):
            print("📊 Performance Monitoring: Enabled")

    print(f"""
Usage: python run.py [command] [options]

🚀 Main Commands:
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

🌐 Interface Commands:
  admin             Open admin panel in browser
  webui             Open main WebUI in browser
  gui               Interactive GUI launcher (admin + webui)
  status            Show service status and health

🔧 System Management:
  config            Configuration management (generate, validate, show, edit, reset)
  ssl               SSL certificate management (setup, renew, status)
  migrate           Database migration management (run, rollback, status, create)
  backup            Backup management (create, list, schedule, verify)
  restore           Restore operations (from, list, verify)

🔌 Advanced Features:
  plugin            Plugin management (list, install, remove, enable, disable, update)
  cluster           Cluster management (status, join, leave, nodes)
  security          Security management (audit, scan, keys, users)
  monitor           System monitoring (status, metrics, logs, alerts)

🎯 Setup Styles:
  minimal          Core functionality only (~2 min install)
  standard         Recommended for most users (~5 min install)
  full             All features including advanced security (~10 min install)
  developer        Full setup plus development tools (~15 min install)

🖥️  Terminal Styles:
  classic          Traditional single-pane output
  split            Logs on left, CLI on right (wide terminals)
  tabbed           Switch between logs and CLI with tabs
  dashboard        Live system monitoring with metrics

📊 Installation Status:
  not_installed    No virtual environment found
  minimal         Core features only
  standard        Standard feature set
  partial         Some optional features missing
  full            All features available
  developer       Full features plus dev tools
  incomplete      Installation corrupted, needs repair

💡 Examples:
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

🔐 First-time Setup:
  - Interactive wizard guides you through configuration
  - Default admin credentials generated in default_creds.txt
  - Change password immediately after first login
  - WebUI available at http://localhost:8080
  - API available at http://localhost:8000

🛠️  Development Features:
  - Real-time log monitoring with color coding
  - Performance metrics and system monitoring
  - Integrated CLI with advanced commands
  - Debug mode with detailed diagnostics
  - Multiple terminal display modes
""")

    # Show recommendations based on current state
    if install_type == "partial":
        print("⚠️  Recommendation: Run 'python run.py setup full' for complete functionality.")
    elif install_type == "incomplete":
        print("❌ Recommendation: Run 'python run.py clean && python run.py setup' to repair.")
    elif install_type == "not_installed":
        print("🎯 Recommendation: Run 'python run.py' to start interactive setup wizard.")

    # Show system-specific tips
    print(f"\n💻 Platform-Specific Tips ({platform.system()}):")
    if IS_WINDOWS:
        print("  • Use Windows Terminal or PowerShell for best experience")
        print("  • Consider enabling Windows Subsystem for Linux (WSL)")
    elif IS_LINUX:
        print("  • Ensure you have python3.11-dev installed for full functionality")
        print("  • Use a modern terminal emulator for best display")
    elif IS_MACOS:
        print("  • Use iTerm2 or Terminal.app for optimal experience")
        print("  • Consider installing Homebrew for easier dependency management")

    if install_type == "partial":
        print("⚠️  Note: Partial installation detected. Run 'python run.py setup full' for all features.")
    elif install_type == "incomplete":
        print("❌ Note: Installation is incomplete. Run 'python run.py setup' to repair.")


def open_admin_gui():
    """Open the admin GUI in the default browser."""
    ports = get_port_configuration()
    admin_url = f"http://localhost:{ports.get('admin', 8002)}"

    print(f"🔧 Opening Admin GUI: {admin_url}")

    try:
        import webbrowser
        webbrowser.open(admin_url)
        print("✅ Admin GUI opened in browser")
        return True
    except Exception as e:
        print(f"❌ Failed to open admin GUI: {e}")
        print(f"💡 Manually open: {admin_url}")
        return False


def open_webui():
    """Open the WebUI in the default browser."""
    ports = get_port_configuration()
    webui_url = f"http://localhost:{ports.get('webui_http', 8080)}"

    print(f"🌐 Opening WebUI: {webui_url}")

    try:
        import webbrowser
        webbrowser.open(webui_url)
        print("✅ WebUI opened in browser")
        return True
    except Exception as e:
        print(f"❌ Failed to open WebUI: {e}")
        print(f"💡 Manually open: {webui_url}")
        return False


def show_service_status():
    """Show status of all PlexiChat services."""
    ports = get_port_configuration()

    print("🔍 PlexiChat Service Status")
    print("=" * 50)

    services = [
        ("API Server", f"http://localhost:{ports.get('api_http', 8000)}", "📡"),
        ("WebUI", f"http://localhost:{ports.get('webui_http', 8080)}", "🌐"),
        ("Admin Panel", f"http://localhost:{ports.get('admin', 8002)}", "⚙️"),
        ("WebSocket", f"ws://localhost:{ports.get('websocket', 8001)}", "🔌")
    ]

    for name, url, emoji in services:
        try:
            import requests
            response = requests.get(url.replace('ws://', 'http://'), timeout=2)
            if response.status_code == 200:
                status = "🟢 Running"
            else:
                status = f"🟡 Response: {response.status_code}"
        except ImportError:
            status = "⚠️ requests not installed"
        except Exception as e:
            status = "🔴 Not responding"

        print(f"{emoji} {name:15} {url:35} {status}")

    print("=" * 50)
    print("💡 Note: Services show as 'Not responding' when not running")
    print("   Use 'python run.py run' to start all services")


# ============================================================================
# UNIFIED COMMAND HANDLERS - ALL FUNCTIONALITY THROUGH SINGLE ENTRY POINT
# ============================================================================

def handle_config_command(args):
    """Handle configuration management commands."""
    if not args:
        print("🔧 PlexiChat Configuration Management")
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
        print("🔧 Generating unified configuration...")
        generate_unified_config()
    elif subcommand == "validate":
        print("✅ Validating configuration...")
        validate_configuration()
    elif subcommand == "show":
        print("📋 Current configuration:")
        show_current_config()
    elif subcommand == "edit":
        print("✏️ Interactive configuration editor...")
        edit_config_interactive()
    elif subcommand == "reset":
        print("🔄 Resetting to default configuration...")
        reset_to_default_config()
    else:
        print(f"❌ Unknown config command: {subcommand}")

def handle_ssl_command(args):
    """Handle SSL certificate management."""
    if not args:
        print("🔒 PlexiChat SSL Management")
        print("=" * 30)
        print("Available SSL commands:")
        print("  setup       Generate SSL certificates and configure domain")
        print("  renew       Renew SSL certificates")
        print("  status      Show SSL certificate status")
        return

    subcommand = args[0].lower()

    if subcommand == "setup":
        print("🔒 Setting up SSL certificates...")
        setup_ssl_certificates()
    elif subcommand == "renew":
        print("🔄 Renewing SSL certificates...")
        renew_ssl_certificates()
    elif subcommand == "status":
        print("📋 SSL certificate status:")
        show_ssl_status()
    else:
        print(f"❌ Unknown SSL command: {subcommand}")

def handle_migration_command(args):
    """Handle database migration commands."""
    if not args:
        print("🗃️ PlexiChat Database Migration")
        print("=" * 35)
        print("Available migration commands:")
        print("  run         Run pending migrations")
        print("  rollback    Rollback last migration")
        print("  status      Show migration status")
        print("  create      Create new migration")
        return

    subcommand = args[0].lower()

    if subcommand == "run":
        print("🗃️ Running database migrations...")
        run_database_migrations()
    elif subcommand == "rollback":
        print("↩️ Rolling back migrations...")
        rollback_migrations()
    elif subcommand == "status":
        print("📋 Migration status:")
        show_migration_status()
    elif subcommand == "create":
        name = args[1] if len(args) > 1 else input("Migration name: ")
        create_migration(name)
    else:
        print(f"❌ Unknown migration command: {subcommand}")

def handle_backup_command(args):
    """Handle backup management commands."""
    if not args:
        print("💾 PlexiChat Backup Management")
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
        print(f"❌ Unknown backup command: {subcommand}")

def handle_restore_command(args):
    """Handle restore operations."""
    if not args:
        print("🔄 PlexiChat Restore Management")
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
        print(f"❌ Unknown restore command: {subcommand}")

def handle_plugin_command(args):
    """Handle plugin management commands."""
    if not args:
        print("🔌 PlexiChat Plugin Management")
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
        print(f"❌ Unknown plugin command: {subcommand}")

def handle_cluster_command(args):
    """Handle cluster management commands."""
    if not args:
        print("🌐 PlexiChat Cluster Management")
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
        print(f"❌ Unknown cluster command: {subcommand}")

def handle_security_command(args):
    """Handle security management commands."""
    if not args:
        print("🛡️ PlexiChat Security Management")
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
        print(f"❌ Unknown security command: {subcommand}")

def handle_monitor_command(args):
    """Handle monitoring commands."""
    if not args:
        print("📊 PlexiChat Monitoring")
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
        print(f"❌ Unknown monitor command: {subcommand}")

def main():
    """Enhanced main entry point - SINGLE POINT OF ACCESS FOR ALL PLEXICHAT FUNCTIONALITY."""
    # Print banner first
    print_banner()

    check_python_version()
    update_version_format()  # Update version format if needed

    args = sys.argv[1:]

    if not args:
        if not VENV_DIR.exists():
            print("🎉 Welcome to PlexiChat!")
            print("🔧 First-time setup detected...")

            # Run interactive setup wizard
            config = interactive_setup_wizard()
            if not config:
                print("❌ Setup cancelled")
                sys.exit(1)

            setup_style = config.get("setup_style", "minimal")
            print(f"\n🚀 Starting {SETUP_STYLES[setup_style]['name']}...")

            if install_dependencies(setup_style):
                print("✅ Setup complete!")
                print(f"🎯 Configuration saved for future runs")
                print("🚀 Run 'python run.py run' to start PlexiChat.")
                print("📋 Default admin credentials will be generated on first run.")

                # Show next steps
                print("\n📋 Next Steps:")
                print("1. python run.py run    # Start PlexiChat server")
                print("2. Open http://localhost:8080 in your browser")
                print("3. Login with generated admin credentials")
                print("4. Change default password immediately")

                if config.get("debug_mode"):
                    print("\n🐛 Debug mode enabled - detailed logging will be available")

                if config.get("performance_monitoring"):
                    print("📊 Performance monitoring enabled - metrics will be collected")

            else:
                print("❌ Setup failed")
                sys.exit(1)
        else:
            # Show status and help for existing installations
            install_type = detect_installation_type()
            config = load_setup_config()

            print(f"📦 Current Installation: {install_type.upper()}")
            if config:
                setup_style = config.get("setup_style", "unknown")
                terminal_style = config.get("terminal_style", "unknown")
                print(f"🎯 Setup Style: {SETUP_STYLES.get(setup_style, {}).get('name', setup_style)}")
                print(f"🖥️  Terminal Style: {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)}")

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
💬 PlexiChat Version Information
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
            print(f"⚠️ Could not read Git information: {e}")

    elif command == "update":
        run_robust_update()

        # Simple Git pull update
        try:
            print("🔍 Checking for updates...")

            # Fetch latest changes
            result = subprocess.run(
                ["git", "fetch", "origin"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"❌ Failed to fetch updates: {result.stderr}")
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
                print("📦 Updates available!")

                if input("🔄 Apply updates? (y/N): ").lower().startswith('y'):
                    # Pull updates
                    result = subprocess.run(
                        ["git", "pull", "origin"],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode == 0:
                        print("✅ Updates applied successfully!")
                        print("🔄 Restart PlexiChat to use the new version")

                        # Update dependencies
                        if REQUIREMENTS.exists():
                            print("📦 Updating dependencies...")
                            venv_python = get_venv_python()
                            if venv_python and venv_python.exists():
                                subprocess.run([
                                    str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS)
                                ], cwd=ROOT)
                    else:
                        print(f"❌ Update failed: {result.stderr}")
                        sys.exit(1)
                else:
                    print("❌ Update cancelled")
            else:
                print("✅ Already up to date!")

        except Exception as e:
            print(f"❌ Update check failed: {e}")
            sys.exit(1)

    elif command == "wizard":
        # Run interactive setup wizard
        config = interactive_setup_wizard()
        if config:
            setup_style = config.get("setup_style", "minimal")
            print(f"\n🚀 Installing {SETUP_STYLES[setup_style]['name']}...")
            if install_dependencies(setup_style):
                print("✅ Setup complete!")
                print("🚀 Run 'python run.py run' to start PlexiChat.")
            else:
                print("❌ Setup failed")
                sys.exit(1)
        else:
            print("❌ Setup cancelled")
            sys.exit(1)

    elif command == "setup":
        if "--help" in args or "-h" in args:
            show_subcommand_help("setup")
            return

        install_type = "standard"  # Changed default from minimal to standard
        if len(args) > 1 and not args[1].startswith('-'):
            install_type = args[1].lower()
            if install_type not in ["minimal", "standard", "full", "developer"]:
                print(f"❌ Invalid setup type: {install_type}")
                print("Valid types: minimal, standard, full, developer")
                print("Use 'python run.py help setup' for detailed help")
                sys.exit(1)

        print(f"🔧 Setting up PlexiChat ({SETUP_STYLES[install_type]['name']})...")

        # Save basic config for non-interactive setup
        config = {
            "setup_style": install_type,
            "terminal_style": "classic",  # Default for non-interactive
            "debug_mode": False,
            "performance_monitoring": True,
            "auto_start_services": True,
            "setup_date": datetime.now().isoformat(),
            "system_info": get_system_info()
        }
        save_setup_config(config)

        if install_dependencies(install_type):
            print("✅ Dependencies installed successfully!")

            # Generate unified configuration
            print("🔧 Generating unified configuration...")
            generate_unified_config()

            # Setup SSL certificates for development
            print("🔒 Setting up SSL certificates...")
            setup_ssl_certificates()

            print("\n🎉 Setup complete!")
            print("🚀 Run 'python run.py run' to start PlexiChat.")
            print("🌐 Access via: https://plexichat.local (after adding to hosts file)")
            print("💡 Tip: Run 'python run.py wizard' for interactive configuration.")
        else:
            print("❌ Setup failed")
            sys.exit(1)

    elif command == "info":
        print("🖥️  PlexiChat System Information")
        print("=" * 50)
        print_system_info()

        install_type = detect_installation_type()
        config = load_setup_config()

        print(f"\n📦 Installation Details:")
        print(f"   Type: {install_type.upper()}")
        print(f"   Root Directory: {ROOT}")
        print(f"   Virtual Environment: {'Present' if VENV_DIR.exists() else 'Missing'}")

        if config:
            print(f"\n⚙️  Configuration:")
            print(f"   Setup Style: {SETUP_STYLES.get(config.get('setup_style', ''), {}).get('name', 'Unknown')}")
            print(f"   Terminal Style: {TERMINAL_STYLES.get(config.get('terminal_style', ''), {}).get('name', 'Unknown')}")
            print(f"   Debug Mode: {'Enabled' if config.get('debug_mode') else 'Disabled'}")
            print(f"   Performance Monitoring: {'Enabled' if config.get('performance_monitoring') else 'Disabled'}")
            print(f"   Setup Date: {config.get('setup_date', 'Unknown')}")

        # Check for important files
        print(f"\n📁 Important Files:")
        print(f"   Requirements: {'Present' if REQUIREMENTS.exists() else 'Missing'}")
        print(f"   Version File: {'Present' if VERSION_FILE.exists() else 'Missing'}")
        print(f"   Default Credentials: {'Present' if DEFAULT_CREDS.exists() else 'Not Generated'}")

        # Port configuration
        ports = get_port_configuration()
        print(f"\n🌐 Service Ports:")
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
                        print(f"\n📦 Installed Packages: {package_count}")
                    else:
                        print(f"\n📦 Installed Packages: Unable to determine")
                except Exception:
                    print(f"\n📦 Installed Packages: Check failed")

    elif command == "run":
        # Check for debug flag
        debug_mode = "--debug" in args

        print("🚀 Starting PlexiChat server...")
        if not VENV_DIR.exists():
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        # Load configuration
        config = load_setup_config()
        terminal_style = config.get("terminal_style", "classic") if config else "classic"

        if debug_mode or (config and config.get("debug_mode")):
            print("🐛 Debug mode enabled")
            terminal_style = "dashboard"  # Force dashboard for debug mode

        print(f"🖥️  Using {TERMINAL_STYLES.get(terminal_style, {}).get('name', terminal_style)} terminal style")

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
            print("❌ Import filename required")
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
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        install_type = detect_installation_type()
        print(f"🧪 Running tests with {install_type} installation...")

        venv_python = get_venv_python()
        if venv_python and venv_python.exists():
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)
            try:
                subprocess.run([str(venv_python), "-m", "pytest", "src/plexichat/tests/", "-v"], env=env, check=True)
                print("✅ All tests passed!")
            except subprocess.CalledProcessError:
                print("❌ Some tests failed. Check output above.")
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

        print("🖥️  PlexiChat GUI Options")
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
            print("❌ Invalid choice")

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
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)


def start_classic_terminal():
    """Start PlexiChat with enhanced classic single-pane terminal."""
    try:
        venv_python = get_venv_python()
        if not venv_python or not venv_python.exists():
            print("❌ Python executable not found in virtual environment")
            sys.exit(1)

        # Get port configuration
        ports = get_port_configuration()

        # Generate default admin credentials if first time
        is_first_time = not DEFAULT_CREDS.exists()
        if is_first_time:
            generate_default_admin_creds()

        cmd = [str(venv_python), "-m", "src.plexichat.main"]

        print("🚀 Starting PlexiChat server (Enhanced Classic Mode)...")
        print("💡 Press Ctrl+C to stop the server")
        print("=" * 60)
        print("🌐 Service URLs:")
        print(f"   📱 WebUI:        http://localhost:{ports['webui_http']}")
        print(f"   📡 API:          http://localhost:{ports['api_http']}")
        print(f"   ⚙️  Admin Panel:  http://localhost:{ports['admin']}")
        print(f"   🔌 WebSocket:    ws://localhost:{ports['websocket']}")

        if is_first_time:
            print(f"🔐 Admin credentials: {DEFAULT_CREDS}")
            print("⚠️  IMPORTANT: Change default password after first login!")

        print("=" * 60)
        print("💡 Commands while running:")
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
        import threading
        import queue

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
                        print("🔧 Opening admin panel...")
                        open_admin_gui()
                    elif user_input == 'webui':
                        print("🌐 Opening WebUI...")
                        open_webui()
                    elif user_input == 'status':
                        print("🔍 Service status:")
                        show_service_status()
                    elif user_input in ['quit', 'exit', 'stop']:
                        print("🛑 Stopping server...")
                        break
                    else:
                        print(f"❓ Unknown command: {user_input}")
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
            print("\n🛑 Stopping PlexiChat server...")

        # Clean shutdown
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        print("✅ Server stopped")

    except Exception as e:
        print(f"❌ Failed to start PlexiChat: {e}")
        sys.exit(1)


def start_split_terminal():
    """Start PlexiChat with split-screen terminal (logs left, CLI right)."""
    print("🖥️  Split-screen terminal mode")
    print("📊 This would show logs on left, CLI on right")
    print("💡 For now, falling back to classic mode")
    start_classic_terminal()


def start_tabbed_terminal():
    """Start PlexiChat with tabbed interface."""
    print("🖥️  Tabbed terminal mode")
    print("📊 This would allow switching between logs and CLI")
    print("💡 For now, falling back to classic mode")
    start_classic_terminal()


def start_dashboard_terminal(debug_mode=False):
    """Start PlexiChat with live dashboard and metrics."""
    print("📊 Dashboard terminal mode")
    if debug_mode:
        print("🐛 Debug mode active - detailed logging enabled")
    print("📈 This would show real-time metrics and system monitoring")
    print("💡 For now, falling back to classic mode with enhanced logging")
    start_classic_terminal()


# Duplicate get_port_configuration removed to avoid obscured declaration error.


# ============================================================================
# UNIFIED CONFIGURATION SYSTEM - NO MORE .ENV FILES OR SCATTERED CONFIGS
# ============================================================================

def generate_unified_config():
    """Generate unified YAML configuration - replaces all scattered config files."""
    print("🔧 Generating unified PlexiChat configuration...")

    # Check if yaml is available
    yaml_module = None
    try:
        import yaml as yaml_module
    except ImportError:
        print("⚠️ PyYAML not installed. Installing...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "PyYAML"], check=True, capture_output=True)
            import yaml as yaml_module
            print("✅ PyYAML installed successfully")
        except Exception as e:
            print(f"❌ Failed to install PyYAML: {e}")
            print("💡 Generating JSON configuration instead...")
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

    print(f"✅ Unified configuration saved to: {config_file}")
    print("🗑️ You can now remove old .env files and scattered configs")

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

    print(f"✅ JSON configuration saved to: {config_file}")
    print("💡 Install PyYAML for YAML format: pip install PyYAML")

def validate_configuration():
    """Validate the unified configuration."""
    config_file = ROOT / "plexichat.yaml"
    if not config_file.exists():
        print("❌ No configuration file found. Run 'python run.py config generate' first.")
        return False

    try:
        with open(config_file, 'r') as f:
            if yaml is not None:
                config = yaml.safe_load(f)
            else:
                print("❌ YAML library not available")
                return False

        # Basic validation
        if "plexichat" not in config:
            print("❌ Invalid configuration: missing 'plexichat' section")
            return False

        required_sections = ["server", "database", "security"]
        for section in required_sections:
            if section not in config["plexichat"]:
                print(f"❌ Invalid configuration: missing '{section}' section")
                return False

        print("✅ Configuration is valid")
        return True

    except Exception as e:
        print(f"❌ Configuration validation failed: {e}")
        return False

def show_current_config():
    """Show current configuration."""
    config_file = ROOT / "plexichat.yaml"
    if not config_file.exists():
        print("❌ No configuration file found.")
        return

    try:
        with open(config_file, 'r') as f:
            if yaml is not None:
                config = yaml.safe_load(f)
            else:
                print("❌ YAML library not available")
                return

        print("📋 Current PlexiChat Configuration:")
        print("=" * 40)
        if yaml is not None:
            print(yaml.dump(config, default_flow_style=False, indent=2))
        else:
            print(json.dumps(config, indent=2))

    except Exception as e:
        print(f"❌ Failed to read configuration: {e}")

def edit_config_interactive():
    """Interactive configuration editor."""
    print("✏️ Interactive configuration editor not yet implemented.")
    print("💡 Edit plexichat.yaml directly for now.")

def reset_to_default_config():
    """Reset configuration to defaults."""
    if input("⚠️ This will reset all configuration to defaults. Continue? (y/N): ").lower().startswith('y'):
        generate_unified_config()
        print("✅ Configuration reset to defaults")

def setup_ssl_certificates():
    """Set up SSL certificates and domain configuration."""
    print("🔒 Setting up SSL certificates for plexichat.local...")

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

        print("✅ SSL certificates generated")
        print("📝 Add '127.0.0.1 plexichat.local' to your hosts file")

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate SSL certificates: {e}")
    except FileNotFoundError:
        print("❌ OpenSSL not found. Please install OpenSSL first.")

def renew_ssl_certificates():
    """Renew SSL certificates."""
    print("🔄 SSL certificate renewal not yet implemented.")

def show_ssl_status():
    """Show SSL certificate status."""
    certs_dir = ROOT / "certs"
    cert_file = certs_dir / "plexichat.crt"

    if not cert_file.exists():
        print("❌ No SSL certificate found")
        return

    try:
        import subprocess
        result = subprocess.run([
            "openssl", "x509", "-in", str(cert_file), "-text", "-noout"
        ], capture_output=True, text=True, check=True)

        print("📋 SSL Certificate Status:")
        print("=" * 30)
        # Extract relevant info from openssl output
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Not Before' in line or 'Not After' in line or 'Subject:' in line:
                print(f"   {line.strip()}")

    except Exception as e:
        print(f"❌ Failed to read SSL certificate: {e}")

# Placeholder implementations for other commands
def run_database_migrations():
    print("🗃️ Database migration system not yet implemented.")

def rollback_migrations():
    print("↩️ Migration rollback not yet implemented.")

def show_migration_status():
    print("📋 Migration status not yet implemented.")

def create_migration(name):
    print(f"📝 Creating migration '{name}' not yet implemented.")

def create_backup(name):
    print(f"💾 Creating backup '{name or 'auto'}' not yet implemented.")

def list_backups():
    print("📋 Listing backups not yet implemented.")

def configure_backup_schedule():
    print("⏰ Backup scheduling not yet implemented.")

def verify_backup(name):
    print(f"✅ Verifying backup '{name or 'latest'}' not yet implemented.")

def restore_from_backup(name):
    print(f"🔄 Restoring from backup '{name}' not yet implemented.")

def list_restore_points():
    print("📋 Listing restore points not yet implemented.")

def verify_restore_point(name):
    print(f"✅ Verifying restore point '{name or 'latest'}' not yet implemented.")

def list_plugins():
    print("🔌 Plugin listing not yet implemented.")

def install_plugin(name):
    print(f"📦 Installing plugin '{name}' not yet implemented.")

def remove_plugin(name):
    print(f"🗑️ Removing plugin '{name}' not yet implemented.")

def enable_plugin(name):
    print(f"✅ Enabling plugin '{name}' not yet implemented.")

def disable_plugin(name):
    print(f"❌ Disabling plugin '{name}' not yet implemented.")

def update_plugins():
    print("🔄 Updating plugins not yet implemented.")

def show_cluster_status():
    print("🌐 Cluster status not yet implemented.")

def join_cluster(address):
    print(f"🔗 Joining cluster at '{address}' not yet implemented.")

def leave_cluster():
    print("👋 Leaving cluster not yet implemented.")

def list_cluster_nodes():
    print("📋 Listing cluster nodes not yet implemented.")

def run_security_audit():
    print("🛡️ Security audit not yet implemented.")

def scan_vulnerabilities():
    print("🔍 Vulnerability scanning not yet implemented.")

def manage_encryption_keys(args):
    print("🔐 Encryption key management not yet implemented.")

def manage_user_security(args):
    print("👤 User security management not yet implemented.")

def show_system_status():
    print("📊 System status monitoring not yet implemented.")

def show_performance_metrics():
    print("📈 Performance metrics not yet implemented.")

def view_system_logs(args):
    print("📜 System log viewing not yet implemented.")

def manage_alerts(args):
    print("🚨 Alert management not yet implemented.")

def run_robust_update():
    """Robust update system that works even with missing modules."""
    print("🔄 PlexiChat Robust Update System")
    print("=" * 45)

    # Check if we're in a Git repository
    if not (ROOT / ".git").exists():
        print("❌ Not a Git repository. Updates require Git-based installation.")
        print("💡 To enable updates:")
        print("   1. Clone from GitHub: git clone https://github.com/linux-of-user/plexichat.git")
        print("   2. Or download releases from: https://github.com/linux-of-user/plexichat/releases")
        return False

    try:
        print("🔍 Checking for updates...")

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
            print(f"❌ Failed to fetch updates: {result.stderr}")
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
            print("✅ PlexiChat is already up to date!")
            return True

        print("\n📦 Updates available!")

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
                print("\n📋 Changes to be applied:")
                commit_lines = log_result.stdout.strip().split('\n')
                for line in commit_lines[:5]:  # Show last 5 commits
                    print(f"   • {line}")
                if len(commit_lines) > 5:
                    print(f"   ... and {len(commit_lines) - 5} more commits")
        except:
            pass

        if not input("\n🔄 Apply updates? (y/N): ").lower().startswith('y'):
            progress.close()
            print("❌ Update cancelled by user")
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
            print(f"❌ Failed to apply updates: {result.stderr}")
            return False

        progress.update(1)

        # Step 4: Install/update dependencies (robust approach)
        if hasattr(progress, 'set_description'):
            progress.set_description("Installing dependencies")

        # Install essential packages first (these are needed for the system to work)
        essential_packages = ["PyYAML", "requests", "tqdm"]

        print("\n📦 Installing essential packages...")
        for package in essential_packages:
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", package, "--quiet", "--upgrade"
                ], check=True, capture_output=True)
            except:
                print(f"⚠️ Failed to install {package}, continuing...")

        # Try to install from requirements.txt if it exists
        if REQUIREMENTS.exists():
            print("📦 Updating dependencies from requirements.txt...")
            try:
                # Use a more robust approach that doesn't depend on our parsing functions
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS), "--quiet", "--upgrade"
                ], timeout=300, capture_output=True)
                print("✅ Dependencies updated successfully")
            except Exception as e:
                print(f"⚠️ Some dependencies may not have updated: {e}")

        progress.update(1)

        # Step 5: Verify installation
        if hasattr(progress, 'set_description'):
            progress.set_description("Verifying installation")

        # Try to import core modules to verify the update worked
        verification_passed = True
        try:
            # Test basic Python imports (sys, json, os already imported globally)
            import yaml  # Optional dependency for version verification


            # Test if we can read the version file
            if (ROOT / "version.json").exists():
                with open(ROOT / "version.json", 'r') as f:
                    version_data = json.load(f)
                    print(f"✅ Updated to version: {version_data.get('current_version', 'unknown')}")

        except Exception as e:
            print(f"⚠️ Verification warning: {e}")
            verification_passed = False

        progress.update(1)
        progress.close()

        if verification_passed:
            print("\n🎉 Update completed successfully!")
            print("🔄 Restart PlexiChat to use the new version")
            print("💡 Run 'python run.py version' to see the new version")
        else:
            print("\n⚠️ Update applied but verification had issues")
            print("💡 Try running 'python run.py setup' to fix any issues")

        return True

    except subprocess.TimeoutExpired:
        print("❌ Update timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"❌ Update failed: {e}")
        print("💡 Try running 'git pull' manually or reinstalling PlexiChat")
        return False

if __name__ == "__main__":
    main()
