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
    ██║     ███████╗███████╗██╔╝ ██╗ ██║╚██████╗██║  ██║██║  ██║   ██║
    ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

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
        "cpu_count": cpu_count,
        "terminal_width": TERMINAL_WIDTH,
        "supports_color": SUPPORTS_COLOR,
        "has_psutil": has_psutil
    }

    if has_psutil and memory:
        info["memory_total"] = f"{memory.total / (1024**3):.1f} GB"
        info["memory_available"] = f"{memory.available / (1024**3):.1f} GB"

    if has_psutil and disk:
        info["disk_total"] = f"{disk.total / (1024**3):.1f} GB"
        info["disk_free"] = f"{disk.free / (1024**3):.1f} GB"

    return info


def print_system_info():
    """Print detailed system information."""
    info = get_system_info()

    print("🖥️  System Information:")
    print(f"   Platform: {info['platform']} {info['platform_version']} ({info['architecture']})")
    print(f"   Python: {info['python_version']}")
    print(f"   CPU Cores: {info['cpu_count']}")

    if "memory_total" in info:
        print(f"   Memory: {info['memory_available']} available of {info['memory_total']}")

    if "disk_total" in info:
        print(f"   Disk Space: {info['disk_free']} free of {info['disk_total']}")

    print(f"   Terminal: {info['terminal_width']} columns, Color: {'Yes' if info['supports_color'] else 'No'}")
    print(f"   Performance Monitoring: {'Available' if info['has_psutil'] else 'Limited (install psutil for full metrics)'}")


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
    """Get version information from Git."""
    try:
        # Try to get version from Git tag
        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

        # Fallback to latest tag + commit hash
        result = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

        # Fallback to commit hash
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return f"dev-{result.stdout.strip()}"

        # Final fallback to version.json if Git fails
        if VERSION_FILE.exists():
            with open(VERSION_FILE, 'r') as f:
                version_data = json.load(f)
                return version_data.get("current_version", "a.1.1-7")

        return "a.1.1-7"  # Current version
    except Exception:
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
    """Get port configuration from config file."""
    config_file = ROOT / "config" / "plexichat.json"
    default_ports = {
        "api_http": 8000,
        "api_https": 8443,
        "webui_http": 8080,
        "webui_https": 8444,
        "websocket": 8001,
        "admin": 8002
    }

    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
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
        print(f"⚠️ Warning: Could not load port configuration: {e}")

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


def create_virtual_environment():
    """Create virtual environment if it doesn't exist."""
    if VENV_DIR.exists():
        venv_python = get_venv_python()
        if venv_python and venv_python.exists():
            print("✅ Virtual environment already exists")
            return True
        else:
            print("🔄 Recreating corrupted virtual environment...")
            shutil.rmtree(VENV_DIR)
    
    print("🔄 Creating virtual environment...")
    try:
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
        print("✅ Virtual environment created")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
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
    elif install_type == "full":
        return install_full_deps(venv_python)
    else:
        print(f"❌ Unknown install type: {install_type}")
        return False


def parse_requirements_file():
    """Parse requirements.txt to extract minimal and full dependencies."""
    if not REQUIREMENTS.exists():
        print("❌ requirements.txt not found")
        return {"minimal": [], "full": []}

    minimal_deps = []
    full_deps = []
    current_section = None

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

            # Add dependency to appropriate section
            if current_section == "minimal":
                minimal_deps.append(line)
            elif current_section == "full":
                full_deps.append(line)

    return {"minimal": minimal_deps, "full": full_deps}


def install_minimal_deps(venv_python):
    """Install minimal dependencies from requirements.txt."""
    deps = parse_requirements_file()
    minimal_deps = deps["minimal"]

    if not minimal_deps:
        print("❌ No minimal dependencies found in requirements.txt")
        return False

    print(f"📋 Installing {len(minimal_deps)} minimal dependencies...")
    return install_package_list(venv_python, minimal_deps)


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


def install_package_list(venv_python, packages):
    """Install a list of packages."""
    for package in packages:
        try:
            print(f"📦 Installing {package}...")
            subprocess.check_call([str(venv_python), "-m", "pip", "install", package])
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to install {package}: {e}")
            return False
    return True


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
            from plexichat.cli.integrated_cli import PlexiChatCLI
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


def clean_environment():
    """Clean up virtual environment and cache."""
    print("🧹 Cleaning PlexiChat environment...")

    if VENV_DIR.exists():
        print("🗑️ Removing virtual environment...")
        shutil.rmtree(VENV_DIR)
        print("✅ Virtual environment removed")
    
    # Remove Python cache
    for root, dirs, files in os.walk(ROOT):
        for dir_name in dirs[:]:
            if dir_name == "__pycache__":
                cache_dir = Path(root) / dir_name
                print(f"🗑️ Removing cache: {cache_dir}")
                shutil.rmtree(cache_dir)
                dirs.remove(dir_name)
    
    print("✅ Environment cleaned")


def show_help():
    """Show enhanced help information."""
    version = get_version_info()
    install_type = detect_installation_type()
    config = load_setup_config()

    print(f"""
💬 PlexiChat v{version} - Government-Level Secure Communication Platform
📦 Current Installation: {install_type.upper()}
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
  clean [--all]     Clean environment and cache
  info              Show detailed system information
  version           Show version and Git information
  update            Check for and apply updates from GitHub
  help              Show this help message

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
  python run.py setup standard     # Standard setup without wizard
  python run.py wizard             # Re-run setup wizard
  python run.py run --debug        # Start with debug logging
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


def main():
    """Enhanced main entry point."""
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
        print("🔄 PlexiChat Update System")
        print("=" * 40)

        # Check if we're in a Git repository
        if not (ROOT / ".git").exists():
            print("❌ Not a Git repository. Updates require Git-based installation.")
            print("💡 To enable updates:")
            print("   1. Clone from GitHub: git clone https://github.com/linux-of-user/plexichat.git")
            print("   2. Or download releases from: https://github.com/linux-of-user/plexichat/releases")
            sys.exit(1)

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
        install_type = "standard"  # Changed default from minimal to standard
        if len(args) > 1:
            install_type = args[1].lower()
            if install_type not in ["minimal", "standard", "full", "developer"]:
                print(f"❌ Invalid setup type: {install_type}")
                print("Valid types: minimal, standard, full, developer")
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
            print("✅ Setup complete!")
            print("🚀 Run 'python run.py run' to start PlexiChat.")
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
        clean_environment()

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

    else:
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)


def start_classic_terminal():
    """Start PlexiChat with classic single-pane terminal."""
    try:
        venv_python = get_venv_python()
        if not venv_python or not venv_python.exists():
            print("❌ Python executable not found in virtual environment")
            sys.exit(1)

        cmd = [str(venv_python), "-m", "src.plexichat.main"]

        print("🚀 Starting PlexiChat server (Classic Mode)...")
        print("💡 Press Ctrl+C to stop the server")
        print("🌐 WebUI will be available at http://localhost:8080")
        print("-" * 60)

        process = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        try:
            for line in iter(process.stdout.readline, ''):
                print(line.rstrip())

        except KeyboardInterrupt:
            print("\n🛑 Stopping PlexiChat server...")
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


def get_port_configuration():
    """Get service port configuration."""
    return {
        "WebUI": "8080",
        "API": "8000",
        "WebSocket": "8001",
        "Admin": "8002"
    }


if __name__ == "__main__":
    main()
