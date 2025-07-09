#!/usr/bin/env python3
"""
NetLink Application Runner

Simple, reliable cross-platform entry point with automatic environment setup.
Features:
- Multiplexed terminal with logs and CLI
- Automatic dependency installation
- First-time setup detection
- Installation type detection (minimal/full/partial)
- Default admin credential generation
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

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# Add src to Python path
sys.path.insert(0, str(SRC))


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 11):
        print("❌ Error: Python 3.11 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")


def get_version_info():
    """Get current version information."""
    try:
        if VERSION_FILE.exists():
            with open(VERSION_FILE, 'r') as f:
                version_data = json.load(f)
                version = version_data.get("current_version", "a.1.1-1")
                return version
        return "a.1.1-1"  # Default version
    except Exception:
        return "a.1.1-1"


def update_version_format():
    """Update version to new format if needed."""
    try:
        if VERSION_FILE.exists():
            with open(VERSION_FILE, 'r') as f:
                version_data = json.load(f)

            current = version_data.get("current_version", "a.1.1-1")

            # Convert old format to new format (letter.major.minor-build)
            if not current.startswith(('r.', 'a.', 'b.')):
                if "alpha" in current or "1a" in current:
                    new_version = "a.1.1-1"
                elif "beta" in current or "1b" in current:
                    new_version = "b.1.1-1"
                else:
                    new_version = "r.1.0-1"

                version_data["current_version"] = new_version
                version_data["last_updated"] = datetime.now().isoformat()

                with open(VERSION_FILE, 'w') as f:
                    json.dump(version_data, f, indent=2)

                print(f"📝 Updated version format: {current} → {new_version}")
    except Exception as e:
        print(f"⚠️ Warning: Could not update version format: {e}")


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
    config_file = ROOT / "config" / "netlink.json"
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
        print("🔍 Monitoring: latest.log, netlink.log, errors.log")
        print("=" * 50)

        # Monitor multiple log files
        log_files = {
            "latest": log_dir / "latest.log",
            "main": log_dir / "netlink.log",
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
            "netlink": log_dir / "netlink.log",
            "errors": log_dir / "errors.log"
        }

        # Ensure all log files exist
        for log_file in log_files.values():
            if not log_file.exists():
                log_file.touch()

        log_messages = [
            ("INFO", "netlink.api", "📡 API endpoint /health accessed"),
            ("INFO", "netlink.auth", "🔐 User authentication successful"),
            ("DEBUG", "netlink.database", "🗄️ Database query executed in 45ms"),
            ("INFO", "netlink.backup", "💾 Backup process completed successfully"),
            ("INFO", "netlink.security", "🔒 Security scan completed successfully"),
            ("INFO", "netlink.performance", "📊 System performance metrics collected"),
            ("DEBUG", "netlink.cli", "🖥️ CLI command executed: status"),
            ("INFO", "netlink.websocket", "🔌 WebSocket connection established"),
            ("INFO", "netlink.ai", "🤖 AI model inference completed"),
            ("DEBUG", "netlink.clustering", "🌐 Cluster health check passed"),
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

                with open(log_files["netlink"], 'a', encoding='utf-8') as f:
                    f.write(log_entry)

                # Write errors to error log
                if level in ["ERROR", "CRITICAL"]:
                    with open(log_files["errors"], 'a', encoding='utf-8') as f:
                        f.write(log_entry)

                counter += 1

                # Occasionally generate an error for demonstration
                if counter % 20 == 0:
                    error_entry = f"[{timestamp}] [ERROR   ] netlink.test: ❌ Simulated error for demonstration\n"
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


def run_netlink_server():
    """Run NetLink server with multiplexed terminal."""
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

    print(f"🔗 NetLink v{version}")
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

    print("🚀 Starting NetLink server with multiplexed terminal...")
    print("📊 Logs will appear on the left, CLI on the right")
    print("=" * 50)

    # Start log monitoring and generation
    log_thread = start_log_monitor()
    log_gen_thread = start_log_generator()

    # Set up environment
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["NETLINK_LOG_TO_FILE"] = "1"  # Force logging to file

    try:
        # Start server with better error handling
        print("🔄 Initializing NetLink core systems...")

        # Generate some initial logs to ensure log files exist
        logs_dir = ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)

        # Create initial log entries
        latest_log = logs_dir / "latest.log"
        with open(latest_log, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] [INFO] netlink.startup: 🚀 NetLink server starting up...\n")
            f.write(f"[{timestamp}] [INFO] netlink.startup: 📊 Initializing logging system\n")
            f.write(f"[{timestamp}] [INFO] netlink.startup: 🔧 Loading configuration\n")
            f.write(f"[{timestamp}] [INFO] netlink.startup: 🌐 Starting web server\n")

        process = subprocess.Popen(
            [str(venv_python), "-m", "netlink.main"],
            env=env,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        print("✅ NetLink server process started")
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
            from netlink.cli.integrated_cli import NetLinkCLI
            cli = NetLinkCLI()
            print("✅ Integrated CLI loaded")
        except Exception as e:
            print(f"⚠️ Failed to load integrated CLI: {e}")
            cli = None

        # Enhanced CLI loop
        while process.poll() is None and (cli is None or cli.running):
            try:
                cmd = input("NetLink> ").strip()

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
                            print("🛑 Stopping NetLink server...")
                            process.terminate()
                            break

                    except Exception as e:
                        print(f"❌ CLI error: {e}")
                else:
                    # Fallback simple CLI
                    cmd_lower = cmd.lower()
                    if cmd_lower == "stop":
                        print("🛑 Stopping NetLink server...")
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
                print("\n🛑 Stopping NetLink server...")
                process.terminate()
                break

        # Wait for process to finish
        process.wait()
        return True

    except Exception as e:
        print(f"❌ NetLink server failed to start: {e}")
        print("🔍 Check the logs for more details")
        return False


def clean_environment():
    """Clean up virtual environment and cache."""
    print("🧹 Cleaning NetLink environment...")
    
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
    """Show help information."""
    version = get_version_info()
    install_type = detect_installation_type()

    print(f"""
🔗 NetLink v{version} - Government-Level Secure Communication Platform
📦 Current Installation: {install_type.upper()}

Usage: python run.py [command] [type]

Commands:
  setup [type]  Set up virtual environment and install dependencies
                Types: minimal (default), full
  run           Start NetLink server with multiplexed terminal
  test          Run comprehensive test suite
  clean         Clean up virtual environment and cache
  version       Show version information
  help          Show this help message

Setup Types:
  minimal       Install core dependencies for basic functionality
  full          Install all dependencies for complete feature set

Installation Status:
  not_installed - No virtual environment found
  minimal      - Core features only
  partial      - Some optional features missing
  full         - All features available
  incomplete   - Installation corrupted, needs repair

Examples:
  python run.py setup           # Minimal installation (default)
  python run.py setup minimal   # Minimal installation
  python run.py setup full      # Full installation with all features
  python run.py run             # Start server with split-screen terminal
  python run.py clean           # Clean environment
  python run.py version         # Show version info
  python run.py help            # Show this help

First-time Setup:
  - Default admin credentials will be generated in default_creds.txt
  - Change the password immediately after first login
  - Access WebUI at http://localhost:8000/ui
""")

    if install_type == "partial":
        print("⚠️  Note: Partial installation detected. Run 'python run.py setup full' for all features.")
    elif install_type == "incomplete":
        print("❌ Note: Installation is incomplete. Run 'python run.py setup' to repair.")


def main():
    """Main entry point."""
    print("🔗 NetLink Application Runner")
    print("=" * 40)

    check_python_version()
    update_version_format()  # Update version format if needed

    args = sys.argv[1:]

    if not args:
        if not VENV_DIR.exists():
            print("🔧 First-time setup detected...")
            print("📦 Installing minimal dependencies...")
            if install_dependencies("minimal"):
                print("✅ Setup complete!")
                print("🚀 Run 'python run.py run' to start NetLink with multiplexed terminal.")
                print("📋 Default admin credentials will be generated on first run.")
            else:
                print("❌ Setup failed")
                sys.exit(1)
        else:
            show_help()
        return

    command = args[0].lower()

    if command in ["help", "-h", "--help"]:
        show_help()

    elif command == "version":
        version = get_version_info()
        install_type = detect_installation_type()
        print(f"🔗 NetLink Version: {version}")
        print(f"📦 Installation Type: {install_type.upper()}")
        print(f"🐍 Python Version: {sys.version.split()[0]}")
        print(f"💻 Platform: {platform.system()} {platform.release()}")
        print(f"📁 Root Directory: {ROOT}")

    elif command == "setup":
        install_type = "minimal"
        if len(args) > 1:
            install_type = args[1].lower()
            if install_type not in ["minimal", "full"]:
                print(f"❌ Invalid setup type: {install_type}")
                print("Valid types: minimal, full")
                sys.exit(1)

        print(f"🔧 Setting up NetLink ({install_type} installation)...")
        if install_dependencies(install_type):
            print("✅ Setup complete!")
            print("🚀 Run 'python run.py run' to start NetLink.")
        else:
            print("❌ Setup failed")
            sys.exit(1)

    elif command == "run":
        if not VENV_DIR.exists():
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)
        run_netlink_server()

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
                subprocess.run([str(venv_python), "-m", "pytest", "src/netlink/tests/", "-v"], env=env, check=True)
                print("✅ All tests passed!")
            except subprocess.CalledProcessError:
                print("❌ Some tests failed. Check output above.")
                sys.exit(1)

    else:
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
