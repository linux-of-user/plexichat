#!/usr/bin/env python3
"""
NetLink Main Entry Point - Root Runner with Auto-Setup

Main entry point that handles environment setup, dependency installation,
and runs the comprehensive NetLink system.
"""

import sys
import os
import subprocess
import json
import time
import threading
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any

# Set up paths
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
CONFIG_DIR = ROOT / "config"
LOGS_DIR = ROOT / "logs"
DATA_DIR = ROOT / "data"
REQUIREMENTS = ROOT / "requirements.txt"

# Add src to Python path for imports
sys.path.insert(0, str(SRC))

def ensure_directories():
    """Ensure required directories exist."""
    required_dirs = [CONFIG_DIR, LOGS_DIR, DATA_DIR, ROOT / "backups", ROOT / "databases"]
    for directory in required_dirs:
        directory.mkdir(exist_ok=True)
    return True

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print(f"❌ Python 3.8+ required (found {sys.version_info.major}.{sys.version_info.minor})")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True

def check_pip_available():
    """Check if pip is available."""
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"],
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False

def install_core_dependencies():
    """Install core dependencies only."""
    print("🔧 Installing core NetLink dependencies...")

    # Check if pip is available
    if not check_pip_available():
        print("⚠️ pip not available. Attempting to run without dependencies...")
        print("💡 You may need to install dependencies manually:")
        print("   pip install fastapi uvicorn customtkinter pillow")
        return True  # Continue anyway

    core_deps = [
        "fastapi==0.115.12",
        "uvicorn[standard]==0.31.0",
        "starlette==0.41.2",
        "sqlmodel==0.0.24",
        "sqlalchemy==2.0.31",
        "aiosqlite==0.19.0",
        "pydantic==2.5.0",
        "python-jose[cryptography]==3.3.0",
        "passlib[bcrypt]==1.7.4",
        "cryptography==42.0.5",
        "bleach==6.1.0",
        "python-magic==0.4.27",
        "pycryptodome==3.19.0",
        "argon2-cffi==23.1.0",
        "requests==2.31.0",
        "aiofiles==23.2.1",
        "python-multipart==0.0.6",
        "jinja2==3.1.2",
        "websockets==12.0",
        "pyyaml==6.0.1"
    ]

    try:
        # Upgrade pip first (skip if pip not available)
        if check_pip_available():
            print("📦 Upgrading pip...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])
        else:
            print("⚠️ Skipping pip upgrade - pip not available")

        # Install core dependencies one by one
        for dep in core_deps:
            try:
                print(f"📦 Installing {dep.split('==')[0]}...")
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", dep
                ])
            except subprocess.CalledProcessError as e:
                print(f"⚠️ Failed to install {dep}: {e}")
                # Continue with other dependencies

        # Install optional GUI dependencies
        print("🖥️ Installing GUI dependencies...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "customtkinter", "pillow"
            ])
            print("✅ GUI dependencies installed!")
        except subprocess.CalledProcessError:
            print("⚠️ GUI dependencies failed (optional)")

        print("✅ Core dependencies installed successfully!")
        return True

    except Exception as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def install_dependencies():
    """Install Python dependencies with fallback to core only."""
    print("🔧 Installing NetLink dependencies...")

    # Check if requirements.txt exists
    if not REQUIREMENTS.exists():
        print(f"❌ Requirements file not found: {REQUIREMENTS}")
        return install_core_dependencies()

    try:
        # Upgrade pip first (skip if pip not available)
        if check_pip_available():
            print("📦 Upgrading pip...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])
        else:
            print("⚠️ Skipping pip upgrade - pip not available")

        # Try to install full requirements
        print("📦 Installing full requirements...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ Full dependencies installed successfully!")
            return True
        else:
            print("⚠️ Some dependencies failed, installing core dependencies only...")
            return install_core_dependencies()

    except Exception as e:
        print(f"⚠️ Full installation failed: {e}")
        print("🔄 Falling back to core dependencies...")
        return install_core_dependencies()

def verify_installation():
    """Verify that the installation is working."""
    print("🔍 Verifying installation...")

    try:
        # Test critical imports
        critical_imports = [
            "fastapi",
            "uvicorn",
            "sqlmodel",
            "pydantic",
            "cryptography",
            "bcrypt"
        ]

        failed_imports = []
        for module in critical_imports:
            try:
                __import__(module)
            except ImportError:
                failed_imports.append(module)

        if failed_imports:
            print(f"❌ Missing critical modules: {failed_imports}")
            return False

        print("✅ Critical modules verified!")
        return True

    except Exception as e:
        print(f"❌ Installation verification failed: {e}")
        return False

def auto_setup():
    """Automatic setup on first run."""
    print("🚀 NetLink Auto-Setup")
    print("=" * 40)

    # Check Python version
    if not check_python_version():
        return False

    # Ensure directories exist
    print("📁 Creating directories...")
    ensure_directories()
    print("✅ Directories created!")

    # Install dependencies
    if not install_dependencies():
        return False

    # Verify installation
    if not verify_installation():
        return False

    print("🎉 Auto-setup completed successfully!")
    return True

def check_setup():
    """Check if setup is needed."""
    # Check if basic directories exist
    required_dirs = [CONFIG_DIR, LOGS_DIR, DATA_DIR, ROOT / "backups"]
    missing_dirs = [d for d in required_dirs if not d.exists()]

    # Check if we can import critical modules
    try:
        import fastapi
        import uvicorn
        modules_ok = True
    except ImportError:
        modules_ok = False

    return len(missing_dirs) == 0 and modules_ok

def run_netlink_with_args(args):
    """Run NetLink with the provided arguments."""
    try:
        # Handle different commands
        if not args or args[0] in ['-h', '--help']:
            # Show help
            from netlink.run import main as run_main
            run_main()
            return

        command = args[0]

        if command == "install":
            success = install_dependencies()
            if len(args) > 1 and "--setup-db" in args:
                # Import the comprehensive runner from src for database setup
                from netlink.run import NetLinkRunner
                runner = NetLinkRunner()
                runner.setup_database()

        elif command == "run":
            # Import the comprehensive runner from src
            from netlink.run import NetLinkRunner
            runner = NetLinkRunner()

            # Parse host and port from args
            host = None
            port = None
            debug = False

            i = 1
            while i < len(args):
                if args[i] == "--host" and i + 1 < len(args):
                    host = args[i + 1]
                    i += 2
                elif args[i] == "--port" and i + 1 < len(args):
                    port = int(args[i + 1])
                    i += 2
                elif args[i] == "--debug":
                    debug = True
                    i += 1
                else:
                    i += 1

            runner.run_server(host, port, debug)

        elif command == "gui":
            # Handle GUI command specially - don't require full setup
            print("🖥️ Starting NetLink GUI...")

            # Try to run GUI with minimal setup
            try:
                # Add src to path
                src_path = os.path.join(os.path.dirname(__file__), "src")
                if src_path not in sys.path:
                    sys.path.insert(0, src_path)

                # Import and use the comprehensive runner for GUI only
                from netlink.run import NetLinkRunner
                runner = NetLinkRunner()
                success = runner.run_gui()

                if not success:
                    print("❌ GUI failed to start")
                    sys.exit(1)

            except ImportError as e:
                print(f"❌ Could not import NetLink runner: {e}")
                print("💡 Trying direct GUI launch...")

                # Try direct GUI launch
                gui_script = os.path.join(os.path.dirname(__file__), "src", "netlink", "gui", "netlink_admin_gui.py")
                if os.path.exists(gui_script):
                    # Install GUI dependencies first with bulletproof method
                    print("📦 Installing GUI dependencies...")
                    gui_deps = ["customtkinter", "pillow", "requests"]

                    # Try multiple installation strategies
                    strategies = [
                        [sys.executable, "-m", "pip", "install", "--user"],
                        [sys.executable, "-m", "pip", "install"],
                        ["pip3", "install", "--user"],
                        ["pip", "install", "--user"],
                        ["python3", "-m", "pip", "install", "--user"],
                        ["python", "-m", "pip", "install", "--user"]
                    ]

                    installed_any = False
                    for strategy in strategies:
                        try:
                            # Test strategy
                            test_cmd = strategy[:-1] + ["--version"]
                            test_result = subprocess.run(test_cmd, capture_output=True, timeout=5)
                            if test_result.returncode != 0:
                                continue

                            print(f"💡 Using: {' '.join(strategy)}")

                            # Install dependencies
                            for dep in gui_deps:
                                try:
                                    result = subprocess.run(strategy + [dep],
                                                          capture_output=True, timeout=60)
                                    if result.returncode == 0:
                                        print(f"✅ {dep} installed")
                                        installed_any = True
                                except:
                                    pass

                            if installed_any:
                                break

                        except:
                            continue

                    if not installed_any:
                        print("⚠️ Could not install GUI dependencies automatically")

                    # Launch GUI directly
                    env = os.environ.copy()
                    env['PYTHONPATH'] = src_path + os.pathsep + env.get('PYTHONPATH', '')

                    result = subprocess.run([sys.executable, gui_script], env=env)
                    sys.exit(result.returncode)
                else:
                    print(f"❌ GUI script not found at: {gui_script}")
                    sys.exit(1)

        else:
            # For all other commands, import and use the comprehensive runner
            from netlink.run import NetLinkRunner
            runner = NetLinkRunner()

            if command == "full":
                # Parse host and port from args
                host = None
                port = None

                i = 1
                while i < len(args):
                    if args[i] == "--host" and i + 1 < len(args):
                        host = args[i + 1]
                        i += 2
                    elif args[i] == "--port" and i + 1 < len(args):
                        port = int(args[i + 1])
                        i += 2
                    else:
                        i += 1

                runner.run_full(host, port)

            elif command == "cli":
                cli_args = args[1:] if len(args) > 1 else []
                if "--admin" in cli_args:
                    cli_args.remove("--admin")
                    runner.run_admin_cli(cli_args)
                else:
                    runner.run_cli(cli_args)

            elif command == "upgrade":
                runner.upgrade()

            elif command == "status":
                runner.status()

            elif command == "test":
                runner.test()

            elif command == "setup-db":
                runner.setup_database()

            elif command == "check":
                runner.system_check()

            else:
                print(f"❌ Unknown command: {command}")
                from netlink.run import main as run_main
                run_main()

    except ImportError as e:
        print(f"❌ Error importing NetLink runner: {e}")
        print("This usually means dependencies are not installed.")
        print("🔧 Running auto-setup...")
        if auto_setup():
            print("✅ Setup complete! Please run your command again.")
        else:
            print("❌ Auto-setup failed. Please check the error messages above.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error running NetLink: {e}")
        sys.exit(1)

# Main entry point
if __name__ == "__main__":
    try:
        # Get command line arguments
        args = sys.argv[1:]  # Remove script name

        # Skip setup for GUI command - handle it specially
        if args and args[0] == "gui":
            run_netlink_with_args(args)
        else:
            # Check if setup is needed for other commands
            if not check_setup():
                print("🔧 First-time setup detected...")
                if not auto_setup():
                    print("❌ Setup failed. Please check the error messages above.")
                    sys.exit(1)

            # Run NetLink with command line arguments
            run_netlink_with_args(args)

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
