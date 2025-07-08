#!/usr/bin/env python3
"""
NetLink Main Runner - Comprehensive Management System
Provides installation, server management, GUI, CLI, and maintenance commands.
"""

import argparse
import subprocess
import sys
import os
import json
import time
import threading
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any

# Set up paths
ROOT = Path(__file__).parent.parent.parent.resolve()  # Go up to project root
SRC = ROOT / "src"
CONFIG_DIR = ROOT / "config"
LOGS_DIR = ROOT / "logs"
DATA_DIR = ROOT / "data"
REQUIREMENTS = ROOT / "requirements.txt"

# Add src to Python path for imports
sys.path.insert(0, str(SRC))

# Auto-setup check and execution
def ensure_setup():
    """Ensure NetLink is properly set up."""
    setup_script = ROOT / "scripts" / "auto_setup.py"

    # Check if basic directories exist
    required_dirs = [CONFIG_DIR, LOGS_DIR, DATA_DIR, ROOT / "backups", ROOT / "databases"]
    missing_dirs = [d for d in required_dirs if not d.exists()]

    if missing_dirs or not (CONFIG_DIR / "netlink.json").exists():
        print("🔧 First-time setup detected, running auto-setup...")
        try:
            result = subprocess.run([sys.executable, str(setup_script)],
                                  capture_output=True, text=True, cwd=ROOT)
            if result.returncode != 0:
                print(f"❌ Auto-setup failed: {result.stderr}")
                return False
            print("✅ Auto-setup completed successfully")
        except Exception as e:
            print(f"❌ Auto-setup error: {e}")
            return False

    return True

# Only ensure setup if not being imported for GUI
if __name__ == "__main__" or "gui" not in sys.argv:
    if not ensure_setup():
        print("❌ Setup failed. Please run 'python scripts/auto_setup.py' manually.")
        sys.exit(1)

# Add src to Python path
sys.path.insert(0, str(SRC))

class NetLinkRunner:
    """Main NetLink application runner."""

    def __init__(self):
        self.version = "1.0.0-alpha.1"
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        config_file = CONFIG_DIR / "netlink.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load config: {e}")

        # Default configuration
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False,
                "auto_reload": False
            },
            "security": {
                "https_enabled": False,
                "https_cert_file": None,
                "https_key_file": None,
                "auto_cert": False
            },
            "database": {
                "url": "sqlite:///./data/netlink.db",
                "auto_migrate": True
            },
            "gui": {
                "auto_start": False,
                "minimize_to_tray": True
            },
            "features": {
                "auto_backup": True,
                "integrity_check": True,
                "plugin_system": True
            }
        }

        # Save default config
        self._save_config(default_config)
        return default_config

    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file."""
        config_file = CONFIG_DIR / "netlink.json"
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save config: {e}")

    def install_dependencies(self):
        """Install Python dependencies."""
        print("🔧 Installing NetLink dependencies...")

        # Check if requirements.txt exists
        if not REQUIREMENTS.exists():
            print(f"❌ Requirements file not found: {REQUIREMENTS}")
            return False

        try:
            # Upgrade pip first
            print("📦 Upgrading pip...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])

            # Install requirements
            print("📦 Installing requirements...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)
            ])

            # Install optional GUI dependencies
            print("🖥️ Installing GUI dependencies...")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", "customtkinter", "pillow"
                ])
                print("✅ GUI dependencies installed!")
            except subprocess.CalledProcessError:
                print("⚠️ GUI dependencies failed (optional)")

            print("✅ Dependencies installed successfully!")

            # Verify installation
            return self.verify_installation()

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False

    def verify_installation(self):
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

            # Test NetLink imports
            try:
                from netlink.app.main import app
                print("✅ NetLink main app import successful!")
            except ImportError as e:
                print(f"⚠️ NetLink app import failed: {e}")

            return True

        except Exception as e:
            print(f"❌ Installation verification failed: {e}")
            return False

    def setup_database(self):
        """Set up the database."""
        print("🗄️ Setting up database...")
        try:
            # Try to use the database setup script
            setup_script = ROOT / "scripts" / "setup_database.py"
            if setup_script.exists():
                print("🔧 Running database setup script...")
                result = subprocess.run([sys.executable, str(setup_script)], cwd=ROOT)
                if result.returncode == 0:
                    print("✅ Database setup completed!")
                    return True
                else:
                    print("❌ Database setup script failed")
                    return False

            # Fallback to wizard import
            from netlink.core.database_setup_wizard import DatabaseSetupWizard
            wizard = DatabaseSetupWizard()
            result = wizard.setup_database()
            if result.get("success", False):
                print("✅ Database setup completed!")
                return True
            else:
                print(f"❌ Database setup failed: {result.get('error', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"❌ Database setup failed: {e}")
            return False

    def run_server(self, host: str = None, port: int = None, debug: bool = False):
        """Run the NetLink server."""
        host = host or self.config["server"]["host"]
        port = port or self.config["server"]["port"]

        print(f"🚀 Starting NetLink Server v{self.version}")
        print(f"   Server: http://{host}:{port}")
        print(f"   Admin Panel: http://{host}:{port}/ui")
        print(f"   API Docs: http://{host}:{port}/docs")
        print(f"   Management: http://{host}:{port}/management")
        print("Press Ctrl+C to stop")

        try:
            # Check if HTTPS is enabled
            https_config = self.config.get("security", {})
            if https_config.get("https_enabled"):
                cert_file = https_config.get("https_cert_file")
                key_file = https_config.get("https_key_file")

                if cert_file and key_file and Path(cert_file).exists() and Path(key_file).exists():
                    print(f"🔒 HTTPS enabled with certificates")
                    import uvicorn
                    uvicorn.run(
                        "netlink.app.main:app",
                        host=host,
                        port=port,
                        ssl_keyfile=key_file,
                        ssl_certfile=cert_file,
                        reload=debug,
                        log_level="debug" if debug else "info"
                    )
                    return

            # Run with HTTP
            import uvicorn
            uvicorn.run(
                "netlink.app.main:app",
                host=host,
                port=port,
                reload=debug,
                log_level="debug" if debug else "info"
            )

        except KeyboardInterrupt:
            print("\n🛑 Server stopped by user")
        except Exception as e:
            print(f"❌ Server error: {e}")
            return False
        return True

    def run_gui(self):
        """Run the GUI dashboard with auto-installation and venv support."""
        print("🖥️ Starting NetLink GUI Dashboard...")

        # Check if GUI directory exists in the correct location
        gui_dir = ROOT / "src" / "netlink" / "gui"
        if not gui_dir.exists():
            print(f"❌ GUI directory not found at: {gui_dir}")
            # Try alternative location
            alt_gui_dir = ROOT / "gui"
            if alt_gui_dir.exists():
                gui_dir = alt_gui_dir
                print(f"✅ Found GUI at alternative location: {gui_dir}")
            else:
                print("❌ GUI directory not found in any expected location")
                return False

        # Try to use existing venv or create one
        venv_python = self._ensure_gui_venv()
        if venv_python:
            return self._run_gui_with_venv(venv_python, gui_dir)

        # Fallback: try with current Python after installing dependencies
        if not self._ensure_gui_dependencies():
            return False

        return self._run_gui_direct(gui_dir)

    def _ensure_gui_venv(self):
        """Ensure GUI virtual environment exists with dependencies."""
        venv_dir = ROOT / "gui_venv"

        # Check if venv already exists and works
        if venv_dir.exists():
            venv_python = self._get_venv_python(venv_dir)
            if venv_python and self._check_venv_dependencies(venv_python):
                print("✅ Using existing GUI virtual environment")
                return venv_python

        # Create new venv
        print("🔧 Creating GUI virtual environment...")
        try:
            # Create venv
            result = subprocess.run([
                sys.executable, "-m", "venv", str(venv_dir)
            ], capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                print(f"❌ Failed to create venv: {result.stderr}")
                return None

            venv_python = self._get_venv_python(venv_dir)
            if not venv_python:
                print("❌ Could not find venv Python executable")
                return None

            # Install dependencies in venv
            print("📦 Installing GUI dependencies in virtual environment...")
            deps = ["customtkinter", "pillow", "requests"]

            for dep in deps:
                print(f"📦 Installing {dep}...")
                result = subprocess.run([
                    venv_python, "-m", "pip", "install", dep
                ], capture_output=True, text=True, timeout=120)

                if result.returncode == 0:
                    print(f"✅ {dep} installed in venv")
                else:
                    print(f"❌ Failed to install {dep} in venv: {result.stderr[:200]}")

            # Verify dependencies
            if self._check_venv_dependencies(venv_python):
                print("✅ GUI virtual environment ready!")
                return venv_python
            else:
                print("❌ GUI dependencies not working in venv")
                return None

        except Exception as e:
            print(f"❌ Error creating GUI venv: {e}")
            return None

    def _get_venv_python(self, venv_dir):
        """Get Python executable path for venv."""
        if os.name == 'nt':  # Windows
            python_exe = venv_dir / "Scripts" / "python.exe"
        else:  # Unix/Linux/Mac
            python_exe = venv_dir / "bin" / "python"

        if python_exe.exists():
            return str(python_exe)
        return None

    def _check_venv_dependencies(self, venv_python):
        """Check if venv has required GUI dependencies."""
        deps = ["customtkinter", "PIL", "requests"]

        for dep in deps:
            try:
                result = subprocess.run([
                    venv_python, "-c", f"import {dep}"
                ], capture_output=True, timeout=10)

                if result.returncode != 0:
                    return False
            except:
                return False

        return True

    def _run_gui_with_venv(self, venv_python, gui_dir):
        """Run GUI using virtual environment."""
        try:
            gui_script = gui_dir / "netlink_admin_gui.py"
            if not gui_script.exists():
                print(f"❌ GUI script not found at: {gui_script}")
                return False

            print("🚀 Launching NetLink Admin GUI with virtual environment...")

            # Set up environment
            env = os.environ.copy()
            src_path = str(ROOT / "src")
            gui_path = str(gui_dir)
            env['PYTHONPATH'] = f"{src_path}{os.pathsep}{gui_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

            # Launch GUI with venv Python
            result = subprocess.run([
                venv_python, str(gui_script)
            ], cwd=str(gui_dir), env=env)

            return result.returncode == 0

        except Exception as e:
            print(f"❌ GUI venv launch error: {e}")
            return False

    def _run_gui_direct(self, gui_dir):
        """Run GUI directly with current Python."""
        try:
            gui_script = gui_dir / "netlink_admin_gui.py"
            if not gui_script.exists():
                print(f"❌ GUI script not found at: {gui_script}")
                return False

            print("🚀 Launching NetLink Admin GUI...")

            # Add GUI directory and src to path
            gui_path = str(gui_dir)
            src_path = str(ROOT / "src")

            for path in [gui_path, src_path]:
                if path not in sys.path:
                    sys.path.insert(0, path)

            # Set up environment
            env = os.environ.copy()
            env['PYTHONPATH'] = f"{src_path}{os.pathsep}{gui_path}{os.pathsep}{env.get('PYTHONPATH', '')}"

            # Launch GUI
            result = subprocess.run([
                sys.executable, str(gui_script)
            ], cwd=str(gui_dir), env=env)

            return result.returncode == 0

        except Exception as e:
            print(f"❌ GUI direct launch error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _ensure_gui_dependencies(self):
        """Ensure GUI dependencies are installed on any OS with bulletproof installation."""
        print("🔍 Checking GUI dependencies...")

        # List of required GUI dependencies
        gui_deps = [
            "customtkinter",
            "pillow",
            "requests"
        ]

        # Check tkinter first (usually comes with Python)
        try:
            import tkinter
            print("✅ tkinter found")
        except ImportError:
            print("❌ tkinter missing - this usually comes with Python")
            print("💡 On Ubuntu/Debian: sudo apt-get install python3-tk")
            print("💡 On CentOS/RHEL: sudo yum install tkinter")
            print("💡 On macOS: tkinter should be included with Python")
            return False

        # Check which dependencies are missing
        missing_deps = []
        for dep in gui_deps:
            try:
                if dep == "pillow":
                    import PIL
                    print(f"✅ {dep} found")
                elif dep == "customtkinter":
                    import customtkinter
                    print(f"✅ {dep} found")
                elif dep == "requests":
                    import requests
                    print(f"✅ {dep} found")
                else:
                    __import__(dep)
                    print(f"✅ {dep} found")
            except ImportError:
                missing_deps.append(dep)
                print(f"❌ {dep} missing")

        # Install missing dependencies if any
        if missing_deps:
            return self._install_dependencies_bulletproof(missing_deps)

        print("✅ All GUI dependencies are available!")
        return True

    def _install_dependencies_bulletproof(self, deps):
        """Bulletproof dependency installation that works on any OS."""
        print(f"📦 Installing missing GUI dependencies: {', '.join(deps)}")

        # Step 1: Ensure pip is available
        if not self._ensure_pip():
            return False

        # Step 2: Try multiple installation strategies
        strategies = [
            # Strategy 1: Direct python -m pip
            [sys.executable, "-m", "pip", "install", "--user"],
            [sys.executable, "-m", "pip", "install"],

            # Strategy 2: Try different pip executables
            ["pip3", "install", "--user"],
            ["pip", "install", "--user"],
            ["pip3", "install"],
            ["pip", "install"],

            # Strategy 3: Try with different python executables
            ["python3", "-m", "pip", "install", "--user"],
            ["python", "-m", "pip", "install", "--user"],
            ["python3", "-m", "pip", "install"],
            ["python", "-m", "pip", "install"],
        ]

        # Try each strategy
        for strategy in strategies:
            print(f"💡 Trying: {' '.join(strategy)}")

            # Test if this strategy works
            test_cmd = strategy[:-1] + ["--version"]  # Remove install, add --version
            try:
                test_result = subprocess.run(
                    test_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if test_result.returncode != 0:
                    continue

            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                continue

            # Try installing with this strategy
            success_count = 0
            for dep in deps:
                try:
                    print(f"📦 Installing {dep}...")
                    result = subprocess.run(
                        strategy + [dep],
                        capture_output=True,
                        text=True,
                        timeout=180  # 3 minutes per package
                    )

                    if result.returncode == 0:
                        print(f"✅ {dep} installed successfully")
                        success_count += 1
                    else:
                        print(f"⚠️ {dep} installation had issues: {result.stderr[:200]}")

                except subprocess.TimeoutExpired:
                    print(f"⏰ Timeout installing {dep}")
                except Exception as e:
                    print(f"❌ Error installing {dep}: {e}")

            # If we installed at least some packages, verify them
            if success_count > 0:
                print("🔍 Verifying installations...")
                verified_count = 0

                for dep in deps:
                    try:
                        if dep == "pillow":
                            import PIL
                        elif dep == "customtkinter":
                            import customtkinter
                        elif dep == "requests":
                            import requests
                        else:
                            __import__(dep)
                        print(f"✅ {dep} verified")
                        verified_count += 1
                    except ImportError:
                        print(f"❌ {dep} still not available")

                # If all dependencies are now available, we're done
                if verified_count == len(deps):
                    print("✅ All GUI dependencies installed and verified!")
                    return True
                elif verified_count > 0:
                    print(f"✅ {verified_count}/{len(deps)} dependencies working")

        # If we get here, installation failed
        print("❌ Could not install all GUI dependencies automatically")
        print("💡 Please try manual installation:")
        print(f"   python -m pip install --user {' '.join(deps)}")
        print("💡 Or create a virtual environment:")
        print("   python -m venv netlink_env")
        print("   # Activate: netlink_env\\Scripts\\activate (Windows) or source netlink_env/bin/activate (Linux/Mac)")
        print(f"   pip install {' '.join(deps)}")
        return False

    def _ensure_pip(self):
        """Ensure pip is available, install if necessary."""
        print("🔍 Checking pip availability...")

        # Try different ways to check pip
        pip_check_commands = [
            [sys.executable, "-m", "pip", "--version"],
            ["pip3", "--version"],
            ["pip", "--version"],
            ["python3", "-m", "pip", "--version"],
            ["python", "-m", "pip", "--version"]
        ]

        for cmd in pip_check_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"✅ pip found: {' '.join(cmd)}")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                continue

        print("❌ pip not found, attempting to install...")

        # Try to install pip
        pip_install_strategies = [
            # Strategy 1: ensurepip
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            [sys.executable, "-m", "ensurepip"],

            # Strategy 2: get-pip.py download and install
            "download_get_pip"
        ]

        for strategy in pip_install_strategies:
            if strategy == "download_get_pip":
                if self._install_pip_via_get_pip():
                    return True
            else:
                try:
                    print(f"💡 Trying: {' '.join(strategy)}")
                    result = subprocess.run(strategy, capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        print("✅ pip installed successfully")
                        return True
                    else:
                        print(f"⚠️ pip installation attempt failed: {result.stderr[:200]}")
                except Exception as e:
                    print(f"❌ pip installation error: {e}")

        print("❌ Could not install pip automatically")
        return False

    def _install_pip_via_get_pip(self):
        """Install pip by downloading get-pip.py."""
        try:
            print("📥 Downloading get-pip.py...")
            import urllib.request
            import tempfile

            with tempfile.NamedTemporaryFile(mode='w+b', suffix='.py', delete=False) as f:
                urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', f.name)
                get_pip_path = f.name

            print("🔧 Installing pip...")
            result = subprocess.run([sys.executable, get_pip_path],
                                  capture_output=True, text=True, timeout=120)

            # Clean up
            os.unlink(get_pip_path)

            if result.returncode == 0:
                print("✅ pip installed via get-pip.py")
                return True
            else:
                print(f"❌ get-pip.py failed: {result.stderr[:200]}")
                return False

        except Exception as e:
            print(f"❌ get-pip.py download/install failed: {e}")
            return False

    def run_cli(self, args):
        """Run the CLI interface."""
        try:
            # Try to import and run CLI
            try:
                from netlink.cli.main_cli import NetLinkCLI
                cli = NetLinkCLI()
                cli.run(args)
                return True
            except ImportError:
                # Fallback to direct CLI script
                cli_script = SRC / "netlink" / "cli" / "main_cli.py"
                if cli_script.exists():
                    cmd = [sys.executable, str(cli_script)] + (args or [])
                    result = subprocess.run(cmd, cwd=ROOT)
                    return result.returncode == 0
                else:
                    print("❌ CLI not available")
                    return False
        except Exception as e:
            print(f"❌ CLI error: {e}")
            return False

    def run_admin_cli(self, args):
        """Run the admin CLI interface."""
        try:
            # Try to import and run admin CLI
            try:
                from netlink.cli.admin_cli import AdminCLI
                cli = AdminCLI()

                # If args provided, construct sys.argv for argparse
                if args:
                    original_argv = sys.argv[:]
                    sys.argv = ['admin_cli'] + args
                    try:
                        cli.run()
                    finally:
                        sys.argv = original_argv
                else:
                    cli.run()
                return True
            except ImportError:
                # Fallback to direct CLI script
                cli_script = SRC / "netlink" / "cli" / "admin_cli.py"
                if cli_script.exists():
                    cmd = [sys.executable, str(cli_script)] + (args or [])
                    result = subprocess.run(cmd, cwd=ROOT)
                    return result.returncode == 0
                else:
                    print("❌ Admin CLI not available")
                    return False
        except Exception as e:
            print(f"❌ Admin CLI error: {e}")
            return False

    def system_check(self):
        """Comprehensive system check."""
        print("🔍 NetLink System Check")
        print("=" * 40)

        checks_passed = 0
        total_checks = 0

        # Check Python version
        total_checks += 1
        if sys.version_info >= (3, 8):
            print("✅ Python version: OK")
            checks_passed += 1
        else:
            print(f"❌ Python version: {sys.version} (requires 3.8+)")

        # Check directories
        total_checks += 1
        required_dirs = [CONFIG_DIR, DATA_DIR, LOGS_DIR, ROOT / "backups", ROOT / "src"]
        missing_dirs = [d for d in required_dirs if not d.exists()]
        if not missing_dirs:
            print("✅ Directory structure: OK")
            checks_passed += 1
        else:
            print(f"❌ Missing directories: {missing_dirs}")

        # Check configuration
        total_checks += 1
        config_file = CONFIG_DIR / "netlink.json"
        if config_file.exists():
            print("✅ Configuration file: OK")
            checks_passed += 1
        else:
            print("❌ Configuration file: Missing")

        # Check requirements
        total_checks += 1
        if REQUIREMENTS.exists():
            print("✅ Requirements file: OK")
            checks_passed += 1
        else:
            print("❌ Requirements file: Missing")

        # Check main application
        total_checks += 1
        main_app = SRC / "netlink" / "app" / "main.py"
        if main_app.exists():
            print("✅ Main application: OK")
            checks_passed += 1
        else:
            print("❌ Main application: Missing")

        print(f"\n📊 System Check Results: {checks_passed}/{total_checks} checks passed")

        if checks_passed == total_checks:
            print("🎉 System is ready!")
            return True
        else:
            print("⚠️ System needs attention")
            if missing_dirs:
                print("💡 Run: python scripts/auto_setup.py")
            return False

    def run_web_only(self, host: str = None, port: int = None):
        """Run web server only (no GUI)."""
        return self.run_server(host, port, debug=False)

    def run_full(self, host: str = None, port: int = None):
        """Run server with GUI dashboard."""
        host = host or self.config["server"]["host"]
        port = port or self.config["server"]["port"]

        print("🚀 Starting NetLink Full System...")

        # Start server in background thread
        server_thread = threading.Thread(
            target=self.run_server,
            args=(host, port, False),
            daemon=True
        )
        server_thread.start()

        # Wait a moment for server to start
        time.sleep(2)

        # Start GUI
        return self.run_gui()

    def upgrade(self):
        """Upgrade NetLink system using new update system."""
        print("🔄 Upgrading NetLink...")
        try:
            # Use new update system
            import asyncio
            from netlink.cli.update_cli import UpdateCLI

            update_cli = UpdateCLI()

            # Create mock args for upgrade
            class MockArgs:
                def __init__(self):
                    self.to = None
                    self.latest = True
                    self.stable = False
                    self.force = False
                    self.dry_run = False

            args = MockArgs()
            success = asyncio.run(update_cli.handle_upgrade(args))

            if success:
                print("✅ Upgrade completed successfully!")
            else:
                print("❌ Upgrade failed")
                return False

        except ImportError:
            print("⚠️ New update system not available, trying legacy updater...")
            try:
                from netlink.app.core.updater import NetLinkUpdater
                updater = NetLinkUpdater()

                # Check for updates
                update_info = updater.check_for_updates()
                if update_info.get("update_available"):
                    print(f"📦 Update available: v{update_info['latest_version']}")

                    # Perform update
                    result = updater.perform_hot_update(update_info)
                    if result.get("success"):
                        print("✅ Update completed successfully!")
                        if result.get("restart_required"):
                            print("🔄 Restart required to complete update")
                    else:
                        print(f"❌ Update failed: {result.get('message')}")
                        return False
                else:
                    print("✅ NetLink is already up to date!")

            except ImportError:
                print("⚠️ Updater module not available")
                print("💡 Manual update: git pull && pip install -r requirements.txt")
                return False

        except Exception as e:
            print(f"❌ Upgrade error: {e}")
            return False
        return True

    def status(self):
        """Show system status."""
        print(f"📊 NetLink v{self.version} Status")
        print("=" * 40)

        # Check server status
        try:
            import requests
            host = self.config["server"]["host"]
            port = self.config["server"]["port"]

            if host == "0.0.0.0":
                host = "localhost"

            # Try multiple endpoints
            endpoints = ["/api/status", "/health", "/"]
            server_running = False

            for endpoint in endpoints:
                try:
                    response = requests.get(f"http://{host}:{port}{endpoint}", timeout=3)
                    if response.status_code in [200, 404]:  # 404 is also a valid response
                        server_running = True
                        break
                except:
                    continue

            if server_running:
                print("🟢 Server: Running")
            else:
                print("🔴 Server: Not running")
        except Exception as e:
            print(f"🔴 Server: Not running ({e})")

        # Check database
        try:
            # Try multiple database manager imports
            db_connected = False
            try:
                from netlink.app.db.database_manager import DatabaseManager
                db = DatabaseManager()
                if hasattr(db, 'test_connection') and db.test_connection():
                    db_connected = True
            except ImportError:
                try:
                    from netlink.app.db.enhanced_database_manager import EnhancedDatabaseManager
                    db = EnhancedDatabaseManager()
                    if hasattr(db, 'test_connection') and db.test_connection():
                        db_connected = True
                except ImportError:
                    pass

            if db_connected:
                print("🟢 Database: Connected")
            else:
                print("🔴 Database: Connection failed")
        except Exception as e:
            print(f"🔴 Database: Not available ({e})")

        # Check file system
        required_dirs = [CONFIG_DIR, DATA_DIR, LOGS_DIR, ROOT / "backups"]
        missing_dirs = [d for d in required_dirs if not d.exists()]

        if missing_dirs:
            print(f"⚠️ Missing directories: {[str(d) for d in missing_dirs]}")
        else:
            print("🟢 File system: OK")

        # Show configuration
        print(f"🔧 Config: {CONFIG_DIR / 'netlink.json'}")
        print(f"📁 Data: {DATA_DIR}")
        print(f"📋 Logs: {LOGS_DIR}")

        # Show recent log file
        latest_log = LOGS_DIR / "latest.log"
        if latest_log.exists():
            print(f"📄 Latest log: {latest_log} ({latest_log.stat().st_size} bytes)")
        else:
            print("📄 Latest log: Not found")

    def test(self):
        """Run system tests."""
        print("🧪 Running NetLink system tests...")
        try:
            # Try to find and run system validator
            test_files = [
                ROOT / "tests" / "validate_system.py",
                ROOT / "tests" / "final_validation.py",
                ROOT / "tests" / "quick_test.py"
            ]

            test_run = False
            for test_file in test_files:
                if test_file.exists():
                    print(f"🔍 Running {test_file.name}...")
                    result = subprocess.run([sys.executable, str(test_file)], cwd=ROOT)
                    test_run = True
                    if result.returncode == 0:
                        print(f"✅ {test_file.name} passed!")
                    else:
                        print(f"❌ {test_file.name} failed!")
                    break

            if not test_run:
                # Fallback to import-based testing
                try:
                    from tests.validate_system import SystemValidator
                    validator = SystemValidator()
                    results = validator.run_all_tests()

                    if results.get("success"):
                        print("✅ All tests passed!")
                    else:
                        print("❌ Some tests failed:")
                        for test, result in results.get("tests", {}).items():
                            status = "✅" if result else "❌"
                            print(f"  {status} {test}")
                except ImportError:
                    print("⚠️ No test files found")
                    print("💡 Basic system check:")
                    self.status()
                    return True

        except Exception as e:
            print(f"❌ Test error: {e}")
            return False
        return True


def main():
    """Main entry point."""
    runner = NetLinkRunner()

    parser = argparse.ArgumentParser(
        description=f"NetLink v{runner.version} - Government-Level Secure Communication Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py install              # Install dependencies
  python run.py run                  # Run server only
  python run.py gui                  # Run GUI dashboard
  python run.py full                 # Run server + GUI
  python run.py cli --help           # CLI help
  python run.py upgrade              # Upgrade system
  python run.py status               # Show status
  python run.py test                 # Run tests
  python run.py check                # System check
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Install command
    install_parser = subparsers.add_parser("install", help="Install dependencies and setup")
    install_parser.add_argument("--setup-db", action="store_true", help="Also setup database")

    # Run command (server only)
    run_parser = subparsers.add_parser("run", help="Run NetLink server")
    run_parser.add_argument("--host", default=None, help="Host to bind (default from config)")
    run_parser.add_argument("--port", type=int, default=None, help="Port to bind (default from config)")
    run_parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    # GUI command
    gui_parser = subparsers.add_parser("gui", help="Run GUI dashboard")

    # Full command (server + GUI)
    full_parser = subparsers.add_parser("full", help="Run server with GUI dashboard")
    full_parser.add_argument("--host", default=None, help="Host to bind (default from config)")
    full_parser.add_argument("--port", type=int, default=None, help="Port to bind (default from config)")

    # CLI command
    cli_parser = subparsers.add_parser("cli", help="Run CLI interface")
    cli_parser.add_argument("cli_args", nargs="*", help="CLI arguments")
    cli_parser.add_argument("--admin", action="store_true", help="Run admin CLI")
    cli_parser.add_argument("--interactive", action="store_true", help="Interactive mode")

    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade NetLink system")

    # Update commands (new system)
    update_parser = subparsers.add_parser("update", help="Advanced update system")
    update_subparsers = update_parser.add_subparsers(dest="update_command", help="Update commands")

    # Update check
    update_check_parser = update_subparsers.add_parser("check", help="Check for updates")

    # Update version
    update_version_parser = update_subparsers.add_parser("version", help="Show version info")
    update_version_parser.add_argument("--detailed", action="store_true", help="Show detailed info")

    # Update upgrade
    update_upgrade_parser = update_subparsers.add_parser("upgrade", help="Upgrade to newer version")
    update_upgrade_parser.add_argument("--to", type=str, help="Target version")
    update_upgrade_parser.add_argument("--latest", action="store_true", help="Upgrade to latest")
    update_upgrade_parser.add_argument("--stable", action="store_true", help="Upgrade to stable")

    # Update changelog
    update_changelog_parser = update_subparsers.add_parser("changelog", help="Show changelog")
    update_changelog_parser.add_argument("--version", type=str, help="Specific version")
    update_changelog_parser.add_argument("--since", type=str, help="Since version")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show system status")

    # Test command
    test_parser = subparsers.add_parser("test", help="Run system tests")

    # Setup database command
    setup_db_parser = subparsers.add_parser("setup-db", help="Setup database")

    # System check command
    check_parser = subparsers.add_parser("check", help="Run comprehensive system check")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "install":
            success = runner.install_dependencies()
            if success and args.setup_db:
                runner.setup_database()

        elif args.command == "run":
            runner.run_server(args.host, args.port, args.debug)

        elif args.command == "gui":
            runner.run_gui()

        elif args.command == "full":
            runner.run_full(args.host, args.port)

        elif args.command == "cli":
            if args.admin:
                runner.run_admin_cli(args.cli_args)
            else:
                runner.run_cli(args.cli_args)

        elif args.command == "upgrade":
            runner.upgrade()

        elif args.command == "update":
            # Handle new update system commands
            if args.update_command:
                try:
                    import asyncio
                    from netlink.cli.update_cli import UpdateCLI

                    update_cli = UpdateCLI()

                    # Convert args to list format for update CLI
                    update_args = [args.update_command]

                    if hasattr(args, 'detailed') and args.detailed:
                        update_args.append('--detailed')
                    if hasattr(args, 'to') and args.to:
                        update_args.extend(['--to', args.to])
                    if hasattr(args, 'latest') and args.latest:
                        update_args.append('--latest')
                    if hasattr(args, 'stable') and args.stable:
                        update_args.append('--stable')
                    if hasattr(args, 'version') and args.version:
                        update_args.extend(['--version', args.version])
                    if hasattr(args, 'since') and args.since:
                        update_args.extend(['--since', args.since])

                    success = asyncio.run(update_cli.run(update_args))
                    if not success:
                        sys.exit(1)

                except ImportError:
                    print("⚠️ Advanced update system not available")
                    print("💡 Use 'python run.py upgrade' for basic upgrade")
            else:
                print("❓ Use 'python run.py update --help' for update commands")

        elif args.command == "status":
            runner.status()

        elif args.command == "test":
            runner.test()

        elif args.command == "setup-db":
            runner.setup_database()

        elif args.command == "check":
            runner.system_check()

        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()