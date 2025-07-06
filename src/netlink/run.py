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
ROOT = Path(__file__).parent.resolve()
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

# Ensure setup is complete
if not ensure_setup():
    print("❌ Setup failed. Please run 'python scripts/auto_setup.py' manually.")
    sys.exit(1)

# Add src to Python path
sys.path.insert(0, str(SRC))

class NetLinkRunner:
    """Main NetLink application runner."""

    def __init__(self):
        self.version = "3.0.0"
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
        """Run the GUI dashboard."""
        print("🖥️ Starting NetLink GUI Dashboard...")

        # Check if GUI directory exists
        gui_dir = ROOT / "gui"
        if not gui_dir.exists():
            print("❌ GUI directory not found")
            return False

        # Add GUI directory to path
        gui_path = str(gui_dir)
        if gui_path not in sys.path:
            sys.path.insert(0, gui_path)

        try:
            # Try to import from GUI directory
            gui_script = gui_dir / "netlink_admin_gui.py"
            if gui_script.exists():
                print("🚀 Launching NetLink Admin GUI...")
                result = subprocess.run([sys.executable, str(gui_script)], cwd=str(gui_dir))
                return result.returncode == 0
            else:
                print("❌ GUI script not found")
                return False

        except ImportError as e:
            print(f"❌ GUI dependencies missing: {e}")
            print("Install with: pip install customtkinter pillow")
            return False
        except Exception as e:
            print(f"❌ GUI error: {e}")
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
        """Upgrade NetLink system."""
        print("🔄 Upgrading NetLink...")
        try:
            # Try to import updater
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