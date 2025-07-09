#!/usr/bin/env python3
"""
NetLink Application Runner

Cross-platform entry point with automatic environment setup and dependency installation.
Simple, reliable, and fast.
"""

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path
from typing import Optional

# Set up paths
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
VENV_DIR = ROOT / ".venv"
CONFIG_DIR = ROOT / "config"
LOGS_DIR = ROOT / "logs"
DATA_DIR = ROOT / "data"
DEPENDENCIES = ROOT / "dependencies.txt"
REQUIREMENTS = ROOT / "requirements.txt"

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# Add src to Python path for imports
sys.path.insert(0, str(SRC))

def ensure_directories():
    """Ensure required directories exist."""
    required_dirs = [CONFIG_DIR, LOGS_DIR, DATA_DIR, ROOT / "backups", ROOT / "databases"]
    for directory in required_dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return True


def get_venv_python() -> Optional[Path]:
    """Get the Python executable path for the virtual environment."""
    if IS_WINDOWS:
        return VENV_DIR / "Scripts" / "python.exe"
    else:
        return VENV_DIR / "bin" / "python"


def get_venv_pip() -> Optional[Path]:
    """Get the pip executable path for the virtual environment."""
    if IS_WINDOWS:
        return VENV_DIR / "Scripts" / "pip.exe"
    else:
        return VENV_DIR / "bin" / "pip"


def create_virtual_environment() -> bool:
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

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print(f"❌ Python 3.8+ required (found {sys.version_info.major}.{sys.version_info.minor})")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True

def check_pip_available():
    """Check if pip is available."""
    print(f"🔍 Checking pip availability with Python: {sys.executable}")

    # Try direct pip command first (since it works on this system)
    try:
        result = subprocess.run(["pip", "--version"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Found pip: {result.stdout.strip()}")
            return "pip"
    except:
        pass

    # Try python -m pip as fallback
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Found python -m pip: {result.stdout.strip()}")
            return "python_m_pip"
    except:
        pass

    print("❌ pip not found")
    return None

def scan_for_imports() -> Dict[str, List[str]]:
    """Scan source code for import statements to detect required packages."""
    print("🔍 Scanning source code for dependencies...")

    imports = {
        'standard': [],
        'third_party': [],
        'missing': []
    }

    # Standard library modules (Python 3.11+)
    stdlib_modules = {
        'os', 'sys', 'json', 'time', 'datetime', 'pathlib', 'asyncio', 'logging',
        'subprocess', 'threading', 'multiprocessing', 'collections', 'itertools',
        'functools', 'typing', 'dataclasses', 'enum', 'abc', 'contextlib', 'weakref',
        'hashlib', 'secrets', 'uuid', 'base64', 'urllib', 'http', 'email', 'html',
        'xml', 'sqlite3', 'csv', 'configparser', 'argparse', 'shutil', 'tempfile',
        'glob', 'fnmatch', 're', 'string', 'math', 'random', 'statistics', 'decimal',
        'fractions', 'socket', 'ssl', 'platform', 'getpass', 'pwd', 'grp'
    }

    # Package name mappings for different Python versions
    package_mappings = {
        'Crypto': ['pycryptodome', 'pycrypto'],
        'PIL': ['pillow'],
        'cv2': ['opencv-python'],
        'sklearn': ['scikit-learn'],
        'yaml': ['pyyaml'],
        'dotenv': ['python-dotenv'],
        'jose': ['python-jose'],
        'magic': ['python-magic'],
        'dateutil': ['python-dateutil'],
        'multipart': ['python-multipart'],
        'redis': ['redis'],
        'psycopg2': ['psycopg2-binary'],
        'MySQLdb': ['mysqlclient'],
        'pymysql': ['pymysql'],
        'sqlite3': [],  # Built-in
        'tkinter': [],  # Built-in
        'customtkinter': ['customtkinter'],
    }

    import_pattern = re.compile(r'^\s*(?:from\s+(\S+)\s+import|import\s+(\S+))', re.MULTILINE)

    for py_file in Path(SRC).rglob("*.py"):
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for match in import_pattern.finditer(content):
                module = match.group(1) or match.group(2)
                if module:
                    # Get top-level module name
                    top_module = module.split('.')[0]

                    if top_module in stdlib_modules:
                        if top_module not in imports['standard']:
                            imports['standard'].append(top_module)
                    elif top_module.startswith('netlink'):
                        continue  # Skip internal imports
                    else:
                        # Map to package name
                        package_name = package_mappings.get(top_module, [top_module])[0] if package_mappings.get(top_module) else top_module
                        if package_name and package_name not in imports['third_party']:
                            imports['third_party'].append(package_name)

        except Exception as e:
            print(f"⚠️ Error scanning {py_file}: {e}")

    print(f"📊 Found {len(imports['third_party'])} third-party dependencies")
    return imports


def install_dependencies_in_venv(install_type: str = "minimal") -> bool:
    """Install dependencies in virtual environment."""
    if not create_virtual_environment():
        return False

    venv_python = get_venv_python()

    if not venv_python or not venv_python.exists():
        print("❌ Virtual environment Python not found")
        return False

    print(f"📦 Installing {install_type} dependencies in virtual environment...")

    # Upgrade pip first
    try:
        print("📦 Upgrading pip...")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"])
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to upgrade pip: {e}")

    # Install based on type
    if install_type == "minimal":
        return install_minimal_dependencies(venv_python)
    elif install_type == "full":
        return install_full_dependencies(venv_python)
    elif install_type == "auto":
        return install_auto_dependencies(venv_python)
    else:
        print(f"❌ Unknown install type: {install_type}")
        return False


def install_minimal_dependencies(venv_python: Path) -> bool:
    """Install minimal dependencies for basic functionality."""
    minimal_deps = [
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.20.0",
        "starlette>=0.27.0",
        "pydantic>=2.0.0",
        "aiosqlite>=0.19.0",
        "aiofiles>=23.0.0",
        "python-multipart>=0.0.6",
        "jinja2>=3.1.0",
        "pycryptodome>=3.19.0",  # For crypto functionality
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.0",
    ]

    print("📋 Installing minimal dependencies...")
    return install_package_list(venv_python, minimal_deps)


def install_full_dependencies(venv_python: Path) -> bool:
    """Install full dependencies from pyproject.toml."""
    if PYPROJECT_TOML.exists():
        print("📋 Installing full dependencies from pyproject.toml...")
        try:
            subprocess.check_call([str(venv_python), "-m", "pip", "install", "-e", "."])
            print("✅ Full dependencies installed from pyproject.toml")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to install from pyproject.toml: {e}")
            print("🔄 Falling back to requirements.txt...")

    # Fallback to requirements.txt
    if REQUIREMENTS.exists():
        print("📋 Installing from requirements.txt...")
        try:
            subprocess.check_call([str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS)])
            print("✅ Dependencies installed from requirements.txt")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install from requirements.txt: {e}")
            return False

    print("❌ No dependency file found")
    return False


def install_auto_dependencies(venv_python: Path) -> bool:
    """Automatically detect and install required dependencies."""
    imports = scan_for_imports()

    # Start with minimal deps
    if not install_minimal_dependencies(venv_python):
        return False

    # Install detected third-party packages
    if imports['third_party']:
        print(f"📦 Installing {len(imports['third_party'])} detected dependencies...")
        return install_package_list(venv_python, imports['third_party'], ignore_errors=True)

    return True


def install_package_list(venv_python: Path, packages: List[str], ignore_errors: bool = False) -> bool:
    """Install a list of packages."""
    failed_packages = []

    for package in packages:
        try:
            print(f"📦 Installing {package}...")
            result = subprocess.run([
                str(venv_python), "-m", "pip", "install", package
            ], capture_output=True, text=True)

            if result.returncode != 0:
                print(f"⚠️ Failed to install {package}: {result.stderr}")
                failed_packages.append(package)
                if not ignore_errors:
                    return False
            else:
                print(f"✅ Installed {package}")

        except Exception as e:
            print(f"⚠️ Error installing {package}: {e}")
            failed_packages.append(package)
            if not ignore_errors:
                return False

    if failed_packages:
        print(f"⚠️ Failed to install: {', '.join(failed_packages)}")
        return ignore_errors

    return True


def check_missing_dependencies() -> List[str]:
    """Check for missing dependencies by trying to import them."""
    imports = scan_for_imports()
    missing = []

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        return ["Virtual environment not found"]

    print("🔍 Checking for missing dependencies...")

    for package in imports['third_party']:
        try:
            # Try to import the package
            result = subprocess.run([
                str(venv_python), "-c", f"import {package}"
            ], capture_output=True, text=True, timeout=5)

            if result.returncode != 0:
                missing.append(package)
        except:
            missing.append(package)

    return missing


def install_core_dependencies():
    """Install core dependencies only."""
    print("🔧 Installing core NetLink dependencies...")

    # Check if pip is available
    pip_method = check_pip_available()
    if not pip_method:
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
        # Upgrade pip first
        print("📦 Upgrading pip...")
        if pip_method == "python_m_pip":
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        else:
            subprocess.check_call(["pip", "install", "--upgrade", "pip"])

        # Install core dependencies one by one
        for dep in core_deps:
            try:
                print(f"📦 Installing {dep.split('==')[0]}...")
                if pip_method == "python_m_pip":
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                else:
                    subprocess.check_call(["pip", "install", dep])
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

    # Check if we can import critical modules using the same Python executable
    try:
        result = subprocess.run([
            sys.executable, "-c",
            "import fastapi, uvicorn, sqlmodel, pydantic, cryptography; print('OK')"
        ], capture_output=True, text=True, timeout=10)
        modules_ok = result.returncode == 0 and "OK" in result.stdout
    except:
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

def run_netlink_server():
    """Run NetLink server using virtual environment."""
    if not VENV_DIR.exists():
        print("❌ Virtual environment not found. Run setup first.")
        return False

    venv_python = get_venv_python()
    if not venv_python or not venv_python.exists():
        print("❌ Virtual environment Python not found")
        return False

    print("🚀 Starting NetLink server...")

    # Set up environment
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)

    try:
        # Run the server
        subprocess.run([
            str(venv_python), "-m", "netlink.main"
        ], env=env, cwd=str(ROOT))
        return True
    except KeyboardInterrupt:
        print("\n🛑 NetLink server stopped by user")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ NetLink server failed: {e}")
        return False


def show_help():
    """Show help information."""
    print("""
🔗 NetLink - Government-Level Secure Communication Platform

Usage: python run.py [command] [type/options]

Commands:
  setup [type]  Set up virtual environment and install dependencies
                Types: minimal, full, auto (default: minimal)
  run           Start NetLink server
  test          Run tests
  check         Check for missing dependencies
  clean         Clean up virtual environment and cache
  help          Show this help message

Setup Types:
  minimal       Install only core dependencies for basic functionality
  full          Install all dependencies from pyproject.toml
  auto          Automatically detect and install required dependencies

Options:
  --dev         Development mode
  --debug       Debug mode
  --port PORT   Specify port (default: 8000)
  --host HOST   Specify host (default: 127.0.0.1)

Examples:
  python run.py setup minimal   # Minimal installation
  python run.py setup full      # Full installation with all features
  python run.py setup auto      # Auto-detect dependencies
  python run.py run             # Start server
  python run.py check           # Check for missing dependencies
  python run.py clean           # Clean environment
""")


def clean_environment():
    """Clean up virtual environment and cache."""
    print("🧹 Cleaning NetLink environment...")

    # Remove virtual environment
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


def main():
    """Main entry point."""
    args = sys.argv[1:]

    if not args:
        # No arguments - check if setup is needed
        if not VENV_DIR.exists():
            print("🔧 First-time setup detected...")
            if install_dependencies_in_venv("minimal"):
                print("✅ Setup complete! Run 'python run.py run' to start NetLink.")
            else:
                print("❌ Setup failed. Please check the error messages above.")
                sys.exit(1)
        else:
            show_help()
        return

    command = args[0].lower()

    if command in ["help", "-h", "--help"]:
        show_help()

    elif command == "setup":
        install_type = "minimal"
        if len(args) > 1:
            install_type = args[1].lower()
            if install_type not in ["minimal", "full", "auto"]:
                print(f"❌ Invalid setup type: {install_type}")
                print("Valid types: minimal, full, auto")
                sys.exit(1)

        print(f"🔧 Setting up NetLink ({install_type} installation)...")
        if install_dependencies_in_venv(install_type):
            print("✅ Setup complete!")

            # Check for missing dependencies
            missing = check_missing_dependencies()
            if missing:
                print(f"⚠️ Some dependencies may be missing: {', '.join(missing[:5])}")
                print("💡 You can install them later through the WebUI or run 'python run.py setup auto'")
        else:
            print("❌ Setup failed")
            sys.exit(1)

    elif command == "check":
        if not VENV_DIR.exists():
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        missing = check_missing_dependencies()
        if missing:
            print(f"❌ Missing dependencies: {', '.join(missing)}")
            print("💡 Run 'python run.py setup auto' to install missing dependencies")
        else:
            print("✅ All dependencies are available")

    elif command == "run":
        if not VENV_DIR.exists():
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        # Quick dependency check
        missing = check_missing_dependencies()
        if missing:
            print(f"⚠️ Missing dependencies detected: {', '.join(missing[:3])}")
            print("🔄 Attempting to install missing dependencies...")
            venv_python = get_venv_python()
            if venv_python:
                install_package_list(venv_python, missing, ignore_errors=True)

        run_netlink_server()

    elif command == "clean":
        clean_environment()

    elif command == "test":
        if not VENV_DIR.exists():
            print("❌ Environment not set up. Run 'python run.py setup' first.")
            sys.exit(1)

        venv_python = get_venv_python()
        if venv_python and venv_python.exists():
            env = os.environ.copy()
            env["PYTHONPATH"] = str(SRC)
            subprocess.run([str(venv_python), "-m", "pytest", "src/netlink/tests/"], env=env)

    else:
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
