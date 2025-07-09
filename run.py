#!/usr/bin/env python3
"""
NetLink Application Runner

Simple, reliable cross-platform entry point with automatic environment setup.
"""

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path

# Set up paths
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
VENV_DIR = ROOT / ".venv"
DEPENDENCIES = ROOT / "dependencies.txt"

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


def install_minimal_deps(venv_python):
    """Install minimal dependencies for basic functionality."""
    minimal_deps = [
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.20.0",
        "starlette>=0.27.0",
        "pydantic>=2.0.0",
        "sqlalchemy>=2.0.0",
        "sqlmodel>=0.0.20",
        "aiosqlite>=0.19.0",
        "aiofiles>=23.0.0",
        "python-multipart>=0.0.6",
        "jinja2>=3.1.0",
        "pycryptodome>=3.19.0",
        "python-jose[cryptography]>=3.3.0",
        "PyJWT>=2.8.0",
        "passlib[bcrypt]>=1.7.4",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.0",
        "rich>=13.0.0",
        "typer>=0.9.0",
        "colorama>=0.4.6",
        "argon2-cffi>=23.1.0",
        "requests>=2.30.0"
    ]
    
    print("📋 Installing minimal dependencies...")
    return install_package_list(venv_python, minimal_deps)


def install_full_deps(venv_python):
    """Install full dependencies from dependencies.txt."""
    if DEPENDENCIES.exists():
        print("📋 Installing full dependencies from dependencies.txt...")
        try:
            subprocess.check_call([str(venv_python), "-m", "pip", "install", "-r", str(DEPENDENCIES)])
            print("✅ Full dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install from dependencies.txt: {e}")
            return False
    else:
        print("❌ dependencies.txt not found")
        return False


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
        subprocess.run([str(venv_python), "-m", "netlink.main"], env=env, cwd=str(ROOT))
        return True
    except KeyboardInterrupt:
        print("\n🛑 NetLink server stopped by user")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ NetLink server failed: {e}")
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
    print("""
🔗 NetLink - Government-Level Secure Communication Platform

Usage: python run.py [command] [type]

Commands:
  setup [type]  Set up virtual environment and install dependencies
                Types: minimal (default), full
  run           Start NetLink server
  test          Run tests
  clean         Clean up virtual environment and cache
  help          Show this help message

Setup Types:
  minimal       Install only core dependencies for basic functionality
  full          Install all dependencies from dependencies.txt

Examples:
  python run.py setup           # Minimal installation (default)
  python run.py setup minimal   # Minimal installation
  python run.py setup full      # Full installation
  python run.py run             # Start server
  python run.py clean           # Clean environment
  python run.py help            # Show this help
""")


def main():
    """Main entry point."""
    check_python_version()
    
    args = sys.argv[1:]
    
    if not args:
        if not VENV_DIR.exists():
            print("🔧 First-time setup detected...")
            if install_dependencies("minimal"):
                print("✅ Setup complete! Run 'python run.py run' to start NetLink.")
            else:
                print("❌ Setup failed")
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
            if install_type not in ["minimal", "full"]:
                print(f"❌ Invalid setup type: {install_type}")
                print("Valid types: minimal, full")
                sys.exit(1)
        
        print(f"🔧 Setting up NetLink ({install_type} installation)...")
        if install_dependencies(install_type):
            print("✅ Setup complete!")
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
