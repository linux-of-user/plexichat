#!/usr/bin/env python3
"""
NetLink GUI Launcher
Launcher script for the NetLink Admin GUI application.
"""

import sys
import os
import subprocess
import importlib.util
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = [
        'customtkinter',
        'requests',
        'Pillow',
        'cryptography'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'Pillow':
                import PIL
            else:
                importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)
    
    return missing_packages


def install_dependencies():
    """Install missing dependencies."""
    print("Installing GUI dependencies...")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def launch_gui():
    """Launch the NetLink Admin GUI."""
    try:
        # Add current directory to Python path
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        
        # Import and run the GUI
        from netlink_admin_gui import NetLinkAdminGUI
        
        print("🚀 Launching NetLink Admin GUI...")
        app = NetLinkAdminGUI()
        app.run()
        
    except ImportError as e:
        print(f"❌ Failed to import GUI module: {e}")
        print("Please ensure all dependencies are installed.")
        return False
    except Exception as e:
        print(f"❌ Failed to launch GUI: {e}")
        return False
    
    return True


def main():
    """Main launcher function."""
    print("🔒 NetLink Admin GUI Launcher")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    # Check dependencies
    missing = check_dependencies()
    
    if missing:
        print(f"⚠️  Missing dependencies: {', '.join(missing)}")
        
        response = input("Install missing dependencies? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            if not install_dependencies():
                print("❌ Failed to install dependencies. Exiting.")
                sys.exit(1)
        else:
            print("❌ Cannot launch GUI without required dependencies.")
            sys.exit(1)
    else:
        print("✅ All dependencies are available")
    
    # Launch GUI
    print("\n🚀 Starting NetLink Admin GUI...")
    
    if not launch_gui():
        print("❌ Failed to launch GUI application")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 GUI launcher interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Launcher error: {e}")
        sys.exit(1)
