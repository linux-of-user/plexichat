#!/usr/bin/env python3
"""
Development setup script to install plexichat package in development mode
"""

import sys
import subprocess
import os
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return success status"""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ {cmd}")
            return True
        else:
            print(f"✗ {cmd}")
            print(f"  Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ {cmd}")
        print(f"  Exception: {e}")
        return False

def main():
    """Setup development environment"""
    print("Setting up PlexiChat development environment...")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("pyproject.toml"):
        print("✗ pyproject.toml not found. Please run from the project root.")
        return 1
    
    # Install in development mode
    success = run_command("pip install -e .")
    
    if success:
        print("=" * 50)
        print("✓ Development setup complete!")
        print("You can now import plexichat modules.")
    else:
        print("=" * 50)
        print("✗ Development setup failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
