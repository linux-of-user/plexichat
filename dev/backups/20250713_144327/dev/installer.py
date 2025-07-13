#!/usr/bin/env python3
"""
PlexiChat Dev Installer
======================

Installs all runtime and (optionally) dev dependencies for PlexiChat development.

Usage:
  python dev/installer.py           # Installs runtime dependencies only
  python dev/installer.py --dev     # Installs runtime + dev dependencies
"""

import subprocess
import sys
import os
from pathlib import Path

RUNTIME_REQ = Path("requirements.txt")
DEV_REQ = Path("dev/requirements-dev.txt")


def install_requirements(requirements_file):
    print(f"Installing dependencies from {requirements_file} ...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)])


def main():
    dev_mode = "--dev" in sys.argv
    install_requirements(RUNTIME_REQ)
    if dev_mode:
        install_requirements(DEV_REQ)
        print("Dev dependencies installed.")
    else:
        print("Dev dependencies NOT installed. Use --dev to install them.")

if __name__ == "__main__":
    main() 