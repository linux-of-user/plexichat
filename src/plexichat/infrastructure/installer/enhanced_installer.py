from typing import Dict, List, Optional, Any
import subprocess
import sys
import os
from pathlib import Path


#!/usr/bin/env python3
"""
Enhanced PlexiChat Installer
===========================

Installs all runtime dependencies, and (optionally) dev dependencies and tools.

Usage:
  python src/plexichat/infrastructure/installer/enhanced_installer.py           # Runtime only
  python src/plexichat/infrastructure/installer/enhanced_installer.py --dev     # Runtime + dev tools
"""


RUNTIME_REQ = Path("requirements.txt")
DEV_INSTALLER = Path("dev/installer.py")


def main():
    """main function."""
    dev_mode = "--dev" in sys.argv
    print("Installing runtime dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(RUNTIME_REQ)])
    if dev_mode:
        print("Installing dev dependencies and tools...")
        subprocess.check_call([sys.executable, str(DEV_INSTALLER), "--dev"])
        print("Dev tools installed.")
    else:
        print("Dev tools NOT installed. Use --dev to install them.")
    print("Installation complete.")

if __name__ == "__main__":
    main()
