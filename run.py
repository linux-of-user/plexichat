#!/usr/bin/env python3
"""
NetLink Main Runner - Entry Point
Simple entry point that imports and runs the main runner from src.
"""

import sys
from pathlib import Path

# Add src to Python path
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

# Import and run the main runner
if __name__ == "__main__":
    try:
        from netlink.run import main
        main()
    except ImportError as e:
        print(f"❌ Error importing NetLink runner: {e}")
        print("Make sure you're running this from the NetLink root directory.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error running NetLink: {e}")
        sys.exit(1)
