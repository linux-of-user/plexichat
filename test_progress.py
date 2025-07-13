import sys
import time
from pathlib import Path

from run import DualProgressBar

#!/usr/bin/env python3
"""
Test script to demonstrate the improved dual progress bar system.
"""

# Add the current directory to Python path to import from run.py
sys.path.insert(0, str(from pathlib import Path
Path(__file__).parent))

# Import the DualProgressBar class from run.py
def test_dual_progress_bars():
    """Test the dual progress bar system."""
    print("Testing Enhanced Dual Progress Bar System")
    print("=" * 50)
    
    # Simulate installing 5 packages
    packages = [
        "fastapi",
        "uvicorn[standard]",
        "sqlalchemy",
        "pydantic",
        "python-multipart"
    ]
    
    # Create progress bar
    progress = DualProgressBar(len(packages))
    
    for i, package in enumerate(packages):
        print(f"\nStarting installation of {package}...")
        
        # Update overall progress
        progress.update_overall(i + 1, package)
        
        # Simulate installation process with different statuses
        for step in range(3):
            if step == 0:
                progress.update_package(package, "Installing")
                time.sleep(0.5)
            elif step == 1:
                progress.update_package(package, "Installing")
                time.sleep(0.5)
            else:
                # Simulate success or failure
                if package == "sqlalchemy":  # Simulate failure
                    progress.update_package(package, "Failed")
                    time.sleep(0.3)
                else:
                    progress.update_package(package, "Installed")
                    time.sleep(0.2)
    
    # Finish the progress bars
    progress.finish("All packages processed")
    
    print("\nTest completed!")

if __name__ == "__main__":
    test_dual_progress_bars() 