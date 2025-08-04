#!/usr/bin/env python3
"""
Check our progress on fixing pyright errors
"""

import subprocess
import sys
import os

def run_pyright():
    """Run pyright and capture output"""
    try:
        # Run pyright and capture output
        result = subprocess.run(
            ["npx", "pyright", "--outputjson"],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print("✓ Pyright completed successfully")
        else:
            print("⚠ Pyright completed with issues")
        
        # Parse the output to count errors
        output = result.stdout
        if "errors" in output and "warnings" in output:
            # Extract error and warning counts
            lines = output.split('\n')
            for line in lines:
                if "errors" in line and "warnings" in line:
                    print(f"Result: {line}")
                    break
        else:
            print("Output:", output[-500:])  # Last 500 chars
            
        return True
        
    except subprocess.TimeoutExpired:
        print("⚠ Pyright timed out after 2 minutes")
        return False
    except Exception as e:
        print(f"✗ Error running pyright: {e}")
        return False

def main():
    """Main function"""
    print("Checking pyright progress...")
    print("=" * 50)
    
    # Check if npx is available
    try:
        subprocess.run(["npx", "--version"], capture_output=True, check=True)
        print("✓ npx is available")
    except:
        print("✗ npx not available, cannot run pyright")
        return 1
    
    # Run pyright
    success = run_pyright()
    
    print("=" * 50)
    if success:
        print("✓ Progress check completed")
    else:
        print("⚠ Progress check had issues")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
