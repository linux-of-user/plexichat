"""
Simple NetLink System Validation
Quick validation without complex imports.
"""

import sys
import os
from pathlib import Path

def validate_python_version():
    """Check Python version."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required, found {version.major}.{version.minor}")
        return False
    else:
        print(f"✅ Python version {version.major}.{version.minor}.{version.micro} is compatible")
        return True

def validate_dependencies():
    """Check critical dependencies."""
    print("\n📦 Checking dependencies...")
    
    deps = ["fastapi", "uvicorn", "pydantic"]
    success = True
    
    for dep in deps:
        try:
            __import__(dep)
            print(f"✅ {dep} available")
        except ImportError:
            print(f"❌ {dep} missing")
            success = False
    
    return success

def validate_file_structure():
    """Check essential files."""
    print("\n📁 Checking file structure...")
    
    files = [
        "run.py",
        "requirements.txt",
        "README.md",
        "src/netlink/app/main_working.py",
        "src/netlink/app/logger_simple.py",
        "src/netlink/core/launcher.py",
        "src/netlink/cli/app.py"
    ]
    
    success = True
    for file_path in files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            success = False
    
    return success

def validate_app_import():
    """Test if the main app can be imported."""
    print("\n🔧 Checking app import...")
    
    try:
        sys.path.insert(0, "src")
        from netlink.app.main_working import app
        print("✅ Main app imported successfully")
        return True
    except Exception as e:
        print(f"❌ App import failed: {e}")
        return False

def run_simple_validation():
    """Run simple validation."""
    print("🚀 NetLink Simple System Validation")
    print("=" * 50)
    
    checks = [
        validate_python_version(),
        validate_dependencies(),
        validate_file_structure(),
        validate_app_import()
    ]
    
    passed = sum(checks)
    total = len(checks)
    
    print(f"\n📊 Validation Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("✅ All validations passed! System is ready.")
        return True
    else:
        print("❌ Some validations failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = run_simple_validation()
    sys.exit(0 if success else 1)
