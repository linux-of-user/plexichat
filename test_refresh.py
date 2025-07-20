#!/usr/bin/env python3
"""Test script for the refresh functionality."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_version_manager():
    """Test version manager functionality."""
    try:
        from plexichat.core.versioning.version_manager import VersionManager
        vm = VersionManager()
        print(f"✓ Version Manager loaded successfully")
        print(f"  Current version: {vm.current_version}")
        print(f"  Version type: {vm.version_type}")
        print(f"  Build number: {vm.build_number}")
        return True
    except Exception as e:
        print(f"✗ Version Manager failed: {e}")
        return False

def test_refresh_function():
    """Test refresh function import."""
    try:
        from run import run_refresh_current_version
        print(f"✓ Refresh function imported successfully")
        return True
    except Exception as e:
        print(f"✗ Refresh function import failed: {e}")
        return False

def test_version_json():
    """Test version.json file."""
    try:
        import json
        with open("version.json", "r") as f:
            version_data = json.load(f)
        print(f"✓ version.json loaded successfully")
        print(f"  Version: {version_data.get('current_version')}")
        print(f"  Features: {len(version_data.get('features', {}))}")
        return True
    except Exception as e:
        print(f"✗ version.json test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing PlexiChat Update System Components")
    print("=" * 50)
    
    tests = [
        ("Version Manager", test_version_manager),
        ("Refresh Function", test_refresh_function),
        ("Version JSON", test_version_json),
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\nTesting {name}...")
        if test_func():
            passed += 1
        
    print(f"\n" + "=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! Update system is ready.")
        return True
    else:
        print("✗ Some tests failed.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
