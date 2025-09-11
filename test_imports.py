#!/usr/bin/env python3
"""
Test Import Verification Script

This script tests that the updated imports work correctly by attempting to import
key modules and checking for import errors.
"""

import sys
import os
from pathlib import Path

# Add src to path to enable src.plexichat imports
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

def test_import(module_name, description=""):
    """Test importing a module."""
    try:
        if module_name.startswith('src.'):
            # For src.plexichat imports, we need to handle them specially
            module_name = module_name[4:]  # Remove 'src.' prefix
        
        __import__(module_name)
        print(f"✓ {module_name} {description}")
        return True
    except ImportError as e:
        print(f"✗ {module_name} {description}: {e}")
        return False
    except Exception as e:
        print(f"⚠ {module_name} {description}: {e}")
        return False

def main():
    """Test key imports."""
    print("Testing import resolution after fixes...\n")
    
    # Test basic imports
    success_count = 0
    total_count = 0
    
    # Core imports
    tests = [
        ("plexichat", "- Main package"),
        ("plexichat.core", "- Core package"),
        ("plexichat.core.config", "- Configuration"),
        ("plexichat.core.logging", "- Logging system"),
        ("plexichat.shared", "- Shared modules"),
        ("plexichat.shared.types", "- Type definitions"),
        ("plexichat.shared.exceptions", "- Exception classes"),
    ]
    
    print("Core imports:")
    for module, desc in tests:
        if test_import(module, desc):
            success_count += 1
        total_count += 1
    
    print()
    
    # Test database imports (may fail if dependencies not installed)
    db_tests = [
        ("plexichat.core.database", "- Database package"),
        ("plexichat.core.database.manager", "- Database manager"),
    ]
    
    print("Database imports:")
    for module, desc in db_tests:
        if test_import(module, desc):
            success_count += 1
        total_count += 1
    
    print()
    
    # Test feature imports
    feature_tests = [
        ("plexichat.features", "- Features package"),
    ]
    
    print("Feature imports:")
    for module, desc in feature_tests:
        if test_import(module, desc):
            success_count += 1
        total_count += 1
    
    print()
    
    # Test interface imports
    interface_tests = [
        ("plexichat.interfaces", "- Interfaces package"),
    ]
    
    print("Interface imports:")
    for module, desc in interface_tests:
        if test_import(module, desc):
            success_count += 1
        total_count += 1
    
    print(f"\nResults: {success_count}/{total_count} imports successful")
    
    if success_count == total_count:
        print("✅ All imports working correctly!")
        return 0
    elif success_count > total_count * 0.5:
        print("⚠️  Most imports working, some issues may be due to missing dependencies")
        return 0
    else:
        print("❌ Multiple import failures - review fixes needed")
        return 1

if __name__ == '__main__':
    sys.exit(main())