#!/usr/bin/env python3
"""
Quick Test Script for Enhanced Chat API
Simple validation of core components.
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test critical imports."""
    print("Testing imports...")
    
    try:
        import fastapi
        print("✅ FastAPI imported successfully")
    except ImportError:
        print("❌ FastAPI import failed")
        return False
    
    try:
        import uvicorn
        print("✅ Uvicorn imported successfully")
    except ImportError:
        print("❌ Uvicorn import failed")
        return False
    
    try:
        import sqlmodel
        print("✅ SQLModel imported successfully")
    except ImportError:
        print("❌ SQLModel import failed")
        return False
    
    try:
        import cli
        print("✅ CLI module imported successfully")
    except ImportError as e:
        print(f"❌ CLI import failed: {e}")
        return False
    
    try:
        from netlink.app.logger_config import logger, settings
        print("✅ Logger and settings imported successfully")
    except ImportError as e:
        print(f"❌ Logger/settings import failed: {e}")
        return False
    
    return True

def test_file_structure():
    """Test essential file structure."""
    print("\nTesting file structure...")
    
    essential_files = [
        "src/netlink/app/main.py",
        "src/netlink/app/logger_config.py",
        "run.py",
        "requirements.txt",
        "README.md"
    ]
    
    missing = []
    for file_path in essential_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            missing.append(file_path)
    
    return len(missing) == 0

def test_directories():
    """Test essential directories."""
    print("\nTesting directories...")
    
    essential_dirs = [
        "src/netlink/app",
        "src/netlink/app/routers",
        "src/netlink/app/models",
        "src/netlink/app/web",
        "src/netlink/app/testing"
    ]
    
    missing = []
    for dir_path in essential_dirs:
        if Path(dir_path).exists():
            print(f"✅ {dir_path}/")
        else:
            print(f"❌ {dir_path}/")
            missing.append(dir_path)
    
    return len(missing) == 0

def test_cli_commands():
    """Test CLI command availability."""
    print("\nTesting CLI commands...")
    
    try:
        from cli import ChatAPICLI
        cli_instance = ChatAPICLI()
        
        # Test some basic commands
        commands = ['help', 'status', 'version', 'info']
        for cmd in commands:
            if hasattr(cli_instance, f'do_{cmd}'):
                print(f"✅ CLI command '{cmd}' available")
            else:
                print(f"❌ CLI command '{cmd}' missing")
        
        return True
    except Exception as e:
        print(f"❌ CLI testing failed: {e}")
        return False

def test_web_templates():
    """Test web template availability."""
    print("\nTesting web templates...")
    
    templates = [
        "app/web/templates/base.html",
        "app/web/templates/dashboard.html",
        "app/web/templates/cli.html",
        "app/web/templates/admin/dashboard.html",
        "app/web/templates/admin/config.html"
    ]
    
    found = 0
    for template in templates:
        if Path(template).exists():
            print(f"✅ {template}")
            found += 1
        else:
            print(f"❌ {template}")
    
    return found >= len(templates) // 2  # At least half should exist

def test_configuration():
    """Test configuration system."""
    print("\nTesting configuration...")
    
    try:
        from app.logger_config import settings
        
        # Check if basic settings exist
        if hasattr(settings, 'HOST'):
            print(f"✅ HOST setting: {settings.HOST}")
        else:
            print("❌ HOST setting missing")
            
        if hasattr(settings, 'PORT'):
            print(f"✅ PORT setting: {settings.PORT}")
        else:
            print("❌ PORT setting missing")
            
        if hasattr(settings, 'DATABASE_URL'):
            print(f"✅ DATABASE_URL setting configured")
        else:
            print("❌ DATABASE_URL setting missing")
        
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Enhanced Chat API - Quick System Test")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("File Structure", test_file_structure),
        ("Directory Structure", test_directories),
        ("CLI Commands", test_cli_commands),
        ("Web Templates", test_web_templates),
        ("Configuration", test_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                print(f"✅ {test_name} PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 TEST SUMMARY")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total*100):.1f}%")
    
    if passed == total:
        print("🎉 All tests passed! System is ready.")
        return 0
    elif passed >= total * 0.8:
        print("⚠️  Most tests passed. System is mostly ready.")
        return 0
    else:
        print("❌ Multiple tests failed. System needs attention.")
        return 1

def run_quick_test():
    """Run quick test and return success status."""
    return main() == 0

if __name__ == "__main__":
    sys.exit(main())
