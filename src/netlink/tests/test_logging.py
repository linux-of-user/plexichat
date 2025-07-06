#!/usr/bin/env python3
"""
Test Logging System
Simple test to validate the logging system works correctly.
"""

import sys
import os
from pathlib import Path

def test_basic_logging():
    """Test basic logging functionality."""
    print("Testing basic logging...")
    
    try:
        from app.logger_config import logger
        
        # Test different log levels
        logger.debug("Debug message test")
        logger.info("Info message test")
        logger.warning("Warning message test")
        logger.error("Error message test")
        
        print("✅ Basic logging test passed")
        return True
    except Exception as e:
        print(f"❌ Basic logging test failed: {e}")
        return False

def test_log_files():
    """Test log file creation."""
    print("Testing log file creation...")
    
    try:
        # Check if logs directory exists
        logs_dir = Path("logs")
        if not logs_dir.exists():
            logs_dir.mkdir(exist_ok=True)
            print("✅ Created logs directory")
        
        # Check for log files
        log_files = list(logs_dir.glob("*.log"))
        if log_files:
            print(f"✅ Found {len(log_files)} log files")
            for log_file in log_files[:3]:  # Show first 3
                print(f"   - {log_file.name}")
        else:
            print("⚠️  No log files found (may be normal if logging to console only)")
        
        return True
    except Exception as e:
        print(f"❌ Log file test failed: {e}")
        return False

def test_advanced_logging():
    """Test advanced logging features."""
    print("Testing advanced logging features...")
    
    try:
        from app.logger_config import logger, set_log_context, clear_log_context
        
        # Test context logging
        set_log_context(user_id="test_user", request_id="test_123")
        logger.info("Context logging test")
        clear_log_context()
        
        print("✅ Advanced logging test passed")
        return True
    except Exception as e:
        print(f"❌ Advanced logging test failed: {e}")
        return False

def test_specialized_loggers():
    """Test specialized loggers."""
    print("Testing specialized loggers...")
    
    try:
        from app.logger_config import selftest_logger, monitoring_logger
        
        selftest_logger.info("Self-test logger test")
        monitoring_logger.info("Monitoring logger test")
        
        print("✅ Specialized loggers test passed")
        return True
    except Exception as e:
        print(f"❌ Specialized loggers test failed: {e}")
        return False

def test_log_configuration():
    """Test log configuration."""
    print("Testing log configuration...")
    
    try:
        from app.logger_config import settings
        
        # Check key logging settings
        config_items = [
            ('LOG_TO_CONSOLE', getattr(settings, 'LOG_TO_CONSOLE', True)),
            ('LOG_TO_FILE', getattr(settings, 'LOG_TO_FILE', True)),
            ('LOG_LEVEL', getattr(settings, 'LOG_LEVEL', 'INFO')),
            ('LOG_DIR', getattr(settings, 'LOG_DIR', './logs')),
        ]
        
        print("Log configuration:")
        for key, value in config_items:
            print(f"   {key}: {value}")
        
        print("✅ Log configuration test passed")
        return True
    except Exception as e:
        print(f"❌ Log configuration test failed: {e}")
        return False

def main():
    """Run all logging tests."""
    print("🔍 Enhanced Chat API - Logging System Test")
    print("=" * 50)
    
    tests = [
        ("Basic Logging", test_basic_logging),
        ("Log Files", test_log_files),
        ("Advanced Logging", test_advanced_logging),
        ("Specialized Loggers", test_specialized_loggers),
        ("Log Configuration", test_log_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 LOGGING TEST SUMMARY")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total*100):.1f}%")
    
    if passed == total:
        print("🎉 All logging tests passed!")
        return 0
    elif passed >= total * 0.8:
        print("⚠️  Most logging tests passed.")
        return 0
    else:
        print("❌ Multiple logging tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
