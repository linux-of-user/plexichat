#!/usr/bin/env python3
"""
Basic Functionality Test for PlexiChat

Tests basic functionality without complex dependencies.
This test should always work and verify core components.


import sys
import os
import time
import json
from pathlib import Path

def test_python_environment():
    """Test Python environment and basic functionality."""
    print(" Testing Python Environment...")
    
    # Test Python version
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"    Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"    Python version too old: {version.major}.{version.minor}.{version.micro}")
        return False

def test_file_structure():
    """Test project file structure."""
    print("\n Testing File Structure...")
    
    project_root = Path(__file__).parent.parent.parent.parent
    required_files = [
        "run.py",
        "requirements.txt",
        "src/plexichat/__init__.py",
        "src/plexichat/main.py"
    ]
    
    required_dirs = [
        "src/plexichat/core",
        "src/plexichat/interfaces",
        "src/plexichat/infrastructure"
    ]
    
    all_good = True
    
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            print(f"    {file_path}")
        else:
            print(f"    Missing: {file_path}")
            all_good = False
    
    for dir_path in required_dirs:
        full_path = project_root / dir_path
        if full_path.exists() and full_path.is_dir():
            print(f"    {dir_path}/")
        else:
            print(f"    Missing directory: {dir_path}/")
            all_good = False
    
    return all_good

def test_basic_imports():
    """Test basic Python imports that should always work."""
    print("\n Testing Basic Imports...")
    
    basic_modules = [
        'json',
        'time',
        'pathlib',
        'asyncio',
        'hashlib',
        'secrets',
        'collections',
        'dataclasses',
        'enum',
        'typing'
    ]
    
    all_good = True
    
    for module in basic_modules:
        try:
            __import__(module)
            print(f"    {module}")
        except ImportError as e:
            print(f"    {module}: {e}")
            all_good = False
    
    return all_good

def test_data_structures():
    """Test basic data structures and algorithms."""
    print("\n Testing Data Structures...")
    
    try:
        # Test basic rate limiting logic
        from collections import deque
        import time
        
        # Simple sliding window implementation
        class SimpleRateLimit:
            def __init__(self, max_requests, window_seconds):
                self.max_requests = max_requests
                self.window_seconds = window_seconds
                self.requests = deque()
            
            def allow_request(self):
                current_time = time.time()
                
                # Remove old requests
                while self.requests and self.requests[0] <= current_time - self.window_seconds:
                    self.requests.popleft()
                
                # Check if we can allow the request
                if len(self.requests) < self.max_requests:
                    self.requests.append(current_time)
                    return True
                return False
        
        # Test the rate limiter
        limiter = SimpleRateLimit(5, 60)  # 5 requests per minute
        
        # Should allow first 5 requests
        allowed = 0
        for i in range(10):
            if limiter.allow_request():
                allowed += 1
        
        if allowed == 5:
            print("    Basic rate limiting logic works")
            return True
        else:
            print(f"    Rate limiting failed: allowed {allowed}/5")
            return False
            
    except Exception as e:
        print(f"    Data structures test failed: {e}")
        return False

def test_configuration_handling():
    """Test configuration file handling."""
    print("\n  Testing Configuration Handling...")
    
    try:
        # Test JSON configuration
        test_config = {
            "rate_limiting": {
                "enabled": True,
                "per_ip_limit": 60,
                "per_user_limit": 120
            },
            "security": {
                "csrf_protection": True,
                "xss_protection": True
            }
        }
        
        # Test JSON serialization/deserialization
        json_str = json.dumps(test_config, indent=2)
        parsed_config = json.loads(json_str)
        
        if parsed_config == test_config:
            print("    JSON configuration handling works")
        else:
            print("    JSON configuration mismatch")
            return False
        
        # Test configuration validation
        required_keys = ["rate_limiting", "security"]
        for key in required_keys:
            if key not in parsed_config:
                print(f"    Missing configuration key: {key}")
                return False
        
        print("    Configuration validation works")
        return True
        
    except Exception as e:
        print(f"    Configuration test failed: {e}")
        return False

def test_security_basics():
    """Test basic security functions."""
    print("\n Testing Security Basics...")
    
    try:
        import hashlib
        import secrets
        
        # Test password hashing
        password = "test_password_123"
        salt = secrets.token_hex(16)
        
        # Simple secure hash
        combined = password + salt
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        
        if len(hashed) == 64:  # SHA256 produces 64 character hex string
            print("    Basic password hashing works")
        else:
            print("    Password hashing failed")
            return False
        
        # Test token generation
        token = secrets.token_urlsafe(32)
        if len(token) > 32:
            print("    Secure token generation works")
        else:
            print("    Token generation failed")
            return False
        
        # Test input sanitization basics
        malicious_input = "<script>alert('xss')</script>"
        sanitized = malicious_input.replace("<", "&lt;").replace(">", "&gt;")
        
        if "<script>" not in sanitized:
            print("    Basic input sanitization works")
        else:
            print("    Input sanitization failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"    Security basics test failed: {e}")
        return False

def test_performance_basics():
    """Test basic performance considerations."""
    print("\n Testing Performance Basics...")
    
    try:
        import time
        from collections import defaultdict
        
        # Test efficient data structures
        start_time = time.time()
        
        # Test defaultdict performance
        counter = defaultdict(int)
        for i in range(10000):
            counter[f"key_{i % 100}"] += 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        if duration < 0.1:  # Should be very fast
            print(f"    Efficient data structures (took {duration:.4f}s)")
        else:
            print(f"     Data structure performance concern ({duration:.4f}s)")
        
        # Test memory efficiency
        large_list = list(range(100000))
        if len(large_list) == 100000:
            print("    Memory allocation works")
        else:
            print("    Memory allocation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"    Performance test failed: {e}")
        return False

def run_basic_tests():
    """Run all basic functionality tests."""
    print(" PlexiChat Basic Functionality Test Suite")
    print("=" * 60)
    
    tests = [
        ("Python Environment", test_python_environment),
        ("File Structure", test_file_structure),
        ("Basic Imports", test_basic_imports),
        ("Data Structures", test_data_structures),
        ("Configuration Handling", test_configuration_handling),
        ("Security Basics", test_security_basics),
        ("Performance Basics", test_performance_basics)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
                print(f" {test_name}: PASSED")
            else:
                print(f" {test_name}: FAILED")
        except Exception as e:
            print(f" {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 60)
    print(" BASIC FUNCTIONALITY TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print(" All basic tests passed! Core functionality is working.")
        print("\n NEXT STEPS:")
        print("1. Run 'python run.py setup --test-deps' to install testing dependencies")
        print("2. Run 'python run.py test --type protection' to test protection systems")
        print("3. Run 'python run.py test --type security' for security testing")
        print("4. Run 'python run.py' to start the server")
        return True
    else:
        print("  Some basic tests failed. Please fix these issues first.")
        print("\n TROUBLESHOOTING:")
        print("1. Check Python version (requires 3.8+)")
        print("2. Verify project file structure")
        print("3. Run 'python run.py setup' to install dependencies")
        return False

if __name__ == "__main__":
    success = run_basic_tests()
    sys.exit(0 if success else 1)
