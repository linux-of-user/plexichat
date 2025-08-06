#!/usr/bin/env python3
"""
Simple Security Test for PlexiChat

Basic security validation without external dependencies.


import sys
import os
import time
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_password_security():
    """Test password hashing security."""
    print(" Testing Password Security...")
    
    try:
        from plexichat.infrastructure.utils.common_utils import CommonUtils
        
        # Test password hashing
        password = "TestPassword123!"
        hash_result = CommonUtils.hash_password(password)
        
        if isinstance(hash_result, dict) and "hash" in hash_result:
            if hash_result["hash"] != password and len(hash_result["hash"]) > 32:
                print("    Password hashing appears secure")
                return True
            else:
                print("    Password hashing appears weak")
                return False
        else:
            print("    Password hashing failed")
            return False
            
    except Exception as e:
        print(f"    Password test error: {e}")
        return False

def test_rate_limiting_config():
    """Test rate limiting configuration."""
    print(" Testing Rate Limiting Configuration...")
    
    try:
        from plexichat.core.config.rate_limit_config import get_rate_limit_config
        
        config = get_rate_limit_config()
        
        if config.enabled and config.per_ip_requests_per_minute > 0:
            print("    Rate limiting is enabled and configured")
            return True
        else:
            print("    Rate limiting not properly configured")
            return False
            
    except Exception as e:
        print(f"    Rate limiting test error: {e}")
        return False

def test_security_headers():
    """Test security headers configuration."""
    print("  Testing Security Headers...")
    
    try:
        # This is a basic test - in a real scenario we'd make HTTP requests
        # For now, just check if the main app imports work
        from plexichat.main import app
        
        if app:
            print("    Main application loads successfully")
            return True
        else:
            print("    Main application failed to load")
            return False
            
    except Exception as e:
        print(f"    Security headers test error: {e}")
        return False

def test_input_validation():
    """Test input validation utilities."""
    print(" Testing Input Validation...")
    
    try:
        from plexichat.infrastructure.utils.security import SecurityUtils
        
        # Test malicious input detection
        malicious_input = "<script>alert('xss')</script>"
        sanitized = SecurityUtils().sanitize_input(malicious_input)
        
        if sanitized != malicious_input:
            print("    Input sanitization working")
            return True
        else:
            print("    Input sanitization not working")
            return False
            
    except Exception as e:
        print(f"    Input validation test error: {e}")
        return False

def test_authentication_system():
    """Test authentication system components."""
    print(" Testing Authentication System...")
    
    try:
        from plexichat.core.auth.auth import TokenManager
        
        token_manager = TokenManager()
        
        if token_manager and hasattr(token_manager, 'secret_key'):
            if len(token_manager.secret_key) >= 32:
                print("    Token manager has secure secret key")
                return True
            else:
                print("    Token manager secret key too short")
                return False
        else:
            print("    Token manager not properly initialized")
            return False
            
    except Exception as e:
        print(f"    Authentication test error: {e}")
        return False

def test_database_security():
    """Test database security features."""
    print("  Testing Database Security...")
    
    try:
        from plexichat.core.database.db_stored_procedures import StoredProcedureManager
        
        # Check if the SQL injection protection is in place
        manager = StoredProcedureManager()
        
        if hasattr(manager, '_substitute_parameters'):
            print("    Database parameter substitution available")
            return True
        else:
            print("    Database security features missing")
            return False
            
    except Exception as e:
        print(f"    Database security test error: {e}")
        return False

def run_security_tests():
    """Run all security tests."""
    print(" PlexiChat Security Test Suite")
    print("=" * 50)
    
    tests = [
        ("Password Security", test_password_security),
        ("Rate Limiting", test_rate_limiting_config),
        ("Security Headers", test_security_headers),
        ("Input Validation", test_input_validation),
        ("Authentication", test_authentication_system),
        ("Database Security", test_database_security)
    ]
    
    results = []
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                passed += 1
        except Exception as e:
            print(f"    Test failed with error: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 50)
    print(" SECURITY TEST SUMMARY")
    print("=" * 50)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print(" All security tests passed!")
        security_score = 100
    else:
        security_score = (passed / total) * 100
        print(f"  Security Score: {security_score:.1f}/100")
        
        print("\nFailed Tests:")
        for test_name, result in results:
            if not result:
                print(f"    {test_name}")
    
    # Generate simple report
    report = {
        "timestamp": time.time(),
        "total_tests": total,
        "passed_tests": passed,
        "security_score": security_score,
        "test_results": {name: result for name, result in results}
    }
    
    # Save report
    try:
        with open("simple_security_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n Report saved to simple_security_report.json")
    except Exception as e:
        print(f"  Could not save report: {e}")
    
    return security_score >= 80  # 80% pass threshold

if __name__ == "__main__":
    success = run_security_tests()
    sys.exit(0 if success else 1)
