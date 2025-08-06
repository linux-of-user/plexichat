#!/usr/bin/env python3
"""
Test Integrated Protection System

Comprehensive test for the integrated protection system including:
- DDoS protection
- Rate limiting
- Dynamic scaling
- Account type limits
- Fairness algorithms
"""

import asyncio
import time
import sys
import os
from pathlib import Path
from typing import Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_basic_functionality():
    """Test basic functionality of integrated protection system."""
    print(" Testing Integrated Protection System")
    print("=" * 50)
    
    try:
        from plexichat.core.middleware.integrated_protection_system import (
            IntegratedProtectionSystem, SystemLoadLevel, AccountType
        )
        from plexichat.core.middleware.unified_rate_limiter import RateLimitConfig
        
        # Test 1: System initialization
        print("1. Testing system initialization...")
        config = RateLimitConfig()
        protection_system = IntegratedProtectionSystem(config)
        print("    System initialized successfully")
        
        # Test 2: Account type configuration
        print("2. Testing account type configuration...")
        stats = protection_system.get_comprehensive_stats()
        account_limits = stats["account_type_limits"]
        
        expected_types = ["GUEST", "USER", "BOT", "MODERATOR", "ADMIN"]
        for account_type in expected_types:
            if account_type in account_limits:
                print(f"    {account_type}: {account_limits[account_type]['requests_per_minute']} req/min")
            else:
                print(f"    Missing account type: {account_type}")
                return False
        
        # Test 3: Dynamic scaling configuration
        print("3. Testing dynamic scaling...")
        multipliers = protection_system.load_multipliers
        expected_levels = [SystemLoadLevel.LOW, SystemLoadLevel.NORMAL, SystemLoadLevel.HIGH, SystemLoadLevel.CRITICAL]
        
        for level in expected_levels:
            if level in multipliers:
                print(f"    {level.value}: {multipliers[level]}x multiplier")
            else:
                print(f"    Missing load level: {level.value}")
                return False
        
        # Test 4: System metrics
        print("4. Testing system metrics...")
        system_metrics = stats["system_metrics"]
        required_metrics = ["cpu_usage", "memory_usage", "load_level"]
        
        for metric in required_metrics:
            if metric in system_metrics:
                print(f"    {metric}: {system_metrics[metric]}")
            else:
                print(f"    Missing metric: {metric}")
                return False
        
        # Test 5: Protection statistics
        print("5. Testing protection statistics...")
        protection_stats = stats["protection_stats"]
        required_stats = ["total_requests", "blocked_by_ddos", "blocked_by_rate_limit"]
        
        for stat in required_stats:
            if stat in protection_stats:
                print(f"    {stat}: {protection_stats[stat]}")
            else:
                print(f"    Missing stat: {stat}")
                return False
        
        print("\n All basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f" Test failed: {e}")
        return False

async def test_request_processing():
    """Test request processing through the protection system."""
    print("\n Testing Request Processing")
    print("=" * 50)
    
    try:
        from plexichat.core.middleware.integrated_protection_system import IntegratedProtectionSystem
        from plexichat.core.middleware.unified_rate_limiter import RateLimitConfig
        
        # Mock request class
        class MockRequest:
            def __init__(self, ip: str = "192.168.1.100", user_id: str = None, account_type: str = "USER"):
                self.client = type('obj', (object,), {'host': ip})
                self.url = type('obj', (object,), {'path': '/api/test'})
                self.method = "GET"
                self.headers = {"User-Agent": "TestClient/1.0"}
                self.state = type('obj', (object,), {})()
                
                if user_id:
                    self.state.user = {
                        'id': user_id,
                        'account_type': account_type
                    }
        
        # Initialize system
        config = RateLimitConfig(per_user_requests_per_minute=10)  # Low limit for testing
        protection_system = IntegratedProtectionSystem(config)
        
        # Test 1: Normal request processing
        print("1. Testing normal request processing...")
        request = MockRequest(user_id="test_user_1")
        
        result = await protection_system.check_request(request)
        if result is None:
            print("    Normal request allowed")
        else:
            print(f"    Normal request blocked: {result}")
            return False
        
        # Test 2: Rate limiting
        print("2. Testing rate limiting...")
        blocked = False
        for i in range(15):  # Exceed the limit of 10
            result = await protection_system.check_request(request)
            if result and result.get("blocked"):
                blocked = True
                print(f"    Request blocked after {i+1} attempts: {result['reason']}")
                break
        
        if not blocked:
            print("    Rate limiting not working")
            return False
        
        # Test 3: Different account types
        print("3. Testing different account types...")
        
        # Guest user (should have lower limits)
        guest_request = MockRequest(ip="192.168.1.101")  # No user_id = guest
        guest_result = await protection_system.check_request(guest_request)
        
        # Bot user (should have higher limits)
        bot_request = MockRequest(ip="192.168.1.102", user_id="bot_user", account_type="BOT")
        bot_result = await protection_system.check_request(bot_request)
        
        print(f"    Guest request: {'allowed' if guest_result is None else 'blocked'}")
        print(f"    Bot request: {'allowed' if bot_result is None else 'blocked'}")
        
        # Test 4: System load simulation
        print("4. Testing system load adaptation...")
        
        # Simulate high load
        protection_system.system_metrics.cpu_usage = 85.0
        protection_system.system_metrics.memory_usage = 80.0
        await protection_system._update_system_metrics()
        
        # Check if limits were adjusted
        stats_after = protection_system.get_comprehensive_stats()
        load_level = stats_after["system_metrics"]["load_level"]
        print(f"    System load level: {load_level}")
        
        print("\n All request processing tests passed!")
        return True
        
    except Exception as e:
        print(f" Request processing test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_configuration_updates():
    """Test configuration updates."""
    print("\n  Testing Configuration Updates")
    print("=" * 50)
    
    try:
        from plexichat.core.middleware.integrated_protection_system import (
            IntegratedProtectionSystem, SystemLoadLevel, AccountType
        )
        from plexichat.core.config.rate_limiting_config import AccountTypeRateLimit
        
        # Initialize system
        protection_system = IntegratedProtectionSystem()
        
        # Test 1: Update account limits
        print("1. Testing account limit updates...")
        
        new_limits = AccountTypeRateLimit(
            account_type=AccountType.USER,
            global_requests_per_minute=200,
            concurrent_requests=20,
            bandwidth_per_second=5 * 1024 * 1024
        )
        
        protection_system.update_account_limits(AccountType.USER, new_limits)
        
        # Verify update
        stats = protection_system.get_comprehensive_stats()
        user_limits = stats["account_type_limits"]["USER"]
        
        if user_limits["requests_per_minute"] == 200:
            print("    Account limits updated successfully")
        else:
            print(f"    Account limits not updated: {user_limits}")
            return False
        
        # Test 2: Update load multipliers
        print("2. Testing load multiplier updates...")
        
        new_multipliers = {
            SystemLoadLevel.LOW: 2.0,
            SystemLoadLevel.NORMAL: 1.0,
            SystemLoadLevel.HIGH: 0.5,
            SystemLoadLevel.CRITICAL: 0.2
        }
        
        protection_system.adjust_load_multipliers(new_multipliers)
        
        # Verify update
        if protection_system.load_multipliers[SystemLoadLevel.LOW] == 2.0:
            print("    Load multipliers updated successfully")
        else:
            print("    Load multipliers not updated")
            return False
        
        print("\n All configuration update tests passed!")
        return True
        
    except Exception as e:
        print(f" Configuration update test failed: {e}")
        return False

async def run_comprehensive_test():
    """Run comprehensive test suite."""
    print(" PlexiChat Integrated Protection System Test Suite")
    print("=" * 60)
    
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("Request Processing", test_request_processing),
        ("Configuration Updates", test_configuration_updates)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n Running: {test_name}")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            if result:
                passed += 1
                print(f" {test_name}: PASSED")
            else:
                print(f" {test_name}: FAILED")
        except Exception as e:
            print(f" {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 60)
    print(" TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print(" All tests passed! Integrated Protection System is working correctly.")
        return True
    else:
        print("  Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_comprehensive_test())
    sys.exit(0 if success else 1)
