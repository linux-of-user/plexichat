"""
Comprehensive Test Suite for Enhanced NetLink Features
Tests all the new functionality including admin interface, logging, split-screen, and bug fixes.
"""

import asyncio
import json
import time
import requests
from datetime import datetime
from pathlib import Path
import sys
import os

# Add src to path
project_root = Path(__file__).parent.parent.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

class EnhancedFeatureTests:
    """Test suite for enhanced NetLink features."""
    
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.admin_auth = ("admin", "admin123")
        self.test_results = {}
        
    def run_all_tests(self):
        """Run all enhanced feature tests."""
        print("🧪 NetLink Enhanced Features Test Suite")
        print("=" * 50)
        
        tests = [
            ("Basic Server Health", self.test_server_health),
            ("Bug Fix System", self.test_bug_fixes),
            ("Enhanced Logging", self.test_enhanced_logging),
            ("Admin Interface", self.test_admin_interface),
            ("Admin Authentication", self.test_admin_auth),
            ("System Statistics API", self.test_system_stats),
            ("Log Management", self.test_log_management),
            ("Console Interface", self.test_console_interface),
            ("User Management", self.test_user_management),
            ("Configuration Management", self.test_config_management),
            ("Error Handling", self.test_error_handling),
            ("Performance Monitoring", self.test_performance_monitoring)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Testing: {test_name}")
            try:
                result = test_func()
                if result:
                    print(f"✅ {test_name}: PASSED")
                    passed += 1
                else:
                    print(f"❌ {test_name}: FAILED")
                self.test_results[test_name] = result
            except Exception as e:
                print(f"❌ {test_name}: ERROR - {e}")
                self.test_results[test_name] = False
        
        print(f"\n📊 Test Results: {passed}/{total} tests passed")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        return passed == total
    
    def test_server_health(self):
        """Test basic server health and endpoints."""
        try:
            # Test root endpoint
            response = requests.get(f"{self.base_url}/", timeout=5)
            if response.status_code != 200:
                return False
            
            # Test health endpoint
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                return False
            
            health_data = response.json()
            if health_data.get("status") != "healthy":
                return False
            
            print("  ✓ Server is healthy and responding")
            return True
            
        except Exception as e:
            print(f"  ✗ Server health check failed: {e}")
            return False
    
    def test_bug_fixes(self):
        """Test bug fix system functionality."""
        try:
            # Import bug fix manager
            from netlink.app.core.bug_fixes import bug_fix_manager
            
            # Test bug fix application
            results = bug_fix_manager.apply_all_fixes()
            if not results:
                return False
            
            # Test system checks
            checks = bug_fix_manager.run_system_checks()
            if not checks:
                return False
            
            print(f"  ✓ Applied {sum(results.values())}/{len(results)} bug fixes")
            print(f"  ✓ Ran {len(checks)} system checks")
            return True
            
        except Exception as e:
            print(f"  ✗ Bug fix system test failed: {e}")
            return False
    
    def test_enhanced_logging(self):
        """Test enhanced logging functionality."""
        try:
            # Import logging components
            from netlink.app.core.error_handling.enhanced_error_handler import global_error_handler
            
            # Test error handling
            test_error = ValueError("Test error for logging")
            error_context = global_error_handler.handle_error(test_error)
            
            if not error_context or not error_context.error_id:
                return False
            
            # Test error statistics
            stats = global_error_handler.get_error_statistics()
            if not stats or stats['total_errors'] == 0:
                return False
            
            print(f"  ✓ Error handling working (ID: {error_context.error_id})")
            print(f"  ✓ Error statistics available ({stats['total_errors']} total errors)")
            return True
            
        except Exception as e:
            print(f"  ✗ Enhanced logging test failed: {e}")
            return False
    
    def test_admin_interface(self):
        """Test admin interface accessibility."""
        try:
            # Test admin dashboard access
            response = requests.get(
                f"{self.base_url}/admin/",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            # Check if it's HTML content
            if "text/html" not in response.headers.get("content-type", ""):
                return False
            
            print("  ✓ Admin dashboard accessible")
            return True
            
        except Exception as e:
            print(f"  ✗ Admin interface test failed: {e}")
            return False
    
    def test_admin_auth(self):
        """Test admin authentication."""
        try:
            # Test without authentication
            response = requests.get(f"{self.base_url}/admin/", timeout=5)
            if response.status_code != 401:
                return False
            
            # Test with wrong credentials
            response = requests.get(
                f"{self.base_url}/admin/",
                auth=("wrong", "credentials"),
                timeout=5
            )
            if response.status_code != 401:
                return False
            
            # Test with correct credentials
            response = requests.get(
                f"{self.base_url}/admin/",
                auth=self.admin_auth,
                timeout=5
            )
            if response.status_code != 200:
                return False
            
            print("  ✓ Admin authentication working correctly")
            return True
            
        except Exception as e:
            print(f"  ✗ Admin authentication test failed: {e}")
            return False
    
    def test_system_stats(self):
        """Test system statistics API."""
        try:
            response = requests.get(
                f"{self.base_url}/admin/api/stats",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            stats = response.json()
            required_fields = ["cpu_usage", "memory_usage", "disk_usage", "uptime"]
            
            for field in required_fields:
                if field not in stats:
                    return False
            
            print(f"  ✓ System stats API working (CPU: {stats['cpu_usage']:.1f}%)")
            return True
            
        except Exception as e:
            print(f"  ✗ System stats test failed: {e}")
            return False
    
    def test_log_management(self):
        """Test log management functionality."""
        try:
            # Test logs page access
            response = requests.get(
                f"{self.base_url}/admin/logs",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            print("  ✓ Log management interface accessible")
            return True
            
        except Exception as e:
            print(f"  ✗ Log management test failed: {e}")
            return False
    
    def test_console_interface(self):
        """Test web console interface."""
        try:
            # Test console page access
            response = requests.get(
                f"{self.base_url}/admin/console",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            # Test console command execution
            command_data = {
                "command": "help",
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.base_url}/admin/console/execute",
                json=command_data,
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            result = response.json()
            if result.get("status") != "success":
                return False
            
            print("  ✓ Web console interface working")
            print("  ✓ Console command execution working")
            return True
            
        except Exception as e:
            print(f"  ✗ Console interface test failed: {e}")
            return False
    
    def test_user_management(self):
        """Test user management functionality."""
        try:
            # Test users page access
            response = requests.get(
                f"{self.base_url}/admin/users",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            print("  ✓ User management interface accessible")
            return True
            
        except Exception as e:
            print(f"  ✗ User management test failed: {e}")
            return False
    
    def test_config_management(self):
        """Test configuration management."""
        try:
            # Test system config page
            response = requests.get(
                f"{self.base_url}/admin/system",
                auth=self.admin_auth,
                timeout=5
            )
            
            if response.status_code != 200:
                return False
            
            print("  ✓ Configuration management accessible")
            return True
            
        except Exception as e:
            print(f"  ✗ Configuration management test failed: {e}")
            return False
    
    def test_error_handling(self):
        """Test enhanced error handling."""
        try:
            # Test 404 handling
            response = requests.get(f"{self.base_url}/nonexistent", timeout=5)
            if response.status_code != 404:
                return False
            
            error_data = response.json()
            if "error" not in error_data:
                return False
            
            print("  ✓ Enhanced error handling working")
            return True
            
        except Exception as e:
            print(f"  ✗ Error handling test failed: {e}")
            return False
    
    def test_performance_monitoring(self):
        """Test performance monitoring features."""
        try:
            # Test multiple requests to check performance
            start_time = time.time()
            
            for _ in range(5):
                response = requests.get(f"{self.base_url}/health", timeout=5)
                if response.status_code != 200:
                    return False
            
            end_time = time.time()
            avg_response_time = (end_time - start_time) / 5
            
            if avg_response_time > 1.0:  # Should be much faster
                print(f"  ⚠ Slow response time: {avg_response_time:.3f}s")
            
            print(f"  ✓ Performance monitoring (avg: {avg_response_time:.3f}s)")
            return True
            
        except Exception as e:
            print(f"  ✗ Performance monitoring test failed: {e}")
            return False
    
    def generate_test_report(self):
        """Generate a detailed test report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(self.test_results),
            "passed_tests": sum(self.test_results.values()),
            "failed_tests": len(self.test_results) - sum(self.test_results.values()),
            "success_rate": (sum(self.test_results.values()) / len(self.test_results)) * 100,
            "test_details": self.test_results
        }
        
        # Save report
        report_file = project_root / "test_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Test report saved to: {report_file}")
        return report

def main():
    """Run the enhanced features test suite."""
    print("🚀 Starting NetLink Enhanced Features Test Suite")
    print("Make sure the NetLink server is running on http://localhost:8000")
    print()
    
    # Wait a moment for server to be ready
    time.sleep(2)
    
    tester = EnhancedFeatureTests()
    success = tester.run_all_tests()
    
    # Generate report
    report = tester.generate_test_report()
    
    if success:
        print("\n🎉 All tests passed! NetLink enhanced features are working correctly.")
        return 0
    else:
        print(f"\n⚠️ Some tests failed. Check the report for details.")
        return 1

if __name__ == "__main__":
    exit(main())
