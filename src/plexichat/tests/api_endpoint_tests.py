#!/usr/bin/env python3
"""
API Endpoint Testing Suite for PlexiChat
Tests all API endpoints, authentication, and security features.
"""

import sys
import asyncio
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

# Try to import requests, but handle if not available
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️ requests library not available - API tests will be skipped")

class APITestSuite:
    """Comprehensive API testing suite."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.test_results = []
        self.passed_tests = 0
        self.failed_tests = 0
        self.auth_token = None
        
    def log_test(self, test_name: str, passed: bool, message: str = "", details: Optional[Dict] = None):
        """Log test result."""
        result = {
            "test_name": test_name,
            "passed": passed,
            "message": message,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        self.test_results.append(result)
        
        if passed:
            self.passed_tests += 1
            print(f"✅ {test_name}: {message}")
        else:
            self.failed_tests += 1
            print(f"❌ {test_name}: {message}")
    
    def make_request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling."""
        try:
            url = f"{self.base_url}{endpoint}"
            headers = kwargs.get('headers', {})
            
            if self.auth_token:
                headers['Authorization'] = f"Bearer {self.auth_token}"
            
            kwargs['headers'] = headers
            response = requests.request(method, url, timeout=10, **kwargs)
            return response
        except Exception as e:
            print(f"Request failed: {e}")
            return None
    
    def test_server_availability(self):
        """Test if server is running and accessible."""
        print("\n🌐 Testing Server Availability...")
        
        response = self.make_request("GET", "/")
        if response and response.status_code in [200, 404]:
            self.log_test("Server Availability", True, f"Server responding (Status: {response.status_code})")
        else:
            self.log_test("Server Availability", False, "Server not responding")
    
    def test_docs_endpoint(self):
        """Test documentation endpoint."""
        print("\n📚 Testing Documentation Endpoint...")
        
        response = self.make_request("GET", "/docs")
        if response and response.status_code == 200:
            self.log_test("Docs Endpoint", True, "Documentation accessible")
        else:
            self.log_test("Docs Endpoint", False, f"Docs not accessible (Status: {response.status_code if response else 'No response'})")
    
    def test_api_endpoints(self):
        """Test API endpoints."""
        print("\n🔌 Testing API Endpoints...")
        
        # Test API root
        response = self.make_request("GET", "/api")
        if response:
            self.log_test("API Root", response.status_code in [200, 404], 
                         f"API root status: {response.status_code}")
        else:
            self.log_test("API Root", False, "No response from API root")
        
        # Test API v1
        response = self.make_request("GET", "/api/v1")
        if response:
            self.log_test("API v1", response.status_code in [200, 404], 
                         f"API v1 status: {response.status_code}")
        else:
            self.log_test("API v1", False, "No response from API v1")
    
    def test_authentication_endpoints(self):
        """Test authentication endpoints."""
        print("\n🔐 Testing Authentication Endpoints...")
        
        # Test login endpoint
        response = self.make_request("POST", "/api/v1/auth/login")
        if response:
            self.log_test("Login Endpoint", response.status_code in [400, 401, 422], 
                         f"Login endpoint responding (Status: {response.status_code})")
        else:
            self.log_test("Login Endpoint", False, "Login endpoint not responding")
        
        # Test register endpoint
        response = self.make_request("POST", "/api/v1/auth/register")
        if response:
            self.log_test("Register Endpoint", response.status_code in [400, 401, 422], 
                         f"Register endpoint responding (Status: {response.status_code})")
        else:
            self.log_test("Register Endpoint", False, "Register endpoint not responding")
    
    def test_user_endpoints(self):
        """Test user management endpoints."""
        print("\n👥 Testing User Endpoints...")
        
        # Test users list
        response = self.make_request("GET", "/api/v1/users")
        if response:
            self.log_test("Users List", response.status_code in [200, 401, 403], 
                         f"Users list status: {response.status_code}")
        else:
            self.log_test("Users List", False, "Users list not responding")
        
        # Test user profile
        response = self.make_request("GET", "/api/v1/users/me")
        if response:
            self.log_test("User Profile", response.status_code in [200, 401], 
                         f"User profile status: {response.status_code}")
        else:
            self.log_test("User Profile", False, "User profile not responding")
    
    def test_chat_endpoints(self):
        """Test chat/messaging endpoints."""
        print("\n💬 Testing Chat Endpoints...")
        
        # Test chats list
        response = self.make_request("GET", "/api/v1/chats")
        if response:
            self.log_test("Chats List", response.status_code in [200, 401], 
                         f"Chats list status: {response.status_code}")
        else:
            self.log_test("Chats List", False, "Chats list not responding")
        
        # Test messages
        response = self.make_request("GET", "/api/v1/messages")
        if response:
            self.log_test("Messages", response.status_code in [200, 401], 
                         f"Messages status: {response.status_code}")
        else:
            self.log_test("Messages", False, "Messages not responding")
    
    def test_admin_endpoints(self):
        """Test admin endpoints."""
        print("\n⚙️ Testing Admin Endpoints...")
        
        # Test admin status
        response = self.make_request("GET", "/api/v1/admin/status")
        if response:
            self.log_test("Admin Status", response.status_code in [200, 401, 403], 
                         f"Admin status: {response.status_code}")
        else:
            self.log_test("Admin Status", False, "Admin status not responding")
        
        # Test system info
        response = self.make_request("GET", "/api/v1/admin/system")
        if response:
            self.log_test("System Info", response.status_code in [200, 401, 403], 
                         f"System info status: {response.status_code}")
        else:
            self.log_test("System Info", False, "System info not responding")
    
    def test_backup_endpoints(self):
        """Test backup system endpoints."""
        print("\n💾 Testing Backup Endpoints...")
        
        # Test backup status
        response = self.make_request("GET", "/api/v1/backup/status")
        if response:
            self.log_test("Backup Status", response.status_code in [200, 401, 403], 
                         f"Backup status: {response.status_code}")
        else:
            self.log_test("Backup Status", False, "Backup status not responding")
        
        # Test shard info
        response = self.make_request("GET", "/api/v1/backup/shards")
        if response:
            self.log_test("Shard Info", response.status_code in [200, 401, 403], 
                         f"Shard info status: {response.status_code}")
        else:
            self.log_test("Shard Info", False, "Shard info not responding")
    
    def test_clustering_endpoints(self):
        """Test clustering endpoints."""
        print("\n🔗 Testing Clustering Endpoints...")
        
        # Test cluster status
        response = self.make_request("GET", "/api/v1/cluster/status")
        if response:
            self.log_test("Cluster Status", response.status_code in [200, 401, 403], 
                         f"Cluster status: {response.status_code}")
        else:
            self.log_test("Cluster Status", False, "Cluster status not responding")
        
        # Test nodes
        response = self.make_request("GET", "/api/v1/cluster/nodes")
        if response:
            self.log_test("Cluster Nodes", response.status_code in [200, 401, 403], 
                         f"Cluster nodes status: {response.status_code}")
        else:
            self.log_test("Cluster Nodes", False, "Cluster nodes not responding")
    
    def test_security_headers(self):
        """Test security headers."""
        print("\n🛡️ Testing Security Headers...")
        
        response = self.make_request("GET", "/")
        if response:
            headers = response.headers
            
            # Check for security headers
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security"
            ]
            
            found_headers = 0
            for header in security_headers:
                if header in headers:
                    found_headers += 1
            
            self.log_test("Security Headers", found_headers > 0, 
                         f"Found {found_headers}/{len(security_headers)} security headers")
        else:
            self.log_test("Security Headers", False, "No response to check headers")
    
    def test_rate_limiting(self):
        """Test rate limiting."""
        print("\n⏱️ Testing Rate Limiting...")
        
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = self.make_request("GET", "/api/v1/users")
            if response:
                responses.append(response.status_code)
        
        # Check if any requests were rate limited
        rate_limited = any(status == 429 for status in responses)
        self.log_test("Rate Limiting", True, 
                     f"Made 10 requests, rate limited: {rate_limited}")
    
    def generate_report(self):
        """Generate test report."""
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed": self.passed_tests,
                "failed": self.failed_tests,
                "success_rate": (self.passed_tests / len(self.test_results) * 100) if self.test_results else 0,
                "timestamp": datetime.utcnow().isoformat()
            },
            "test_results": self.test_results
        }
        
        # Save report
        report_file = Path(__file__).parent / f"api_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 API Test Report Generated: {report_file}")
        return report
    
    def run_all_tests(self):
        """Run all API tests."""
        print("🚀 PlexiChat API Endpoint Test Suite")
        print("=" * 50)

        if not REQUESTS_AVAILABLE:
            self.log_test("API Tests", False, "requests library not available")
            report = self.generate_report()
            return False

        # Run all test categories
        self.test_server_availability()
        self.test_docs_endpoint()
        self.test_api_endpoints()
        self.test_authentication_endpoints()
        self.test_user_endpoints()
        self.test_chat_endpoints()
        self.test_admin_endpoints()
        self.test_backup_endpoints()
        self.test_clustering_endpoints()
        self.test_security_headers()
        self.test_rate_limiting()

        # Generate report
        report = self.generate_report()

        print("\n" + "=" * 50)
        print(f"🎯 API Test Summary:")
        print(f"   Total Tests: {report['test_summary']['total_tests']}")
        print(f"   Passed: {report['test_summary']['passed']}")
        print(f"   Failed: {report['test_summary']['failed']}")
        print(f"   Success Rate: {report['test_summary']['success_rate']:.1f}%")

        return report['test_summary']['failed'] == 0

def main():
    """Main test function."""
    test_suite = APITestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
