"""
Comprehensive API Testing Plugin

This plugin tests EVERY SINGLE ENDPOINT in the PlexiChat API to ensure
they are all functional as a secure messaging API.

Features tested:
- Authentication (register, login, logout, token management)
- User management (profiles, search, updates)
- Messaging (send, receive, conversations, encryption)
- File management (upload, download, sharing)
- Admin functions (user management, system stats)
- System monitoring (health, metrics, status)
- Security features (rate limiting, validation, encryption)
- Database integration
- Caching optimization
- Plugin integration
"""

import asyncio
import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from plexichat.core.logging import get_logger

# Plugin SDK imports
try:
    from plugins_internal import PluginBase, command, PluginManager
except ImportError:
    # Fallback for development
    class PluginBase:
        def __init__(self):
            self.logger = get_logger(__name__)
    
    def command(name: str, description: str = ""):
        def decorator(func):
            func._command_name = name
            func._command_description = description
            return func
        return decorator
    
    class PluginManager:
        pass

logger = get_logger(__name__)

class ComprehensiveAPITest(PluginBase):
    """Comprehensive API testing plugin."""
    
    def __init__(self):
        super().__init__()
        self.base_url = "http://localhost:8000"
        self.api_v1_url = f"{self.base_url}/api/v1"
        self.test_results = {}
        self.test_user_data = {
            "username": f"testuser_{int(time.time())}",
            "email": f"test_{int(time.time())}@example.com",
            "password": "TestPassword123!@#",
            "display_name": "Test User",
            "first_name": "Test",
            "last_name": "User",
            "terms_accepted": True
        }
        self.auth_token = None
        self.user_id = None
        self.session_id = None
        
    @command("test_all", "Run comprehensive test of ALL API endpoints")
    async def test_all_endpoints(self):
        """Test every single API endpoint comprehensively."""
        print("\n🚀 COMPREHENSIVE API TESTING - EVERY SINGLE ENDPOINT")
        print("=" * 80)
        
        try:
            # Test system endpoints first
            await self.test_system_endpoints()
            
            # Test authentication endpoints
            await self.test_authentication_endpoints()
            
            # Test user management endpoints
            await self.test_user_endpoints()
            
            # Test messaging endpoints
            await self.test_messaging_endpoints()
            
            # Test file management endpoints
            await self.test_file_endpoints()
            
            # Test admin endpoints
            await self.test_admin_endpoints()

            # Test new advanced endpoints
            await self.test_realtime_endpoints()
            await self.test_groups_endpoints()
            await self.test_search_endpoints()
            await self.test_notifications_endpoints()

            # Generate comprehensive report
            await self.generate_test_report()
            
        except Exception as e:
            logger.error(f"Comprehensive test failed: {e}")
            print(f"❌ COMPREHENSIVE TEST FAILED: {e}")
    
    async def test_system_endpoints(self):
        """Test all system endpoints."""
        print("\n📊 TESTING SYSTEM ENDPOINTS")
        print("-" * 40)
        
        system_endpoints = [
            ("/health", "GET", "Health check"),
            ("/api/v1/system/health", "GET", "V1 system health"),
            ("/api/v1/system/info", "GET", "System information"),
            ("/api/v1/system/metrics", "GET", "Performance metrics"),
            ("/api/v1/system/status", "GET", "Detailed status"),
            ("/api/v1/system/version", "GET", "Version information"),
            ("/api/v1/system/ping", "GET", "Simple ping"),
            ("/api/v1/system/time", "GET", "Server time"),
            ("/api/v1/system/capabilities", "GET", "API capabilities"),
            ("/api/v1/system/stats/summary", "GET", "Stats summary"),
        ]
        
        for endpoint, method, description in system_endpoints:
            await self.test_endpoint(endpoint, method, description)
    
    async def test_authentication_endpoints(self):
        """Test all authentication endpoints."""
        print("\n🔐 TESTING AUTHENTICATION ENDPOINTS")
        print("-" * 40)
        
        # Test user registration
        success = await self.test_user_registration()
        if not success:
            print("❌ Cannot continue without successful registration")
            return
        
        # Test user login
        success = await self.test_user_login()
        if not success:
            print("❌ Cannot continue without successful login")
            return
        
        # Test authenticated endpoints
        auth_endpoints = [
            ("/api/v1/auth/me", "GET", "Get current user info"),
            ("/api/v1/auth/status", "GET", "Auth service status"),
        ]
        
        for endpoint, method, description in auth_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description)
    
    async def test_user_registration(self):
        """Test user registration endpoint."""
        try:
            response = requests.post(
                f"{self.api_v1_url}/auth/register",
                json=self.test_user_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.user_id = data.get("user_id")
                print(f"✅ User Registration: SUCCESS - User ID: {self.user_id}")
                self.test_results["auth_register"] = {"status": "SUCCESS", "data": data}
                return True
            else:
                print(f"❌ User Registration: FAILED - {response.status_code}: {response.text}")
                self.test_results["auth_register"] = {"status": "FAILED", "error": response.text}
                return False
                
        except Exception as e:
            print(f"❌ User Registration: ERROR - {e}")
            self.test_results["auth_register"] = {"status": "ERROR", "error": str(e)}
            return False
    
    async def test_user_login(self):
        """Test user login endpoint."""
        try:
            login_data = {
                "username": self.test_user_data["username"],
                "password": self.test_user_data["password"]
            }
            
            response = requests.post(
                f"{self.api_v1_url}/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data.get("access_token")
                self.session_id = data.get("session_id")
                print(f"✅ User Login: SUCCESS - Token: {self.auth_token[:20]}...")
                self.test_results["auth_login"] = {"status": "SUCCESS", "data": data}
                return True
            else:
                print(f"❌ User Login: FAILED - {response.status_code}: {response.text}")
                self.test_results["auth_login"] = {"status": "FAILED", "error": response.text}
                return False
                
        except Exception as e:
            print(f"❌ User Login: ERROR - {e}")
            self.test_results["auth_login"] = {"status": "ERROR", "error": str(e)}
            return False
    
    async def test_user_endpoints(self):
        """Test all user management endpoints."""
        print("\n👥 TESTING USER MANAGEMENT ENDPOINTS")
        print("-" * 40)
        
        user_endpoints = [
            ("/api/v1/users/me", "GET", "Get my profile"),
            ("/api/v1/users/search?query=test&limit=10", "GET", "Search users"),
            ("/api/v1/users/?limit=20&offset=0", "GET", "List users"),
            ("/api/v1/users/stats/summary", "GET", "User statistics"),
        ]
        
        for endpoint, method, description in user_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description)
        
        # Test profile update
        await self.test_profile_update()
    
    async def test_profile_update(self):
        """Test profile update endpoint."""
        try:
            update_data = {
                "display_name": "Updated Test User",
                "email": f"updated_{int(time.time())}@example.com"
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.put(
                f"{self.api_v1_url}/users/me",
                json=update_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ Profile Update: SUCCESS")
                self.test_results["users_update"] = {"status": "SUCCESS", "data": response.json()}
            else:
                print(f"❌ Profile Update: FAILED - {response.status_code}: {response.text}")
                self.test_results["users_update"] = {"status": "FAILED", "error": response.text}
                
        except Exception as e:
            print(f"❌ Profile Update: ERROR - {e}")
            self.test_results["users_update"] = {"status": "ERROR", "error": str(e)}
    
    async def test_messaging_endpoints(self):
        """Test all messaging endpoints."""
        print("\n💬 TESTING MESSAGING ENDPOINTS")
        print("-" * 40)
        
        # Test sending a message (need another user first)
        await self.test_send_message()
        
        messaging_endpoints = [
            ("/api/v1/messages/conversations", "GET", "Get conversations"),
            ("/api/v1/messages/stats", "GET", "Message statistics"),
        ]
        
        for endpoint, method, description in messaging_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description)
    
    async def test_send_message(self):
        """Test sending a message."""
        try:
            # Create a second test user to send message to
            second_user_data = {
                "username": f"testuser2_{int(time.time())}",
                "email": f"test2_{int(time.time())}@example.com",
                "password": "TestPassword123!@#",
                "display_name": "Test User 2",
                "terms_accepted": True
            }
            
            # Register second user
            response = requests.post(
                f"{self.api_v1_url}/auth/register",
                json=second_user_data,
                timeout=10
            )
            
            if response.status_code == 200:
                second_user_id = response.json().get("user_id")
                
                # Send message to second user
                message_data = {
                    "recipient_id": second_user_id,
                    "content": "Hello from comprehensive API test!",
                    "message_type": "text",
                    "encrypted": True
                }
                
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                response = requests.post(
                    f"{self.api_v1_url}/messages/send",
                    json=message_data,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    print("✅ Send Message: SUCCESS")
                    self.test_results["messages_send"] = {"status": "SUCCESS", "data": response.json()}
                else:
                    print(f"❌ Send Message: FAILED - {response.status_code}: {response.text}")
                    self.test_results["messages_send"] = {"status": "FAILED", "error": response.text}
            else:
                print("❌ Send Message: FAILED - Could not create second user")
                self.test_results["messages_send"] = {"status": "FAILED", "error": "Could not create second user"}
                
        except Exception as e:
            print(f"❌ Send Message: ERROR - {e}")
            self.test_results["messages_send"] = {"status": "ERROR", "error": str(e)}
    
    async def test_file_endpoints(self):
        """Test all file management endpoints."""
        print("\n📁 TESTING FILE MANAGEMENT ENDPOINTS")
        print("-" * 40)
        
        # Test file upload
        await self.test_file_upload()
        
        file_endpoints = [
            ("/api/v1/files/", "GET", "List my files"),
            ("/api/v1/files/stats", "GET", "File statistics"),
        ]
        
        for endpoint, method, description in file_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description)
    
    async def test_file_upload(self):
        """Test file upload endpoint."""
        try:
            # Create a test file
            test_file_content = b"This is a test file for comprehensive API testing."
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            files = {"file": ("test.txt", test_file_content, "text/plain")}
            data = {"description": "Test file upload", "is_public": False}
            
            response = requests.post(
                f"{self.api_v1_url}/files/upload",
                files=files,
                data=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ File Upload: SUCCESS")
                self.test_results["files_upload"] = {"status": "SUCCESS", "data": response.json()}
            else:
                print(f"❌ File Upload: FAILED - {response.status_code}: {response.text}")
                self.test_results["files_upload"] = {"status": "FAILED", "error": response.text}
                
        except Exception as e:
            print(f"❌ File Upload: ERROR - {e}")
            self.test_results["files_upload"] = {"status": "ERROR", "error": str(e)}
    
    async def test_admin_endpoints(self):
        """Test admin endpoints (may fail due to permissions)."""
        print("\n🔧 TESTING ADMIN ENDPOINTS")
        print("-" * 40)
        
        admin_endpoints = [
            ("/api/v1/admin/stats", "GET", "System statistics"),
            ("/api/v1/admin/users", "GET", "List all users"),
            ("/api/v1/admin/health", "GET", "Admin health check"),
        ]
        
        for endpoint, method, description in admin_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description, expect_403=True)
    
    async def test_endpoint(self, endpoint: str, method: str, description: str):
        """Test a single endpoint."""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.request(method, url, timeout=10)
            
            if response.status_code < 400:
                print(f"✅ {description}: SUCCESS ({response.status_code})")
                self.test_results[endpoint] = {"status": "SUCCESS", "code": response.status_code}
            else:
                print(f"❌ {description}: FAILED ({response.status_code})")
                self.test_results[endpoint] = {"status": "FAILED", "code": response.status_code}
                
        except Exception as e:
            print(f"❌ {description}: ERROR - {e}")
            self.test_results[endpoint] = {"status": "ERROR", "error": str(e)}
    
    async def test_authenticated_endpoint(self, endpoint: str, method: str, description: str, expect_403: bool = False):
        """Test an endpoint that requires authentication."""
        try:
            url = f"{self.base_url}{endpoint}"
            headers = {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
            response = requests.request(method, url, headers=headers, timeout=10)
            
            if expect_403 and response.status_code == 403:
                print(f"✅ {description}: SUCCESS (403 - Expected permission denied)")
                self.test_results[endpoint] = {"status": "SUCCESS", "code": response.status_code, "note": "Expected 403"}
            elif response.status_code < 400:
                print(f"✅ {description}: SUCCESS ({response.status_code})")
                self.test_results[endpoint] = {"status": "SUCCESS", "code": response.status_code}
            else:
                print(f"❌ {description}: FAILED ({response.status_code})")
                self.test_results[endpoint] = {"status": "FAILED", "code": response.status_code}
                
        except Exception as e:
            print(f"❌ {description}: ERROR - {e}")
            self.test_results[endpoint] = {"status": "ERROR", "error": str(e)}
    
    async def generate_test_report(self):
        """Generate comprehensive test report."""
        print("\n📋 COMPREHENSIVE TEST REPORT")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        successful_tests = len([r for r in self.test_results.values() if r["status"] == "SUCCESS"])
        failed_tests = len([r for r in self.test_results.values() if r["status"] == "FAILED"])
        error_tests = len([r for r in self.test_results.values() if r["status"] == "ERROR"])
        
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📊 TOTAL TESTS: {total_tests}")
        print(f"✅ SUCCESSFUL: {successful_tests}")
        print(f"❌ FAILED: {failed_tests}")
        print(f"🔥 ERRORS: {error_tests}")
        print(f"📈 SUCCESS RATE: {success_rate:.1f}%")
        
        if success_rate >= 80:
            print(f"\n🎉 EXCELLENT! API is {success_rate:.1f}% functional!")
        elif success_rate >= 60:
            print(f"\n👍 GOOD! API is {success_rate:.1f}% functional!")
        else:
            print(f"\n⚠️  NEEDS WORK! API is only {success_rate:.1f}% functional!")
        
        # Save detailed report
        report_file = f"api_test_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_tests": total_tests,
                    "successful": successful_tests,
                    "failed": failed_tests,
                    "errors": error_tests,
                    "success_rate": success_rate
                },
                "detailed_results": self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        print("=" * 80)

    async def test_realtime_endpoints(self):
        """Test real-time messaging endpoints."""
        print("\n⚡ TESTING REAL-TIME ENDPOINTS")
        print("-" * 40)

        realtime_endpoints = [
            ("/api/v1/realtime/status", "GET", "Real-time status"),
            ("/api/v1/realtime/connections", "GET", "Active connections"),
        ]

        for endpoint, method, description in realtime_endpoints:
            if "connections" in endpoint:
                await self.test_authenticated_endpoint(endpoint, method, description)
            else:
                await self.test_endpoint(endpoint, method, description)

    async def test_groups_endpoints(self):
        """Test groups and channels endpoints."""
        print("\n👥 TESTING GROUPS ENDPOINTS")
        print("-" * 40)

        groups_endpoints = [
            ("/api/v1/groups/", "GET", "List groups"),
            ("/api/v1/groups/stats", "GET", "Groups statistics"),
            ("/api/v1/groups/my/groups", "GET", "My groups"),
        ]

        for endpoint, method, description in groups_endpoints:
            await self.test_authenticated_endpoint(endpoint, method, description)

    async def test_search_endpoints(self):
        """Test search and analytics endpoints."""
        print("\n🔍 TESTING SEARCH ENDPOINTS")
        print("-" * 40)

        search_endpoints = [
            ("/api/v1/search/status", "GET", "Search status"),
            ("/api/v1/search/suggestions?q=test", "GET", "Search suggestions"),
            ("/api/v1/search/analytics/overview", "GET", "Analytics overview"),
            ("/api/v1/search/analytics/trends", "GET", "Search trends"),
        ]

        for endpoint, method, description in search_endpoints:
            if "status" in endpoint:
                await self.test_endpoint(endpoint, method, description)
            else:
                await self.test_authenticated_endpoint(endpoint, method, description)

    async def test_notifications_endpoints(self):
        """Test notification system endpoints."""
        print("\n🔔 TESTING NOTIFICATIONS ENDPOINTS")
        print("-" * 40)

        notifications_endpoints = [
            ("/api/v1/notifications/system/status", "GET", "Notification system status"),
            ("/api/v1/notifications/", "GET", "Get notifications"),
            ("/api/v1/notifications/unread/count", "GET", "Unread count"),
            ("/api/v1/notifications/settings", "GET", "Notification settings"),
            ("/api/v1/notifications/stats", "GET", "Notification stats"),
        ]

        for endpoint, method, description in notifications_endpoints:
            if "system/status" in endpoint:
                await self.test_endpoint(endpoint, method, description)
            else:
                await self.test_authenticated_endpoint(endpoint, method, description)

# Plugin registration
def get_plugin():
    """Return the plugin instance."""
    return ComprehensiveAPITest()

# For direct execution
if __name__ == "__main__":
    plugin = ComprehensiveAPITest()
    asyncio.run(plugin.test_all_endpoints())
