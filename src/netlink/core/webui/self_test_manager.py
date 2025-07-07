"""
NetLink WebUI Self-Test Manager

Comprehensive self-test system for WebUI components including security,
performance, connectivity, database, and API testing.
"""

import asyncio
import time
import json
import requests
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path

from .config_manager import get_webui_config
from .auth_storage import get_auth_storage
from .mfa_manager import get_mfa_manager

logger = logging.getLogger(__name__)

class TestStatus(Enum):
    """Test status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"

@dataclass
class TestResult:
    """Individual test result."""
    test_id: str
    test_name: str
    category: str
    status: TestStatus
    message: str
    details: Dict[str, Any]
    duration: float
    timestamp: datetime
    error: Optional[str] = None

@dataclass
class TestSuite:
    """Test suite results."""
    suite_id: str
    suite_name: str
    category: str
    tests: List[TestResult]
    total_tests: int
    passed_tests: int
    failed_tests: int
    warning_tests: int
    skipped_tests: int
    total_duration: float
    started_at: datetime
    completed_at: Optional[datetime] = None

class SelfTestManager:
    """Self-test manager for WebUI components."""
    
    def __init__(self):
        self.config = get_webui_config()
        self.test_config = self.config.self_test_config
        
        # Test results storage
        self.test_results = {}  # suite_id -> TestSuite
        self.test_history = []  # List of completed test suites
        
        # Test registry
        self.test_registry = {}  # category -> List[test_function]
        
        # Register built-in tests
        self._register_builtin_tests()
        
        logger.info("Self-Test Manager initialized")
    
    def _register_builtin_tests(self):
        """Register built-in test functions."""
        # Security tests
        self.register_test("security", "auth_system_test", self._test_auth_system)
        self.register_test("security", "mfa_system_test", self._test_mfa_system)
        self.register_test("security", "session_security_test", self._test_session_security)
        self.register_test("security", "encryption_test", self._test_encryption)
        
        # Performance tests
        self.register_test("performance", "response_time_test", self._test_response_times)
        self.register_test("performance", "memory_usage_test", self._test_memory_usage)
        self.register_test("performance", "concurrent_users_test", self._test_concurrent_users)
        
        # Connectivity tests
        self.register_test("connectivity", "port_accessibility_test", self._test_port_accessibility)
        self.register_test("connectivity", "ssl_certificate_test", self._test_ssl_certificate)
        self.register_test("connectivity", "websocket_test", self._test_websocket_connection)
        
        # Database tests
        self.register_test("database", "connection_test", self._test_database_connection)
        self.register_test("database", "auth_storage_test", self._test_auth_storage)
        self.register_test("database", "backup_integrity_test", self._test_backup_integrity)
        
        # API tests
        self.register_test("api", "endpoint_availability_test", self._test_api_endpoints)
        self.register_test("api", "authentication_test", self._test_api_authentication)
        self.register_test("api", "rate_limiting_test", self._test_api_rate_limiting)
    
    def register_test(self, category: str, test_name: str, test_function: Callable):
        """Register a test function."""
        if category not in self.test_registry:
            self.test_registry[category] = []
        
        self.test_registry[category].append({
            'name': test_name,
            'function': test_function
        })
    
    async def run_all_tests(self) -> TestSuite:
        """Run all registered tests."""
        suite_id = f"full_test_{int(time.time())}"
        suite = TestSuite(
            suite_id=suite_id,
            suite_name="Full System Test",
            category="all",
            tests=[],
            total_tests=0,
            passed_tests=0,
            failed_tests=0,
            warning_tests=0,
            skipped_tests=0,
            total_duration=0.0,
            started_at=datetime.utcnow()
        )
        
        # Run tests by category
        for category in self.test_config.test_categories:
            if category in self.test_registry:
                category_results = await self._run_category_tests(category)
                suite.tests.extend(category_results)
        
        # Calculate summary
        suite.total_tests = len(suite.tests)
        suite.passed_tests = len([t for t in suite.tests if t.status == TestStatus.PASSED])
        suite.failed_tests = len([t for t in suite.tests if t.status == TestStatus.FAILED])
        suite.warning_tests = len([t for t in suite.tests if t.status == TestStatus.WARNING])
        suite.skipped_tests = len([t for t in suite.tests if t.status == TestStatus.SKIPPED])
        suite.total_duration = sum(t.duration for t in suite.tests)
        suite.completed_at = datetime.utcnow()
        
        # Store results
        self.test_results[suite_id] = suite
        self.test_history.append(suite)
        
        # Export results if configured
        if self.test_config.export_results:
            await self._export_test_results(suite)
        
        logger.info(f"Test suite completed: {suite.passed_tests}/{suite.total_tests} passed")
        return suite
    
    async def run_category_tests(self, category: str) -> TestSuite:
        """Run tests for a specific category."""
        suite_id = f"{category}_test_{int(time.time())}"
        suite = TestSuite(
            suite_id=suite_id,
            suite_name=f"{category.title()} Tests",
            category=category,
            tests=[],
            total_tests=0,
            passed_tests=0,
            failed_tests=0,
            warning_tests=0,
            skipped_tests=0,
            total_duration=0.0,
            started_at=datetime.utcnow()
        )
        
        if category in self.test_registry:
            suite.tests = await self._run_category_tests(category)
            
            # Calculate summary
            suite.total_tests = len(suite.tests)
            suite.passed_tests = len([t for t in suite.tests if t.status == TestStatus.PASSED])
            suite.failed_tests = len([t for t in suite.tests if t.status == TestStatus.FAILED])
            suite.warning_tests = len([t for t in suite.tests if t.status == TestStatus.WARNING])
            suite.skipped_tests = len([t for t in suite.tests if t.status == TestStatus.SKIPPED])
            suite.total_duration = sum(t.duration for t in suite.tests)
        
        suite.completed_at = datetime.utcnow()
        self.test_results[suite_id] = suite
        
        return suite
    
    async def _run_category_tests(self, category: str) -> List[TestResult]:
        """Run all tests in a category."""
        results = []
        
        if category not in self.test_registry:
            return results
        
        for test_info in self.test_registry[category]:
            test_name = test_info['name']
            test_function = test_info['function']
            
            start_time = time.time()
            try:
                result = await test_function()
                duration = time.time() - start_time
                
                test_result = TestResult(
                    test_id=f"{category}_{test_name}_{int(time.time())}",
                    test_name=test_name,
                    category=category,
                    status=result.get('status', TestStatus.FAILED),
                    message=result.get('message', ''),
                    details=result.get('details', {}),
                    duration=duration,
                    timestamp=datetime.utcnow(),
                    error=result.get('error')
                )
                
            except Exception as e:
                duration = time.time() - start_time
                test_result = TestResult(
                    test_id=f"{category}_{test_name}_{int(time.time())}",
                    test_name=test_name,
                    category=category,
                    status=TestStatus.FAILED,
                    message=f"Test execution failed: {str(e)}",
                    details={},
                    duration=duration,
                    timestamp=datetime.utcnow(),
                    error=str(e)
                )
            
            results.append(test_result)
        
        return results
    
    # Built-in test functions
    async def _test_auth_system(self) -> Dict[str, Any]:
        """Test authentication system."""
        try:
            auth_storage = get_auth_storage()
            health_status = await auth_storage.health_check()
            
            if all(health_status.values()):
                return {
                    'status': TestStatus.PASSED,
                    'message': 'Authentication system is healthy',
                    'details': {'backends': health_status}
                }
            else:
                return {
                    'status': TestStatus.WARNING,
                    'message': 'Some authentication backends are unhealthy',
                    'details': {'backends': health_status}
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Authentication system test failed',
                'error': str(e)
            }
    
    async def _test_mfa_system(self) -> Dict[str, Any]:
        """Test MFA system."""
        try:
            mfa_manager = get_mfa_manager()
            
            if mfa_manager.is_mfa_enabled():
                methods = mfa_manager.get_available_mfa_methods()
                return {
                    'status': TestStatus.PASSED,
                    'message': f'MFA system enabled with {len(methods)} methods',
                    'details': {'methods': methods}
                }
            else:
                return {
                    'status': TestStatus.WARNING,
                    'message': 'MFA system is disabled',
                    'details': {}
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'MFA system test failed',
                'error': str(e)
            }
    
    async def _test_session_security(self) -> Dict[str, Any]:
        """Test session security."""
        try:
            # Test session timeout configuration
            timeout_with_mfa = self.config.get_session_timeout(True)
            timeout_without_mfa = self.config.get_session_timeout(False)
            
            if timeout_with_mfa > timeout_without_mfa:
                return {
                    'status': TestStatus.PASSED,
                    'message': 'Session security properly configured',
                    'details': {
                        'timeout_with_mfa': timeout_with_mfa,
                        'timeout_without_mfa': timeout_without_mfa
                    }
                }
            else:
                return {
                    'status': TestStatus.WARNING,
                    'message': 'Session timeout configuration may be insecure',
                    'details': {
                        'timeout_with_mfa': timeout_with_mfa,
                        'timeout_without_mfa': timeout_without_mfa
                    }
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Session security test failed',
                'error': str(e)
            }
    
    async def _test_encryption(self) -> Dict[str, Any]:
        """Test encryption functionality."""
        try:
            # Test encryption/decryption
            test_data = "test_encryption_data"
            encrypted = self.config.cipher.encrypt(test_data.encode())
            decrypted = self.config.cipher.decrypt(encrypted).decode()
            
            if decrypted == test_data:
                return {
                    'status': TestStatus.PASSED,
                    'message': 'Encryption system working correctly',
                    'details': {}
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': 'Encryption/decryption mismatch',
                    'details': {}
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Encryption test failed',
                'error': str(e)
            }
    
    async def _test_response_times(self) -> Dict[str, Any]:
        """Test API response times."""
        try:
            port = self.config.get_port_for_service('api')
            test_url = f"http://localhost:{port}/api/v1/"
            
            start_time = time.time()
            response = requests.get(test_url, timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200 and response_time < 1.0:
                return {
                    'status': TestStatus.PASSED,
                    'message': f'API response time: {response_time:.3f}s',
                    'details': {'response_time': response_time}
                }
            elif response_time >= 1.0:
                return {
                    'status': TestStatus.WARNING,
                    'message': f'Slow API response time: {response_time:.3f}s',
                    'details': {'response_time': response_time}
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': f'API request failed: {response.status_code}',
                    'details': {'status_code': response.status_code}
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Response time test failed',
                'error': str(e)
            }
    
    async def _test_memory_usage(self) -> Dict[str, Any]:
        """Test memory usage."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            if memory_mb < 500:  # Less than 500MB
                return {
                    'status': TestStatus.PASSED,
                    'message': f'Memory usage: {memory_mb:.1f}MB',
                    'details': {'memory_mb': memory_mb}
                }
            elif memory_mb < 1000:  # Less than 1GB
                return {
                    'status': TestStatus.WARNING,
                    'message': f'High memory usage: {memory_mb:.1f}MB',
                    'details': {'memory_mb': memory_mb}
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': f'Excessive memory usage: {memory_mb:.1f}MB',
                    'details': {'memory_mb': memory_mb}
                }
        except Exception as e:
            return {
                'status': TestStatus.SKIPPED,
                'message': 'Memory usage test skipped (psutil not available)',
                'error': str(e)
            }
    
    async def _test_concurrent_users(self) -> Dict[str, Any]:
        """Test concurrent user handling."""
        # Placeholder for concurrent user testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'Concurrent user test not implemented',
            'details': {}
        }
    
    async def _test_port_accessibility(self) -> Dict[str, Any]:
        """Test port accessibility."""
        try:
            import socket
            
            primary_port = self.config.port_config.primary_port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('localhost', primary_port))
            sock.close()
            
            if result == 0:
                return {
                    'status': TestStatus.PASSED,
                    'message': f'Port {primary_port} is accessible',
                    'details': {'port': primary_port}
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': f'Port {primary_port} is not accessible',
                    'details': {'port': primary_port}
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Port accessibility test failed',
                'error': str(e)
            }
    
    async def _test_ssl_certificate(self) -> Dict[str, Any]:
        """Test SSL certificate."""
        if not self.config.port_config.ssl_enabled:
            return {
                'status': TestStatus.SKIPPED,
                'message': 'SSL not enabled',
                'details': {}
            }
        
        # Placeholder for SSL certificate testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'SSL certificate test not implemented',
            'details': {}
        }
    
    async def _test_websocket_connection(self) -> Dict[str, Any]:
        """Test WebSocket connection."""
        # Placeholder for WebSocket testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'WebSocket test not implemented',
            'details': {}
        }
    
    async def _test_database_connection(self) -> Dict[str, Any]:
        """Test database connection."""
        try:
            auth_storage = get_auth_storage()
            health_status = await auth_storage.health_check()
            
            if health_status.get('primary', False):
                return {
                    'status': TestStatus.PASSED,
                    'message': 'Database connection healthy',
                    'details': health_status
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': 'Database connection failed',
                    'details': health_status
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'Database connection test failed',
                'error': str(e)
            }
    
    async def _test_auth_storage(self) -> Dict[str, Any]:
        """Test authentication storage."""
        return await self._test_auth_system()
    
    async def _test_backup_integrity(self) -> Dict[str, Any]:
        """Test backup integrity."""
        # Placeholder for backup integrity testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'Backup integrity test not implemented',
            'details': {}
        }
    
    async def _test_api_endpoints(self) -> Dict[str, Any]:
        """Test API endpoint availability."""
        try:
            port = self.config.get_port_for_service('api')
            endpoints = ['/api/v1/', '/api/beta/', '/api/']
            
            results = {}
            for endpoint in endpoints:
                try:
                    url = f"http://localhost:{port}{endpoint}"
                    response = requests.get(url, timeout=5)
                    results[endpoint] = response.status_code
                except Exception as e:
                    results[endpoint] = f"Error: {str(e)}"
            
            successful_endpoints = [ep for ep, status in results.items() if isinstance(status, int) and status < 400]
            
            if len(successful_endpoints) == len(endpoints):
                return {
                    'status': TestStatus.PASSED,
                    'message': 'All API endpoints accessible',
                    'details': results
                }
            elif len(successful_endpoints) > 0:
                return {
                    'status': TestStatus.WARNING,
                    'message': f'{len(successful_endpoints)}/{len(endpoints)} endpoints accessible',
                    'details': results
                }
            else:
                return {
                    'status': TestStatus.FAILED,
                    'message': 'No API endpoints accessible',
                    'details': results
                }
        except Exception as e:
            return {
                'status': TestStatus.FAILED,
                'message': 'API endpoint test failed',
                'error': str(e)
            }
    
    async def _test_api_authentication(self) -> Dict[str, Any]:
        """Test API authentication."""
        # Placeholder for API authentication testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'API authentication test not implemented',
            'details': {}
        }
    
    async def _test_api_rate_limiting(self) -> Dict[str, Any]:
        """Test API rate limiting."""
        # Placeholder for API rate limiting testing
        return {
            'status': TestStatus.SKIPPED,
            'message': 'API rate limiting test not implemented',
            'details': {}
        }
    
    async def _export_test_results(self, suite: TestSuite):
        """Export test results to file."""
        try:
            results_dir = Path("test_results")
            results_dir.mkdir(exist_ok=True)
            
            filename = f"test_results_{suite.started_at.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = results_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(asdict(suite), f, indent=2, default=str)
            
            logger.info(f"Test results exported to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export test results: {e}")
    
    def get_test_results(self, suite_id: str) -> Optional[TestSuite]:
        """Get test results by suite ID."""
        return self.test_results.get(suite_id)
    
    def get_latest_test_results(self) -> Optional[TestSuite]:
        """Get the latest test results."""
        if self.test_history:
            return self.test_history[-1]
        return None
    
    def get_test_history(self, limit: int = 10) -> List[TestSuite]:
        """Get test history."""
        return self.test_history[-limit:]

    async def schedule_tests(self):
        """Schedule automatic test runs."""
        if not self.test_config.enabled:
            return

        # Run startup tests if configured
        if self.test_config.auto_run_on_startup:
            logger.info("Running startup self-tests")
            await self.run_all_tests()

        # Schedule periodic tests (simplified implementation)
        # In production, use a proper scheduler like APScheduler
        for schedule in self.test_config.scheduled_runs:
            logger.info(f"Test scheduled: {schedule}")

# Global self-test manager instance
self_test_manager = SelfTestManager()

def get_self_test_manager() -> SelfTestManager:
    """Get the global self-test manager."""
    return self_test_manager
