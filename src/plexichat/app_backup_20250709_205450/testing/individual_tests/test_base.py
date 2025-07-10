"""
Base test class with common utilities for individual endpoint tests.
Provides test data generation, authentication helpers, and result tracking.
"""

import asyncio
import random
import string
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json

from netlink.app.logger_config import logger


@dataclass
class TestResult:
    """Individual test result with detailed information."""
    test_name: str
    category: str
    endpoint: str
    method: str
    status: str  # "passed", "failed", "skipped", "warning"
    duration_ms: float
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    performance_metrics: Dict[str, float] = None
    code_coverage: Dict[str, bool] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.performance_metrics is None:
            self.performance_metrics = {}
        if self.code_coverage is None:
            self.code_coverage = {}


class TestDataGenerator:
    """Generates random test data for comprehensive testing."""
    
    @staticmethod
    def random_string(length: int = 10, include_special: bool = False) -> str:
        """Generate random string with optional special characters."""
        chars = string.ascii_letters + string.digits
        if include_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def random_email() -> str:
        """Generate random email address."""
        domains = ["example.com", "test.org", "demo.net", "sample.io"]
        username = TestDataGenerator.random_string(8).lower()
        domain = random.choice(domains)
        return f"{username}@{domain}"
    
    @staticmethod
    def random_username() -> str:
        """Generate random username."""
        prefixes = ["user", "test", "demo", "sample", "admin", "mod"]
        suffix = TestDataGenerator.random_string(6).lower()
        return f"{random.choice(prefixes)}_{suffix}"
    
    @staticmethod
    def random_password(length: int = 12) -> str:
        """Generate secure random password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(length))
        # Ensure it has at least one of each type
        if not any(c.isupper() for c in password):
            password = password[:-1] + random.choice(string.ascii_uppercase)
        if not any(c.islower() for c in password):
            password = password[:-1] + random.choice(string.ascii_lowercase)
        if not any(c.isdigit() for c in password):
            password = password[:-1] + random.choice(string.digits)
        return password
    
    @staticmethod
    def random_message_content(length: int = None) -> str:
        """Generate random message content."""
        if length is None:
            length = random.randint(10, 500)
        
        words = [
            "hello", "world", "test", "message", "content", "random", "data",
            "communication", "secure", "platform", "netlink", "system",
            "user", "admin", "moderator", "backup", "recovery", "shard",
            "device", "network", "encryption", "security", "government",
            "level", "redundancy", "intelligent", "distribution", "monitoring"
        ]
        
        message_words = []
        current_length = 0
        
        while current_length < length:
            word = random.choice(words)
            if current_length + len(word) + 1 <= length:
                message_words.append(word)
                current_length += len(word) + 1
            else:
                break
        
        return " ".join(message_words)
    
    @staticmethod
    def random_user_data() -> Dict[str, Any]:
        """Generate complete random user data."""
        return {
            "username": TestDataGenerator.random_username(),
            "email": TestDataGenerator.random_email(),
            "password": TestDataGenerator.random_password(),
            "display_name": TestDataGenerator.random_string(15),
            "bio": TestDataGenerator.random_message_content(100),
            "location": random.choice(["New York", "London", "Tokyo", "Berlin", "Sydney"]),
            "website": f"https://{TestDataGenerator.random_string(8).lower()}.com"
        }
    
    @staticmethod
    def random_device_data() -> Dict[str, Any]:
        """Generate random device registration data."""
        device_types = ["desktop", "laptop", "server", "mobile", "tablet"]
        connection_types = ["ethernet", "wifi", "cellular", "satellite"]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
        
        return {
            "device_name": f"TestDevice_{TestDataGenerator.random_string(6)}",
            "device_type": random.choice(device_types),
            "hardware_id": f"MAC:{':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])}",
            "total_storage_gb": random.uniform(10.0, 1000.0),
            "connection_type": random.choice(connection_types),
            "ip_address": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "hostname": f"test-{TestDataGenerator.random_string(8).lower()}",
            "port": random.randint(8000, 9000),
            "prefer_own_messages": random.choice([True, False]),
            "allow_critical_data": random.choice([True, False]),
            "storage_priority": random.randint(1, 10),
            "geographic_region": random.choice(regions)
        }
    
    @staticmethod
    def random_backup_data() -> Dict[str, Any]:
        """Generate random backup creation data."""
        security_levels = ["unclassified", "confidential", "secret", "top_secret"]
        
        return {
            "backup_name": f"test_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{TestDataGenerator.random_string(4)}",
            "security_level": random.choice(security_levels),
            "include_user_data": random.choice([True, False]),
            "include_system_config": random.choice([True, False]),
            "compression_level": random.randint(1, 9),
            "encryption_enabled": True
        }


class BaseEndpointTest:
    """Base class for individual endpoint tests."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.test_results: List[TestResult] = []
        self.test_users: List[Dict[str, Any]] = []
        self.auth_tokens: Dict[str, str] = {}
        self.test_data_generator = TestDataGenerator()
        
    async def setup_test_environment(self) -> bool:
        """Set up test environment with test users and data."""
        try:
            logger.info(f"🔧 Setting up test environment for {self.__class__.__name__}")
            
            # Generate test users
            for i in range(5):  # Create 5 test users
                user_data = self.test_data_generator.random_user_data()
                self.test_users.append(user_data)
            
            # Register test users and get auth tokens
            await self._register_test_users()
            
            logger.info(f"✅ Test environment setup completed with {len(self.test_users)} users")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to setup test environment: {e}")
            return False
    
    async def cleanup_test_environment(self) -> bool:
        """Clean up test environment and data."""
        try:
            logger.info(f"🧹 Cleaning up test environment for {self.__class__.__name__}")
            
            # Clean up test users, messages, files, etc.
            await self._cleanup_test_data()
            
            self.test_results.clear()
            self.test_users.clear()
            self.auth_tokens.clear()
            
            logger.info("✅ Test environment cleanup completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to cleanup test environment: {e}")
            return False
    
    async def _register_test_users(self):
        """Register test users and obtain auth tokens."""
        # This would be implemented by subclasses to register users
        # and obtain authentication tokens for testing
        pass
    
    async def _cleanup_test_data(self):
        """Clean up test data created during testing."""
        # This would be implemented by subclasses to clean up
        # test-specific data
        pass
    
    def record_test_result(
        self,
        test_name: str,
        category: str,
        endpoint: str,
        method: str,
        status: str,
        duration_ms: float,
        **kwargs
    ) -> TestResult:
        """Record a test result with detailed information."""
        result = TestResult(
            test_name=test_name,
            category=category,
            endpoint=endpoint,
            method=method,
            status=status,
            duration_ms=duration_ms,
            **kwargs
        )
        
        self.test_results.append(result)
        
        # Log result
        status_emoji = {
            "passed": "✅",
            "failed": "❌", 
            "skipped": "⏭️",
            "warning": "⚠️"
        }.get(status, "❓")
        
        logger.info(f"{status_emoji} {test_name}: {status} ({duration_ms:.1f}ms)")
        
        return result
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of all test results."""
        total_tests = len(self.test_results)
        if total_tests == 0:
            return {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "warnings": 0}
        
        passed = len([r for r in self.test_results if r.status == "passed"])
        failed = len([r for r in self.test_results if r.status == "failed"])
        skipped = len([r for r in self.test_results if r.status == "skipped"])
        warnings = len([r for r in self.test_results if r.status == "warning"])
        
        avg_duration = sum(r.duration_ms for r in self.test_results) / total_tests
        
        return {
            "total": total_tests,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "warnings": warnings,
            "success_rate": (passed / total_tests) * 100,
            "average_duration_ms": avg_duration,
            "total_duration_ms": sum(r.duration_ms for r in self.test_results)
        }
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests for this endpoint category."""
        try:
            # Setup test environment
            if not await self.setup_test_environment():
                return {"error": "Failed to setup test environment"}
            
            # Run tests (implemented by subclasses)
            await self._run_endpoint_tests()
            
            # Get summary
            summary = self.get_test_summary()
            
            # Cleanup
            await self.cleanup_test_environment()
            
            return {
                "summary": summary,
                "results": [result.__dict__ for result in self.test_results]
            }
            
        except Exception as e:
            logger.error(f"Failed to run tests: {e}")
            return {"error": str(e)}
    
    async def _run_endpoint_tests(self):
        """Run endpoint-specific tests (implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement _run_endpoint_tests")
    
    def generate_test_id(self) -> str:
        """Generate unique test ID."""
        return f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
