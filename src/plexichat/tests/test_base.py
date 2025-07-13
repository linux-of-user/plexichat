"""
Base test class with common utilities for PlexiChat tests.
Provides test data generation, authentication helpers, and result tracking.
"""

import logging
import random
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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
    def generate_username(length: int = 8) -> str:
        """Generate random username."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    @staticmethod
    def generate_email() -> str:
        """Generate random email address."""
        username = TestDataGenerator.generate_username(6)
        domains = ['test.com', 'example.org', 'demo.net']
        return f"{username}@{random.choice(domains)}"
    
    @staticmethod
    def generate_password(length: int = 12) -> str:
        """Generate secure random password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choices(chars, k=length))
    
    @staticmethod
    def generate_message_content(length: int = 50) -> str:
        """Generate random message content."""
        words = ['hello', 'world', 'test', 'message', 'content', 'random', 'data']
        return ' '.join(random.choices(words, k=length//6))


class BaseTest:
    """Base test class with common functionality."""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session_token = None
        self.test_results = []
        self.data_generator = TestDataGenerator()
    
    def add_result(self, result: TestResult):
        """Add test result to collection."""
        self.test_results.append(result)
        
        # Log result
        if result.status == "passed":
            logger.info(f"✅ {result.test_name}: {result.status}")
        elif result.status == "failed":
            logger.error(f"❌ {result.test_name}: {result.error_message}")
        elif result.status == "warning":
            logger.warning(f"⚠️ {result.test_name}: {result.error_message}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get test summary statistics."""
        total = len(self.test_results)
        passed = len([r for r in self.test_results if r.status == "passed"])
        failed = len([r for r in self.test_results if r.status == "failed"])
        warnings = len([r for r in self.test_results if r.status == "warning"])
        
        return {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "success_rate": (passed / total * 100) if total > 0 else 0,
            "results": self.test_results
        }
    
    async def setup(self):
        """Setup test environment."""
    
    async def teardown(self):
        """Cleanup test environment."""
    
    async def run_all_tests(self):
        """Run all tests in this test class."""
        await self.setup()
        try:
            # Override in subclasses
            pass
        finally:
            await self.teardown()
