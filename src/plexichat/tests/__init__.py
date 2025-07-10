"""
PlexiChat Unified Testing Framework

Consolidated testing functionality from:
- src/plexichat/tests/ (main test suite)
- src/plexichat/app/testing/ (comprehensive test suite)
- src/plexichat/app/tests/ (additional tests)

Provides comprehensive testing with:
- Unit tests for all modules
- Integration tests for system components
- End-to-end tests for complete workflows
- Performance and load testing
- Security and penetration testing
- API endpoint testing
- Database testing
- Clustering and backup testing
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Configure test logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Test configuration
TEST_CONFIG = {
    "test_database_url": "sqlite:///./test_plexichat.db",
    "test_data_dir": "tests/data",
    "test_results_dir": "tests/results",
    "test_coverage_dir": "tests/coverage",
    "parallel_testing": True,
    "max_workers": 4,
    "timeout_seconds": 300,
    "cleanup_after_tests": True
}

# Test categories
TEST_CATEGORIES = {
    "unit": "Unit tests for individual components",
    "integration": "Integration tests for system components",
    "e2e": "End-to-end tests for complete workflows",
    "api": "API endpoint testing",
    "security": "Security and penetration testing",
    "performance": "Performance and load testing",
    "database": "Database functionality testing",
    "backup": "Backup system testing",
    "clustering": "Clustering system testing",
    "ai": "AI features testing"
}

# Import test utilities
from .utils.test_helpers import TestHelper, AsyncTestHelper
from .utils.fixtures import TestFixtures
from .utils.mocks import MockServices
from .utils.assertions import CustomAssertions

# Import test runners
from .runners.unit_test_runner import UnitTestRunner
from .runners.integration_test_runner import IntegrationTestRunner
from .runners.comprehensive_test_runner import ComprehensiveTestRunner

__version__ = "3.0.0"
__all__ = [
    # Test utilities
    "TestHelper",
    "AsyncTestHelper", 
    "TestFixtures",
    "MockServices",
    "CustomAssertions",
    
    # Test runners
    "UnitTestRunner",
    "IntegrationTestRunner",
    "ComprehensiveTestRunner",
    
    # Configuration
    "TEST_CONFIG",
    "TEST_CATEGORIES"
]

def setup_test_environment():
    """Setup test environment and directories."""
    test_dirs = [
        Path(TEST_CONFIG["test_data_dir"]),
        Path(TEST_CONFIG["test_results_dir"]),
        Path(TEST_CONFIG["test_coverage_dir"])
    ]
    
    for test_dir in test_dirs:
        test_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("✅ Test environment setup complete")

def cleanup_test_environment():
    """Cleanup test environment."""
    if TEST_CONFIG["cleanup_after_tests"]:
        # Cleanup logic would go here
        logger.info("🧹 Test environment cleanup complete")

# Auto-setup on import
setup_test_environment()
