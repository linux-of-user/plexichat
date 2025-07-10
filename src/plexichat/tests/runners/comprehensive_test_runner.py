"""Comprehensive test runner."""
import logging
from .unit_test_runner import UnitTestRunner
from .integration_test_runner import IntegrationTestRunner

logger = logging.getLogger(__name__)

class ComprehensiveTestRunner:
    """Run comprehensive test suite."""
    
    def __init__(self):
        self.unit_runner = UnitTestRunner()
        self.integration_runner = IntegrationTestRunner()
    
    async def run_all_tests(self):
        """Run all test categories."""
        logger.info("🚀 Running comprehensive test suite...")
        
        results = {
            "unit_tests": await self.unit_runner.run_tests(),
            "integration_tests": await self.integration_runner.run_tests()
        }
        
        logger.info("✅ Comprehensive test suite complete")
        return results
