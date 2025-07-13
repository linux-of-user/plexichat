import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict

from .test_api_endpoints import APIEndpointTest
from .test_config import ConfigTest
from .test_database import DatabaseTest
from .test_ssl import SSLTest

"""
PlexiChat Test Runner

Comprehensive test runner for all PlexiChat functionality including:
- Database connectivity tests
- SSL/TLS tests  
- API endpoint tests
- Configuration tests
- Optional feature tests
"""

# Add src to path for imports
sys.path.insert(0, str(from pathlib import Path
Path(__file__).parent.parent.parent))

logger = logging.getLogger(__name__)


class PlexiChatTestRunner:
    """Main test runner for PlexiChat test suite."""
    
    def __init__(self):
        self.test_classes = [
            ConfigTest,
            DatabaseTest,
            SSLTest,
            APIEndpointTest
        ]
        self.all_results = []
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all test suites."""
        print(" PlexiChat Test Suite")
        print("=" * 50)
        
        start_time = time.time()
        suite_results = {}
        
        for test_class in self.test_classes:
            test_name = test_class.__name__
            print(f"\n Running {test_name}...")
            print("-" * 30)
            
            try:
                test_instance = test_class()
                await test_instance.run_all_tests()
                
                # Get test results
                summary = test_instance.get_summary()
                suite_results[test_name] = summary
                self.all_results.extend(test_instance.test_results)
                
                # Print summary
                summary['total_tests']
                passed = summary['passed']
                failed = summary['failed']
                warnings = summary['warnings']
                
                print(f" Passed: {passed}")
                print(f" Failed: {failed}")
                print(f"  Warnings: {warnings}")
                print(f" Success Rate: {summary['success_rate']:.1f}%")
                
            except Exception as e:
                print(f" Test suite {test_name} failed: {e}")
                suite_results[test_name] = {
                    "error": str(e),
                    "total_tests": 0,
                    "passed": 0,
                    "failed": 1,
                    "warnings": 0,
                    "success_rate": 0
                }
        
        # Overall summary
        total_duration = time.time() - start_time
        overall_summary = self.get_overall_summary(suite_results, total_duration)
        
        self.print_final_summary(overall_summary)
        
        return overall_summary
    
    def get_overall_summary(self, suite_results: Dict[str, Any], duration: float) -> Dict[str, Any]:
        """Calculate overall test summary."""
        total_tests = sum(suite.get('total_tests', 0) for suite in suite_results.values())
        total_passed = sum(suite.get('passed', 0) for suite in suite_results.values())
        total_failed = sum(suite.get('failed', 0) for suite in suite_results.values())
        total_warnings = sum(suite.get('warnings', 0) for suite in suite_results.values())
        
        return {
            "total_tests": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "warnings": total_warnings,
            "success_rate": (total_passed / total_tests * 100) if total_tests > 0 else 0,
            "duration": duration,
            "suite_results": suite_results,
            "all_results": self.all_results
        }
    
    def print_final_summary(self, summary: Dict[str, Any]):
        """Print final test summary."""
        print("\n" + "=" * 50)
        print(" Final Test Results")
        print("=" * 50)
        
        print(f" Total Tests: {summary['total_tests']}")
        print(f" Passed: {summary['passed']}")
        print(f" Failed: {summary['failed']}")
        print(f"  Warnings: {summary['warnings']}")
        print(f" Success Rate: {summary['success_rate']:.1f}%")
        print(f"  Duration: {summary['duration']:.2f}s")
        
        # Show failed tests
        failed_tests = [r for r in self.all_results if r.status == "failed"]
        if failed_tests:
            print(f"\n Failed Tests ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"   {test.test_name} ({test.category}): {test.error_message}")
        
        # Show warnings
        warning_tests = [r for r in self.all_results if r.status == "warning"]
        if warning_tests:
            print(f"\n  Warnings ({len(warning_tests)}):")
            for test in warning_tests:
                print(f"   {test.test_name} ({test.category}): {test.error_message}")
        
        # Overall status
        if summary['failed'] == 0:
            if summary['warnings'] == 0:
                print("\n All tests passed!")
            else:
                print(f"\n All tests passed with {summary['warnings']} warnings")
        else:
            print(f"\n {summary['failed']} tests failed")
    
    def run_specific_category(self, category: str) -> Dict[str, Any]:
        """Run tests for a specific category."""
        category_map = {
            'config': ConfigTest,
            'database': DatabaseTest,
            'ssl': SSLTest,
            'api': APIEndpointTest
        }
        
        if category not in category_map:
            print(f" Unknown test category: {category}")
            print(f"Available categories: {', '.join(category_map.keys())}")
            return {}
        
        test_class = category_map[category]
        return asyncio.run(self._run_single_test_class(test_class))
    
    async def _run_single_test_class(self, test_class) -> Dict[str, Any]:
        """Run a single test class."""
        test_instance = test_class()
        await test_instance.run_all_tests()
        return test_instance.get_summary()


async def main():
    """Main entry point for test runner."""
    runner = PlexiChatTestRunner()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        category = sys.argv[1]
        print(f" Running {category} tests...")
        result = runner.run_specific_category(category)
        if result:
            print(f" {category} tests completed")
    else:
        # Run all tests
        await runner.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
