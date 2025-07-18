# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Test Runner

Comprehensive test runner that can be executed from the CLI or standalone.
Provides detailed reporting and can run specific test categories or all tests.
"""

import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from . import ()
    TestSuite, TestResult, TEST_CONFIG, TEST_CATEGORIES,
    cleanup_test_data, create_test_directories
)

# Import all test suites
from .test_api_endpoints import api_tests
from .test_security import security_tests
from .test_features import feature_tests
from .test_performance import performance_tests
from .test_integration import integration_tests

logger = logging.getLogger(__name__)

class TestRunner:
    """Main test runner for PlexiChat tests."""

    def __init__(self):
        self.test_suites = {
            'api': api_tests,
            'security': security_tests,
            'features': feature_tests,
            'performance': performance_tests,
            'integration': integration_tests
        }

        self.results = {}
        self.start_time = None
        self.end_time = None

    async def run_all_tests(self, categories: Optional[List[str]] = None, )
                           verbose: bool = True) -> Dict[str, Any]:
        """Run all tests or specific categories."""
        logger.info("🚀 Starting PlexiChat Test Suite")
        logger.info("=" * 60)

        self.start_time = time.time()

        # Determine which test suites to run
        if categories:
            suites_to_run = {k: v for k, v in self.test_suites.items() if k in categories}
        else:
            suites_to_run = self.test_suites

        if not suites_to_run:
            logger.error(f"No test suites found for categories: {categories}")
            return {'error': 'No test suites found'}

        logger.info(f"Running {len(suites_to_run)} test suite(s): {list(suites_to_run.keys())}")

        # Setup test environment
        create_test_directories()

        # Run each test suite
        for suite_name, test_suite in suites_to_run.items():
            logger.info(f"\n📋 Running {suite_name.upper()} tests...")
            logger.info("-" * 40)

            try:
                suite_results = await test_suite.run_all()
                self.results[suite_name] = {
                    'suite': test_suite,
                    'results': suite_results,
                    'passed': sum(1 for r in suite_results if r.passed),
                    'failed': sum(1 for r in suite_results if not r.passed),
                    'total': len(suite_results)
                }

                # Log suite summary
                suite_info = self.results[suite_name]
                logger.info(f"✅ {suite_name.upper()}: {suite_info['passed']}/{suite_info['total']} tests passed")

                if suite_info['failed'] > 0:
                    logger.warning(f"❌ {suite_info['failed']} tests failed in {suite_name}")

            except Exception as e:
                logger.error(f"❌ Error running {suite_name} tests: {e}")
                self.results[suite_name] = {
                    'error': str(e),
                    'passed': 0,
                    'failed': 1,
                    'total': 1
                }

        self.end_time = time.time()

        # Generate final report
        report = self.generate_report(verbose)

        # Cleanup
        if TEST_CONFIG['cleanup_after_tests']:
            cleanup_test_data()

        return report

    def generate_report(self, verbose: bool = True) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_duration = self.end_time - self.start_time if self.end_time and self.start_time else 0

        # Calculate overall statistics
        total_passed = sum(suite.get('passed', 0) for suite in self.results.values())
        total_failed = sum(suite.get('failed', 0) for suite in self.results.values())
        total_tests = sum(suite.get('total', 0) for suite in self.results.values())

        success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

        report = {
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': total_duration,
            'summary': {
                'total_tests': total_tests,
                'passed': total_passed,
                'failed': total_failed,
                'success_rate': success_rate
            },
            'suites': {},
            'failed_tests': []
        }

        # Add suite details
        for suite_name, suite_data in self.results.items():
            if 'error' in suite_data:
                report['suites'][suite_name] = {
                    'error': suite_data['error'],
                    'status': 'error'
                }
                continue

            suite_report = {
                'passed': suite_data['passed'],
                'failed': suite_data['failed'],
                'total': suite_data['total'],
                'success_rate': (suite_data['passed'] / suite_data['total'] * 100) if suite_data['total'] > 0 else 0,
                'tests': []
            }

            # Add individual test results
            for result in suite_data['results']:
                test_info = {
                    'name': result.name,
                    'passed': result.passed,
                    'duration': result.duration,
                    'category': result.category
                }

                if not result.passed:
                    test_info['error'] = result.error
                    report['failed_tests'].append({)
                        'suite': suite_name,
                        'test': result.name,
                        'error': result.error
                    })

                suite_report['tests'].append(test_info)

            report['suites'][suite_name] = suite_report

        # Print summary
        self.print_summary(report, verbose)

        return report

    def print_summary(self, report: Dict[str, Any], verbose: bool = True):
        """Print test summary to console."""
        logger.info("\n" + "=" * 60)
        logger.info("🏁 TEST SUMMARY")
        logger.info("=" * 60)

        summary = report['summary']
        logger.info(f"Total Tests: {summary['total_tests']}")
        logger.info(f"Passed: {summary['passed']} ✅")
        logger.info(f"Failed: {summary['failed']} ❌")
        logger.info(f"Success Rate: {summary['success_rate']:.1f}%")
        logger.info(f"Duration: {report['duration_seconds']:.2f} seconds")

        # Suite breakdown
        logger.info("\n📊 SUITE BREAKDOWN:")
        for suite_name, suite_data in report['suites'].items():
            if 'error' in suite_data:
                logger.info(f"  {suite_name.upper()}: ERROR - {suite_data['error']}")
            else:
                logger.info(f"  {suite_name.upper()}: {suite_data['passed']}/{suite_data['total']} ")
                           f"({suite_data['success_rate']:.1f}%)")

        # Failed tests
        if report['failed_tests']:
            logger.info("\n❌ FAILED TESTS:")
            for failed_test in report['failed_tests']:
                logger.info(f"  {failed_test['suite']}.{failed_test['test']}: {failed_test['error']}")

        # Overall result
        if summary['failed'] == 0:
            logger.info("\n🎉 ALL TESTS PASSED! PlexiChat is working correctly.")
        else:
            logger.info(f"\n⚠️  {summary['failed']} test(s) failed. Check the details above.")

        logger.info("=" * 60)

    def save_report(self, report: Dict[str, Any], filename: Optional[str] = None):
        """Save test report to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_report_{timestamp}.json"

        report_path = TEST_CONFIG['test_data_dir'] / 'reports' / filename
        report_path.parent.mkdir(exist_ok=True)

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"📄 Test report saved: {report_path}")

async def run_tests(categories: Optional[List[str]] = None, )
                   verbose: bool = True,
                   save_report: bool = True) -> Dict[str, Any]:
    """Main function to run tests."""
    runner = TestRunner()
    report = await runner.run_all_tests(categories, verbose)

    if save_report:
        runner.save_report(report)

    return report

def main():
    """CLI entry point for test runner."""
    import argparse

    parser = argparse.ArgumentParser(description="PlexiChat Test Runner")
    parser.add_argument('--categories', nargs='+', )
                       choices=['api', 'security', 'features', 'performance', 'integration'],
                       help='Test categories to run (default: all)')
    parser.add_argument('--verbose', action='store_true', default=True,)
                       help='Verbose output')
    parser.add_argument('--no-cleanup', action='store_true',)
                       help='Skip cleanup after tests')
    parser.add_argument('--save-report', action='store_true', default=True,)
                       help='Save test report to file')

    args = parser.parse_args()

    # Update config based on args
    if args.no_cleanup:
        TEST_CONFIG['cleanup_after_tests'] = False

    # Run tests
    try:
        report = asyncio.run(run_tests())
            categories=args.categories,
            verbose=args.verbose,
            save_report=args.save_report
        ))

        # Exit with appropriate code
        if report['summary']['failed'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        logger.info("\n⚠️ Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Test runner error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
