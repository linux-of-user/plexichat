"""
CLI Test Commands

Provides test execution capabilities from within the PlexiChat CLI.
Allows running comprehensive test suites and individual test categories.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

# Add tests to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from plexichat.tests.test_runner import run_tests, TestRunner
    from plexichat.tests import TEST_CATEGORIES, TEST_CONFIG
    TESTS_AVAILABLE = True
except ImportError as e:
    TESTS_AVAILABLE = False
    TEST_CATEGORIES = ['api', 'security', 'features', 'performance', 'integration']
    logging.warning(f"Test system not available: {e}")

logger = logging.getLogger(__name__)

class TestCLI:
    """CLI interface for test execution."""

    def __init__(self):
        self.runner = TestRunner() if TESTS_AVAILABLE else None

    async def run_all_tests(self, verbose: bool = True, save_report: bool = True) -> Dict[str, Any]:
        """Run all test suites."""
        if not TESTS_AVAILABLE:
            logger.error("Test system not available. Check test dependencies.")
            return {'error': 'Test system not available'}

        logger.info("🚀 Running ALL PlexiChat tests...")

        try:
            report = await run_tests(
                categories=None,
                verbose=verbose,
                save_report=save_report
            )
            return report
        except Exception as e:
            logger.error(f"Error running tests: {e}")
            return {'error': str(e)}

    async def run_category_tests(self, categories: List[str],
                                verbose: bool = True,
                                save_report: bool = True) -> Dict[str, Any]:
        """Run specific test categories."""
        if not TESTS_AVAILABLE:
            logger.error("Test system not available. Check test dependencies.")
            return {'error': 'Test system not available'}

        # Validate categories
        invalid_categories = [cat for cat in categories if cat not in TEST_CATEGORIES]
        if invalid_categories:
            logger.error(f"Invalid test categories: {invalid_categories}")
            logger.info(f"Available categories: {', '.join(TEST_CATEGORIES)}")
            return {'error': f'Invalid categories: {invalid_categories}'}

        logger.info(f"🚀 Running {', '.join(categories).upper()} tests...")

        try:
            report = await run_tests(
                categories=categories,
                verbose=verbose,
                save_report=save_report
            )
            return report
        except Exception as e:
            logger.error(f"Error running tests: {e}")
            return {'error': str(e)}

    async def run_quick_tests(self) -> Dict[str, Any]:
        """Run quick smoke tests."""
        if not TESTS_AVAILABLE:
            logger.error("Test system not available. Check test dependencies.")
            return {'error': 'Test system not available'}

        logger.info("Running quick smoke tests...")

        # Run only API tests for quick validation
        return await self.run_category_tests(['api'], verbose=False, save_report=False)

    def list_test_categories(self):
        """List available test categories."""
        logger.info("📋 Available Test Categories:")
        logger.info("-" * 30)

        category_descriptions = {
            'api': 'API endpoint tests (authentication, CRUD operations)',
            'security': 'Security tests (SQL injection, XSS, rate limiting)',
            'features': 'Feature tests (rich text, emojis, file attachments)',
            'performance': 'Performance tests (load testing, response times)',
            'integration': 'Integration tests (end-to-end workflows)'
        }

        for category in TEST_CATEGORIES:
            description = category_descriptions.get(category, 'Test category')
            logger.info(f"  {category.upper():<12} - {description}")

        logger.info("\nUsage:")
        logger.info("  test run all                    # Run all tests")
        logger.info("  test run api security           # Run specific categories")
        logger.info("  test quick                      # Run quick smoke tests")

    def show_test_config(self):
        """Show current test configuration."""
        if not TESTS_AVAILABLE:
            logger.error("Test system not available.")
            return

        logger.info("Test Configuration:")
        logger.info("-" * 25)
        logger.info(f"Base URL: {TEST_CONFIG.get('base_url', 'Not set')}")
        logger.info(f"Timeout: {TEST_CONFIG.get('timeout', 'Not set')} seconds")
        logger.info(f"Cleanup: {TEST_CONFIG.get('cleanup_after_tests', 'Not set')}")
        logger.info(f"Verbose: {TEST_CONFIG.get('verbose', 'Not set')}")
        logger.info(f"Test Data Dir: {TEST_CONFIG.get('test_data_dir', 'Not set')}")

    async def validate_test_environment(self) -> bool:
        """Validate that the test environment is ready."""
        if not TESTS_AVAILABLE:
            logger.error("Test system not available.")
            return False

        logger.info("🔍 Validating test environment...")

        # Check if server is running
        try:
            import requests
            base_url = TEST_CONFIG.get('base_url', 'http://localhost:8001')
            response = requests.get(f"{base_url}/health", timeout=5)

            if response.status_code == 200:
                logger.info("Server is running and accessible")
                return True
            else:
                logger.warning(f"Server returned status {response.status_code}")
                return False

        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to server. Make sure PlexiChat is running.")
            return False
        except Exception as e:
            logger.error(f"Error checking server: {e}")
            return False

# Global test CLI instance
test_cli = TestCLI()

async def handle_test_command(args: List[str]) -> None:
    """Handle test CLI commands."""
    if not args:
        logger.info("Usage: test <command> [options]")
        logger.info("Commands:")
        logger.info("  run [categories...]  - Run tests (all or specific categories)")
        logger.info("  quick               - Run quick smoke tests")
        logger.info("  list                - List available test categories")
        logger.info("  config              - Show test configuration")
        logger.info("  validate            - Validate test environment")
        return

    command = args[0].lower()

    if command == 'run':
        if len(args) == 1 or (len(args) == 2 and args[1] == 'all'):
            # Run all tests
            await test_cli.run_all_tests()
        else:
            # Run specific categories
            categories = args[1:]
            await test_cli.run_category_tests(categories)

    elif command == 'quick':
        await test_cli.run_quick_tests()

    elif command == 'list':
        test_cli.list_test_categories()

    elif command == 'config':
        test_cli.show_test_config()

    elif command == 'validate':
        is_valid = await test_cli.validate_test_environment()
        if is_valid:
            logger.info("Test environment is ready")
        else:
            logger.error("Test environment validation failed")

    else:
        logger.error(f"Unknown test command: {command}")
        logger.info("Available commands: run, quick, list, config, validate")

def create_test_parser():
    """Create argument parser for test commands."""
    import argparse

    parser = argparse.ArgumentParser(description="PlexiChat Test Commands")
    subparsers = parser.add_subparsers(dest='command', help='Test commands')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run tests')
    run_parser.add_argument('categories', nargs='*',
                           choices=TEST_CATEGORIES + ['all'],
                           help='Test categories to run (default: all)')
    run_parser.add_argument('--no-save', action='store_true',
                           help='Do not save test report')
    run_parser.add_argument('--quiet', action='store_true',
                           help='Reduce output verbosity')

    # Quick command
    subparsers.add_parser('quick', help='Run quick smoke tests')

    # List command
    subparsers.add_parser('list', help='List available test categories')

    # Config command
    subparsers.add_parser('config', help='Show test configuration')

    # Validate command
    subparsers.add_parser('validate', help='Validate test environment')

    return parser

async def main():
    """Main entry point for test CLI."""
    parser = create_test_parser()
    args = parser.parse_args()

    if args.command == 'run':
        categories = args.categories if args.categories and 'all' not in args.categories else None
        await test_cli.run_category_tests(
            categories or TEST_CATEGORIES,
            verbose=not args.quiet,
            save_report=not args.no_save
        )
    elif args.command == 'quick':
        await test_cli.run_quick_tests()
    elif args.command == 'list':
        test_cli.list_test_categories()
    elif args.command == 'config':
        test_cli.show_test_config()
    elif args.command == 'validate':
        await test_cli.validate_test_environment()
    else:
        parser.print_help()

if __name__ == '__main__':
    asyncio.run(main())
