"""
Test Plugin - Comprehensive Testing Suite

This plugin provides comprehensive testing capabilities for all PlexiChat endpoints
and system components. It integrates with the unified test manager and exposes
test commands through the CLI system.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from plexichat.core.plugins.manager import PluginInterface

logger = logging.getLogger(__name__)

class Plugin(PluginInterface):
    """Comprehensive test plugin for PlexiChat."""

    def __init__(self, plugin_id: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(plugin_id, config)
        self.name = "Test Plugin"
        self.version = "1.0.0"
        self.description = "Comprehensive test suite plugin"
        self.author = "PlexiChat Team"
        self.type = "testing"
        self.test_manager = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.reports_dir = Path(__file__).parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)



    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Import the unified test manager
            try:
                from plexichat.tests.unified_test_manager import unified_test_manager
                self.test_manager = unified_test_manager
                self.logger.info("Test manager initialized successfully")
            except ImportError as e:
                self.logger.error(f"Failed to import test manager: {e}")
                return False

            self.logger.info("Test plugin initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize test plugin: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("Test plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during test plugin cleanup: {e}")
            return False

    async def shutdown(self) -> bool:
        """Shutdown the plugin."""
        return await self.cleanup()

    def get_commands(self) -> Dict[str, Any]:
        """Get plugin CLI commands."""
        return {
            "run_tests": self._cmd_run_tests,
            "list_categories": self._cmd_list_categories,
            "test_endpoints": self._cmd_test_endpoints,
            "test_plugins": self._cmd_test_plugins,
            "generate_report": self._cmd_generate_report,
        }

    def get_event_handlers(self) -> Dict[str, Any]:
        """Get plugin event handlers."""
        return {}

    async def handle_command(self, command: str, args: List[str]) -> Dict[str, Any]:
        """Handle CLI commands (legacy support)."""
        commands = self.get_commands()
        if command in commands:
            return await commands[command](*args)
        else:
            return {"error": f"Unknown command: {command}"}

    async def _cmd_run_tests(self, *args) -> Dict[str, Any]:
        """Handle run_tests command."""
        if not self.test_manager:
            print("❌ Test manager not available")
            return {"error": "Test manager not available"}

        # Parse arguments
        categories = None
        verbose = False
        save_report = True

        args_list = list(args)
        i = 0
        while i < len(args_list):
            if args_list[i] == "--categories" and i + 1 < len(args_list):
                categories = args_list[i + 1].split(",")
                i += 2
            elif args_list[i] == "--verbose":
                verbose = True
                i += 1
            elif args_list[i] == "--no-save":
                save_report = False
                i += 1
            else:
                i += 1

        try:
            print(f"🧪 Running tests with categories: {categories or 'all'}, verbose: {verbose}")
            results = await self.test_manager.run_tests(categories, verbose, save_report)

            # Print summary
            summary = results.get("summary", {})
            total = summary.get("total_tests", 0)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            duration = summary.get("duration", 0)

            print(f"✅ Tests completed: {passed}/{total} passed, {failed} failed in {duration:.2f}s")

            return {
                "success": True,
                "message": "Tests completed successfully",
                "results": results
            }

        except Exception as e:
            self.logger.error(f"Error running tests: {e}")
            print(f"❌ Error running tests: {e}")
            return {"error": str(e)}

    async def _cmd_list_categories(self, *args) -> Dict[str, Any]:
        """Handle list_categories command."""
        if not self.test_manager:
            print("❌ Test manager not available")
            return {"error": "Test manager not available"}

        try:
            categories = getattr(self.test_manager, 'test_categories', {})
            print("📋 Available test categories:")
            for category, description in categories.items():
                print(f"  • {category}: {description}")

            return {
                "success": True,
                "categories": categories
            }
        except Exception as e:
            print(f"❌ Error listing categories: {e}")
            return {"error": str(e)}

    async def _cmd_test_endpoints(self, *args) -> Dict[str, Any]:
        """Handle test_endpoints command."""
        if not self.test_manager:
            print("❌ Test manager not available")
            return {"error": "Test manager not available"}

        try:
            print("🌐 Running endpoint tests...")
            results = await self.test_manager.run_tests(["api"], verbose=True, save_report=True)

            summary = results.get("summary", {})
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            print(f"✅ Endpoint tests completed: {passed} passed, {failed} failed")

            return {
                "success": True,
                "message": "Endpoint tests completed",
                "results": results
            }
        except Exception as e:
            print(f"❌ Error testing endpoints: {e}")
            return {"error": str(e)}

    async def _cmd_test_plugins(self, *args) -> Dict[str, Any]:
        """Handle test_plugins command."""
        if not self.test_manager:
            print("❌ Test manager not available")
            return {"error": "Test manager not available"}

        try:
            print("🔌 Running plugin tests...")
            results = await self.test_manager.run_tests(["plugins"], verbose=True, save_report=True)

            summary = results.get("summary", {})
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            print(f"✅ Plugin tests completed: {passed} passed, {failed} failed")

            return {
                "success": True,
                "message": "Plugin tests completed",
                "results": results
            }
        except Exception as e:
            print(f"❌ Error testing plugins: {e}")
            return {"error": str(e)}

    async def _cmd_generate_report(self, *args) -> Dict[str, Any]:
        """Handle generate_report command."""
        try:
            # Generate a comprehensive test report
            if not self.test_manager:
                print("❌ Test manager not available")
                return {"error": "Test manager not available"}

            print("📊 Generating comprehensive test report...")
            # Run all tests
            results = await self.test_manager.run_tests(None, True, True)

            # Generate summary report
            summary = {
                "timestamp": datetime.now().isoformat(),
                "total_tests": results["summary"]["total_tests"],
                "passed": results["summary"]["passed"],
                "failed": results["summary"]["failed"],
                "success_rate": (results["summary"]["passed"] / results["summary"]["total_tests"] * 100) if results["summary"]["total_tests"] > 0 else 0,
                "duration": results["summary"]["duration"]
            }

            # Save summary report
            report_file = self.reports_dir / f"test_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(summary, f, indent=2)

            print(f"✅ Test report generated: {report_file}")
            print(f"📈 Success rate: {summary['success_rate']:.1f}%")

            return {
                "success": True,
                "message": f"Test report generated: {report_file}",
                "summary": summary
            }

        except Exception as e:
            print(f"❌ Error generating report: {e}")
            return {"error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run plugin self-tests."""
        tests = [
            ("test_manager_availability", self._test_test_manager_availability),
            ("command_handling", self._test_command_handling),
            ("report_generation", self._test_report_generation)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results

    async def _test_test_manager_availability(self) -> Dict[str, Any]:
        """Test that test manager is available."""
        try:
            if self.test_manager is None:
                return {"success": False, "error": "Test manager not available"}
            return {"success": True, "message": "Test manager is available"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _test_command_handling(self) -> Dict[str, Any]:
        """Test command handling functionality."""
        try:
            # Test list_categories command
            result = await self.handle_command("list_categories", [])
            if "error" in result:
                return {"success": False, "error": f"Command handling failed: {result['error']}"}
            return {"success": True, "message": "Command handling working"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _test_report_generation(self) -> Dict[str, Any]:
        """Test report generation functionality."""
        try:
            # Test that we can create report directory
            test_report_dir = self.reports_dir / "test"
            test_report_dir.mkdir(exist_ok=True)
            test_report_dir.rmdir()
            return {"success": True, "message": "Report generation capability verified"}
        except Exception as e:
            return {"success": False, "error": str(e)}

# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return TestPlugin()
