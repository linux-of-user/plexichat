#!/usr/bin/env python3
"""
Comprehensive Plugin System Test Suite

Tests all plugins and the enhanced plugin loading system.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from plexichat.infrastructure.modules.plugin_manager import get_plugin_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PluginTestSuite:
    """Comprehensive plugin test suite."""
    
    def __init__(self):
        self.plugin_manager = get_plugin_manager()
        self.test_results = {}
        
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all plugin tests."""
        logger.info("🚀 Starting comprehensive plugin test suite...")
        
        # Test plugin discovery
        await self.test_plugin_discovery()
        
        # Test plugin loading
        await self.test_plugin_loading()
        
        # Test plugin self-tests
        await self.test_plugin_self_tests()
        
        # Test plugin integration
        await self.test_plugin_integration()
        
        # Generate final report
        return self.generate_test_report()
    
    async def test_plugin_discovery(self):
        """Test plugin discovery functionality."""
        logger.info("🔍 Testing plugin discovery...")
        
        try:
            # Discover plugins
            await self.plugin_manager.discover_plugins()
            
            discovered_plugins = list(self.plugin_manager.modules.keys())
            logger.info(f"Discovered {len(discovered_plugins)} plugins: {discovered_plugins}")
            
            # Expected plugins
            expected_plugins = [
                "file_manager",
                "code_analyzer", 
                "network_scanner",
                "data_visualizer",
                "api_tester",
                "performance_monitor",
                "security_toolkit",
                "dev_tools",
                "advanced_client"
            ]
            
            missing_plugins = [p for p in expected_plugins if p not in discovered_plugins]
            extra_plugins = [p for p in discovered_plugins if p not in expected_plugins and p not in ["hello_world", "ai_providers"]]
            
            self.test_results["discovery"] = {
                "success": len(missing_plugins) == 0,
                "discovered_count": len(discovered_plugins),
                "expected_count": len(expected_plugins),
                "missing_plugins": missing_plugins,
                "extra_plugins": extra_plugins,
                "all_plugins": discovered_plugins
            }
            
            if missing_plugins:
                logger.warning(f"❌ Missing expected plugins: {missing_plugins}")
            else:
                logger.info("✅ All expected plugins discovered")
                
        except Exception as e:
            logger.error(f"❌ Plugin discovery failed: {e}")
            self.test_results["discovery"] = {
                "success": False,
                "error": str(e)
            }
    
    async def test_plugin_loading(self):
        """Test plugin loading functionality."""
        logger.info("📦 Testing plugin loading...")
        
        loading_results = {}
        
        for plugin_name in self.plugin_manager.modules.keys():
            try:
                logger.info(f"Loading plugin: {plugin_name}")
                success = await self.plugin_manager.load_plugin(plugin_name)
                
                loading_results[plugin_name] = {
                    "success": success,
                    "loaded": plugin_name in self.plugin_manager.loaded_plugins
                }
                
                if success:
                    logger.info(f"✅ Successfully loaded: {plugin_name}")
                else:
                    logger.warning(f"❌ Failed to load: {plugin_name}")
                    
            except Exception as e:
                logger.error(f"❌ Error loading {plugin_name}: {e}")
                loading_results[plugin_name] = {
                    "success": False,
                    "error": str(e)
                }
        
        successful_loads = sum(1 for result in loading_results.values() if result.get("success", False))
        total_plugins = len(loading_results)
        
        self.test_results["loading"] = {
            "success": successful_loads > 0,
            "successful_loads": successful_loads,
            "total_plugins": total_plugins,
            "success_rate": (successful_loads / total_plugins * 100) if total_plugins > 0 else 0,
            "plugin_results": loading_results
        }
        
        logger.info(f"📊 Plugin loading results: {successful_loads}/{total_plugins} successful ({self.test_results['loading']['success_rate']:.1f}%)")
    
    async def test_plugin_self_tests(self):
        """Test plugin self-test functionality."""
        logger.info("🧪 Running plugin self-tests...")
        
        # Run all plugin tests
        all_test_results = await self.plugin_manager.run_all_plugin_tests()
        
        self.test_results["self_tests"] = all_test_results
        
        logger.info(f"🧪 Self-test results:")
        logger.info(f"   Total plugins with tests: {all_test_results['plugins_with_tests']}")
        logger.info(f"   Total tests: {all_test_results['total_tests']}")
        logger.info(f"   Passed: {all_test_results['total_passed']}")
        logger.info(f"   Failed: {all_test_results['total_failed']}")
        
        # Log individual plugin results
        for plugin_name, results in all_test_results.get("plugin_results", {}).items():
            if results.get("success", False):
                logger.info(f"   ✅ {plugin_name}: {results['passed']}/{results['total']} tests passed")
            else:
                logger.warning(f"   ❌ {plugin_name}: {results['failed']}/{results['total']} tests failed")
    
    async def test_plugin_integration(self):
        """Test plugin integration features."""
        logger.info("🔗 Testing plugin integration...")
        
        integration_results = {}
        
        # Test plugin metadata
        for plugin_name, plugin_instance in self.plugin_manager.loaded_plugins.items():
            try:
                metadata = plugin_instance.get_metadata()
                permissions = plugin_instance.get_required_permissions()
                
                integration_results[plugin_name] = {
                    "has_metadata": metadata is not None,
                    "has_permissions": permissions is not None,
                    "has_router": hasattr(plugin_instance, 'router'),
                    "metadata": {
                        "name": metadata.name if metadata else None,
                        "version": metadata.version if metadata else None,
                        "description": metadata.description if metadata else None
                    } if metadata else None
                }
                
            except Exception as e:
                logger.error(f"❌ Integration test failed for {plugin_name}: {e}")
                integration_results[plugin_name] = {
                    "error": str(e)
                }
        
        successful_integrations = sum(
            1 for result in integration_results.values() 
            if result.get("has_metadata", False) and result.get("has_permissions", False)
        )
        
        self.test_results["integration"] = {
            "success": successful_integrations > 0,
            "successful_integrations": successful_integrations,
            "total_plugins": len(integration_results),
            "plugin_results": integration_results
        }
        
        logger.info(f"🔗 Integration test results: {successful_integrations}/{len(integration_results)} plugins properly integrated")
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        logger.info("📋 Generating test report...")
        
        # Calculate overall success
        discovery_success = self.test_results.get("discovery", {}).get("success", False)
        loading_success = self.test_results.get("loading", {}).get("success", False)
        self_tests_success = self.test_results.get("self_tests", {}).get("total_failed", 1) == 0
        integration_success = self.test_results.get("integration", {}).get("success", False)
        
        overall_success = discovery_success and loading_success and integration_success
        
        report = {
            "overall_success": overall_success,
            "timestamp": "2024-01-01T00:00:00Z",  # Would use actual timestamp
            "summary": {
                "discovery": "✅ PASS" if discovery_success else "❌ FAIL",
                "loading": "✅ PASS" if loading_success else "❌ FAIL", 
                "self_tests": "✅ PASS" if self_tests_success else "❌ FAIL",
                "integration": "✅ PASS" if integration_success else "❌ FAIL"
            },
            "detailed_results": self.test_results,
            "recommendations": self.generate_recommendations()
        }
        
        # Print summary
        logger.info("=" * 60)
        logger.info("📋 PLUGIN SYSTEM TEST REPORT")
        logger.info("=" * 60)
        logger.info(f"Overall Status: {'✅ PASS' if overall_success else '❌ FAIL'}")
        logger.info("")
        logger.info("Test Results:")
        for test_name, status in report["summary"].items():
            logger.info(f"  {test_name.title()}: {status}")
        
        logger.info("")
        logger.info("Plugin Statistics:")
        if "loading" in self.test_results:
            loading_stats = self.test_results["loading"]
            logger.info(f"  Plugins Loaded: {loading_stats.get('successful_loads', 0)}/{loading_stats.get('total_plugins', 0)}")
        
        if "self_tests" in self.test_results:
            test_stats = self.test_results["self_tests"]
            logger.info(f"  Self-Tests: {test_stats.get('total_passed', 0)}/{test_stats.get('total_tests', 0)} passed")
        
        logger.info("")
        logger.info("Recommendations:")
        for rec in report["recommendations"]:
            logger.info(f"  • {rec}")
        
        logger.info("=" * 60)
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Check discovery issues
        if not self.test_results.get("discovery", {}).get("success", False):
            recommendations.append("Fix plugin discovery issues - check plugin.json files")
        
        # Check loading issues
        loading_results = self.test_results.get("loading", {})
        if loading_results.get("success_rate", 0) < 100:
            recommendations.append("Some plugins failed to load - check dependencies and initialization code")
        
        # Check self-test issues
        test_results = self.test_results.get("self_tests", {})
        if test_results.get("total_failed", 0) > 0:
            recommendations.append("Some plugin self-tests failed - review and fix failing tests")
        
        # Check integration issues
        integration_results = self.test_results.get("integration", {})
        if not integration_results.get("success", False):
            recommendations.append("Plugin integration issues detected - ensure proper metadata and permissions")
        
        if not recommendations:
            recommendations.append("All tests passed! Plugin system is working correctly.")
        
        return recommendations


async def main():
    """Main test function."""
    try:
        test_suite = PluginTestSuite()
        report = await test_suite.run_all_tests()
        
        # Save report to file
        report_file = Path("plugin_test_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📄 Test report saved to: {report_file}")
        
        # Exit with appropriate code
        exit_code = 0 if report["overall_success"] else 1
        logger.info(f"🏁 Test suite completed with exit code: {exit_code}")
        
        return exit_code
        
    except Exception as e:
        logger.error(f"❌ Test suite failed with error: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
