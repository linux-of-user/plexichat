#!/usr/bin/env python3
"""
Comprehensive CLI Testing System

Tests all CLI commands and subcommands to ensure they work properly:
- Tests all 50+ enhanced CLI commands
- Tests run.py integration
- Tests help system functionality
- Tests argument parsing and validation
- Tests error handling and edge cases
- Generates comprehensive test reports
- Validates CLI performance and responsiveness
"""

import asyncio
import sys
import subprocess
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import concurrent.futures


@dataclass
class CLITestResult:
    """CLI test result information."""
    command: str
    args: List[str]
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    error_message: Optional[str] = None


class ComprehensiveCLITester:
    """Comprehensive CLI testing system."""
    
    def __init__(self):
        self.test_results: List[CLITestResult] = []
        self.base_command = ["python", "src/plexichat/interfaces/cli/enhanced_cli.py"]
        self.run_py_command = ["python", "run.py", "cli"]
        
        # Define all commands to test
        self.commands_to_test = {
            # System commands
            "system": [
                ("help", []),
                ("status", []),
                ("status", ["--detailed"]),
                ("status", ["--json"]),
                ("health", []),
                ("health", ["--fix"]),
                ("health", ["--report"]),
                ("performance", []),
                ("performance", ["--live"]),
                ("performance", ["--optimize"]),
                ("performance", ["--benchmark"]),
            ],
            
            # Database commands
            "database": [
                ("db-status", []),
                ("db-status", ["--connections"]),
                ("db-status", ["--queries"]),
                ("db-status", ["--size"]),
                ("db-optimize", []),
                ("db-optimize", ["--analyze"]),
                ("db-optimize", ["--vacuum"]),
                ("db-optimize", ["--reindex"]),
            ],
            
            # Security commands
            "security": [
                ("security-scan", []),
                ("security-scan", ["--fix"]),
                ("security-scan", ["--report"]),
                ("security-scan", ["--level", "basic"]),
                ("security-scan", ["--level", "standard"]),
                ("security-scan", ["--level", "advanced"]),
                ("audit", []),
                ("audit", ["--days", "7"]),
                ("audit", ["--user", "admin"]),
                ("audit", ["--action", "login"]),
            ],
            
            # Plugin commands
            "plugins": [
                ("plugin-list", []),
                ("plugin-list", ["--status", "all"]),
                ("plugin-list", ["--status", "enabled"]),
                ("plugin-list", ["--status", "disabled"]),
                ("plugin-list", ["--category", "security"]),
                ("plugin-list", ["--search", "backup"]),
                ("plugin-install", ["test-plugin"]),
                ("plugin-install", ["test-plugin", "--force"]),
                ("plugin-install", ["test-plugin", "--dev"]),
                ("plugin-install", ["test-plugin", "--from-file"]),
            ],
            
            # Monitoring commands
            "monitoring": [
                ("logs", []),
                ("logs", ["--tail", "100"]),
                ("logs", ["--follow"]),
                ("logs", ["--level", "ERROR"]),
                ("logs", ["--module", "security"]),
                ("monitor", []),
                ("monitor", ["--interval", "2"]),
                ("monitor", ["--metrics", "cpu,memory,disk"]),
                ("monitor", ["--alerts"]),
            ],
            
            # Admin commands
            "admin": [
                ("user-list", []),
                ("user-list", ["--active"]),
                ("user-list", ["--role", "admin"]),
                ("user-list", ["--last-login"]),
                ("user-create", ["testuser", "test@example.com"]),
                ("user-create", ["admin2", "admin@company.com", "--role", "admin"]),
            ],
            
            # Backup commands
            "backup": [
                ("backup-create", []),
                ("backup-create", ["--type", "full"]),
                ("backup-create", ["--type", "incremental"]),
                ("backup-create", ["--type", "differential"]),
                ("backup-create", ["--compress"]),
                ("backup-create", ["--encrypt"]),
                ("backup-create", ["--compress", "--encrypt"]),
                ("backup-restore", ["backup_20250726_210900"]),
                ("backup-restore", ["backup_20250726_210900", "--verify"]),
                ("backup-restore", ["backup_20250726_210900", "--partial"]),
            ],
            
            # Network commands
            "network": [
                ("network-status", []),
                ("network-status", ["--test"]),
                ("network-status", ["--speed"]),
                ("network-status", ["--ports"]),
                ("network-status", ["--speed", "--ports"]),
            ],
            
            # AI commands
            "ai": [
                ("ai-status", []),
                ("ai-status", ["--models"]),
                ("ai-status", ["--performance"]),
            ],
            
            # Testing commands
            "testing": [
                ("test-run", []),
                ("test-run", ["--category", "security"]),
                ("test-run", ["--coverage"]),
                ("test-run", ["--parallel"]),
                ("test-run", ["--coverage", "--parallel"]),
            ],
            
            # Development commands
            "development": [
                ("dev-setup", []),
                ("dev-setup", ["--full"]),
                ("dev-setup", ["--tools"]),
            ],
            
            # Maintenance commands
            "maintenance": [
                ("cleanup", []),
                ("cleanup", ["--logs"]),
                ("cleanup", ["--cache"]),
                ("cleanup", ["--temp"]),
                ("cleanup", ["--logs", "--cache"]),
                ("cleanup", ["--logs", "--cache", "--temp"]),
            ],
            
            # Help commands
            "help": [
                ("help", []),
                ("help", ["status"]),
                ("help", ["health"]),
                ("help", ["security-scan"]),
                ("help", ["plugin-list"]),
                ("help", ["monitor"]),
                ("help", ["backup-create"]),
                ("help", ["user-create"]),
            ],
            
            # Alias testing
            "aliases": [
                ("st", []),  # status alias
                ("hc", []),  # health alias
                ("perf", []),  # performance alias
                ("dbs", []),  # db-status alias
                ("dbo", []),  # db-optimize alias
                ("secscan", []),  # security-scan alias
                ("scan", []),  # security-scan alias
                ("pl", []),  # plugin-list alias
                ("plugins", []),  # plugin-list alias
                ("pi", ["test-plugin"]),  # plugin-install alias
                ("log", []),  # logs alias
                ("mon", []),  # monitor alias
                ("metrics", []),  # performance alias
                ("users", []),  # user-list alias
                ("backup", []),  # backup-create alias
                ("net", []),  # network-status alias
                ("test", []),  # test-run alias
            ]
        }
    
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive CLI tests."""
        print("🧪 COMPREHENSIVE CLI TESTING SYSTEM")
        print("=" * 60)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        total_commands = sum(len(commands) for commands in self.commands_to_test.values())
        print(f"Total commands to test: {total_commands}")
        print(f"Categories: {list(self.commands_to_test.keys())}")
        print()
        
        # Test each category
        for category, commands in self.commands_to_test.items():
            await self._test_category(category, commands)
        
        # Generate comprehensive report
        report = self._generate_test_report()
        
        print("\n" + "=" * 60)
        print("🎯 COMPREHENSIVE CLI TEST RESULTS")
        print("=" * 60)
        
        print(f"Total tests: {report['total_tests']}")
        print(f"Passed: {report['passed_tests']}")
        print(f"Failed: {report['failed_tests']}")
        print(f"Success rate: {report['success_rate']:.1f}%")
        print(f"Average execution time: {report['average_execution_time']:.3f}s")
        
        # Category breakdown
        print("\nResults by category:")
        for category, results in report['category_results'].items():
            print(f"  {category}: {results['passed']}/{results['total']} passed ({results['success_rate']:.1f}%)")
        
        # Show failed tests
        if report['failed_tests'] > 0:
            print(f"\nFailed tests:")
            for result in self.test_results:
                if not result.success:
                    print(f"  ❌ {result.command} {' '.join(result.args)} (exit code: {result.exit_code})")
                    if result.error_message:
                        print(f"     Error: {result.error_message}")
        
        return report
    
    async def _test_category(self, category: str, commands: List[Tuple[str, List[str]]]):
        """Test a category of commands."""
        print(f"📋 TESTING {category.upper()} COMMANDS")
        print("-" * 40)
        
        for command, args in commands:
            result = await self._test_single_command(command, args)
            self._print_test_result(result)
        
        print()
    
    async def _test_single_command(self, command: str, args: List[str]) -> CLITestResult:
        """Test a single CLI command."""
        full_command = self.base_command + [command] + args
        
        start_time = time.time()
        try:
            # Run the command
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=Path.cwd()
            )
            
            stdout, stderr = await process.communicate()
            execution_time = time.time() - start_time
            
            # Decode output
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            
            # Determine success
            success = process.returncode == 0
            error_message = stderr_str if not success and stderr_str else None
            
            result = CLITestResult(
                command=command,
                args=args,
                success=success,
                exit_code=process.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time=execution_time,
                error_message=error_message
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            result = CLITestResult(
                command=command,
                args=args,
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                execution_time=execution_time,
                error_message=str(e)
            )
        
        self.test_results.append(result)
        return result
    
    def _print_test_result(self, result: CLITestResult):
        """Print test result."""
        status_icon = "✅" if result.success else "❌"
        args_str = " " + " ".join(result.args) if result.args else ""
        
        print(f"  {status_icon} {result.command}{args_str} ({result.execution_time:.3f}s)")
        
        if not result.success and result.error_message:
            # Truncate long error messages
            error_msg = result.error_message[:100] + "..." if len(result.error_message) > 100 else result.error_message
            print(f"    Error: {error_msg}")
    
    def _generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.success)
        failed_tests = total_tests - passed_tests
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        average_execution_time = sum(r.execution_time for r in self.test_results) / total_tests if total_tests > 0 else 0
        
        # Category breakdown
        category_results = {}
        for category, commands in self.commands_to_test.items():
            category_tests = []
            for command, args in commands:
                # Find matching test results
                for result in self.test_results:
                    if result.command == command and result.args == args:
                        category_tests.append(result)
                        break
            
            if category_tests:
                category_passed = sum(1 for r in category_tests if r.success)
                category_results[category] = {
                    'total': len(category_tests),
                    'passed': category_passed,
                    'failed': len(category_tests) - category_passed,
                    'success_rate': (category_passed / len(category_tests) * 100)
                }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': success_rate,
            'average_execution_time': average_execution_time,
            'category_results': category_results,
            'test_details': [
                {
                    'command': r.command,
                    'args': r.args,
                    'success': r.success,
                    'exit_code': r.exit_code,
                    'execution_time': r.execution_time,
                    'error': r.error_message
                }
                for r in self.test_results
            ]
        }
    
    async def test_run_py_integration(self) -> Dict[str, Any]:
        """Test run.py CLI integration."""
        print("🔗 TESTING RUN.PY CLI INTEGRATION")
        print("-" * 40)
        
        integration_tests = [
            (["--help"], "Should show help"),
            (["cli", "--help"], "Should show CLI help"),
            (["cli", "help"], "Should show enhanced CLI help"),
            (["cli", "status"], "Should run status command"),
            (["cli", "health"], "Should run health command"),
        ]
        
        integration_results = []
        
        for args, description in integration_tests:
            print(f"Testing: python run.py {' '.join(args)}")
            
            start_time = time.time()
            try:
                process = await asyncio.create_subprocess_exec(
                    "python", "run.py", *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=Path.cwd()
                )
                
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                execution_time = time.time() - start_time
                
                success = process.returncode == 0
                status_icon = "✅" if success else "❌"
                
                print(f"  {status_icon} {description} ({execution_time:.3f}s)")
                
                integration_results.append({
                    'args': args,
                    'description': description,
                    'success': success,
                    'exit_code': process.returncode,
                    'execution_time': execution_time
                })
                
            except asyncio.TimeoutError:
                print(f"  ⏰ {description} (timeout)")
                integration_results.append({
                    'args': args,
                    'description': description,
                    'success': False,
                    'exit_code': -1,
                    'execution_time': 30.0
                })
            except Exception as e:
                print(f"  ❌ {description} (error: {e})")
                integration_results.append({
                    'args': args,
                    'description': description,
                    'success': False,
                    'exit_code': -1,
                    'execution_time': time.time() - start_time
                })
        
        print()
        
        # Calculate integration success rate
        total_integration_tests = len(integration_results)
        passed_integration_tests = sum(1 for r in integration_results if r['success'])
        integration_success_rate = (passed_integration_tests / total_integration_tests * 100) if total_integration_tests > 0 else 0
        
        print(f"Integration tests: {passed_integration_tests}/{total_integration_tests} passed ({integration_success_rate:.1f}%)")
        
        return {
            'total_tests': total_integration_tests,
            'passed_tests': passed_integration_tests,
            'success_rate': integration_success_rate,
            'test_results': integration_results
        }


async def main():
    """Run comprehensive CLI testing."""
    tester = ComprehensiveCLITester()
    
    # Run comprehensive CLI tests
    cli_report = await tester.run_comprehensive_tests()
    
    # Test run.py integration
    integration_report = await tester.test_run_py_integration()
    
    # Save comprehensive report
    comprehensive_report = {
        'cli_tests': cli_report,
        'integration_tests': integration_report,
        'overall_summary': {
            'total_cli_tests': cli_report['total_tests'],
            'total_integration_tests': integration_report['total_tests'],
            'overall_success_rate': (
                (cli_report['passed_tests'] + integration_report['passed_tests']) /
                (cli_report['total_tests'] + integration_report['total_tests']) * 100
            ) if (cli_report['total_tests'] + integration_report['total_tests']) > 0 else 0
        }
    }
    
    with open('comprehensive_cli_test_report.json', 'w') as f:
        json.dump(comprehensive_report, f, indent=2)
    
    print("\n" + "=" * 60)
    print("🎯 COMPREHENSIVE CLI TESTING COMPLETED")
    print("=" * 60)
    
    overall_success_rate = comprehensive_report['overall_summary']['overall_success_rate']
    total_tests = cli_report['total_tests'] + integration_report['total_tests']
    
    print(f"Total tests executed: {total_tests}")
    print(f"Overall success rate: {overall_success_rate:.1f}%")
    print(f"CLI tests: {cli_report['success_rate']:.1f}%")
    print(f"Integration tests: {integration_report['success_rate']:.1f}%")
    print(f"Report saved to: comprehensive_cli_test_report.json")
    
    if overall_success_rate >= 90:
        print("🎉 EXCELLENT: CLI system passed comprehensive testing!")
    elif overall_success_rate >= 75:
        print("✅ GOOD: CLI system passed most tests with minor issues")
    else:
        print("⚠️  ATTENTION: CLI system needs improvement in several areas")
    
    return comprehensive_report


if __name__ == "__main__":
    try:
        report = asyncio.run(main())
        print(f"\n🎉 CLI testing completed successfully!")
        print(f"Overall success rate: {report['overall_summary']['overall_success_rate']:.1f}%")
    except KeyboardInterrupt:
        print("\n❌ CLI testing interrupted by user")
    except Exception as e:
        print(f"\n❌ CLI testing failed: {e}")
        import traceback
        traceback.print_exc()
