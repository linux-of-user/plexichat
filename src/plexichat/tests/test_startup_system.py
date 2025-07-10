#!/usr/bin/env python3
"""
Test Unified Startup System
Comprehensive testing of the new unified startup and shutdown system.
"""

import sys
import os
import time
import subprocess
import threading
from pathlib import Path

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text: str, color: str = Colors.WHITE):
    """Print colored text."""
    print(f"{color}{text}{Colors.END}")

def print_success(text: str):
    """Print success message."""
    print_colored(f"✅ {text}", Colors.GREEN)

def print_error(text: str):
    """Print error message."""
    print_colored(f"❌ {text}", Colors.RED)

def print_warning(text: str):
    """Print warning message."""
    print_colored(f"⚠️  {text}", Colors.YELLOW)

def print_info(text: str):
    """Print info message."""
    print_colored(f"ℹ️  {text}", Colors.BLUE)

def print_header(text: str):
    """Print section header."""
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"{text.center(60)}", Colors.BOLD + Colors.CYAN)
    print_colored(f"{'='*60}", Colors.CYAN)

class StartupSystemTester:
    """Test the unified startup system."""
    
    def __init__(self):
        self.test_results = []
        
    def test_file_existence(self):
        """Test that all required startup files exist."""
        print_info("Testing startup file existence...")
        
        required_files = [
            ('run.py', 'Main unified startup script'),
            ('run.sh', 'Linux/macOS wrapper script'),
            ('run.bat', 'Windows wrapper script'),
            ('shutdown.py', 'Clean shutdown script'),
            ('app/main.py', 'FastAPI application'),
            ('cli.py', 'CLI interface'),
        ]
        
        results = []
        for file_path, description in required_files:
            exists = Path(file_path).exists()
            results.append({
                'name': f'{description} ({file_path})',
                'passed': exists,
                'message': 'Found' if exists else 'Missing'
            })
            
            if exists:
                print_success(f"{description}: {file_path}")
            else:
                print_error(f"{description}: {file_path} - MISSING")
        
        return results
    
    def test_script_permissions(self):
        """Test script permissions (Linux/macOS)."""
        print_info("Testing script permissions...")
        
        results = []
        
        if os.name != 'nt':  # Not Windows
            scripts = ['run.sh']
            
            for script in scripts:
                if Path(script).exists():
                    is_executable = os.access(script, os.X_OK)
                    results.append({
                        'name': f'{script} executable permission',
                        'passed': is_executable,
                        'message': 'Executable' if is_executable else 'Not executable'
                    })
                    
                    if is_executable:
                        print_success(f"{script} is executable")
                    else:
                        print_warning(f"{script} is not executable (run: chmod +x {script})")
        else:
            results.append({
                'name': 'Script permissions (Windows)',
                'passed': True,
                'message': 'Not applicable on Windows'
            })
            print_info("Script permissions not applicable on Windows")
        
        return results
    
    def test_validation_mode(self):
        """Test validation mode."""
        print_info("Testing validation mode...")
        
        try:
            # Test validation mode
            result = subprocess.run(
                [sys.executable, 'run.py', '--validate'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            message = "Validation passed" if success else f"Validation failed: {result.stderr}"
            
            if success:
                print_success("Validation mode works")
            else:
                print_error(f"Validation mode failed: {result.stderr}")
            
            return [{
                'name': 'Validation mode',
                'passed': success,
                'message': message
            }]
            
        except subprocess.TimeoutExpired:
            print_error("Validation mode timed out")
            return [{
                'name': 'Validation mode',
                'passed': False,
                'message': 'Timed out after 30 seconds'
            }]
        except Exception as e:
            print_error(f"Validation mode error: {e}")
            return [{
                'name': 'Validation mode',
                'passed': False,
                'message': f'Error: {e}'
            }]
    
    def test_help_mode(self):
        """Test help mode."""
        print_info("Testing help mode...")
        
        try:
            # Test help mode
            result = subprocess.run(
                [sys.executable, 'run.py', '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0 and 'Enhanced Chat API' in result.stdout
            message = "Help displayed correctly" if success else "Help not working"
            
            if success:
                print_success("Help mode works")
            else:
                print_error("Help mode failed")
            
            return [{
                'name': 'Help mode',
                'passed': success,
                'message': message
            }]
            
        except Exception as e:
            print_error(f"Help mode error: {e}")
            return [{
                'name': 'Help mode',
                'passed': False,
                'message': f'Error: {e}'
            }]
    
    def test_shutdown_script(self):
        """Test shutdown script functionality."""
        print_info("Testing shutdown script...")
        
        results = []
        
        # Test shutdown script help
        try:
            result = subprocess.run(
                [sys.executable, 'shutdown.py', '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            results.append({
                'name': 'Shutdown script help',
                'passed': success,
                'message': 'Help works' if success else 'Help failed'
            })
            
            if success:
                print_success("Shutdown script help works")
            else:
                print_error("Shutdown script help failed")
                
        except Exception as e:
            results.append({
                'name': 'Shutdown script help',
                'passed': False,
                'message': f'Error: {e}'
            })
            print_error(f"Shutdown script help error: {e}")
        
        # Test shutdown script list mode
        try:
            result = subprocess.run(
                [sys.executable, 'shutdown.py', '--list'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            success = result.returncode == 0
            results.append({
                'name': 'Shutdown script list mode',
                'passed': success,
                'message': 'List mode works' if success else 'List mode failed'
            })
            
            if success:
                print_success("Shutdown script list mode works")
            else:
                print_error("Shutdown script list mode failed")
                
        except Exception as e:
            results.append({
                'name': 'Shutdown script list mode',
                'passed': False,
                'message': f'Error: {e}'
            })
            print_error(f"Shutdown script list mode error: {e}")
        
        return results
    
    def test_configuration_loading(self):
        """Test configuration loading."""
        print_info("Testing configuration loading...")
        
        try:
            # Test if run.py can load configuration
            import run
            launcher = run.UnifiedLauncher()
            
            # Check if configuration was loaded
            has_host = hasattr(launcher, 'host') and launcher.host
            has_port = hasattr(launcher, 'port') and launcher.port
            has_workers = hasattr(launcher, 'workers') and launcher.workers
            
            success = has_host and has_port and has_workers
            
            if success:
                print_success(f"Configuration loaded: {launcher.host}:{launcher.port} ({launcher.workers} workers)")
            else:
                print_error("Configuration loading failed")
            
            return [{
                'name': 'Configuration loading',
                'passed': success,
                'message': f'Host: {launcher.host}, Port: {launcher.port}, Workers: {launcher.workers}' if success else 'Failed to load configuration'
            }]
            
        except Exception as e:
            print_error(f"Configuration loading error: {e}")
            return [{
                'name': 'Configuration loading',
                'passed': False,
                'message': f'Error: {e}'
            }]
    
    def test_import_dependencies(self):
        """Test that all required dependencies can be imported."""
        print_info("Testing dependency imports...")
        
        dependencies = [
            ('fastapi', 'FastAPI framework'),
            ('uvicorn', 'ASGI server'),
            ('sqlmodel', 'Database ORM'),
            ('psutil', 'System monitoring'),
        ]
        
        results = []
        for module, description in dependencies:
            try:
                __import__(module)
                results.append({
                    'name': f'{module} import',
                    'passed': True,
                    'message': f'{description} available'
                })
                print_success(f"{description} ({module}) imported successfully")
            except ImportError:
                results.append({
                    'name': f'{module} import',
                    'passed': False,
                    'message': f'{description} missing'
                })
                print_error(f"{description} ({module}) import failed")
        
        return results
    
    def run_all_tests(self):
        """Run all startup system tests."""
        print_header("UNIFIED STARTUP SYSTEM TESTS")
        
        test_suites = [
            ("File Existence", self.test_file_existence),
            ("Script Permissions", self.test_script_permissions),
            ("Validation Mode", self.test_validation_mode),
            ("Help Mode", self.test_help_mode),
            ("Shutdown Script", self.test_shutdown_script),
            ("Configuration Loading", self.test_configuration_loading),
            ("Import Dependencies", self.test_import_dependencies),
        ]
        
        all_results = []
        
        for suite_name, test_func in test_suites:
            print_header(f"TESTING {suite_name.upper()}")
            
            try:
                results = test_func()
                all_results.extend(results)
                
                passed = sum(1 for r in results if r['passed'])
                total = len(results)
                
                if passed == total:
                    print_success(f"{suite_name}: {passed}/{total} tests passed")
                else:
                    print_warning(f"{suite_name}: {passed}/{total} tests passed")
                    
            except Exception as e:
                print_error(f"{suite_name} test suite failed: {e}")
                all_results.append({
                    'name': f'{suite_name} suite',
                    'passed': False,
                    'message': f'Suite error: {e}'
                })
        
        # Generate summary
        self.generate_summary(all_results)
        
        return all_results
    
    def generate_summary(self, results):
        """Generate test summary."""
        print_header("TEST SUMMARY")
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['passed'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print_info(f"Total Tests: {total_tests}")
        print_info(f"Passed: {passed_tests}")
        print_info(f"Failed: {failed_tests}")
        print_info(f"Success Rate: {success_rate:.1f}%")
        
        # Show failed tests
        if failed_tests > 0:
            print_header("FAILED TESTS")
            for result in results:
                if not result['passed']:
                    print_error(f"{result['name']}: {result['message']}")
        
        # Final status
        if success_rate >= 95:
            print_success("🎉 EXCELLENT! Startup system is working perfectly.")
        elif success_rate >= 85:
            print_success("✅ GOOD! Startup system is working well with minor issues.")
        elif success_rate >= 70:
            print_warning("⚠️  ACCEPTABLE! Startup system mostly works but needs attention.")
        else:
            print_error("❌ CRITICAL! Startup system has major issues.")

def main():
    """Main test entry point."""
    tester = StartupSystemTester()
    results = tester.run_all_tests()
    
    # Return appropriate exit code
    passed = sum(1 for r in results if r['passed'])
    total = len(results)
    success_rate = (passed / total * 100) if total > 0 else 0
    
    return 0 if success_rate >= 85 else 1

if __name__ == "__main__":
    sys.exit(main())
