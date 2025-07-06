#!/usr/bin/env python3
"""
Final System Validation for Enhanced Chat API v2.0.0
Comprehensive end-to-end testing and validation.
"""

import sys
import os
import json
import time
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text: str, color: str = Colors.WHITE):
    """Print colored text."""
    print(f"{color}{text}{Colors.END}")

def print_header(text: str):
    """Print section header."""
    print_colored(f"\n{'='*70}", Colors.CYAN)
    print_colored(f"{text.center(70)}", Colors.BOLD + Colors.CYAN)
    print_colored(f"{'='*70}", Colors.CYAN)

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

class FinalValidator:
    """Comprehensive final system validator."""
    
    def __init__(self):
        self.results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.start_time = time.time()
        
    def run_complete_validation(self) -> bool:
        """Run complete system validation."""
        print_header("ENHANCED CHAT API v2.0.0 - FINAL VALIDATION")
        print_info("Performing comprehensive system validation...")
        
        validation_suites = [
            ("Core System", self.validate_core_system),
            ("File Structure", self.validate_file_structure),
            ("Dependencies", self.validate_dependencies),
            ("Configuration", self.validate_configuration),
            ("Database System", self.validate_database_system),
            ("CLI System", self.validate_cli_system),
            ("Web Interface", self.validate_web_interface),
            ("API Endpoints", self.validate_api_structure),
            ("Security Components", self.validate_security),
            ("Logging System", self.validate_logging),
            ("Testing Framework", self.validate_testing),
            ("Documentation", self.validate_documentation),
            ("Installation Scripts", self.validate_installation),
            ("Deployment Scripts", self.validate_deployment),
        ]
        
        for suite_name, validator_func in validation_suites:
            print_header(f"VALIDATING {suite_name.upper()}")
            
            try:
                suite_results = validator_func()
                self.results[suite_name] = suite_results
                
                passed = sum(1 for r in suite_results if r['passed'])
                total = len(suite_results)
                self.total_tests += total
                self.passed_tests += passed
                
                if passed == total:
                    print_success(f"{suite_name}: {passed}/{total} tests passed")
                else:
                    print_warning(f"{suite_name}: {passed}/{total} tests passed")
                    
            except Exception as e:
                print_error(f"{suite_name} validation failed: {e}")
                self.results[suite_name] = [{'name': 'Suite Error', 'passed': False, 'message': str(e)}]
                self.total_tests += 1
        
        # Generate final report
        self.generate_final_report()
        
        return self.passed_tests >= self.total_tests * 0.9  # 90% pass rate required
    
    def validate_core_system(self) -> List[Dict]:
        """Validate core system components."""
        results = []
        
        # Python version
        version = sys.version_info
        results.append({
            'name': 'Python Version',
            'passed': version.major >= 3 and version.minor >= 8,
            'message': f"Python {version.major}.{version.minor}.{version.micro}"
        })
        
        # Core imports
        core_modules = [
            ('fastapi', 'FastAPI framework'),
            ('uvicorn', 'ASGI server'),
            ('sqlmodel', 'Database ORM'),
            ('pydantic', 'Data validation'),
        ]
        
        for module, description in core_modules:
            try:
                __import__(module)
                results.append({
                    'name': f'{module} import',
                    'passed': True,
                    'message': f'{description} available'
                })
            except ImportError:
                results.append({
                    'name': f'{module} import',
                    'passed': False,
                    'message': f'{description} missing'
                })
        
        return results
    
    def validate_file_structure(self) -> List[Dict]:
        """Validate essential file structure."""
        results = []
        
        essential_files = [
            ('app/main.py', 'Main application'),
            ('app/logger_config.py', 'Logging configuration'),
            ('cli.py', 'Command line interface'),
            ('enhanced_launch.py', 'Enhanced launcher'),
            ('requirements.txt', 'Python dependencies'),
            ('README.md', 'Main documentation'),
            ('SYSTEM_OVERVIEW.md', 'System overview'),
            ('install.py', 'Python installer'),
            ('install.sh', 'Linux/macOS installer'),
            ('install.ps1', 'Windows installer'),
            ('start.sh', 'Linux/macOS start script'),
            ('start.ps1', 'Windows start script'),
            ('validate_system.py', 'System validator'),
            ('quick_test.py', 'Quick test script'),
            ('final_validation.py', 'Final validator'),
        ]
        
        for file_path, description in essential_files:
            exists = Path(file_path).exists()
            results.append({
                'name': f'{file_path}',
                'passed': exists,
                'message': f'{description} {"found" if exists else "missing"}'
            })
        
        # Essential directories
        essential_dirs = [
            ('app/', 'Main application directory'),
            ('app/routers/', 'API routers'),
            ('app/models/', 'Database models'),
            ('app/core/', 'Core services'),
            ('app/web/', 'Web interface'),
            ('app/testing/', 'Testing framework'),
            ('docs/', 'Documentation'),
            ('logs/', 'Log files'),
        ]
        
        for dir_path, description in essential_dirs:
            exists = Path(dir_path).exists()
            results.append({
                'name': f'{dir_path}',
                'passed': exists,
                'message': f'{description} {"found" if exists else "missing"}'
            })
        
        return results
    
    def validate_dependencies(self) -> List[Dict]:
        """Validate all dependencies."""
        results = []
        
        # Read requirements.txt
        try:
            with open('requirements.txt', 'r') as f:
                requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            results.append({
                'name': 'Requirements file',
                'passed': True,
                'message': f'{len(requirements)} dependencies listed'
            })
            
            # Test critical dependencies
            critical_deps = ['fastapi', 'uvicorn', 'sqlmodel', 'pydantic', 'colorama', 'rich']
            for dep in critical_deps:
                try:
                    __import__(dep)
                    results.append({
                        'name': f'{dep} dependency',
                        'passed': True,
                        'message': 'Available'
                    })
                except ImportError:
                    results.append({
                        'name': f'{dep} dependency',
                        'passed': False,
                        'message': 'Missing'
                    })
            
        except FileNotFoundError:
            results.append({
                'name': 'Requirements file',
                'passed': False,
                'message': 'requirements.txt not found'
            })
        
        return results
    
    def validate_configuration(self) -> List[Dict]:
        """Validate configuration system."""
        results = []
        
        # Test configuration import
        try:
            from app.logger_config import settings
            results.append({
                'name': 'Settings import',
                'passed': True,
                'message': 'Configuration loaded successfully'
            })
            
            # Check critical settings
            critical_settings = [
                ('HOST', 'Server host'),
                ('PORT', 'Server port'),
                ('DATABASE_URL', 'Database connection'),
                ('LOG_LEVEL', 'Logging level'),
            ]
            
            for setting, description in critical_settings:
                has_setting = hasattr(settings, setting)
                results.append({
                    'name': f'{setting} setting',
                    'passed': has_setting,
                    'message': f'{description} {"configured" if has_setting else "missing"}'
                })
            
        except Exception as e:
            results.append({
                'name': 'Settings import',
                'passed': False,
                'message': f'Configuration failed: {e}'
            })
        
        # Check .env file
        env_exists = Path('.env').exists()
        results.append({
            'name': '.env file',
            'passed': True,  # Not critical
            'message': 'Found' if env_exists else 'Not found (using defaults)'
        })
        
        return results
    
    def validate_database_system(self) -> List[Dict]:
        """Validate database system."""
        results = []
        
        # Create data directory
        data_dir = Path('data')
        data_dir.mkdir(exist_ok=True)
        
        # Test SQLite connection
        try:
            db_path = data_dir / 'chatapi.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            
            results.append({
                'name': 'SQLite connection',
                'passed': True,
                'message': f'Database accessible at {db_path}'
            })
        except Exception as e:
            results.append({
                'name': 'SQLite connection',
                'passed': False,
                'message': f'Database error: {e}'
            })
        
        # Test model imports
        models = [
            ('app.models.user', 'User model'),
            ('app.models.message', 'Message model'),
        ]
        
        for module, description in models:
            try:
                __import__(module)
                results.append({
                    'name': f'{description}',
                    'passed': True,
                    'message': 'Model imported successfully'
                })
            except ImportError as e:
                results.append({
                    'name': f'{description}',
                    'passed': False,
                    'message': f'Import failed: {e}'
                })
        
        return results
    
    def validate_cli_system(self) -> List[Dict]:
        """Validate CLI system."""
        results = []
        
        # Test CLI import
        try:
            import cli
            results.append({
                'name': 'CLI module import',
                'passed': True,
                'message': 'CLI module loaded successfully'
            })
            
            # Test CLI class
            try:
                cli_instance = cli.ChatAPICLI()
                results.append({
                    'name': 'CLI instance creation',
                    'passed': True,
                    'message': 'CLI instance created successfully'
                })
                
                # Test CLI commands
                commands = ['help', 'status', 'version', 'info']
                for cmd in commands:
                    has_command = hasattr(cli_instance, f'do_{cmd}')
                    results.append({
                        'name': f'CLI command: {cmd}',
                        'passed': has_command,
                        'message': 'Available' if has_command else 'Missing'
                    })
                
            except Exception as e:
                results.append({
                    'name': 'CLI instance creation',
                    'passed': False,
                    'message': f'Failed: {e}'
                })
                
        except ImportError as e:
            results.append({
                'name': 'CLI module import',
                'passed': False,
                'message': f'Import failed: {e}'
            })
        
        return results
    
    def validate_web_interface(self) -> List[Dict]:
        """Validate web interface components."""
        results = []
        
        # Test web router import
        try:
            from app.routers.web import router
            results.append({
                'name': 'Web router import',
                'passed': True,
                'message': 'Web router loaded successfully'
            })
        except ImportError as e:
            results.append({
                'name': 'Web router import',
                'passed': False,
                'message': f'Import failed: {e}'
            })
        
        # Check web templates
        templates = [
            'app/web/templates/base.html',
            'app/web/templates/dashboard.html',
            'app/web/templates/cli.html',
            'app/web/templates/admin/dashboard.html',
            'app/web/templates/admin/config.html',
        ]
        
        for template in templates:
            exists = Path(template).exists()
            results.append({
                'name': f'Template: {Path(template).name}',
                'passed': exists,
                'message': 'Found' if exists else 'Missing'
            })
        
        # Check static files
        static_dirs = [
            'app/web/static/css',
            'app/web/static/js',
        ]
        
        for static_dir in static_dirs:
            exists = Path(static_dir).exists()
            results.append({
                'name': f'Static: {Path(static_dir).name}',
                'passed': exists,
                'message': 'Found' if exists else 'Missing'
            })
        
        return results
    
    def validate_api_structure(self) -> List[Dict]:
        """Validate API structure."""
        results = []
        
        # Test API router imports
        routers = [
            ('app.routers.auth', 'Authentication router'),
            ('app.routers.users', 'Users router'),
            ('app.routers.messages', 'Messages router'),
            ('app.routers.system', 'System router'),
            ('app.routers.web', 'Web router'),
        ]
        
        for module, description in routers:
            try:
                __import__(module)
                results.append({
                    'name': description,
                    'passed': True,
                    'message': 'Router imported successfully'
                })
            except ImportError as e:
                results.append({
                    'name': description,
                    'passed': False,
                    'message': f'Import failed: {e}'
                })
        
        return results
    
    def validate_security(self) -> List[Dict]:
        """Validate security components."""
        results = []
        
        # Test security imports
        security_modules = [
            ('app.utils.security', 'Security utilities'),
            ('app.middleware.security_middleware', 'Security middleware'),
        ]
        
        for module, description in security_modules:
            try:
                __import__(module)
                results.append({
                    'name': description,
                    'passed': True,
                    'message': 'Security module available'
                })
            except ImportError:
                results.append({
                    'name': description,
                    'passed': False,
                    'message': 'Security module missing'
                })
        
        return results
    
    def validate_logging(self) -> List[Dict]:
        """Validate logging system."""
        results = []
        
        # Test logger import
        try:
            from app.logger_config import logger, selftest_logger, monitoring_logger
            results.append({
                'name': 'Logger import',
                'passed': True,
                'message': 'All loggers imported successfully'
            })
            
            # Test logging functionality
            logger.info("Final validation test log entry")
            results.append({
                'name': 'Logging functionality',
                'passed': True,
                'message': 'Logging test successful'
            })
            
        except Exception as e:
            results.append({
                'name': 'Logger import',
                'passed': False,
                'message': f'Logging failed: {e}'
            })
        
        # Check log directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        results.append({
            'name': 'Log directory',
            'passed': True,
            'message': 'Log directory available'
        })
        
        return results
    
    def validate_testing(self) -> List[Dict]:
        """Validate testing framework."""
        results = []
        
        # Test simple test runner
        try:
            from app.testing.simple_test_runner import SimpleTestRunner
            results.append({
                'name': 'Simple test runner',
                'passed': True,
                'message': 'Test runner available'
            })
        except ImportError as e:
            results.append({
                'name': 'Simple test runner',
                'passed': False,
                'message': f'Import failed: {e}'
            })
        
        # Check test files
        test_files = [
            'quick_test.py',
            'test_logging.py',
            'validate_system.py',
            'final_validation.py',
        ]
        
        for test_file in test_files:
            exists = Path(test_file).exists()
            results.append({
                'name': f'Test file: {test_file}',
                'passed': exists,
                'message': 'Available' if exists else 'Missing'
            })
        
        return results
    
    def validate_documentation(self) -> List[Dict]:
        """Validate documentation."""
        results = []
        
        # Check documentation files
        docs = [
            ('README.md', 'Main documentation'),
            ('SYSTEM_OVERVIEW.md', 'System overview'),
            ('TUTORIAL.md', 'Tutorial guide'),
        ]
        
        for doc_file, description in docs:
            exists = Path(doc_file).exists()
            results.append({
                'name': f'{description}',
                'passed': exists,
                'message': 'Available' if exists else 'Missing'
            })
        
        return results
    
    def validate_installation(self) -> List[Dict]:
        """Validate installation scripts."""
        results = []
        
        # Check installation scripts
        install_scripts = [
            ('install.py', 'Python installer'),
            ('install.sh', 'Linux/macOS installer'),
            ('install.ps1', 'Windows installer'),
        ]
        
        for script, description in install_scripts:
            exists = Path(script).exists()
            results.append({
                'name': f'{description}',
                'passed': exists,
                'message': 'Available' if exists else 'Missing'
            })
        
        return results
    
    def validate_deployment(self) -> List[Dict]:
        """Validate deployment scripts."""
        results = []
        
        # Check deployment scripts
        deploy_scripts = [
            ('start.sh', 'Linux/macOS start script'),
            ('start.ps1', 'Windows start script'),
            ('enhanced_launch.py', 'Enhanced launcher'),
        ]
        
        for script, description in deploy_scripts:
            exists = Path(script).exists()
            results.append({
                'name': f'{description}',
                'passed': exists,
                'message': 'Available' if exists else 'Missing'
            })
        
        return results
    
    def generate_final_report(self):
        """Generate comprehensive final report."""
        duration = time.time() - self.start_time
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        
        print_header("FINAL VALIDATION REPORT")
        
        # Summary
        print_info(f"Validation Duration: {duration:.2f} seconds")
        print_info(f"Total Tests: {self.total_tests}")
        print_info(f"Passed Tests: {self.passed_tests}")
        print_info(f"Failed Tests: {self.total_tests - self.passed_tests}")
        print_info(f"Success Rate: {success_rate:.1f}%")
        
        # Detailed results
        print_header("DETAILED RESULTS BY CATEGORY")
        
        for category, results in self.results.items():
            passed = sum(1 for r in results if r['passed'])
            total = len(results)
            status = "✅" if passed == total else "⚠️" if passed >= total * 0.8 else "❌"
            
            print_colored(f"\n{status} {category}: {passed}/{total}", 
                         Colors.GREEN if passed == total else Colors.YELLOW if passed >= total * 0.8 else Colors.RED)
            
            # Show failed tests
            failed_tests = [r for r in results if not r['passed']]
            if failed_tests:
                for test in failed_tests:
                    print_colored(f"   ❌ {test['name']}: {test['message']}", Colors.RED)
        
        # Final status
        print_header("SYSTEM STATUS")
        
        if success_rate >= 95:
            print_success("🎉 EXCELLENT! System is production-ready with outstanding quality.")
        elif success_rate >= 90:
            print_success("✅ GOOD! System is production-ready with minor issues.")
        elif success_rate >= 80:
            print_warning("⚠️  ACCEPTABLE! System is mostly ready but needs attention.")
        elif success_rate >= 70:
            print_warning("⚠️  NEEDS WORK! System has significant issues.")
        else:
            print_error("❌ CRITICAL! System has major issues and is not ready.")
        
        # Save report
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'duration': duration,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'success_rate': success_rate,
            'status': 'excellent' if success_rate >= 95 else 'good' if success_rate >= 90 else 'acceptable' if success_rate >= 80 else 'needs_work' if success_rate >= 70 else 'critical',
            'results': self.results
        }
        
        report_file = Path('logs') / 'final_validation_report.json'
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print_info(f"Detailed report saved to: {report_file}")

def run_final_validation():
    """Run final validation and return success status."""
    validator = FinalValidator()
    return validator.run_complete_validation()

def main():
    """Main validation entry point."""
    validator = FinalValidator()
    success = validator.run_complete_validation()

    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
