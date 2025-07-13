import os
import sys
import ast
import importlib
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import json
import time
from datetime import datetime
import subprocess
import traceback

#!/usr/bin/env python3
"""
PlexiChat Import Testing Tool
Tests all imports in the codebase and provides detailed feedback.

This script provides:
1. Syntax validation
2. Import testing
3. Dependency resolution
4. Error reporting
"""


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ImportTester:
    """Tests imports in the PlexiChat codebase."""
    
    def __init__(self, root_path: str = "."):
        self.root_path = Path(root_path)
        self.src_path = self.root_path / "src"
        self.dev_path = self.root_path / "dev"
        
        # File extensions to test
        self.python_extensions = {'.py', '.pyi'}
        self.ignore_dirs = {
            '__pycache__', '.git', '.pytest_cache', 'node_modules',
            '.venv', 'venv', 'env', '.env', 'logs', 'temp', 'test_cache',
            'backups', 'data', 'certs'
        }
        
        # Results storage
        self.syntax_errors = defaultdict(list)
        self.import_errors = defaultdict(list)
        self.test_results = {}
        self.fixed_files = []

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []
        
        for root, dirs, files in os.walk(self.root_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                if Path(file).suffix in self.python_extensions:
                    file_path = Path(root) / file
                    python_files.append(file_path)
        
        return python_files

    def test_syntax(self, file_path: Path) -> List[str]:
        """Test syntax of a Python file."""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to parse the file
            ast.parse(content)
            
        except SyntaxError as e:
            errors.append(f"Syntax error at line {e.lineno}: {e.msg}")
        except Exception as e:
            errors.append(f"Error parsing file: {e}")
        
        return errors

    def test_imports_in_file(self, file_path: Path) -> List[str]:
        """Test imports in a single file."""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    try:
                        # Test import
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                try:
                                    importlib.import_module(alias.name)
                                except ImportError as e:
                                    errors.append(f"Import error for '{alias.name}': {e}")
                                except Exception as e:
                                    errors.append(f"Unexpected error importing '{alias.name}': {e}")
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                try:
                                    module = importlib.import_module(node.module)
                                    for alias in node.names:
                                        if alias.name != '*':
                                            if not hasattr(module, alias.name):
                                                errors.append(f"Attribute '{alias.name}' not found in '{node.module}'")
                                except ImportError as e:
                                    errors.append(f"Import error for '{node.module}': {e}")
                                except Exception as e:
                                    errors.append(f"Unexpected error importing from '{node.module}': {e}")
                    except Exception as e:
                        errors.append(f"Error testing import: {e}")
        
        except SyntaxError:
            # Skip files with syntax errors for import testing
            pass
        except Exception as e:
            errors.append(f"Error parsing file: {e}")
        
        return errors

    def test_all_files(self) -> Dict[str, Any]:
        """Test all files in the codebase."""
        logger.info("Testing all Python files...")
        
        python_files = self.find_python_files()
        total_files = len(python_files)
        
        logger.info(f"Found {total_files} Python files to test")
        
        for i, file_path in enumerate(python_files, 1):
            if i % 50 == 0:
                logger.info(f"Progress: {i}/{total_files} files tested")
            
            # Test syntax
            syntax_errors = self.test_syntax(file_path)
            if syntax_errors:
                self.syntax_errors[str(file_path)] = syntax_errors
            
            # Test imports (only if syntax is valid)
            if not syntax_errors:
                import_errors = self.test_imports_in_file(file_path)
                if import_errors:
                    self.import_errors[str(file_path)] = import_errors
        
        return {
            'total_files': total_files,
            'files_with_syntax_errors': len(self.syntax_errors),
            'files_with_import_errors': len(self.import_errors),
            'total_syntax_errors': sum(len(errors) for errors in self.syntax_errors.values()),
            'total_import_errors': sum(len(errors) for errors in self.import_errors.values())
        }

    def fix_common_syntax_errors(self, file_path: Path) -> bool:
        """Attempt to fix common syntax errors in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            fixed = False
            
            # Fix common issues
            lines = content.split('\n')
            fixed_lines = []
            
            for i, line in enumerate(lines):
                # Fix unterminated strings
                if line.count('"') % 2 != 0:
                    line += '"'
                    fixed = True
                
                # Fix unterminated triple quotes
                if line.count('"""') % 2 != 0:
                    line += '"""'
                    fixed = True
                
                # Fix unterminated single quotes
                if line.count("'") % 2 != 0:
                    line += "'"
                    fixed = True
                
                # Fix missing colons after try/except/if/for/while
                if any(keyword in line for keyword in ['try:', 'except:', 'if ', 'for ', 'while ', 'def ', 'class ']):
                    if not line.strip().endswith(':'):
                        line += ':'
                        fixed = True
                
                fixed_lines.append(line)
            
            if fixed:
                fixed_content = '\n'.join(fixed_lines)
                
                # Test if the fix works
                try:
                    ast.parse(fixed_content)
                    # Write the fixed content
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    self.fixed_files.append(str(file_path))
                    return True
                except:
                    # If fix doesn't work, revert
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(original_content)
            
            return False
            
        except Exception as e:
            logger.warning(f"Error fixing {file_path}: {e}")
            return False

    def auto_fix_syntax_errors(self) -> Dict[str, Any]:
        """Attempt to automatically fix syntax errors."""
        logger.info("Attempting to fix syntax errors...")
        
        fixed_count = 0
        total_attempted = 0
        
        for file_path_str in self.syntax_errors.keys():
            file_path = Path(file_path_str)
            if file_path.exists():
                total_attempted += 1
                if self.fix_common_syntax_errors(file_path):
                    fixed_count += 1
        
        return {
            'files_attempted': total_attempted,
            'files_fixed': fixed_count,
            'fixed_files': self.fixed_files
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive test report."""
        logger.info("Generating test report...")
        
        start_time = time.time()
        
        # Test all files
        test_results = self.test_all_files()
        
        # Attempt to fix syntax errors
        fix_results = self.auto_fix_syntax_errors()
        
        # Re-test after fixes
        if fix_results['files_fixed'] > 0:
            logger.info("Re-testing after fixes...")
            self.syntax_errors.clear()
            self.import_errors.clear()
            test_results = self.test_all_files()
        
        analysis_time = time.time() - start_time
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_time_seconds': analysis_time,
            'test_results': test_results,
            'fix_results': fix_results,
            'syntax_errors': dict(self.syntax_errors),
            'import_errors': dict(self.import_errors),
            'recommendations': self.generate_recommendations()
        }
        
        return report

    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        if self.syntax_errors:
            recommendations.append(f"Found {len(self.syntax_errors)} files with syntax errors. These need to be fixed before import testing.")
        
        if self.import_errors:
            recommendations.append(f"Found {len(self.import_errors)} files with import errors. Review and fix these issues.")
        
        if self.fixed_files:
            recommendations.append(f"Automatically fixed {len(self.fixed_files)} files. Review the changes.")
        
        if not self.syntax_errors and not self.import_errors:
            recommendations.append("No major issues found. All imports are working correctly.")
        
        return recommendations

    def save_report(self, report: Dict[str, Any], output_file: str = "import_test_report.json"):
        """Save the test report to a file."""
        output_path = self.dev_path / output_file
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report saved to {output_path}")

    def print_summary(self, report: Dict[str, Any]):
        """Print a summary of the test results."""
        print("\n" + "="*60)
        print("PLEXICHAT IMPORT TEST SUMMARY")
        print("="*60)
        
        test_results = report['test_results']
        fix_results = report['fix_results']
        
        print(f"Total Python files: {test_results['total_files']}")
        print(f"Files with syntax errors: {test_results['files_with_syntax_errors']}")
        print(f"Files with import errors: {test_results['files_with_import_errors']}")
        print(f"Total syntax errors: {test_results['total_syntax_errors']}")
        print(f"Total import errors: {test_results['total_import_errors']}")
        print(f"Files automatically fixed: {fix_results['files_fixed']}")
        print(f"Analysis time: {report['analysis_time_seconds']:.2f} seconds")
        
        if report['syntax_errors']:
            print("\nFiles with syntax errors:")
            for file_path, errors in list(report['syntax_errors'].items())[:5]:  # Show first 5
                print(f"  - {file_path}: {len(errors)} errors")
            if len(report['syntax_errors']) > 5:
                print(f"  ... and {len(report['syntax_errors']) - 5} more files")
        
        if report['import_errors']:
            print("\nFiles with import errors:")
            for file_path, errors in list(report['import_errors'].items())[:5]:  # Show first 5
                print(f"  - {file_path}: {len(errors)} errors")
            if len(report['import_errors']) > 5:
                print(f"  ... and {len(report['import_errors']) - 5} more files")
        
        if fix_results['fixed_files']:
            print("\nAutomatically fixed files:")
            for file_path in fix_results['fixed_files'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(fix_results['fixed_files']) > 5:
                print(f"  ... and {len(fix_results['fixed_files']) - 5} more files")
        
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
        
        print("="*60)

def main():
    """Main function to run the import testing."""
    print("PlexiChat Import Testing Tool")
    print("="*40)
    
    tester = ImportTester()
    
    try:
        # Generate comprehensive report
        report = tester.generate_report()
        
        # Save report
        tester.save_report(report)
        
        # Print summary
        tester.print_summary(report)
        
        print(f"\nDetailed report saved to: dev/import_test_report.json")
        
    except Exception as e:
        logger.error(f"Testing failed: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 