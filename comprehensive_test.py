import os
import sys
import ast
import importlib
import subprocess
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import json


from pathlib import Path
from datetime import datetime

from plexichat.core.config import settings
import logging


#!/usr/bin/env python3
"""
Comprehensive PlexiChat Codebase Test Suite

This script conducts an in-depth analysis of the entire PlexiChat codebase,
identifying issues, testing functionality, and providing detailed reports.
"""

logger = logging.getLogger(__name__)
class CodebaseAnalyzer:
    """Comprehensive codebase analysis and testing."""
    
    def __init__(self, root_path: str = "."):
        self.root_path = from pathlib import Path
Path(root_path)
        self.src_path = self.root_path / "src"
        self.issues = []
        self.test_results = {}
        self.stats = {}
        
    def analyze_imports(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze import statements in a Python file."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module
                    if module and module.startswith('plexichat.'):
                        # Check if this is an absolute import that should be relative
                        if file_path.parts and 'src' in file_path.parts:
                            src_index = file_path.parts.index('src')
                            if len(file_path.parts) > src_index + 2:
                                current_module = '.'.join(file_path.parts[src_index + 2:-1])
                                if current_module:
                                    expected_relative = f"..{'.' * (len(file_path.parts) - src_index - 3)}"
                                    issues.append({
                                        'type': 'absolute_import',
                                        'file': str(file_path),
                                        'line': node.lineno,
                                        'module': module,
                                        'suggestion': f"from {expected_relative}{module.replace('plexichat.', '')}"
                                    })
                                    
        except Exception as e:
            issues.append({
                'type': 'parse_error',
                'file': str(file_path),
                'error': str(e)
            })
            
        return issues
    
    def test_syntax(self, file_path: Path) -> Dict[str, Any]:
        """Test Python syntax of a file."""
        result = {
            'file': str(file_path),
            'syntax_valid': False,
            'error': None
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            ast.parse(content)
            result['syntax_valid'] = True
            
        except SyntaxError as e:
            result['error'] = f"SyntaxError: {e.msg} at line {e.lineno}"
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
            
        return result
    
    def test_imports(self, file_path: Path) -> Dict[str, Any]:
        """Test if a module can be imported."""
        result = {
            'file': str(file_path),
            'importable': False,
            'error': None
        }
        
        try:
            # Convert file path to module path
            if 'src' in file_path.parts:
                src_index = file_path.parts.index('src')
                module_parts = list(file_path.parts[src_index + 1:])
                module_parts[-1] = module_parts[-1].replace('.py', '')
                module_path = '.'.join(module_parts)
                
                # Try to import the module
                module = importlib.import_module(module_path)
                result['importable'] = True
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def analyze_directory(self, directory: Path) -> Dict[str, Any]:
        """Analyze all Python files in a directory."""
        results = {
            'directory': str(directory),
            'files_analyzed': 0,
            'syntax_errors': 0,
            'import_errors': 0,
            'import_issues': 0,
            'files': []
        }
        
        for py_file in directory.rglob("*.py"):
            if py_file.is_file():
                results['files_analyzed'] += 1
                
                # Test syntax
                syntax_result = self.test_syntax(py_file)
                if not syntax_result['syntax_valid']:
                    results['syntax_errors'] += 1
                
                # Test imports
                import_result = self.test_imports(py_file)
                if not import_result['importable']:
                    results['import_errors'] += 1
                
                # Analyze import statements
                import_issues = self.analyze_imports(py_file)
                if import_issues:
                    results['import_issues'] += len(import_issues)
                
                file_result = {
                    'file': str(py_file),
                    'syntax': syntax_result,
                    'imports': import_result,
                    'import_issues': import_issues
                }
                results['files'].append(file_result)
                
        return results
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive test of the entire codebase."""
        logger.info(" Starting comprehensive PlexiChat codebase analysis...")
        logger.info("=" * 60)
        
        results = {
            'timestamp': from datetime import datetime
datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'overall_stats': {},
            'directory_analysis': {},
            'critical_issues': [],
            'recommendations': []
        }
        
        # Analyze main directories
        directories = [
            self.src_path / "plexichat",
            self.root_path / "docs",
            self.root_path / "tests" if (self.root_path / "tests").exists() else None
        ]
        
        total_files = 0
        total_syntax_errors = 0
        total_import_errors = 0
        total_import_issues = 0
        
        for directory in directories:
            if directory and directory.exists():
                logger.info(f"\n Analyzing directory: {directory}")
                dir_results = self.analyze_directory(directory)
                results['directory_analysis'][str(directory)] = dir_results
                
                total_files += dir_results['files_analyzed']
                total_syntax_errors += dir_results['syntax_errors']
                total_import_errors += dir_results['import_errors']
                total_import_issues += dir_results['import_issues']
                
                logger.info(f"   Files analyzed: {dir_results['files_analyzed']}")
                logger.info(f"   Syntax errors: {dir_results['syntax_errors']}")
                logger.info(f"   Import errors: {dir_results['import_errors']}")
                logger.info(f"   Import issues: {dir_results['import_issues']}")
        
        # Overall statistics
        results['overall_stats'] = {
            'total_files': total_files,
            'total_syntax_errors': total_syntax_errors,
            'total_import_errors': total_import_errors,
            'total_import_issues': total_import_issues,
            'success_rate': ((total_files - total_syntax_errors - total_import_errors) / total_files * 100) if total_files > 0 else 0
        }
        
        # Collect critical issues
        for dir_name, dir_results in results['directory_analysis'].items():
            for file_result in dir_results['files']:
                if not file_result['syntax']['syntax_valid']:
                    results['critical_issues'].append({
                        'type': 'syntax_error',
                        'file': file_result['file'],
                        'error': file_result['syntax']['error']
                    })
                
                if not file_result['imports']['importable']:
                    results['critical_issues'].append({
                        'type': 'import_error',
                        'file': file_result['file'],
                        'error': file_result['imports']['error']
                    })
        
        # Generate recommendations
        if total_syntax_errors > 0:
            results['recommendations'].append("Fix syntax errors before proceeding with other tests")
        
        if total_import_errors > 0:
            results['recommendations'].append("Resolve import errors to ensure module functionality")
        
        if total_import_issues > 0:
            results['recommendations'].append("Convert absolute imports to relative imports where appropriate")
        
        # Print summary
        logger.info("\n" + "=" * 60)
        logger.info(" ANALYSIS SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total files analyzed: {total_files}")
        logger.info(f"Syntax errors: {total_syntax_errors}")
        logger.info(f"Import errors: {total_import_errors}")
        logger.info(f"Import issues: {total_import_issues}")
        logger.info(f"Success rate: {results['overall_stats']['success_rate']:.1f}%")
        
        if results['critical_issues']:
            logger.info(f"\n CRITICAL ISSUES FOUND: {len(results['critical_issues'])}")
            for issue in results['critical_issues'][:5]:  # Show first 5
                logger.info(f"  - {issue['type']}: {issue['file']}")
                logger.info(f"    Error: {issue['error']}")
        
        if results['recommendations']:
            logger.info(f"\n RECOMMENDATIONS:")
            for rec in results['recommendations']:
                logger.info(f"  - {rec}")
        
        return results
    
    def test_dependencies(self) -> Dict[str, Any]:
        """Test if all required dependencies are available."""
        logger.info("\n Testing dependencies...")
        
        dependencies = [
            'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy', 'sqlmodel',
            'python-jose', 'passlib', 'cryptography', 'requests', 'aiofiles',
            'python-multipart', 'jinja2', 'typer', 'rich', 'colorama'
        ]
        
        results = {
            'tested_dependencies': len(dependencies),
            'available_dependencies': 0,
            'missing_dependencies': [],
            'dependency_results': {}
        }
        
        for dep in dependencies:
            try:
                importlib.import_module(dep)
                results['available_dependencies'] += 1
                results['dependency_results'][dep] = {'available': True}
            except ImportError:
                results['missing_dependencies'].append(dep)
                results['dependency_results'][dep] = {'available': False}
        
        logger.info(f"Available: {results['available_dependencies']}/{results['tested_dependencies']}")
        if results['missing_dependencies']:
            logger.info(f"Missing: {', '.join(results['missing_dependencies'])}")
        
        return results
    
    def test_configuration(self) -> Dict[str, Any]:
        """Test configuration files and from plexichat.core.config import settings
settings."""
        logger.info("\n Testing configuration...")
        
        config_files = [
            'pyproject.toml',
            'requirements.txt',
            'README.md',
            'LICENSE'
        ]
        
        results = {
            'config_files_checked': len(config_files),
            'config_files_found': 0,
            'missing_config_files': [],
            'config_results': {}
        }
        
        for config_file in config_files:
            config_path = self.root_path / config_file
            if config_path.exists():
                results['config_files_found'] += 1
                results['config_results'][config_file] = {'exists': True}
            else:
                results['missing_config_files'].append(config_file)
                results['config_results'][config_file] = {'exists': False}
        
        logger.info(f"Configuration files found: {results['config_files_found']}/{results['config_files_checked']}")
        if results['missing_config_files']:
            logger.info(f"Missing: {', '.join(results['missing_config_files'])}")
        
        return results
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive test report."""
        report = []
        report.append("# PlexiChat Comprehensive Codebase Test Report")
        report.append(f"Generated: {results['timestamp']}")
        report.append("")
        
        # Overall Statistics
        stats = results['overall_stats']
        report.append("## Overall Statistics")
        report.append(f"- Total files analyzed: {stats['total_files']}")
        report.append(f"- Syntax errors: {stats['total_syntax_errors']}")
        report.append(f"- Import errors: {stats['total_import_errors']}")
        report.append(f"- Import issues: {stats['total_import_issues']}")
        report.append(f"- Success rate: {stats['success_rate']:.1f}%")
        report.append("")
        
        # Critical Issues
        if results['critical_issues']:
            report.append("## Critical Issues")
            for issue in results['critical_issues']:
                report.append(f"- **{issue['type']}**: {issue['file']}")
                report.append(f"  - Error: {issue['error']}")
            report.append("")
        
        # Recommendations
        if results['recommendations']:
            report.append("## Recommendations")
            for rec in results['recommendations']:
                report.append(f"- {rec}")
            report.append("")
        
        # Detailed Analysis
        report.append("## Detailed Analysis")
        for dir_name, dir_results in results['directory_analysis'].items():
            report.append(f"### {dir_name}")
            report.append(f"- Files analyzed: {dir_results['files_analyzed']}")
            report.append(f"- Syntax errors: {dir_results['syntax_errors']}")
            report.append(f"- Import errors: {dir_results['import_errors']}")
            report.append(f"- Import issues: {dir_results['import_issues']}")
            report.append("")
        
        return "\n".join(report)

def main():
    """Main test execution."""
    analyzer = CodebaseAnalyzer()
    
    # Run comprehensive analysis
    results = analyzer.run_comprehensive_test()
    
    # Test dependencies
    dep_results = analyzer.test_dependencies()
    results['dependency_analysis'] = dep_results
    
    # Test configuration
    config_results = analyzer.test_configuration()
    results['configuration_analysis'] = config_results
    
    # Generate and save report
    report = analyzer.generate_report(results)
    
    with open('comprehensive_test_report.md', 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Save detailed results as JSON
    with open('comprehensive_test_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"\n Reports generated:")
    logger.info(f"  - comprehensive_test_report.md")
    logger.info(f"  - comprehensive_test_results.json")
    
    # Return exit code based on critical issues
    if results['critical_issues']:
        logger.info(f"\n Test completed with {len(results['critical_issues'])} critical issues")
        return 1
    else:
        logger.info(f"\n Test completed successfully")
        return 0

if __name__ == "__main__":
    sys.exit(main()) 