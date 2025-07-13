#!/usr/bin/env python3
"""
PlexiChat Codebase Analysis Tool
Analyzes the codebase for unused files and tests all imports.

This script provides:
1. Unused file detection
2. Import testing
3. Dependency analysis
4. Code coverage insights
"""

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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CodebaseAnalyzer:
    """Analyzes the PlexiChat codebase for unused files and import issues."""
    
    def __init__(self, root_path: str = "."):
        self.root_path = Path(root_path)
        self.src_path = self.root_path / "src"
        self.dev_path = self.root_path / "dev"
        
        # File extensions to analyze
        self.python_extensions = {'.py', '.pyi'}
        self.ignore_dirs = {
            '__pycache__', '.git', '.pytest_cache', 'node_modules',
            '.venv', 'venv', 'env', '.env', 'logs', 'temp', 'test_cache',
            'backups', 'data', 'certs'
        }
        
        # Results storage
        self.import_graph = defaultdict(set)
        self.used_files = set()
        self.unused_files = set()
        self.import_errors = []
        self.test_results = {}

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

    def extract_imports_from_file(self, file_path: Path) -> Set[str]:
        """Extract all imports from a Python file."""
        imports = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)
                        # Also add submodules
                        for alias in node.names:
                            if alias.name != '*':
                                imports.add(f"{node.module}.{alias.name}")
        
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
        
        return imports

    def build_import_graph(self, python_files: List[Path]):
        """Build a graph of file dependencies."""
        logger.info("Building import graph...")
        
        for file_path in python_files:
            if file_path.is_file():
                imports = self.extract_imports_from_file(file_path)
                self.import_graph[str(file_path)] = imports

    def find_unused_files(self) -> Set[Path]:
        """Find files that are not imported by any other file."""
        logger.info("Analyzing file usage...")
        
        all_files = set()
        imported_files = set()
        
        # Get all Python files
        python_files = self.find_python_files()
        
        # Build import graph
        self.build_import_graph(python_files)
        
        # Find all files that are imported
        for file_path, imports in self.import_graph.items():
            all_files.add(Path(file_path))
            
            for import_name in imports:
                # Try to resolve the import to a file
                resolved_file = self.resolve_import_to_file(import_name)
                if resolved_file:
                    imported_files.add(resolved_file)
        
        # Files that are not imported
        unused_files = all_files - imported_files
        
        # Filter out test files and main entry points
        filtered_unused = set()
        for file_path in unused_files:
            file_name = file_path.name
            if (not file_name.startswith('test_') and 
                not file_name.endswith('_test.py') and
                file_name not in ['main.py', '__main__.py', 'run.py'] and
                not file_name.startswith('__init__')):
                filtered_unused.add(file_path)
        
        return filtered_unused

    def resolve_import_to_file(self, import_name: str) -> Optional[Path]:
        """Try to resolve an import name to a file path."""
        # Handle relative imports
        if import_name.startswith('.'):
            return None  # Skip relative imports for now
        
        # Try to find the module file
        parts = import_name.split('.')
        
        # Check in src directory first
        src_candidate = self.src_path / '/'.join(parts) / '__init__.py'
        if src_candidate.exists():
            return src_candidate
        
        # Check for .py file
        py_candidate = self.src_path / f"{'/'.join(parts)}.py"
        if py_candidate.exists():
            return py_candidate
        
        # Check in root directory
        root_candidate = self.root_path / f"{'/'.join(parts)}.py"
        if root_candidate.exists():
            return root_candidate
        
        return None

    def test_imports(self) -> Dict[str, List[str]]:
        """Test all imports in the codebase."""
        logger.info("Testing imports...")
        
        import_errors = defaultdict(list)
        python_files = self.find_python_files()
        
        for file_path in python_files:
            if file_path.is_file():
                errors = self.test_file_imports(file_path)
                if errors:
                    import_errors[str(file_path)] = errors
        
        return dict(import_errors)

    def test_file_imports(self, file_path: Path) -> List[str]:
        """Test imports in a single file."""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    try:
                        # Try to import the module
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                try:
                                    importlib.import_module(alias.name)
                                except ImportError as e:
                                    errors.append(f"Import error for '{alias.name}': {e}")
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
                        errors.append(f"Unexpected error testing import: {e}")
        
        except Exception as e:
            errors.append(f"Error parsing file: {e}")
        
        return errors

    def analyze_dependencies(self) -> Dict[str, Any]:
        """Analyze dependencies and provide insights."""
        logger.info("Analyzing dependencies...")
        
        python_files = self.find_python_files()
        total_files = len(python_files)
        
        # Count imports by type
        import_types = defaultdict(int)
        total_imports = 0
        
        for file_path in python_files:
            imports = self.extract_imports_from_file(file_path)
            total_imports += len(imports)
            
            for import_name in imports:
                if import_name.startswith('.'):
                    import_types['relative'] += 1
                elif '.' in import_name:
                    import_types['package'] += 1
                else:
                    import_types['module'] += 1
        
        return {
            'total_files': total_files,
            'total_imports': total_imports,
            'import_types': dict(import_types),
            'average_imports_per_file': total_imports / total_files if total_files > 0 else 0
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive analysis report."""
        logger.info("Generating analysis report...")
        
        start_time = time.time()
        
        # Find unused files
        unused_files = self.find_unused_files()
        
        # Test imports
        import_errors = self.test_imports()
        
        # Analyze dependencies
        dependency_analysis = self.analyze_dependencies()
        
        # Generate file statistics
        python_files = self.find_python_files()
        file_stats = {
            'total_files': len(python_files),
            'unused_files': len(unused_files),
            'files_with_import_errors': len(import_errors),
            'total_import_errors': sum(len(errors) for errors in import_errors.values())
        }
        
        analysis_time = time.time() - start_time
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_time_seconds': analysis_time,
            'file_statistics': file_stats,
            'dependency_analysis': dependency_analysis,
            'unused_files': [str(f) for f in unused_files],
            'import_errors': import_errors,
            'recommendations': self.generate_recommendations(unused_files, import_errors)
        }
        
        return report

    def generate_recommendations(self, unused_files: Set[Path], import_errors: Dict[str, List[str]]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if unused_files:
            recommendations.append(f"Found {len(unused_files)} potentially unused files. Consider removing them if they're not needed.")
        
        if import_errors:
            recommendations.append(f"Found {len(import_errors)} files with import errors. Review and fix these issues.")
        
        if not unused_files and not import_errors:
            recommendations.append("No major issues found. Codebase appears to be well-maintained.")
        
        return recommendations

    def save_report(self, report: Dict[str, Any], output_file: str = "codebase_analysis_report.json"):
        """Save the analysis report to a file."""
        output_path = self.dev_path / output_file
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report saved to {output_path}")

    def print_summary(self, report: Dict[str, Any]):
        """Print a summary of the analysis."""
        print("\n" + "="*60)
        print("PLEXICHAT CODEBASE ANALYSIS SUMMARY")
        print("="*60)
        
        stats = report['file_statistics']
        print(f"Total Python files: {stats['total_files']}")
        print(f"Unused files: {stats['unused_files']}")
        print(f"Files with import errors: {stats['files_with_import_errors']}")
        print(f"Total import errors: {stats['total_import_errors']}")
        print(f"Analysis time: {report['analysis_time_seconds']:.2f} seconds")
        
        if report['unused_files']:
            print("\nUnused files:")
            for file_path in report['unused_files'][:10]:  # Show first 10
                print(f"  - {file_path}")
            if len(report['unused_files']) > 10:
                print(f"  ... and {len(report['unused_files']) - 10} more")
        
        if report['import_errors']:
            print("\nFiles with import errors:")
            for file_path, errors in list(report['import_errors'].items())[:5]:  # Show first 5
                print(f"  - {file_path}: {len(errors)} errors")
            if len(report['import_errors']) > 5:
                print(f"  ... and {len(report['import_errors']) - 5} more files")
        
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
        
        print("="*60)

def main():
    """Main function to run the codebase analysis."""
    print("PlexiChat Codebase Analysis Tool")
    print("="*40)
    
    analyzer = CodebaseAnalyzer()
    
    try:
        # Generate comprehensive report
        report = analyzer.generate_report()
        
        # Save report
        analyzer.save_report(report)
        
        # Print summary
        analyzer.print_summary(report)
        
        print(f"\nDetailed report saved to: dev/codebase_analysis_report.json")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 