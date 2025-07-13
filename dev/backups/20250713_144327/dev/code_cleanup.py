#!/usr/bin/env python3
"""
PlexiChat Code Cleanup Tool
Fixes syntax errors and enhances functionality of files.

This script provides:
1. Syntax error fixing
2. Code enhancement
3. Import optimization
4. Code quality improvements
"""

import os
import sys
import ast
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import json
import time
from datetime import datetime
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CodeCleanup:
    """Cleans up and enhances code in the PlexiChat codebase."""
    
    def __init__(self, root_path: str = "."):
        self.root_path = Path(root_path)
        self.src_path = self.root_path / "src"
        self.dev_path = self.root_path / "dev"
        
        # File extensions to process
        self.python_extensions = {'.py', '.pyi'}
        self.ignore_dirs = {
            '__pycache__', '.git', '.pytest_cache', 'node_modules',
            '.venv', 'venv', 'env', '.env', 'logs', 'temp', 'test_cache',
            'backups', 'data', 'certs'
        }
        
        # Results storage
        self.fixed_files = []
        self.enhanced_files = []
        self.failed_files = []
        self.backup_dir = self.dev_path / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)

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

    def backup_file(self, file_path: Path) -> Path:
        """Create a backup of a file."""
        backup_path = self.backup_dir / file_path.relative_to(self.root_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, backup_path)
        return backup_path

    def fix_syntax_errors(self, file_path: Path) -> bool:
        """Fix common syntax errors in a file."""
        try:
            # Backup the file
            self.backup_file(file_path)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            fixed = False
            
            # Fix common syntax issues
            lines = content.split('\n')
            fixed_lines = []
            
            for i, line in enumerate(lines):
                original_line = line
                
                # Fix unterminated strings
                if line.count('"') % 2 != 0 and not line.strip().endswith('"'):
                    line += '"'
                    fixed = True
                
                # Fix unterminated triple quotes
                if line.count('"""') % 2 != 0 and not line.strip().endswith('"""'):
                    line += '"""'
                    fixed = True
                
                # Fix unterminated single quotes
                if line.count("'") % 2 != 0 and not line.strip().endswith("'"):
                    line += "'"
                    fixed = True
                
                # Fix missing colons after control structures
                if any(keyword in line for keyword in ['try', 'except', 'if ', 'for ', 'while ', 'def ', 'class ']):
                    if not line.strip().endswith(':') and not line.strip().endswith('('):
                        line += ':'
                        fixed = True
                
                # Fix unmatched parentheses
                if line.count('(') > line.count(')'):
                    line += ')'
                    fixed = True
                
                # Fix unmatched brackets
                if line.count('[') > line.count(']'):
                    line += ']'
                    fixed = True
                
                # Fix unmatched braces
                if line.count('{') > line.count('}'):
                    line += '}'
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
            self.failed_files.append(str(file_path))
            return False

    def enhance_file_functionality(self, file_path: Path) -> bool:
        """Enhance the functionality of a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            enhanced = False
            
            # Add missing imports
            if 'import logging' not in content and 'logger' in content:
                content = 'import logging\n\n' + content
                enhanced = True
            
            # Add missing type hints
            if 'from typing import' not in content and 'def ' in content:
                content = 'from typing import Dict, List, Optional, Any\n\n' + content
                enhanced = True
            
            # Add docstrings to functions without them
            lines = content.split('\n')
            enhanced_lines = []
            
            for i, line in enumerate(lines):
                if line.strip().startswith('def ') and not line.strip().startswith('def __'):
                    # Check if next line is not a docstring
                    if i + 1 < len(lines) and not lines[i + 1].strip().startswith('"""'):
                        # Add docstring
                        func_name = line.split('(')[0].split('def ')[1].strip()
                        docstring = f'    """{func_name} function."""'
                        enhanced_lines.append(line)
                        enhanced_lines.append(docstring)
                        enhanced = True
                        continue
                
                enhanced_lines.append(line)
            
            if enhanced:
                enhanced_content = '\n'.join(enhanced_lines)
                
                # Test if the enhancement works
                try:
                    ast.parse(enhanced_content)
                    # Write the enhanced content
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(enhanced_content)
                    self.enhanced_files.append(str(file_path))
                    return True
                except:
                    # If enhancement doesn't work, revert
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(original_content)
            
            return False
            
        except Exception as e:
            logger.warning(f"Error enhancing {file_path}: {e}")
            return False

    def optimize_imports(self, file_path: Path) -> bool:
        """Optimize imports in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            optimized = False
            
            # Parse the file to extract imports
            try:
                tree = ast.parse(content)
            except:
                return False
            
            # Find all imports
            imports = []
            other_lines = []
            
            lines = content.split('\n')
            in_import_section = True
            
            for line in lines:
                if line.strip().startswith(('import ', 'from ')):
                    if in_import_section:
                        imports.append(line)
                    else:
                        # Move import to top
                        imports.append(line)
                        optimized = True
                elif line.strip() and not line.strip().startswith('#'):
                    in_import_section = False
                    other_lines.append(line)
                else:
                    other_lines.append(line)
            
            if optimized:
                # Reorganize content with imports at top
                optimized_content = '\n'.join(imports) + '\n\n' + '\n'.join(other_lines)
                
                # Test if the optimization works
                try:
                    ast.parse(optimized_content)
                    # Write the optimized content
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(optimized_content)
                    return True
                except:
                    # If optimization doesn't work, revert
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(original_content)
            
            return False
            
        except Exception as e:
            logger.warning(f"Error optimizing imports in {file_path}: {e}")
            return False

    def process_file(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file for cleanup and enhancement."""
        results = {
            'syntax_fixed': False,
            'enhanced': False,
            'imports_optimized': False,
            'backup_created': False
        }
        
        try:
            # Create backup
            self.backup_file(file_path)
            results['backup_created'] = True
            
            # Fix syntax errors
            if self.fix_syntax_errors(file_path):
                results['syntax_fixed'] = True
            
            # Enhance functionality
            if self.enhance_file_functionality(file_path):
                results['enhanced'] = True
            
            # Optimize imports
            if self.optimize_imports(file_path):
                results['imports_optimized'] = True
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            self.failed_files.append(str(file_path))
        
        return results

    def cleanup_codebase(self) -> Dict[str, Any]:
        """Clean up the entire codebase."""
        logger.info("Starting codebase cleanup...")
        
        python_files = self.find_python_files()
        total_files = len(python_files)
        
        logger.info(f"Found {total_files} Python files to process")
        
        processed_files = 0
        syntax_fixed = 0
        enhanced = 0
        imports_optimized = 0
        
        for i, file_path in enumerate(python_files, 1):
            if i % 50 == 0:
                logger.info(f"Progress: {i}/{total_files} files processed")
            
            results = self.process_file(file_path)
            processed_files += 1
            
            if results['syntax_fixed']:
                syntax_fixed += 1
            if results['enhanced']:
                enhanced += 1
            if results['imports_optimized']:
                imports_optimized += 1
        
        return {
            'total_files': total_files,
            'processed_files': processed_files,
            'syntax_fixed': syntax_fixed,
            'enhanced': enhanced,
            'imports_optimized': imports_optimized,
            'failed_files': len(self.failed_files)
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive cleanup report."""
        logger.info("Generating cleanup report...")
        
        start_time = time.time()
        
        # Clean up codebase
        cleanup_results = self.cleanup_codebase()
        
        analysis_time = time.time() - start_time
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_time_seconds': analysis_time,
            'cleanup_results': cleanup_results,
            'fixed_files': self.fixed_files,
            'enhanced_files': self.enhanced_files,
            'failed_files': self.failed_files,
            'backup_directory': str(self.backup_dir),
            'recommendations': self.generate_recommendations()
        }
        
        return report

    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on cleanup results."""
        recommendations = []
        
        if self.fixed_files:
            recommendations.append(f"Fixed syntax errors in {len(self.fixed_files)} files.")
        
        if self.enhanced_files:
            recommendations.append(f"Enhanced functionality in {len(self.enhanced_files)} files.")
        
        if self.failed_files:
            recommendations.append(f"Failed to process {len(self.failed_files)} files. Review these manually.")
        
        if not self.fixed_files and not self.enhanced_files:
            recommendations.append("No files needed cleanup. Codebase is in good condition.")
        
        recommendations.append(f"Backups created in: {self.backup_dir}")
        
        return recommendations

    def save_report(self, report: Dict[str, Any], output_file: str = "code_cleanup_report.json"):
        """Save the cleanup report to a file."""
        output_path = self.dev_path / output_file
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report saved to {output_path}")

    def print_summary(self, report: Dict[str, Any]):
        """Print a summary of the cleanup results."""
        print("\n" + "="*60)
        print("PLEXICHAT CODE CLEANUP SUMMARY")
        print("="*60)
        
        cleanup_results = report['cleanup_results']
        
        print(f"Total Python files: {cleanup_results['total_files']}")
        print(f"Files processed: {cleanup_results['processed_files']}")
        print(f"Syntax errors fixed: {cleanup_results['syntax_fixed']}")
        print(f"Files enhanced: {cleanup_results['enhanced']}")
        print(f"Import optimizations: {cleanup_results['imports_optimized']}")
        print(f"Failed files: {cleanup_results['failed_files']}")
        print(f"Analysis time: {report['analysis_time_seconds']:.2f} seconds")
        print(f"Backup directory: {report['backup_directory']}")
        
        if report['fixed_files']:
            print("\nFiles with syntax fixes:")
            for file_path in report['fixed_files'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(report['fixed_files']) > 5:
                print(f"  ... and {len(report['fixed_files']) - 5} more files")
        
        if report['enhanced_files']:
            print("\nEnhanced files:")
            for file_path in report['enhanced_files'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(report['enhanced_files']) > 5:
                print(f"  ... and {len(report['enhanced_files']) - 5} more files")
        
        if report['failed_files']:
            print("\nFailed files:")
            for file_path in report['failed_files'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(report['failed_files']) > 5:
                print(f"  ... and {len(report['failed_files']) - 5} more files")
        
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
        
        print("="*60)

def main():
    """Main function to run the code cleanup."""
    print("PlexiChat Code Cleanup Tool")
    print("="*40)
    
    cleanup = CodeCleanup()
    
    try:
        # Generate comprehensive report
        report = cleanup.generate_report()
        
        # Save report
        cleanup.save_report(report)
        
        # Print summary
        cleanup.print_summary(report)
        
        print(f"\nDetailed report saved to: dev/code_cleanup_report.json")
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 