#!/usr/bin/env python3
"""
PlexiChat Import Update Script

This script updates all import statements after module renaming to remove 'unified_' prefixes
and consolidate logging modules. It performs comprehensive scanning, replacement, and validation.

Usage:
    python update_imports.py [--dry-run] [--verbose]
"""

import os
import re
import ast
import sys
import argparse
import importlib.util
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ImportChange:
    """Represents a single import change made to a file."""
    file_path: str
    line_number: int
    old_import: str
    new_import: str
    change_type: str  # 'import', 'from_import', 'string_reference'


class ImportUpdater:
    """Handles updating import statements and string references in Python files."""
    
    # Mapping of old module names to new module names
    MODULE_MAPPINGS = {
        'unified_config': 'config_manager',
        'unified_security_system': 'security_manager', 
        'unified_plugin_manager': 'plugin_manager',
        'unified_cli': 'cli_manager',
        'unified_rate_limiter': 'rate_limiter',
        'logging_unified': 'logging_system',
        # Handle full module paths
        'plexichat.core.unified_config': 'plexichat.core.config_manager',
        'plexichat.core.security.unified_security_system': 'plexichat.core.security.security_manager',
        'plexichat.core.plugins.unified_plugin_manager': 'plexichat.core.plugins.plugin_manager',
        'plexichat.interfaces.cli.unified_cli': 'plexichat.interfaces.cli.cli_manager',
        'plexichat.core.middleware.unified_rate_limiter': 'plexichat.core.middleware.rate_limiter',
        'plexichat.core.logging_unified': 'plexichat.core.logging_system',
    }
    
    def __init__(self, root_dir: str, dry_run: bool = False, verbose: bool = False):
        self.root_dir = Path(root_dir)
        self.dry_run = dry_run
        self.verbose = verbose
        self.changes: List[ImportChange] = []
        self.errors: List[str] = []
        
    def scan_and_update(self) -> None:
        """Main method to scan and update all files."""
        print(f"Scanning directory: {self.root_dir}")
        print(f"Dry run mode: {self.dry_run}")
        print("-" * 50)
        
        # Find all Python files
        python_files = list(self.root_dir.rglob("*.py"))
        print(f"Found {len(python_files)} Python files")
        
        # Update Python files
        for file_path in python_files:
            try:
                self._update_python_file(file_path)
            except Exception as e:
                error_msg = f"Error processing {file_path}: {str(e)}"
                self.errors.append(error_msg)
                if self.verbose:
                    print(f"ERROR: {error_msg}")
        
        # Find and update other text files (docs, configs, etc.)
        text_files = []
        for pattern in ["*.md", "*.txt", "*.yaml", "*.yml", "*.json", "*.toml", "*.cfg", "*.ini"]:
            text_files.extend(self.root_dir.rglob(pattern))
        
        print(f"Found {len(text_files)} text files to check for string references")
        
        for file_path in text_files:
            try:
                self._update_text_file(file_path)
            except Exception as e:
                error_msg = f"Error processing {file_path}: {str(e)}"
                self.errors.append(error_msg)
                if self.verbose:
                    print(f"ERROR: {error_msg}")
    
    def _update_python_file(self, file_path: Path) -> None:
        """Update import statements in a Python file."""
        if self.verbose:
            print(f"Processing Python file: {file_path}")
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        lines = content.split('\n')
        
        # Track changes for this file
        file_changes = []
        
        # Update import statements using regex patterns
        for old_module, new_module in self.MODULE_MAPPINGS.items():
            # Pattern 1: import old_module
            pattern1 = rf'\bimport\s+{re.escape(old_module)}\b'
            replacement1 = f'import {new_module}'
            
            for match in re.finditer(pattern1, content):
                line_num = content[:match.start()].count('\n') + 1
                file_changes.append(ImportChange(
                    file_path=str(file_path),
                    line_number=line_num,
                    old_import=match.group(),
                    new_import=replacement1,
                    change_type='import'
                ))
            
            content = re.sub(pattern1, replacement1, content)
            
            # Pattern 2: from old_module import ...
            pattern2 = rf'\bfrom\s+{re.escape(old_module)}\s+import\b'
            replacement2 = f'from {new_module} import'
            
            for match in re.finditer(pattern2, content):
                line_num = content[:match.start()].count('\n') + 1
                file_changes.append(ImportChange(
                    file_path=str(file_path),
                    line_number=line_num,
                    old_import=match.group(),
                    new_import=replacement2,
                    change_type='from_import'
                ))
            
            content = re.sub(pattern2, replacement2, content)
            
            # Pattern 3: import old_module as alias
            pattern3 = rf'\bimport\s+{re.escape(old_module)}\s+as\s+\w+'
            
            def replace_import_as(match):
                parts = match.group().split()
                return f'import {new_module} as {parts[3]}'
            
            for match in re.finditer(pattern3, content):
                line_num = content[:match.start()].count('\n') + 1
                file_changes.append(ImportChange(
                    file_path=str(file_path),
                    line_number=line_num,
                    old_import=match.group(),
                    new_import=replace_import_as(match),
                    change_type='import_as'
                ))
            
            content = re.sub(pattern3, replace_import_as, content)
        
        # Update string references (in quotes)
        for old_module, new_module in self.MODULE_MAPPINGS.items():
            # Look for quoted strings containing old module names
            patterns = [
                rf'["\']([^"\']*{re.escape(old_module)}[^"\']*)["\']',
                rf'["\']({re.escape(old_module)})["\']'
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    old_string = match.group(1)
                    new_string = old_string.replace(old_module, new_module)
                    if old_string != new_string:
                        line_num = content[:match.start()].count('\n') + 1
                        file_changes.append(ImportChange(
                            file_path=str(file_path),
                            line_number=line_num,
                            old_import=f'"{old_string}"',
                            new_import=f'"{new_string}"',
                            change_type='string_reference'
                        ))
                        content = content.replace(f'"{old_string}"', f'"{new_string}"')
                        content = content.replace(f"'{old_string}'", f"'{new_string}'")
        
        # Write changes if any were made
        if content != original_content:
            if not self.dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            self.changes.extend(file_changes)
            
            if self.verbose:
                print(f"  Updated {len(file_changes)} imports in {file_path}")
    
    def _update_text_file(self, file_path: Path) -> None:
        """Update string references in text files (docs, configs, etc.)."""
        if self.verbose:
            print(f"Processing text file: {file_path}")
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Skip binary files
            return
        
        original_content = content
        file_changes = []
        
        # Update string references
        for old_module, new_module in self.MODULE_MAPPINGS.items():
            if old_module in content:
                # Count occurrences and their line numbers
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if old_module in line:
                        file_changes.append(ImportChange(
                            file_path=str(file_path),
                            line_number=i + 1,
                            old_import=old_module,
                            new_import=new_module,
                            change_type='string_reference'
                        ))
                
                content = content.replace(old_module, new_module)
        
        # Write changes if any were made
        if content != original_content:
            if not self.dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            self.changes.extend(file_changes)
            
            if self.verbose:
                print(f"  Updated {len(file_changes)} references in {file_path}")
    
    def validate_imports(self) -> List[str]:
        """Validate that all Python files can still be imported after changes."""
        print("\nValidating imports...")
        validation_errors = []
        
        # Get all Python files that were modified
        modified_files = set()
        for change in self.changes:
            if change.file_path.endswith('.py'):
                modified_files.add(change.file_path)
        
        # Try to parse each modified file
        for file_path in modified_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse the AST to check for syntax errors
                ast.parse(content)
                
                if self.verbose:
                    print(f"  ✓ {file_path} - syntax valid")
                    
            except SyntaxError as e:
                error_msg = f"Syntax error in {file_path}: {str(e)}"
                validation_errors.append(error_msg)
                print(f"  ✗ {error_msg}")
            except Exception as e:
                error_msg = f"Error validating {file_path}: {str(e)}"
                validation_errors.append(error_msg)
                print(f"  ✗ {error_msg}")
        
        return validation_errors
    
    def generate_report(self) -> str:
        """Generate a comprehensive report of all changes made."""
        report = []
        report.append("=" * 60)
        report.append("PLEXICHAT IMPORT UPDATE REPORT")
        report.append("=" * 60)
        report.append(f"Root directory: {self.root_dir}")
        report.append(f"Dry run mode: {self.dry_run}")
        report.append(f"Total changes: {len(self.changes)}")
        report.append(f"Errors encountered: {len(self.errors)}")
        report.append("")
        
        # Group changes by file
        changes_by_file = defaultdict(list)
        for change in self.changes:
            changes_by_file[change.file_path].append(change)
        
        # Summary by change type
        change_types = defaultdict(int)
        for change in self.changes:
            change_types[change.change_type] += 1
        
        report.append("SUMMARY BY CHANGE TYPE:")
        report.append("-" * 30)
        for change_type, count in sorted(change_types.items()):
            report.append(f"  {change_type}: {count}")
        report.append("")
        
        # Summary by module mapping
        module_changes = defaultdict(int)
        for change in self.changes:
            for old_module, new_module in self.MODULE_MAPPINGS.items():
                if old_module in change.old_import:
                    module_changes[f"{old_module} → {new_module}"] += 1
                    break
        
        report.append("SUMMARY BY MODULE MAPPING:")
        report.append("-" * 30)
        for mapping, count in sorted(module_changes.items()):
            report.append(f"  {mapping}: {count}")
        report.append("")
        
        # Detailed changes by file
        report.append("DETAILED CHANGES BY FILE:")
        report.append("-" * 30)
        for file_path in sorted(changes_by_file.keys()):
            report.append(f"\n{file_path}:")
            for change in changes_by_file[file_path]:
                report.append(f"  Line {change.line_number}: {change.old_import} → {change.new_import}")
        
        # Errors
        if self.errors:
            report.append("\nERRORS ENCOUNTERED:")
            report.append("-" * 30)
            for error in self.errors:
                report.append(f"  {error}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Update import statements after PlexiChat module renaming",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python update_imports.py                    # Update imports in current directory
  python update_imports.py --dry-run          # Preview changes without applying
  python update_imports.py --verbose          # Show detailed progress
  python update_imports.py --dry-run --verbose # Preview with details
        """
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview changes without applying them'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed progress information'
    )
    
    parser.add_argument(
        '--root-dir',
        default='.',
        help='Root directory to scan (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Determine the root directory (should be the PlexiChat project root)
    root_dir = Path(args.root_dir).resolve()
    
    # Look for src/plexichat directory to confirm we're in the right place
    plexichat_src = root_dir / "src" / "plexichat"
    if not plexichat_src.exists():
        print(f"Warning: {plexichat_src} not found. Are you in the PlexiChat project root?")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Create updater and run
    updater = ImportUpdater(root_dir, dry_run=args.dry_run, verbose=args.verbose)
    
    try:
        # Scan and update files
        updater.scan_and_update()
        
        # Validate imports if not in dry-run mode
        validation_errors = []
        if not args.dry_run:
            validation_errors = updater.validate_imports()
        
        # Generate and display report
        report = updater.generate_report()
        print("\n" + report)
        
        # Save report to file
        report_file = root_dir / "import_update_report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\nReport saved to: {report_file}")
        
        # Exit with appropriate code
        if updater.errors or validation_errors:
            print(f"\nCompleted with {len(updater.errors + validation_errors)} errors.")
            sys.exit(1)
        else:
            print(f"\nCompleted successfully! Updated {len(updater.changes)} imports.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()