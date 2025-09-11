#!/usr/bin/env python3
"""
Import Verification Script for PlexiChat

This script scans all Python files to identify and fix import statement issues:
1. Relative imports (from ..module)
2. Incorrect absolute imports not starting with src.plexichat
3. Direct imports from core, database, auth, etc. without proper prefix

This ensures all imports follow the standardized "src.plexichat.module" format.
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Set

class ImportAnalyzer(ast.NodeVisitor):
    """AST visitor to analyze import statements."""
    
    def __init__(self):
        self.imports = []
        self.from_imports = []
        
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({
                'module': alias.name,
                'line': node.lineno,
                'type': 'import'
            })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        if node.module:
            self.from_imports.append({
                'module': node.module,
                'names': [alias.name for alias in node.names],
                'line': node.lineno,
                'type': 'from_import',
                'level': node.level
            })
        self.generic_visit(node)

def analyze_file(file_path: Path) -> Tuple[List[Dict], List[str]]:
    """Analyze a Python file for import issues."""
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse AST
        tree = ast.parse(content)
        analyzer = ImportAnalyzer()
        analyzer.visit(tree)
        
        # Check for problematic imports
        for imp in analyzer.imports:
            module = imp['module']
            if should_fix_import(module, file_path):
                fixed = fix_import_module(module, file_path)
                if fixed != module:
                    issues.append({
                        'type': 'import',
                        'line': imp['line'],
                        'original': module,
                        'fixed': fixed,
                        'full_line': f"import {module}"
                    })
        
        for imp in analyzer.from_imports:
            module = imp['module']
            level = imp['level']
            
            # Check relative imports
            if level > 0:
                fixed = fix_relative_import(module, level, file_path)
                if fixed:
                    issues.append({
                        'type': 'from_import_relative',
                        'line': imp['line'],
                        'original': module,
                        'fixed': fixed,
                        'level': level,
                        'names': imp['names'],
                        'full_line': f"from {'.' * level}{module or ''} import {', '.join(imp['names'])}"
                    })
            
            # Check absolute imports that need fixing
            elif should_fix_import(module, file_path):
                fixed = fix_import_module(module, file_path)
                if fixed != module:
                    issues.append({
                        'type': 'from_import',
                        'line': imp['line'],
                        'original': module,
                        'fixed': fixed,
                        'names': imp['names'],
                        'full_line': f"from {module} import {', '.join(imp['names'])}"
                    })
        
        return issues, content.splitlines()
        
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return [], []

def should_fix_import(module: str, file_path: Path) -> bool:
    """Check if an import module should be fixed."""
    if not module:
        return False
    
    # Skip standard library and third-party modules
    if is_standard_or_third_party(module):
        return False
    
    # Skip if already correctly formatted
    if module.startswith('src.plexichat.'):
        return False
    
    # Fix these patterns
    problematic_patterns = [
        r'^plexichat\.',  # plexichat.* (should be src.plexichat.*)
        r'^core\.',       # core.*
        r'^database\.',   # database.*
        r'^auth\.',       # auth.*
        r'^logging\.',    # logging.* (when it's our logging)
        r'^shared\.',     # shared.*
        r'^features\.',   # features.*
        r'^infrastructure\.', # infrastructure.*
        r'^interfaces\.',  # interfaces.*
        r'^plugins\.',     # plugins.*
    ]
    
    for pattern in problematic_patterns:
        if re.match(pattern, module):
            return True
    
    return False

def is_standard_or_third_party(module: str) -> bool:
    """Check if module is standard library or third-party."""
    # Common standard library modules
    stdlib_modules = {
        'os', 'sys', 'json', 're', 'time', 'datetime', 'pathlib', 'typing',
        'asyncio', 'logging', 'threading', 'collections', 'dataclasses',
        'enum', 'functools', 'itertools', 'contextlib', 'abc', 'hashlib',
        'secrets', 'uuid', 'base64', 'hmac', 'urllib', 'ipaddress', 'socket',
        'shutil', 'tempfile', 'mimetypes', 'email', 'smtplib', 'ssl', 'gzip',
        'pickle', 'zlib', 'gc', 'weakref', 'resource', 'signal', 'subprocess',
        'tracemalloc', 'statistics', 'math', 'random', 'inspect', 'importlib',
        'ast', 'dis', 'traceback', 'warnings', 'http', 'html', 'xml', 'csv',
        'sqlite3', 'unittest', 'pytest', '__future__', 'copy', 'io'
    }
    
    # Common third-party modules
    third_party_modules = {
        'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy', 'alembic', 'asyncpg',
        'aiopg', 'redis', 'celery', 'jwt', 'bcrypt', 'cryptography', 'pyotp',
        'aiofiles', 'aiohttp', 'requests', 'click', 'typer', 'rich', 'colorama',
        'jinja2', 'psutil', 'prometheus_client', 'aio_pika', 'kafka', 'docker',
        'kubernetes', 'boto3', 'azure', 'google', 'pytest', 'mock', 'faker',
        'numpy', 'pandas', 'matplotlib', 'pillow', 'opencv', 'tensorflow',
        'torch', 'flask', 'django', 'bottle', 'cherrypy', 'pyramid', 'sanic'
    }
    
    first_part = module.split('.')[0]
    return first_part in stdlib_modules or first_part in third_party_modules

def fix_import_module(module: str, file_path: Path) -> str:
    """Fix an import module to use proper src.plexichat prefix."""
    if module.startswith('plexichat.'):
        return f"src.{module}"
    
    # Map direct module references to proper paths
    module_mappings = {
        'core': 'src.plexichat.core',
        'database': 'src.plexichat.core.database', 
        'auth': 'src.plexichat.core.auth',
        'shared': 'src.plexichat.shared',
        'features': 'src.plexichat.features',
        'infrastructure': 'src.plexichat.infrastructure',
        'interfaces': 'src.plexichat.interfaces',
        'plugins': 'src.plexichat.plugins'
    }
    
    for old_prefix, new_prefix in module_mappings.items():
        if module == old_prefix or module.startswith(f"{old_prefix}."):
            return module.replace(old_prefix, new_prefix, 1)
    
    return module

def fix_relative_import(module: str, level: int, file_path: Path) -> str:
    """Convert relative import to absolute import."""
    try:
        # Get the package path from file location
        path_parts = file_path.parts
        
        # Find src/plexichat in the path
        try:
            src_index = path_parts.index('src')
            plexichat_index = src_index + 1
            if plexichat_index < len(path_parts) and path_parts[plexichat_index] == 'plexichat':
                # Build the current package path
                current_pkg_parts = ['src'] + list(path_parts[plexichat_index:file_path.parts.index(file_path.name)])
                
                # Calculate the target package based on relative level
                target_parts = current_pkg_parts[:-level] if level <= len(current_pkg_parts) else ['src', 'plexichat']
                
                if module:
                    target_parts.append(module)
                
                return '.'.join(target_parts)
        except (ValueError, IndexError):
            pass
        
        # Fallback: convert to src.plexichat based import
        if module:
            return f"src.plexichat.{module}"
        else:
            return "src.plexichat"
            
    except Exception:
        # Safe fallback
        return f"src.plexichat.{module}" if module else "src.plexichat"

def scan_all_files() -> Dict[str, List[Dict]]:
    """Scan all Python files in the codebase."""
    issues_by_file = {}
    
    # Scan both src/plexichat and core directories
    scan_dirs = ['src/plexichat', 'core', 'plugins', 'tests']
    
    for scan_dir in scan_dirs:
        if not Path(scan_dir).exists():
            continue
            
        for py_file in Path(scan_dir).rglob('*.py'):
            # Skip __pycache__ and .venv directories
            if '__pycache__' in str(py_file) or '.venv' in str(py_file):
                continue
                
            issues, _ = analyze_file(py_file)
            if issues:
                issues_by_file[str(py_file)] = issues
    
    return issues_by_file

def generate_fixes(issues_by_file: Dict[str, List[Dict]]) -> List[Dict]:
    """Generate fix commands for all issues."""
    fixes = []
    
    for file_path, issues in issues_by_file.items():
        for issue in issues:
            if issue['type'] == 'import':
                old_line = f"import {issue['original']}"
                new_line = f"import {issue['fixed']}"
            elif issue['type'] == 'from_import':
                old_line = f"from {issue['original']} import {', '.join(issue['names'])}"
                new_line = f"from {issue['fixed']} import {', '.join(issue['names'])}"
            elif issue['type'] == 'from_import_relative':
                old_line = issue['full_line']
                new_line = f"from {issue['fixed']} import {', '.join(issue['names'])}"
            else:
                continue
                
            fixes.append({
                'file': file_path,
                'line': issue['line'],
                'old': old_line,
                'new': new_line,
                'type': issue['type']
            })
    
    return fixes

def main():
    """Main function."""
    print("Scanning for import issues...")
    
    issues_by_file = scan_all_files()
    
    if not issues_by_file:
        print("No import issues found!")
        return
    
    print(f"\nFound import issues in {len(issues_by_file)} files:")
    
    total_issues = 0
    for file_path, issues in issues_by_file.items():
        total_issues += len(issues)
        print(f"\n{file_path}: {len(issues)} issues")
        for issue in issues[:3]:  # Show first 3 issues per file
            print(f"  Line {issue['line']}: {issue.get('full_line', issue.get('original', ''))}")
            print(f"    -> {issue['fixed']}")
        if len(issues) > 3:
            print(f"    ... and {len(issues) - 3} more")
    
    print(f"\nTotal issues found: {total_issues}")
    
    # Generate fixes
    fixes = generate_fixes(issues_by_file)
    
    # Write fixes to a file for inspection
    with open('import_fixes.json', 'w') as f:
        import json
        json.dump(fixes, f, indent=2)
    
    print(f"Generated {len(fixes)} fixes saved to import_fixes.json")
    print("Review the fixes before applying them!")

if __name__ == '__main__':
    main()