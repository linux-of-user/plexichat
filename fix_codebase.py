import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

from typing import Optional, Dict, Any, List\nfrom typing import Optional, Dict, Any, List'),
from typing import Optional, Dict, Any, List\nfrom typing import Optional, Dict, Any, List'),
                

from typing import Any, Depends, Dict, List', Optional, Request, 'from, fastapi, import

#!/usr/bin/env python3
"""
Comprehensive codebase fixer for PlexiChat.
Fixes import errors, removes Unicode, and lints the entire codebase.
"""

class CodebaseFixer:
    def __init__(self, root_dir: str = "."):
        self.root_dir = from pathlib import Path
Path(root_dir)
        self.python_files = []
        self.fixed_files = []
        self.errors = []
        
    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
            # Skip common directories that shouldn't be processed
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules', 'venv', '.venv']]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(from pathlib import Path
Path(root) / file)
        
        self.python_files = python_files
        print(f"Found {len(python_files)} Python files")
        return python_files
    
    def remove_unicode_from_file(self, file_path: Path) -> bool:
        """Remove all non-ASCII characters from a Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Remove non-ASCII characters but keep newlines and tabs
            cleaned_content = ''
            for char in content:
                if ord(char) < 128 or char in '\n\t\r':
                    cleaned_content += char
            
            if cleaned_content != content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
                return True
            return False
        except Exception as e:
            self.errors.append(f"Error processing {file_path}: {e}")
            return False
    
    def fix_imports_in_file(self, file_path: Path) -> List[str]:
        """Fix common import issues in a file."""
        fixes = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Fix common import patterns
            import_fixes = [
                # Fix relative imports that are wrong
                (r'from \.\.plexichat\.', 'from plexichat.'),
                (r'from \.plexichat\.', 'from plexichat.'),
                (r'import plexichat\.', 'from plexichat import '),
                
                # Fix missing imports
                (r'from fastapi import Depends
                (r'from fastapi import Request
                # Fix common missing imports
                (r'from plexichat.features.users.user import User
User = Depends', 'from plexichat.features.users.user import User\nfrom plexichat.features.users.user import User
User = Depends'),
                (r'from plexichat.infrastructure.utils.auth import require_admin', 'from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin'),
                (r'from plexichat.infrastructure.utils.auth import get_current_user', 'from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user'),
                (r'settings\.', 'from plexichat.core.config import settings\nfrom plexichat.core.config import settings
settings.'),
                
                # Fix datetime imports
                (r'datetime\.now\(\)', 'from datetime import datetime\nfrom datetime import datetime
datetime.now()'),
                (r'datetime\.utcnow\(\)', 'from datetime import datetime\nfrom datetime import datetime
datetime.utcnow()'),
                
                # Fix Path imports
                (r'Path\(', 'from pathlib import Path\nfrom pathlib import Path
Path('),
                
                # Fix common missing imports
                (r'jwt\.decode', 'import jwt\nimport jwt
jwt.decode'),
                (r'psutil\.', 'import psutil\nimport psutil
psutil.'),
                
                # Fix bare except statements
                (r'except Exception:', 'except Exception:'),
                (r'except Exception:', 'except Exception:'),
            ]
            
            for pattern, replacement in import_fixes:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    fixes.append(f"Fixed pattern: {pattern}")
            
            # Fix import order issues
            lines = content.split('\n')
            import_lines = []
            other_lines = []
            in_import_section = False
            
            for line in lines:
                stripped = line.strip()
                if stripped.startswith(('import ', 'from ')):
                    import_lines.append(line)
                    in_import_section = True
                elif in_import_section and stripped == '':
                    import_lines.append(line)
                else:
                    other_lines.append(line)
                    in_import_section = False
            
            # Reorganize imports
            if import_lines:
                # Sort imports
                stdlib_imports = []
                third_party_imports = []
                local_imports = []
                
                for line in import_lines:
                    if line.strip().startswith(('import ', 'from ')):
                        if 'plexichat' in line:
                            local_imports.append(line)
                        elif any(pkg in line for pkg in ['fastapi', 'pydantic', 'sqlalchemy', 'uvicorn', 'jwt', 'psutil']):
                            third_party_imports.append(line)
                        else:
                            stdlib_imports.append(line)
                    else:
                        # Empty line or comment
                        if stdlib_imports:
                            stdlib_imports.append(line)
                        elif third_party_imports:
                            third_party_imports.append(line)
                        elif local_imports:
                            local_imports.append(line)
                
                # Combine imports in correct order
                new_imports = []
                if stdlib_imports:
                    new_imports.extend(stdlib_imports)
                    new_imports.append('')
                if third_party_imports:
                    new_imports.extend(third_party_imports)
                    new_imports.append('')
                if local_imports:
                    new_imports.extend(local_imports)
                    new_imports.append('')
                
                content = '\n'.join(new_imports + other_lines)
            
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.fixed_files.append(str(file_path))
            
            return fixes
            
        except Exception as e:
            self.errors.append(f"Error fixing imports in {file_path}: {e}")
            return []
    
    def run_linter_on_file(self, file_path: Path) -> List[str]:
        """Run ruff linter on a single file and return errors."""
        try:
            result = subprocess.run(
                ['ruff', 'check', str(file_path), '--output-format=text'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return result.stdout.split('\n')
            return []
        except Exception as e:
            self.errors.append(f"Error running linter on {file_path}: {e}")
            return []
    
    def fix_linter_errors(self, file_path: Path, errors: List[str]) -> List[str]:
        """Attempt to fix linter errors automatically."""
        fixes = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Fix common linter errors
            for error in errors:
                if 'F821' in error:  # Undefined name
                    # Extract the undefined name
                    match = re.search(r"Undefined name `([^`]+)`", error)
                    if match:
                        undefined_name = match.group(1)
                        if undefined_name == 'User':
                            content = re.sub(r'^', 'from plexichat.features.users.user import User\n', content, count=1)
                        elif undefined_name == 'settings':
                            content = re.sub(r'^', 'from plexichat.core.config import settings\n', content, count=1)
                        elif undefined_name == 'datetime':
                            content = re.sub(r'^', 'from datetime import datetime\n', content, count=1)
                        elif undefined_name == 'Path':
                            content = re.sub(r'^', 'from pathlib import Path\n', content, count=1)
                        elif undefined_name == 'jwt':
                            content = re.sub(r'^', 'import jwt\n', content, count=1)
                        elif undefined_name == 'psutil':
                            content = re.sub(r'^', 'import psutil\n', content, count=1)
                
                elif 'E722' in error:  # Bare except
                    content = re.sub(r'except Exception:', 'except Exception:', content)
                    content = re.sub(r'except Exception:', 'except Exception:', content)
                
                elif 'F401' in error:  # Unused import
                    # This is handled by autoflake, but we can add specific fixes here
                    pass
                
                elif 'E402' in error:  # Import not at top
                    # This is handled by isort, but we can add specific fixes here
                    pass
            
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                fixes.append(f"Fixed linter errors in {file_path}")
            
            return fixes
            
        except Exception as e:
            self.errors.append(f"Error fixing linter errors in {file_path}: {e}")
            return []
    
    def process_all_files(self):
        """Process all Python files in the codebase."""
        print("Starting comprehensive codebase fix...")
        
        # Step 1: Find all Python files
        python_files = self.find_python_files()
        
        # Step 2: Remove Unicode from all files
        print("Removing Unicode characters...")
        unicode_fixed = 0
        for file_path in python_files:
            if self.remove_unicode_from_file(file_path):
                unicode_fixed += 1
        print(f"Removed Unicode from {unicode_fixed} files")
        
        # Step 3: Fix imports in all files
        print("Fixing import issues...")
        import_fixes = 0
        for file_path in python_files:
            fixes = self.fix_imports_in_file(file_path)
            if fixes:
                import_fixes += 1
        print(f"Fixed imports in {import_fixes} files")
        
        # Step 4: Run linter and fix errors
        print("Running linter and fixing errors...")
        linter_fixes = 0
        for file_path in python_files:
            errors = self.run_linter_on_file(file_path)
            if errors:
                fixes = self.fix_linter_errors(file_path, errors)
                if fixes:
                    linter_fixes += 1
        
        print(f"Fixed linter errors in {linter_fixes} files")
        
        # Step 5: Run final cleanup tools
        print("Running final cleanup tools...")
        try:
            # Run autoflake again
            subprocess.run(['autoflake', '--in-place', '--remove-unused-variables', 
                          '--remove-all-unused-imports', '--recursive', '.'], 
                         check=True, capture_output=True)
            print(" Autoflake cleanup completed")
        except Exception as e:
            self.errors.append(f"Autoflake error: {e}")
        
        try:
            # Run isort again
            subprocess.run(['isort', '.'], check=True, capture_output=True)
            print(" Isort cleanup completed")
        except Exception as e:
            self.errors.append(f"Isort error: {e}")
        
        # Step 6: Final linter check
        print("Running final linter check...")
        total_errors = 0
        for file_path in python_files:
            errors = self.run_linter_on_file(file_path)
            if errors:
                total_errors += len([e for e in errors if e.strip()])
        
        print(f"Final error count: {total_errors}")
        
        # Print summary
        print("\n" + "="*50)
        print("CODEBASE FIX SUMMARY")
        print("="*50)
        print(f"Files processed: {len(python_files)}")
        print(f"Unicode removed from: {unicode_fixed} files")
        print(f"Import fixes applied to: {import_fixes} files")
        print(f"Linter fixes applied to: {linter_fixes} files")
        print(f"Final error count: {total_errors}")
        
        if self.errors:
            print(f"\nErrors encountered: {len(self.errors)}")
            for error in self.errors[:10]:  # Show first 10 errors
                print(f"  - {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more")
        
        if self.fixed_files:
            print(f"\nFiles modified: {len(self.fixed_files)}")
            for file_path in self.fixed_files[:10]:  # Show first 10
                print(f"  - {file_path}")
            if len(self.fixed_files) > 10:
                print(f"  ... and {len(self.fixed_files) - 10} more")

def main():
    """Main function to run the codebase fixer."""
    fixer = CodebaseFixer()
    fixer.process_all_files()

if __name__ == "__main__":
    main() 