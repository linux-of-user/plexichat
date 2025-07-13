import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Any
import logging


#!/usr/bin/env python3
"""
Comprehensive codebase fixer for PlexiChat.
Fixes import errors, removes Unicode, and lints the entire codebase.
"""

logger = logging.getLogger(__name__)


class CodebaseFixer:
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir)
        self.python_files = []
        self.fixed_files = []
        self.errors = []

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
            # Skip common directories that shouldn't be processed
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d not in ["__pycache__", "node_modules", "venv", ".venv"]
            ]

            for file in files:
                if file.endswith(".py"):
                    python_files.append(Path(root) / file)

        self.python_files = python_files
        logger.info(f"Found {len(python_files)} Python files")
        return python_files

    def remove_unicode_from_file(self, file_path: Path) -> bool:
        """Remove all non-ASCII characters from a Python file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Remove non-ASCII characters but keep newlines and tabs
            cleaned_content = ""
            for char in content:
                if ord(char) < 128 or char in "\n\t\r":
                    cleaned_content += char

            if cleaned_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
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
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Fix common import patterns
            import_fixes = [
                # Fix relative imports that are wrong
                (r"from \.\.plexichat\.", "from plexichat."),
                (r"from \.plexichat\.", "from plexichat."),
                (r"import plexichat\.", "from plexichat import "),
                # Fix missing imports - simplified
                (
                    r"User = Depends",
                    "from plexichat.features.users.user import User\nUser = Depends",
                ),
                (
                    r"require_admin",
                    "from plexichat.infrastructure.utils.auth import require_admin",
                ),
                (
                    r"get_current_user",
                    "from plexichat.infrastructure.utils.auth import get_current_user",
                ),
                # Fix datetime imports
                (r"datetime\.now\(\)", "from datetime import datetime\ndatetime.now()"),
                (
                    r"datetime\.utcnow\(\)",
                    "from datetime import datetime\ndatetime.utcnow()",
                ),
                # Fix Path imports
                (r"Path\(", "from pathlib import Path\nPath("),
                # Fix common missing imports
                (r"jwt\.decode", "import jwt\njwt.decode"),
                (r"psutil\.", "import psutil\npsutil."),
            ]

            for pattern, replacement in import_fixes:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    fixes.append(f"Fixed pattern: {pattern}")

            # Fix import order issues
            lines = content.split("\n")
            import_lines = []
            other_lines = []
            in_import_section = False

            for line in lines:
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    import_lines.append(line)
                    in_import_section = True
                elif in_import_section and stripped == "":
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
                    if line.strip().startswith(("import ", "from ")):
                        if "plexichat" in line:
                            local_imports.append(line)
                        elif any(
                            pkg in line
                            for pkg in [
                                "fastapi",
                                "pydantic",
                                "sqlalchemy",
                                "uvicorn",
                                "jwt",
                                "psutil",
                            ]
                        ):
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
                    new_imports.append("")
                if third_party_imports:
                    new_imports.extend(third_party_imports)
                    new_imports.append("")
                if local_imports:
                    new_imports.extend(local_imports)
                    new_imports.append("")

                content = "\n".join(new_imports + other_lines)

            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
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
                ["ruff", "check", str(file_path), "--output-format=text"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return result.stdout.split("\n")
            return []
        except Exception as e:
            self.errors.append(f"Error running linter on {file_path}: {e}")
            return []

    def fix_linter_errors(self, file_path: Path, errors: List[str]) -> List[str]:
        """Attempt to fix linter errors automatically."""
        fixes = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Fix common linter errors
            for error in errors:
                if "F821" in error:  # Undefined name
                    # Extract the undefined name
                    match = re.search(r"Undefined name `([^`]+)`", error)
                    if match:
                        undefined_name = match.group(1)
                        if undefined_name == "User":
                            content = re.sub(
                                r"^",
                                "from plexichat.features.users.user import User\n",
                                content,
                                count=1,
                            )
                        elif undefined_name == "settings":
                            content = re.sub(
                                r"^",
                                "from plexichat.core.config import settings\n",
                                content,
                                count=1,
                            )
                        elif undefined_name == "datetime":
                            content = re.sub(
                                r"^",
                                "from datetime import datetime\n",
                                content,
                                count=1,
                            )
                        elif undefined_name == "Path":
                            content = re.sub(
                                r"^", "from pathlib import Path\n", content, count=1
                            )
                        elif undefined_name == "jwt":
                            content = re.sub(r"^", "import jwt\n", content, count=1)
                        elif undefined_name == "psutil":
                            content = re.sub(r"^", "import psutil\n", content, count=1)

                elif "E722" in error:  # Bare except
                    content = re.sub(r"except Exception:", "except Exception:", content)

                elif "F401" in error:  # Unused import
                    # This is handled by autoflake, but we can add specific fixes here
                    pass

                elif "E402" in error:  # Import not at top
                    # This is handled by isort, but we can add specific fixes here
                    pass

            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                fixes.append(f"Fixed linter errors in {file_path}")

            return fixes

        except Exception as e:
            self.errors.append(f"Error fixing linter errors in {file_path}: {e}")
            return []

    def process_file(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file and return results."""
        results = {
            "file": str(file_path),
            "unicode_removed": False,
            "imports_fixed": [],
            "linter_errors": [],
            "linter_fixes": [],
        }

        # Remove Unicode characters
        results["unicode_removed"] = self.remove_unicode_from_file(file_path)

        # Fix imports
        results["imports_fixed"] = self.fix_imports_in_file(file_path)

        # Run linter
        results["linter_errors"] = self.run_linter_on_file(file_path)

        # Fix linter errors
        if results["linter_errors"]:
            results["linter_fixes"] = self.fix_linter_errors(
                file_path, results["linter_errors"]
            )

        return results

    def run(self) -> Dict[str, Any]:
        """Run the complete codebase fix process."""
        logger.info("Starting comprehensive codebase fix...")

        # Find all Python files
        python_files = self.find_python_files()

        # Process each file
        results = []
        for file_path in python_files:
            logger.info(f"Processing {file_path}...")
            result = self.process_file(file_path)
            results.append(result)

            if result["unicode_removed"]:
                logger.info("  - Removed Unicode characters")
            if result["imports_fixed"]:
                logger.info(f"  - Fixed {len(result['imports_fixed'])} import issues")
            if result["linter_errors"]:
                logger.info(f"  - Found {len(result['linter_errors'])} linter errors")
            if result["linter_fixes"]:
                logger.info(f"  - Applied {len(result['linter_fixes'])} linter fixes")

        # Summary
        total_files = len(results)
        files_with_unicode = len([r for r in results if r["unicode_removed"]])
        files_with_import_fixes = len([r for r in results if r["imports_fixed"]])
        files_with_linter_errors = len([r for r in results if r["linter_errors"]])
        files_with_linter_fixes = len([r for r in results if r["linter_fixes"]])

        logger.info("\nSummary:")
        logger.info(f"  Total files processed: {total_files}")
        logger.info(f"  Files with Unicode removed: {files_with_unicode}")
        logger.info(f"  Files with import fixes: {files_with_import_fixes}")
        logger.info(f"  Files with linter errors: {files_with_linter_errors}")
        logger.info(f"  Files with linter fixes: {files_with_linter_fixes}")

        if self.errors:
            logger.info("\nErrors encountered:")
            for error in self.errors:
                logger.info(f"  - {error}")

        return {
            "total_files": total_files,
            "files_with_unicode": files_with_unicode,
            "files_with_import_fixes": files_with_import_fixes,
            "files_with_linter_errors": files_with_linter_errors,
            "files_with_linter_fixes": files_with_linter_fixes,
            "errors": self.errors,
            "results": results,
        }


if __name__ == "__main__":
    fixer = CodebaseFixer()
    fixer.run()
