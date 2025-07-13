import logging
import os
import re
from pathlib import Path
from typing import List, Dict, Any


#!/usr/bin/env python3
"""
Script to fix critical syntax errors that prevent black formatting.
"""



class SyntaxErrorFixer:
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir)
        self.python_files = []
        self.fixed_files = []
        self.errors = []

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []
        for root, dirs, files in os.walk(self.root_dir):
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
        print(f"Found {len(python_files)} Python files")
        return python_files

    def fix_syntax_errors_in_file(self, file_path: Path) -> Dict[str, Any]:
        """Fix critical syntax errors in a file."""
        results = {"file": str(file_path), "fixes_applied": 0, "errors": []}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Fix malformed import statements
            fixes = [
                # Fix "from pathlib import Path" in variable assignments
                (
                    r"self\.\w+\s*=\s*from pathlib import Path",
                    "from pathlib import Path\n        self.\\1 = Path",
                ),
                (
                    r"(\w+)\s*=\s*from pathlib import Path",
                    "from pathlib import Path\n\\1 = Path",
                ),
                # Fix "from datetime import datetime" in expressions
                (
                    r"from datetime import datetime\n(\w+)\.now\(\)",
                    "from datetime import datetime\n\\1 = datetime.now()",
                ),
                (
                    r"(\w+)\s*=\s*from datetime import datetime",
                    "from datetime import datetime\n\\1 = datetime.now()",
                ),
                # Fix malformed import statements
                (
                    r"from \.\.\.core\.config import settings",
                    "from plexichat.core.config import settings",
                ),
                (
                    r"from \.\.\.core\.logging import get_logger",
                    "from plexichat.core.logging import get_logger",
                ),
                (
                    r"from \.\.\.core\.auth\.dependencies import",
                    "from plexichat.core.auth.dependencies import",
                ),
                # Fix duplicate imports
                (
                    r"from plexichat\.infrastructure\.utils\.auth import from plexichat\.infrastructure\.utils\.auth import",
                    "from plexichat.infrastructure.utils.auth import",
                ),
                # Fix malformed function definitions
                (
                    r"async def from plexichat\.infrastructure\.utils\.auth import",
                    "async def get_current_user",
                ),
                # Fix malformed expressions
                (r"import psutil\n(\w+)", "import psutil\n\\1 = psutil"),
                (r"import httpx\n(\w+)", "import httpx\n\\1 = httpx"),
                # Fix malformed string literals
                (r'""",\s*$', '""",'),
                (r"", ""),
                (r"", ""),
                # Fix malformed variable assignments
                (
                    r"(\w+)\s*=\s*from pathlib import Path\n(\w+)",
                    "from pathlib import Path\n\\1 = Path\n\\2",
                ),
            ]

            for pattern, replacement in fixes:
                matches = re.findall(pattern, content)
                if matches:
                    content = re.sub(pattern, replacement, content)
                    results["fixes_applied"] += len(matches)

            # Remove trailing whitespace
            lines = content.split("\n")
            cleaned_lines = []
            for line in lines:
                cleaned_lines.append(line.rstrip())
            content = "\n".join(cleaned_lines)

            # Ensure file ends with newline
            if content and not content.endswith("\n"):
                content += "\n"

            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.fixed_files.append(str(file_path))

            return results

        except Exception as e:
            results["errors"].append(str(e))
            self.errors.append(f"Error processing {file_path}: {e}")
            return results

    def run(self) -> Dict[str, Any]:
        """Run the syntax error fixing process."""
        print("Starting syntax error fixing...")

        # Find all Python files
        python_files = self.find_python_files()

        # Process each file
        results = []
        total_fixes = 0

        for file_path in python_files:
            print(f"Processing {file_path}...")
            result = self.fix_syntax_errors_in_file(file_path)
            results.append(result)

            if result["fixes_applied"] > 0:
                print(f"  - Applied {result['fixes_applied']} fixes")
                total_fixes += result["fixes_applied"]

        # Summary
        print("\nSummary:")
        print(f"  Total files processed: {len(results)}")
        print(
            f"  Files with fixes applied: {len([r for r in results if r['fixes_applied'] > 0])}"
        )
        print(f"  Total fixes applied: {total_fixes}")

        if self.errors:
            print("\nErrors encountered:")
            for error in self.errors:
                print(f"  - {error}")

        return {
            "total_files": len(results),
            "files_with_fixes": len([r for r in results if r["fixes_applied"] > 0]),
            "total_fixes": total_fixes,
            "errors": self.errors,
            "results": results,
        }


if __name__ == "__main__":
    fixer = SyntaxErrorFixer()
    results = fixer.run()
