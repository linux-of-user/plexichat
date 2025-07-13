import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any

#!/usr/bin/env python3
"""
Script to replace print statements with proper logging throughout the codebase.
"""


logger = logging.getLogger(__name__)


class PrintToLoggingReplacer:
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

    def replace_prints_in_file(self, file_path: Path) -> Dict[str, Any]:
        """Replace print statements with proper logging in a file."""
        results = {
            "file": str(file_path),
            "prints_replaced": 0,
            "logging_added": False,
            "errors": [],
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Check if logging is already imported
            has_logging_import = (
                "import logging" in content or "from logging import" in content
            )

            # Patterns to match different types of print statements
            print_patterns = [
                # Simple print statements
                (r'print\("([^"]*)"\)', r'logger.info("\1")'),
                (r"print\('([^']*)'\)", r"logger.info('\1')"),
                # Print with variables
                (r'print\(f"([^"]*)"\)', r'logger.info(f"\1")'),
                (r"print\(f'([^']*)'\)", r"logger.info(f'\1')"),
                # Print with expressions
                (r"print\(([^)]+)\)", r"logger.info(\1)"),
                # Print with multiple arguments
                (r"print\(([^)]+), ([^)]+)\)", r'logger.info(f"\1 \2")'),
            ]

            # Apply replacements
            for pattern, replacement in print_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    content = re.sub(pattern, replacement, content)
                    results["prints_replaced"] += len(matches)

            # Add logging import if needed and prints were replaced
            if results["prints_replaced"] > 0 and not has_logging_import:
                # Find the right place to add the import
                lines = content.split("\n")
                import_section_end = 0

                for i, line in enumerate(lines):
                    if line.strip().startswith(("import ", "from ")):
                        import_section_end = i + 1
                    elif line.strip() == "" and import_section_end == 0:
                        import_section_end = i

                # Add logging import
                logging_import = "import logging\n"
                lines.insert(import_section_end, logging_import)
                content = "\n".join(lines)
                results["logging_added"] = True

            # Add logger setup if prints were replaced
            if results["prints_replaced"] > 0:
                # Find a good place to add logger setup (after imports, before functions)
                lines = content.split("\n")
                setup_line = "logger = logging.getLogger(__name__)"

                # Look for a good place to add logger setup
                insert_pos = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith("def ") or line.strip().startswith(
                        "class "
                    ):
                        insert_pos = i
                        break
                    elif line.strip() == "" and i > 0:
                        insert_pos = i

                if insert_pos > 0:
                    lines.insert(insert_pos, setup_line)
                    content = "\n".join(lines)

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
        """Run the print replacement process."""
        logger.info("Starting print to logging replacement...")

        # Find all Python files
        python_files = self.find_python_files()

        # Process each file
        results = []
        total_prints_replaced = 0
        files_with_logging_added = 0

        for file_path in python_files:
            logger.info(f"Processing {file_path}...")
            result = self.replace_prints_in_file(file_path)
            results.append(result)

            if result["prints_replaced"] > 0:
                logger.info(
                    f"  - Replaced {result['prints_replaced']} print statements"
                )
                total_prints_replaced += result["prints_replaced"]

            if result["logging_added"]:
                logger.info("  - Added logging import")
                files_with_logging_added += 1

        # Summary
        logger.info("\nSummary:")
        logger.info(f"  Total files processed: {len(results)}")
        logger.info(
            f"  Files with prints replaced: {len([r for r in results if r['prints_replaced'] > 0])}"
        )
        logger.info(f"  Total print statements replaced: {total_prints_replaced}")
        logger.info(f"  Files with logging added: {files_with_logging_added}")

        if self.errors:
            logger.info("\nErrors encountered:")
            for error in self.errors:
                logger.info(f"  - {error}")

        return {
            "total_files": len(results),
            "files_with_prints_replaced": len(
                [r for r in results if r["prints_replaced"] > 0]
            ),
            "total_prints_replaced": total_prints_replaced,
            "files_with_logging_added": files_with_logging_added,
            "errors": self.errors,
            "results": results,
        }


if __name__ == "__main__":
    replacer = PrintToLoggingReplacer()
    results = replacer.run()
