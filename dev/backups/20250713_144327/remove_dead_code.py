#!/usr/bin/env python3
"""
Script to remove dead code, unused imports, and unused variables throughout the codebase.
"""

import os
import re
import ast
from pathlib import Path
from typing import List, Dict, Any


class DeadCodeRemover:
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
        print(f"Found {len(python_files)} Python files")
        return python_files

    def analyze_file_ast(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a file using AST to find unused imports and variables."""
        results = {
            "file": str(file_path),
            "unused_imports": [],
            "unused_variables": [],
            "dead_code_lines": [],
            "errors": [],
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse the AST
            try:
                tree = ast.parse(content)
            except SyntaxError:
                results["errors"].append("Syntax error in file")
                return results

            # Find all imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(
                            f"{module}.{alias.name}" if module else alias.name
                        )

            # Find all variable assignments
            variables = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            variables.add(target.id)

            # Find all function definitions
            functions = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.add(node.name)

            # Find all class definitions
            classes = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.add(node.name)

            # Find all name usages
            usages = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    usages.add(node.id)

            # Find unused imports (simplified check)
            for imp in imports:
                if imp not in usages and imp.split(".")[-1] not in usages:
                    results["unused_imports"].append(imp)

            # Find unused variables (simplified check)
            for var in variables:
                if var not in usages and var not in functions and var not in classes:
                    results["unused_variables"].append(var)

            return results

        except Exception as e:
            results["errors"].append(str(e))
            self.errors.append(f"Error analyzing {file_path}: {e}")
            return results

    def remove_unused_imports(self, file_path: Path, unused_imports: List[str]) -> bool:
        """Remove unused imports from a file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            lines = content.split("\n")
            new_lines = []

            i = 0
            while i < len(lines):
                line = lines[i].strip()

                # Check if this line is an import that should be removed
                should_remove = False
                for unused_import in unused_imports:
                    if unused_import in line and (
                        line.startswith("import ") or line.startswith("from ")
                    ):
                        should_remove = True
                        break

                if should_remove:
                    # Skip this line
                    i += 1
                else:
                    new_lines.append(lines[i])
                    i += 1

            new_content = "\n".join(new_lines)

            if new_content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                return True

            return False

        except Exception as e:
            self.errors.append(f"Error removing unused imports from {file_path}: {e}")
            return False

    def remove_unused_variables(
        self, file_path: Path, unused_variables: List[str]
    ) -> bool:
        """Remove unused variable assignments from a file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Simple pattern matching to remove unused variable assignments
            for var in unused_variables:
                # Pattern to match variable assignments
                patterns = [
                    rf"^\s*{re.escape(var)}\s*=\s*[^#\n]+$",  # Simple assignment
                    rf"^\s*{re.escape(var)}\s*,\s*[^#\n]+$",  # Multiple assignment
                ]

                for pattern in patterns:
                    content = re.sub(pattern, "", content, flags=re.MULTILINE)

            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                return True

            return False

        except Exception as e:
            self.errors.append(f"Error removing unused variables from {file_path}: {e}")
            return False

    def remove_dead_code(self, file_path: Path) -> bool:
        """Remove obvious dead code patterns."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content

            # Remove empty except blocks
            content = re.sub(r"except\s*Exception\s*:\s*pass", "", content)
            content = re.sub(r"except\s*:\s*pass", "", content)

            # Remove commented out code blocks
            content = re.sub(r"#\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^#\n]+", "", content)

            # Remove empty if blocks
            content = re.sub(r"if\s+[^:]+:\s*pass", "", content)

            # Remove unused function definitions (simple check)
            content = re.sub(
                r"def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\):\s*pass", "", content
            )

            if content != original_content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                return True

            return False

        except Exception as e:
            self.errors.append(f"Error removing dead code from {file_path}: {e}")
            return False

    def process_file(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file and return results."""
        results = {
            "file": str(file_path),
            "unused_imports_removed": 0,
            "unused_variables_removed": 0,
            "dead_code_removed": False,
            "errors": [],
        }

        # Analyze the file
        analysis = self.analyze_file_ast(file_path)
        results["errors"].extend(analysis["errors"])

        # Remove unused imports
        if analysis["unused_imports"]:
            if self.remove_unused_imports(file_path, analysis["unused_imports"]):
                results["unused_imports_removed"] = len(analysis["unused_imports"])

        # Remove unused variables
        if analysis["unused_variables"]:
            if self.remove_unused_variables(file_path, analysis["unused_variables"]):
                results["unused_variables_removed"] = len(analysis["unused_variables"])

        # Remove dead code
        if self.remove_dead_code(file_path):
            results["dead_code_removed"] = True

        if (
            results["unused_imports_removed"] > 0
            or results["unused_variables_removed"] > 0
            or results["dead_code_removed"]
        ):
            self.fixed_files.append(str(file_path))

        return results

    def run(self) -> Dict[str, Any]:
        """Run the dead code removal process."""
        print("Starting dead code removal...")

        # Find all Python files
        python_files = self.find_python_files()

        # Process each file
        results = []
        total_imports_removed = 0
        total_variables_removed = 0
        files_with_dead_code_removed = 0

        for file_path in python_files:
            print(f"Processing {file_path}...")
            result = self.process_file(file_path)
            results.append(result)

            if result["unused_imports_removed"] > 0:
                print(f"  - Removed {result['unused_imports_removed']} unused imports")
                total_imports_removed += result["unused_imports_removed"]

            if result["unused_variables_removed"] > 0:
                print(
                    f"  - Removed {result['unused_variables_removed']} unused variables"
                )
                total_variables_removed += result["unused_variables_removed"]

            if result["dead_code_removed"]:
                print("  - Removed dead code")
                files_with_dead_code_removed += 1

        # Summary
        print("\nSummary:")
        print(f"  Total files processed: {len(results)}")
        print(
            f"  Files with unused imports removed: {len([r for r in results if r['unused_imports_removed'] > 0])}"
        )
        print(
            f"  Files with unused variables removed: {len([r for r in results if r['unused_variables_removed'] > 0])}"
        )
        print(f"  Files with dead code removed: {files_with_dead_code_removed}")
        print(f"  Total unused imports removed: {total_imports_removed}")
        print(f"  Total unused variables removed: {total_variables_removed}")

        if self.errors:
            print("\nErrors encountered:")
            for error in self.errors:
                print(f"  - {error}")

        return {
            "total_files": len(results),
            "files_with_imports_removed": len(
                [r for r in results if r["unused_imports_removed"] > 0]
            ),
            "files_with_variables_removed": len(
                [r for r in results if r["unused_variables_removed"] > 0]
            ),
            "files_with_dead_code_removed": files_with_dead_code_removed,
            "total_imports_removed": total_imports_removed,
            "total_variables_removed": total_variables_removed,
            "errors": self.errors,
            "results": results,
        }


if __name__ == "__main__":
    remover = DeadCodeRemover()
    results = remover.run()
