import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any

#!/usr/bin/env python3
"""
Script to format the codebase using black and run linting with ruff.
"""



class CodeFormatter:
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

    def install_dependencies(self) -> bool:
        """Install required formatting and linting tools."""
        try:
            print("Installing formatting and linting tools...")

            # Install black for code formatting
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "black"],
                check=True,
                capture_output=True,
            )
            print("✓ Black installed")

            # Install ruff for linting
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "ruff"],
                check=True,
                capture_output=True,
            )
            print("✓ Ruff installed")

            return True

        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies: {e}")
            return False

    def format_with_black(self) -> Dict[str, Any]:
        """Format the codebase using black."""
        results = {"files_formatted": 0, "errors": []}

        try:
            print("Formatting code with black...")

            # Run black on the entire codebase
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "black",
                    "--line-length",
                    "88",
                    "--target-version",
                    "py39",
                    str(self.root_dir),
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                print("✓ Code formatted successfully with black")
                # Count files that were formatted
                for line in result.stdout.split("\n"):
                    if line.strip() and "reformatted" in line:
                        results["files_formatted"] += 1
            else:
                print(f"Black formatting errors: {result.stderr}")
                results["errors"].append(f"Black formatting failed: {result.stderr}")

            return results

        except Exception as e:
            error_msg = f"Error running black: {e}"
            print(error_msg)
            results["errors"].append(error_msg)
            return results

    def lint_with_ruff(self) -> Dict[str, Any]:
        """Run linting with ruff."""
        results = {
            "files_linted": 0,
            "issues_found": 0,
            "issues_fixed": 0,
            "errors": [],
        }

        try:
            print("Running linting with ruff...")

            # First, check for issues
            check_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    "--output-format",
                    "text",
                    str(self.root_dir),
                ],
                capture_output=True,
                text=True,
            )

            if check_result.stdout:
                print("Issues found by ruff:")
                print(check_result.stdout)
                results["issues_found"] = (
                    len(check_result.stdout.split("\n")) - 1
                )  # Subtract header

            # Try to fix auto-fixable issues
            fix_result = subprocess.run(
                [sys.executable, "-m", "ruff", "check", "--fix", str(self.root_dir)],
                capture_output=True,
                text=True,
            )

            if fix_result.stdout:
                print("Auto-fixed issues:")
                print(fix_result.stdout)
                results["issues_fixed"] = len(fix_result.stdout.split("\n")) - 1

            # Count files that were processed
            for line in (check_result.stdout + fix_result.stdout).split("\n"):
                if line.strip() and ":" in line and not line.startswith("Found"):
                    results["files_linted"] += 1

            return results

        except Exception as e:
            error_msg = f"Error running ruff: {e}"
            print(error_msg)
            results["errors"].append(error_msg)
            return results

    def run_style_checks(self) -> Dict[str, Any]:
        """Run additional style checks."""
        results = {"files_checked": 0, "style_issues": [], "errors": []}

        try:
            print("Running additional style checks...")

            # Check for common style issues
            for file_path in self.python_files:
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    issues = []

                    # Check for trailing whitespace
                    lines = content.split("\n")
                    for i, line in enumerate(lines, 1):
                        if line.rstrip() != line:
                            issues.append(f"Line {i}: Trailing whitespace")

                    # Check for missing newline at end of file
                    if content and not content.endswith("\n"):
                        issues.append("Missing newline at end of file")

                    # Check for mixed tabs and spaces
                    if "\t" in content and "    " in content:
                        issues.append("Mixed tabs and spaces")

                    if issues:
                        results["style_issues"].append(
                            {"file": str(file_path), "issues": issues}
                        )

                    results["files_checked"] += 1

                except Exception as e:
                    results["errors"].append(f"Error checking {file_path}: {e}")

            return results

        except Exception as e:
            error_msg = f"Error running style checks: {e}"
            print(error_msg)
            results["errors"].append(error_msg)
            return results

    def run(self) -> Dict[str, Any]:
        """Run the complete formatting and linting process."""
        print("Starting code formatting and linting...")

        # Install dependencies
        if not self.install_dependencies():
            return {"error": "Failed to install dependencies"}

        # Find all Python files
        python_files = self.find_python_files()

        # Format with black
        black_results = self.format_with_black()

        # Lint with ruff
        ruff_results = self.lint_with_ruff()

        # Run style checks
        style_results = self.run_style_checks()

        # Summary
        print("\nSummary:")
        print(f"  Files formatted with black: {black_results['files_formatted']}")
        print(f"  Files linted with ruff: {ruff_results['files_linted']}")
        print(f"  Issues found by ruff: {ruff_results['issues_found']}")
        print(f"  Issues auto-fixed by ruff: {ruff_results['issues_fixed']}")
        print(f"  Files with style issues: {len(style_results['style_issues'])}")

        if black_results["errors"]:
            print("\nBlack errors:")
            for error in black_results["errors"]:
                print(f"  - {error}")

        if ruff_results["errors"]:
            print("\nRuff errors:")
            for error in ruff_results["errors"]:
                print(f"  - {error}")

        if style_results["style_issues"]:
            print("\nStyle issues found:")
            for issue in style_results["style_issues"][:10]:  # Show first 10
                print(f"  {issue['file']}:")
                for problem in issue["issues"]:
                    print(f"    - {problem}")

        return {
            "black_results": black_results,
            "ruff_results": ruff_results,
            "style_results": style_results,
            "total_files": len(python_files),
        }


if __name__ == "__main__":
    formatter = CodeFormatter()
    results = formatter.run()
