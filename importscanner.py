#!/usr/bin/env python3
import argparse
import os
import re
import sys
import csv
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
import ast
from collections import defaultdict

DEFAULT_EXCLUDE_DIRS = {
    ".git","venv",".venv","node_modules","dist","build","__pycache__",
    ".mypy_cache",".pytest_cache",".tox",".coverage",".eggs",".idea",".vscode"
}

# --------------------------
# Requirements.txt parsing
# --------------------------

def parse_requirements_txt(requirements_path: Path) -> Set[str]:
    """Parse requirements.txt and extract package names."""
    external_packages = set()

    if not requirements_path.exists():
        return external_packages

    try:
        content = requirements_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Skip section markers and installation instructions
            if line.startswith("===") or line.startswith("Use:"):
                continue

            # Extract package name (before version specifiers)
            # Handle formats like: package>=1.0.0, package[extra]>=1.0.0, package==1.0.0; condition
            package_match = re.match(r'^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)', line)
            if package_match:
                package_name = package_match.group(1)
                # Remove extras like [asyncio] from package[asyncio]
                base_package = re.sub(r'\[.*\]', '', package_name)
                external_packages.add(base_package.lower())

                # Add common import name variations
                import_name = base_package.lower().replace('-', '_')
                external_packages.add(import_name)

                # Add specific mappings for common packages
                package_mappings = {
                    'python-multipart': 'multipart',
                    'python-dotenv': 'dotenv',
                    'python-dateutil': 'dateutil',
                    'python-jose': 'jose',
                    'beautifulsoup4': 'bs4',
                    'pillow': 'PIL',
                    'pyyaml': 'yaml',
                    'sqlalchemy': 'sqlalchemy',
                    'fastapi': 'fastapi',
                    'uvicorn': 'uvicorn',
                    'pydantic': 'pydantic',
                    'httpx': 'httpx',
                    'requests': 'requests',
                    'click': 'click',
                    'typer': 'typer',
                    'rich': 'rich',
                    'colorama': 'colorama',
                    'bcrypt': 'bcrypt',
                    'cryptography': 'cryptography',
                    'websockets': 'websockets',
                    'aiofiles': 'aiofiles',
                    'psutil': 'psutil',
                    'pyqt6': 'PyQt6',
                    'lxml': 'lxml',
                    'markdown': 'markdown',
                    'toml': 'toml',
                    'packaging': 'packaging',
                    'setuptools': 'setuptools',
                    'wheel': 'wheel',
                    'passlib': 'passlib',
                    'pyotp': 'pyotp',
                    'qrcode': 'qrcode',
                    'email-validator': 'email_validator',
                    'tabulate': 'tabulate'
                }

                if base_package.lower() in package_mappings:
                    external_packages.add(package_mappings[base_package.lower()])

    except Exception as e:
        print(f"Warning: Could not parse requirements.txt: {e}", file=sys.stderr)

    # Add standard library modules that are commonly imported
    stdlib_modules = {
        'os', 'sys', 'json', 'time', 'datetime', 'pathlib', 'typing', 'collections',
        'itertools', 'functools', 'operator', 'math', 'random', 'string', 'io',
        'csv', 'xml', 'html', 'urllib', 'http', 'email', 'base64', 'hashlib',
        'hmac', 'secrets', 'uuid', 'pickle', 'sqlite3', 'threading', 'asyncio',
        'concurrent', 'multiprocessing', 'subprocess', 'shutil', 'tempfile',
        'glob', 'fnmatch', 're', 'struct', 'array', 'heapq', 'bisect', 'weakref',
        'copy', 'pprint', 'reprlib', 'enum', 'dataclasses', 'contextlib',
        'abc', 'atexit', 'traceback', 'warnings', 'logging', 'getpass', 'argparse',
        'configparser', 'fileinput', 'linecache', 'shlex', 'platform', 'stat',
        'filecmp', 'tarfile', 'zipfile', 'gzip', 'bz2', 'lzma', 'zlib'
    }
    external_packages.update(stdlib_modules)

    return external_packages

# --------------------------
# Actual import testing
# --------------------------

def test_import_statement(import_record: 'ImportRecord', current_package_parts: List[str]) -> Tuple[bool, str]:
    """
    Actually test if an import statement works by executing it.
    Returns (success, error_message)
    """
    try:
        # Build the import statement to test
        if import_record.is_from:
            if import_record.level > 0:
                # Relative import - need to handle package context
                module_name = '.' * import_record.level
                if import_record.full_module:
                    module_name += import_record.full_module

                # For relative imports, we need to simulate being in the right package
                # This is tricky - we'll try to construct the absolute module name
                if import_record.level <= len(current_package_parts):
                    base_parts = current_package_parts[:-import_record.level] if import_record.level > 0 else current_package_parts
                    if import_record.full_module:
                        abs_module = '.'.join(base_parts + import_record.full_module.split('.'))
                    else:
                        abs_module = '.'.join(base_parts) if base_parts else None

                    if abs_module:
                        # Test absolute version of relative import
                        import_stmt = f"from {abs_module} import {import_record.subname}"
                    else:
                        return False, f"Cannot resolve relative import level {import_record.level}"
                else:
                    return False, f"Relative import level {import_record.level} exceeds package depth"
            else:
                # Absolute from import
                import_stmt = f"from {import_record.full_module} import {import_record.subname}"
        else:
            # Regular import
            import_stmt = f"import {import_record.full_module}"

        # Execute the import in a clean namespace
        test_globals = {}
        exec(import_stmt, test_globals)
        return True, ""

    except ImportError as e:
        return False, f"ImportError: {str(e)}"
    except ModuleNotFoundError as e:
        return False, f"ModuleNotFoundError: {str(e)}"
    except AttributeError as e:
        return False, f"AttributeError: {str(e)}"
    except SyntaxError as e:
        return False, f"SyntaxError: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {type(e).__name__}: {str(e)}"

def test_all_imports_in_file(imports: List['ImportRecord'], current_package_parts: List[str]) -> List[Dict]:
    """
    Test all imports in a file and return failed ones.
    """
    failed_imports = []

    for import_record in imports:
        # Skip star imports and imports in TYPE_CHECKING blocks for actual testing
        if import_record.is_star or import_record.in_type_checking:
            continue

        success, error_msg = test_import_statement(import_record, current_package_parts)

        if not success:
            failed_imports.append({
                "line": import_record.lineno,
                "import": (f"from {'.' * import_record.level}{import_record.full_module or ''} import {import_record.subname}"
                          if import_record.is_from else f"import {import_record.full_module}"),
                "bound_name": import_record.bound_name,
                "error": error_msg,
                "in_type_checking": import_record.in_type_checking
            })

    return failed_imports

# --------------------------
# Filesystem helpers
# --------------------------

def walk_files(root: Path, exclude_names_lower: Set[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in exclude_names_lower]
        for fn in filenames:
            if fn.endswith(".py"):
                yield Path(dirpath) / fn

def git_tracked_files(root: Path) -> List[Path]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "*.py"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        raw = proc.stdout
        items = [x for x in raw.split(b"\x00") if x]
        out = []
        for rel in items:
            p = (root / rel.decode("utf-8", errors="replace")).resolve()
            if p.is_file():
                out.append(p)
        return out
    except Exception as e:
        raise RuntimeError(f"Failed to enumerate Git-tracked files: {e}") from e

def detect_default_import_roots(root: Path) -> List[Path]:
    roots = [root]
    src = root / "src"
    if src.is_dir():
        roots.append(src)
    return roots

# --------------------------
# Package and module resolution
# --------------------------

def has_init(dir_path: Path) -> bool:
    return (dir_path / "__init__.py").exists()

def compute_package_parts(file_path: Path, import_roots: List[Path], allow_namespace: bool) -> List[str]:
    # Determine the package path (list of dirs from import root) for this file.
    # We choose the nearest import root that is an ancestor.
    best_root = None
    for r in import_roots:
        try:
            file_path.relative_to(r)
            if best_root is None or len(str(r)) > len(str(best_root)):
                best_root = r
        except ValueError:
            continue
    if best_root is None:
        return []  # unknown root
    rel = file_path.parent.relative_to(best_root)
    parts = [] if str(rel) == "." else list(rel.parts)

    if allow_namespace:
        return parts
    # Trim prefix until a valid package chain with __init__.py
    acc = []
    cur = best_root
    for part in parts:
        cur = cur / part
        if has_init(cur):
            acc.append(part)
        else:
            acc = []  # reset if chain breaks
    return acc

def module_path_exists(module_parts: List[str], import_roots: List[Path], allow_namespace: bool) -> bool:
    # A module exists if any import_root has file (.../parts.py) or package (.../parts/__init__.py)
    if not module_parts:
        return False
    for root in import_roots:
        mod_file = root.joinpath(*module_parts).with_suffix(".py")
        if mod_file.exists():
            return True
        pkg_dir = root.joinpath(*module_parts)
        if pkg_dir.is_dir():
            if allow_namespace:
                # Accept namespace package dir even if no __init__.py
                return True if any(pkg_dir.iterdir()) or (pkg_dir / "__init__.py").exists() else (pkg_dir / "__init__.py").exists()
            if has_init(pkg_dir):
                return True
    return False

def first_segment_exists(first: str, import_roots: List[Path], allow_namespace: bool) -> bool:
    for root in import_roots:
        if (root / (first + ".py")).exists():
            return True
        d = root / first
        if d.is_dir():
            if allow_namespace:
                return True if any(d.iterdir()) or (d / "__init__.py").exists() else (d / "__init__.py").exists()
            if has_init(d):
                return True
    return False

# --------------------------
# AST scanning for imports and usage
# --------------------------

class ImportRecord:
    def __init__(self, bound_name: str, full_module: Optional[str], is_from: bool,
                 subname: Optional[str], lineno: int, level: int, in_type_checking: bool):
        # bound_name: the identifier introduced in local scope
        # full_module: for import X.Y -> "X.Y"; for from A.B import C -> "A.B"; None for relative with only level and no module when computing base
        # is_from: True if ImportFrom
        # subname: for "from X import Y as Z" -> Y (original imported name), for Import (None)
        # level: relative import level (0 absolute)
        self.bound_name = bound_name
        self.full_module = full_module
        self.is_from = is_from
        self.subname = subname
        self.lineno = lineno
        self.level = level
        self.in_type_checking = in_type_checking
        self.is_star = (subname == "*")

def collect_imports_and_usage(source: str, filename: str) -> Tuple[List[ImportRecord], Set[str], Set[str]]:
    tree = ast.parse(source, filename=filename)
    imports: List[ImportRecord] = []
    used_names: Set[str] = set()
    exported_names: Set[str] = set()  # from __all__ = ["name", ...]

    TYPE_CHECKING_names = set()

    # Find if "from typing import TYPE_CHECKING" or "import typing" used to access TYPE_CHECKING
    class TypeCheckVisitor(ast.NodeVisitor):
        def visit_ImportFrom(self, node: ast.ImportFrom):
            if node.module == "typing":
                for a in node.names:
                    if a.name == "TYPE_CHECKING":
                        TYPE_CHECKING_names.add("TYPE_CHECKING")
        def visit_Import(self, node: ast.Import):
            for a in node.names:
                if a.name == "typing":
                    TYPE_CHECKING_names.add("typing")

    TypeCheckVisitor().visit(tree)

    def is_type_checking_if(test: ast.expr) -> bool:
        # Matches "if TYPE_CHECKING:" or "if typing.TYPE_CHECKING:"
        if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
            return "TYPE_CHECKING" in TYPE_CHECKING_names
        if isinstance(test, ast.Attribute) and isinstance(test.value, ast.Name):
            return test.value.id == "typing" and test.attr == "TYPE_CHECKING" and "typing" in TYPE_CHECKING_names
        return False

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.type_checking_stack: List[bool] = []

        def visit_If(self, node: ast.If):
            self.type_checking_stack.append(is_type_checking_if(node.test))
            self.generic_visit(node)
            self.type_checking_stack.pop()

        def current_in_tc(self) -> bool:
            return any(self.type_checking_stack)

        def visit_Import(self, node: ast.Import):
            in_tc = self.current_in_tc()
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                imports.append(ImportRecord(
                    bound_name=name,
                    full_module=alias.name,
                    is_from=False,
                    subname=None,
                    lineno=node.lineno,
                    level=0,
                    in_type_checking=in_tc
                ))

        def visit_ImportFrom(self, node: ast.ImportFrom):
            in_tc = self.current_in_tc()
            for alias in node.names:
                bound = alias.asname or alias.name
                imports.append(ImportRecord(
                    bound_name=bound,
                    full_module=node.module,
                    is_from=True,
                    subname=alias.name,
                    lineno=node.lineno,
                    level=node.level or 0,
                    in_type_checking=in_tc
                ))

        def visit_Name(self, node: ast.Name):
            if isinstance(node.ctx, (ast.Load, ast.AugLoad, ast.Del)):
                used_names.add(node.id)

        def visit_Assign(self, node: ast.Assign):
            # Capture __all__ = ["x", "y"] or tuple
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    values = []
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Str):
                                values.append(elt.s)
                    elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                        # Handle concatenation of lists of strings
                        def flatten(v):
                            if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
                                for e in v.elts:
                                    if isinstance(e, ast.Str):
                                        yield e.s
                            elif isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
                                yield from flatten(v.left)
                                yield from flatten(v.right)
                        values.extend(flatten(node.value))
                    exported_names.update(values)
            self.generic_visit(node)

    Visitor().visit(tree)
    return imports, used_names, exported_names

# --------------------------
# Core analysis
# --------------------------

def is_local_absolute_import(mod: str, import_roots: List[Path], allow_namespace: bool, ignore_roots: Set[str], external_packages: Set[str]) -> bool:
    # Decide if an absolute module should be treated as local: first segment must exist as a module/package under any import root.
    first = mod.split(".")[0]
    if first in ignore_roots or first.lower() in external_packages:
        return False
    return first_segment_exists(first, import_roots, allow_namespace)

def resolve_relative_base(module_parts: List[str], level: int, current_pkg_parts: List[str]) -> Optional[List[str]]:
    # For relative imports: ascend 'level' and then append module_parts (if any)
    if level <= 0:
        return module_parts
    if level > len(current_pkg_parts):
        return None
    base = current_pkg_parts[: len(current_pkg_parts) - level]
    return base + (module_parts or [])

def analyze_file(
    path: Path,
    import_roots: List[Path],
    allow_namespace: bool,
    ignore_local_roots: Set[str],
    ignore_unused_in_init: bool,
    external_packages: Set[str],
    test_imports: bool = False
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    imports, used_names, exported_names = collect_imports_and_usage(text, str(path))

    # Unused imports: skip those under TYPE_CHECKING blocks, star imports, and optionally __init__.py exports
    unused: List[Dict] = []
    for rec in imports:
        if rec.in_type_checking or rec.is_star:
            continue
        # __init__.py frequently re-exports
        if ignore_unused_in_init and path.name == "__init__.py":
            continue
        name_used = rec.bound_name in used_names or rec.bound_name in exported_names
        if not name_used:
            unused.append({
                "file": str(path),
                "line": rec.lineno,
                "name": rec.bound_name,
                "import": (f"from {'.' * rec.level}{rec.full_module} import {rec.subname}"
                           if rec.is_from else f"import {rec.full_module}"),
            })

    # Broken local imports:
    broken: List[Dict] = []

    # Determine current file's package parts for relative resolution
    pkg_parts = compute_package_parts(path, import_roots, allow_namespace)

    for rec in imports:
        # Only check "local" imports. Skip if under TYPE_CHECKING (often intentionally optional).
        if rec.in_type_checking:
            continue

        if rec.is_from:
            # Relative import or absolute "from X import Y"
            if rec.level and rec.level > 0:
                base_mod_parts = rec.full_module.split(".") if rec.full_module else []
                resolved = resolve_relative_base(base_mod_parts, rec.level, pkg_parts)
                if resolved is None:
                    broken.append({
                        "file": str(path),
                        "line": rec.lineno,
                        "import": f"from {'.'*rec.level}{rec.full_module or ''} import {rec.subname}",
                        "reason": f"Relative import escapes package (level={rec.level})"
                    })
                    continue
                # Check base module existence only; do not require submodule unless explicitly present in module path
                if not module_path_exists(resolved, import_roots, allow_namespace):
                    broken.append({
                        "file": str(path),
                        "line": rec.lineno,
                        "import": f"from {'.'*rec.level}{rec.full_module or ''} import {rec.subname}",
                        "reason": f"Base module not found: {'.'.join(resolved)}"
                    })
            else:
                # Absolute "from X.Y import Z" — treat as local only if first segment exists under project roots
                if not rec.full_module:
                    continue
                if not is_local_absolute_import(rec.full_module, import_roots, allow_namespace, ignore_local_roots, external_packages):
                    continue
                parts = rec.full_module.split(".")
                # Check that X.Y exists (base module). Do not require Z to be a submodule (it may be an attribute).
                if not module_path_exists(parts, import_roots, allow_namespace):
                    broken.append({
                        "file": str(path),
                        "line": rec.lineno,
                        "import": f"from {rec.full_module} import {rec.subname}",
                        "reason": f"Base module not found: {rec.full_module}"
                    })
        else:
            # "import X.Y[.Z]" — if local, require that the full module path exists
            if not rec.full_module:
                continue
            if not is_local_absolute_import(rec.full_module, import_roots, allow_namespace, ignore_local_roots, external_packages):
                continue
            parts = rec.full_module.split(".")
            if not module_path_exists(parts, import_roots, allow_namespace):
                broken.append({
                    "file": str(path),
                    "line": rec.lineno,
                    "import": f"import {rec.full_module}",
                    "reason": f"Module not found: {rec.full_module}"
                })

    # Test actual imports if requested
    import_test_failures = []
    if test_imports:
        import_test_failures = test_all_imports_in_file(imports, pkg_parts)
        # Add file path to each failure
        for failure in import_test_failures:
            failure["file"] = str(path)

    return broken, unused, import_test_failures

# --------------------------
# CLI
# --------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Scan Python files for non-existent LOCAL imports and unused imports."
    )
    p.add_argument("path", nargs="?", default=".", help="Root directory to scan (default: current dir)")
    p.add_argument("-x","--exclude-dir", action="append", default=[], help="Directory name to exclude (repeatable)")
    p.add_argument("--git-tracked", action="store_true", help="Only consider git-tracked files")
    p.add_argument("--allow-namespace", action="store_true", help="Treat directories without __init__.py as packages (PEP 420)")
    p.add_argument("--import-root", action="append", default=[], help="Additional import roots (repeatable). Defaults to root and ./src if present.")
    p.add_argument("--ignore-local-root", action="append", default=[], help="Ignore absolute imports starting with these names (treat as external)")
    p.add_argument("--ignore-unused-in-init", action="store_true", help="Do not flag unused imports in __init__.py")
    p.add_argument("--test-imports", action="store_true", help="Actually test imports by executing them")
    p.add_argument("--broken-csv", default=None, help="Write broken imports to CSV")
    p.add_argument("--unused-csv", default=None, help="Write unused imports to CSV")
    p.add_argument("--import-test-csv", default=None, help="Write import test failures to CSV")
    p.add_argument("-q","--quiet", action="store_true", help="Only print file paths with issues")
    p.add_argument("-f","--fail-on-issues", action="store_true", help="Exit code 2 if any issues found")

    args = p.parse_args()

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"Error: Path not found or not a directory: {root}", file=sys.stderr)
        return 1

    exclude_names_lower = {d.lower() for d in (set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []))}
    try:
        files = git_tracked_files(root) if args.git_tracked else list(walk_files(root, exclude_names_lower))
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Build import roots
    import_roots: List[Path] = []
    if args.import_root:
        for r in args.import_root:
            rp = (root / r).resolve() if not os.path.isabs(r) else Path(r)
            if rp.is_dir():
                import_roots.append(rp)
    else:
        import_roots = detect_default_import_roots(root)
    if root not in import_roots:
        import_roots.insert(0, root)

    ignore_local_roots = set(args.ignore_local_root or [])

    # Parse requirements.txt to get external packages
    requirements_path = root / "requirements.txt"
    external_packages = parse_requirements_txt(requirements_path)
    if not args.quiet:
        print(f"Found {len(external_packages)} external packages in requirements.txt")

    total_files = 0
    all_broken: List[Dict] = []
    all_unused: List[Dict] = []
    all_import_test_failures: List[Dict] = []

    for f in files:
        if any(part.lower() in exclude_names_lower for part in f.parts):
            continue
        try:
            broken, unused, import_test_failures = analyze_file(
                f, import_roots, args.allow_namespace, ignore_local_roots, args.ignore_unused_in_init, external_packages, args.test_imports
            )
            total_files += 1
            all_broken.extend(broken)
            all_unused.extend(unused)
            all_import_test_failures.extend(import_test_failures)
        except SyntaxError as se:
            # Skip files with syntax errors
            print(f"Warning: Skipping {f} due to syntax error at line {se.lineno}: {se.msg}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Skipping {f} due to error: {e}", file=sys.stderr)

    broken_count = len(all_broken)
    unused_count = len(all_unused)
    import_test_failures_count = len(all_import_test_failures)

    if args.broken_csv and all_broken:
        with open(args.broken_csv, "w", newline="", encoding="utf-8") as out:
            w = csv.DictWriter(out, fieldnames=["file","line","import","reason"])
            w.writeheader()
            w.writerows(sorted(all_broken, key=lambda r: (r["file"], r["line"])))
    if args.unused_csv and all_unused:
        with open(args.unused_csv, "w", newline="", encoding="utf-8") as out:
            w = csv.DictWriter(out, fieldnames=["file","line","name","import"])
            w.writeheader()
            w.writerows(sorted(all_unused, key=lambda r: (r["file"], r["line"])))
    if args.import_test_csv and all_import_test_failures:
        with open(args.import_test_csv, "w", newline="", encoding="utf-8") as out:
            w = csv.DictWriter(out, fieldnames=["file","line","import","bound_name","error","in_type_checking"])
            w.writeheader()
            w.writerows(sorted(all_import_test_failures, key=lambda r: (r["file"], r["line"])))

    if args.quiet:
        paths_with_issues = sorted(set([r["file"] for r in all_broken + all_unused + all_import_test_failures]))
        for pth in paths_with_issues:
            print(pth)
    else:
        print(f"Scanned files: {total_files}")
        print(f"Broken local imports: {broken_count}")
        print(f"Unused imports: {unused_count}")
        if args.test_imports:
            print(f"Import test failures: {import_test_failures_count}")
        print()

        if broken_count:
            print("Broken local imports:")
            for r in sorted(all_broken, key=lambda r: (r["file"], r["line"])):
                print(f"  {r['file']}:{r['line']}: {r['import']}  -> {r['reason']}")
            print()
        if unused_count:
            print("Unused imports:")
            for r in sorted(all_unused, key=lambda r: (r["file"], r["line"])):
                print(f"  {r['file']}:{r['line']}: {r['name']}  ({r['import']})")
            print()
        if import_test_failures_count:
            print("Import test failures:")
            for r in sorted(all_import_test_failures, key=lambda r: (r["file"], r["line"])):
                tc_marker = " [TYPE_CHECKING]" if r.get("in_type_checking", False) else ""
                print(f"  {r['file']}:{r['line']}: {r['import']}  -> {r['error']}{tc_marker}")
            print()

        if args.broken_csv:
            print(f"Broken CSV: {args.broken_csv}")
        if args.unused_csv:
            print(f"Unused CSV: {args.unused_csv}")
        if args.import_test_csv:
            print(f"Import test CSV: {args.import_test_csv}")

    if args.fail_on_issues and (broken_count or unused_count or import_test_failures_count):
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())