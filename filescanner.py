#!/usr/bin/env python3
import argparse
import csv
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, List, Set, Tuple, Dict


DEFAULT_TOKENS = [
    'fixed','enhanced','working','clean','temp','tmp','draft','wip','backup','bak',
    'copy','copy of','final','old','new','try','junk','scratch','zzz','hold',
    'obsolete','legacy','deprecated','sample','example','refactor','redo','done',
    'latest','cleaned','ok','good','better','proto','alt','rewrite',
    # version-ish patterns (regex)
    'v\\d+','ver\\d+','final\\d+','final_final','reallyfinal','finalfinal'
]

DEFAULT_EXCLUDE_DIRS = {
    '.git','venv','.venv','node_modules','dist','build','__pycache__',
    '.mypy_cache','.pytest_cache','.tox','.coverage'
}


def build_name_regex(tokens: Iterable[str]) -> re.Pattern:
    parts = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        # If token includes a backslash-digit pattern already, treat it as regex; else escape
        if any(ch.isdigit() for ch in t) and '\\d' in t:
            parts.append(t)
        else:
            parts.append(re.escape(t))
    if not parts:
        # Fallback that never matches
        return re.compile(r'(?!x)x')
    # Match tokens at start/end or separated by typical delimiters
    pattern = r'(?i)(?:^|[-_.\s()])(' + '|'.join(parts) + r')(?:$|[-_.\s()])'
    return re.compile(pattern)


def normalize_exts(exts: Iterable[str]) -> Set[str]:
    out = set()
    for e in exts:
        e = e.strip()
        if not e:
            continue
        if not e.startswith('.'):
            e = '.' + e
        out.add(e.lower())
    return out


def path_has_excluded_component(p: Path, exclude_names_lower: Set[str]) -> bool:
    for part in p.parts:
        if part.lower() in exclude_names_lower:
            return True
    return False


def walk_files(root: Path, exclude_names_lower: Set[str]) -> Iterable[Path]:
    # Efficiently skip excluded dirs during traversal
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if d.lower() not in exclude_names_lower]
        for fn in filenames:
            yield Path(dirpath) / fn


def git_tracked_files(root: Path) -> List[Path]:
    import subprocess
    try:
        # Use NUL-terminated entries to be robust with spaces/newlines
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        raw = proc.stdout
        items = [x for x in raw.split(b"\x00") if x]
        out = []
        for rel in items:
            # Git outputs POSIX-style separators; Path handles this
            p = (root / rel.decode("utf-8", errors="replace")).resolve()
            if p.is_file():
                out.append(p)
        return out
    except Exception as e:
        raise RuntimeError(f"Failed to enumerate Git-tracked files: {e}") from e


def scan(
    root: Path,
    name_regex: re.Pattern,
    exts: Set[str],
    exclude_names_lower: Set[str],
    use_git_tracked: bool
) -> Tuple[List[Dict[str, str]], int]:
    if use_git_tracked:
        files = git_tracked_files(root)
        # Apply exclude filter even on tracked list
        files = [p for p in files if not path_has_excluded_component(p.relative_to(root), exclude_names_lower)]
    else:
        files = list(walk_files(root, exclude_names_lower))

    # Filter by extensions if provided
    if exts:
        files = [p for p in files if p.suffix.lower() in exts]

    findings: List[Dict[str, str]] = []
    for p in files:
        name = p.name
        stem = p.stem  # base name without final suffix
        matches = list(name_regex.finditer(stem))
        if not matches:
            continue
        tokens = {m.group(1).lower() for m in matches}
        for tk in sorted(tokens):
            findings.append({
                "Path": str(p),
                "Name": name,
                "Extension": p.suffix,
                "Token": tk
            })

    return findings, len(files)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recursively find 'silly' filenames like *_fixed.py, -final, (copy), v2, etc."
    )
    parser.add_argument("path", nargs="?", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument("-e", "--ext", action="append", default=[], help="File extension to include (e.g., .py or py). Repeatable.")
    parser.add_argument("-x", "--exclude-dir", action="append", default=[], help="Directory name to exclude. Repeatable.")
    parser.add_argument("-t", "--extra-token", action="append", default=[], help="Additional token/pattern to match. Repeatable.")
    parser.add_argument("--git-tracked", action="store_true", help="Only consider Git-tracked files (respects .gitignore).")
    parser.add_argument("-o", "--output-csv", default=None, help="Write results to CSV (Path,Name,Extension,Token).")
    parser.add_argument("-f", "--fail-on-find", action="store_true", help="Exit with code 2 if any matches are found.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Print only matching paths (one per line).")

    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"Error: Path not found or not a directory: {root}", file=sys.stderr)
        return 1

    exts = normalize_exts(args.ext)
    exclude_names_lower = {d.lower() for d in (set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []))}
    tokens = list(dict.fromkeys(DEFAULT_TOKENS + (args.extra_token or [])))  # preserve order, unique
    name_regex = build_name_regex(tokens)

    try:
        findings, total_scanned = scan(
            root=root,
            name_regex=name_regex,
            exts=exts,
            exclude_names_lower=exclude_names_lower,
            use_git_tracked=args.git_tracked
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not findings:
        if not args.quiet:
            print("No filenames matched the silly-name patterns.")
        return 0

    # Optionally write CSV
    if args.output_csv:
        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Path","Name","Extension","Token"])
            writer.writeheader()
            writer.writerows(sorted(findings, key=lambda r: (r["Token"], r["Name"])))
        if not args.quiet:
            print(f"CSV written: {args.output_csv}")

    paths_sorted = sorted({row["Path"] for row in findings})
    tokens_counter = Counter(row["Token"] for row in findings)
    files_by_token: Dict[str, List[str]] = defaultdict(list)
    for row in findings:
        files_by_token[row["Token"]].append(row["Path"])
    for tk in files_by_token:
        files_by_token[tk] = sorted(set(files_by_token[tk]))

    if args.quiet:
        for p in paths_sorted:
            print(p)
    else:
        print(f"Scanned files: {total_scanned}")
        print(f"Matched files: {len(paths_sorted)}")
        print(f"Tokens found:  {len(tokens_counter)}\n")

        print("Tokens by count:")
        for tk, cnt in tokens_counter.most_common():
            print(f"  {tk}: {cnt}")
        print()

        print("Files by token:")
        for tk in sorted(files_by_token):
            print(f"[{tk}]")
            for p in files_by_token[tk]:
                print(f"  {p}")
            print()

    if args.fail_on_find:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())