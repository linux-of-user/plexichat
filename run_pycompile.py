import os
import py_compile
import sys

def main():
    """
    Recursively finds all .py files in the current directory and its subdirectories
    and tries to compile them.
    Reports any files that fail to compile.
    """
    repo_root = '.'
    failed_files = []

    for root, _, files in os.walk(repo_root):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    # The 'doraise=True' argument makes it raise an exception on failure
                    py_compile.compile(filepath, doraise=True)
                    print(f"Successfully compiled: {filepath}")
                except py_compile.PyCompileError as e:
                    print(f"ERROR: Failed to compile {filepath}", file=sys.stderr)
                    print(f"       {e}", file=sys.stderr)
                    failed_files.append(filepath)
                except Exception as e:
                    print(f"An unexpected error occurred with {filepath}: {e}", file=sys.stderr)
                    failed_files.append(filepath)

    if failed_files:
        print("\nCompilation failed for the following files:", file=sys.stderr)
        for f in failed_files:
            print(f"- {f}", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nAll Python files compiled successfully!")

if __name__ == "__main__":
    main()
