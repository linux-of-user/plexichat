import os
import subprocess

def main():
    for root, _, files in os.walk('.'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    subprocess.run(['python', '-m', 'py_compile', filepath], check=True)
                    print(f"Successfully compiled {filepath}")
                except subprocess.CalledProcessError as e:
                    print(f"Failed to compile {filepath}: {e}")

if __name__ == "__main__":
    main()
