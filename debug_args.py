#!/usr/bin/env python3
"""
Debug script to test argument parsing
"""

import argparse
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_argument_parsing():
    """Test the argument parsing logic from run.py"""
    
    # Create the main parser
    parser = argparse.ArgumentParser(
        description="PlexiChat Server - Test Argument Parsing",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Setup Python environment and dependencies')
    setup_parser.add_argument('--level', choices=['minimal', 'full', 'developer', 'testing'],
                             default='full', help='Installation level')
    setup_parser.add_argument('--force', action='store_true',
                             help='Force reinstall all packages')
    setup_parser.add_argument('--clean', action='store_true',
                             help='Clean install (remove existing venv)')
    setup_parser.add_argument('--test-deps', action='store_true',
                             help='Install testing dependencies')
    setup_parser.add_argument('--no-venv', action='store_true',
                             help='Skip virtual environment creation')
    
    # Clean command
    clean_parser = subparsers.add_parser('clean', help='Clean caches and temporary files')
    clean_parser.add_argument('--all', action='store_true', help='Clean everything including virtual environment')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run tests')
    test_parser.add_argument('--type', choices=['basic', 'unit', 'integration', 'security', 'protection', 'performance', 'simple', 'all'],
                           default='basic', help='Type of tests to run')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    
    # Server arguments (for default command)
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="PlexiChat Test")
    
    print("Argument parsing setup completed successfully!")
    
    # Test parsing some arguments
    test_args = ['test', '--type', 'basic']
    try:
        args = parser.parse_args(test_args)
        print(f"Successfully parsed args: {args}")
        return True
    except Exception as e:
        print(f"Error parsing arguments: {e}")
        return False

if __name__ == "__main__":
    success = test_argument_parsing()
    sys.exit(0 if success else 1)
