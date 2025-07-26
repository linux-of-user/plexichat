#!/usr/bin/env python3
"""
CLI Launcher for PlexiChat

Simple launcher that integrates the enhanced CLI with run.py:
- Provides seamless integration between run.py and enhanced CLI
- Handles all CLI routing and command execution
- Supports both direct CLI usage and run.py integration
- Maintains compatibility with existing CLI commands
"""

import sys
import asyncio
from pathlib import Path

def main():
    """Main CLI launcher entry point."""
    try:
        # Add src to path for imports
        src_path = str(Path(__file__).parent / "src")
        if src_path not in sys.path:
            sys.path.insert(0, src_path)
        
        # Import standalone enhanced CLI
        from standalone_enhanced_cli import standalone_cli as enhanced_cli
        
        # Determine if called from run.py or directly
        if len(sys.argv) >= 2 and sys.argv[1] == "cli":
            # Called from run.py: python run.py cli <command> [args]
            if len(sys.argv) <= 2:
                enhanced_cli.show_help()
                return
            
            command = sys.argv[2] if len(sys.argv) > 2 else "help"
            args = sys.argv[3:] if len(sys.argv) > 3 else []
        else:
            # Called directly: python cli_launcher.py <command> [args]
            if len(sys.argv) <= 1:
                enhanced_cli.show_help()
                return
            
            command = sys.argv[1] if len(sys.argv) > 1 else "help"
            args = sys.argv[2:] if len(sys.argv) > 2 else []
        
        # Execute the command
        success = asyncio.run(enhanced_cli.execute_command(command, args))
        sys.exit(0 if success else 1)
        
    except ImportError as e:
        print(f"Enhanced CLI not available: {e}")
        print("Falling back to basic CLI functionality...")
        
        # Basic fallback functionality
        if len(sys.argv) > 1:
            command = sys.argv[1]
            if command == "help":
                print("PlexiChat CLI - Basic Mode")
                print("Enhanced CLI not available")
                print("Available commands: help, version")
            elif command == "version":
                print("PlexiChat CLI v1.0.0")
            else:
                print(f"Unknown command: {command}")
        else:
            print("PlexiChat CLI - Basic Mode")
            print("Usage: python cli_launcher.py <command>")
        
        sys.exit(1)
        
    except Exception as e:
        print(f"CLI error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
