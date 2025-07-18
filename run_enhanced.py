#!/usr/bin/env python3
"""
PlexiChat Enhanced Run Script

Enhanced runner with comprehensive testing and CLI integration.
This script provides:
- Server startup with proper initialization
- CLI interface for running tests
- Interactive mode for development
- Graceful shutdown handling
"""

import argparse
import asyncio
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from plexichat.interfaces.cli.test_commands import handle_test_command
    from plexichat.core.logging.unified_logging_manager import get_logger
except ImportError as e:
    print(f"Failed to import PlexiChat modules: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


class PlexiChatRunner:
    """PlexiChat server runner with CLI interface."""
    
    def __init__(self, host: str = "localhost", port: int = 8001, debug: bool = False):
        self.host = host
        self.port = port
        self.debug = debug
        self.server_process: Optional[subprocess.Popen] = None
        self.server_ready = threading.Event()
        self.shutdown_event = threading.Event()
        self.logger = None
        
    def start_server(self) -> bool:
        """Start the PlexiChat server."""
        print(f"🚀 Starting PlexiChat server on {self.host}:{self.port}")
        
        # Build command
        cmd = [
            sys.executable, "-m", "plexichat",
            "--host", self.host,
            "--port", str(self.port)
        ]
        
        if self.debug:
            cmd.append("--debug")
        
        try:
            # Start server process
            self.server_process = subprocess.Popen(
                cmd,
                cwd=Path(__file__).parent / "src",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor server output in a separate thread
            monitor_thread = threading.Thread(
                target=self._monitor_server_output,
                daemon=True
            )
            monitor_thread.start()
            
            # Wait for server to be ready
            if self.server_ready.wait(timeout=60):
                print("✅ PlexiChat server is ready!")
                return True
            else:
                print("❌ Server startup timed out")
                self.stop_server()
                return False
                
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
    
    def _monitor_server_output(self):
        """Monitor server output and detect when it's ready."""
        if not self.server_process:
            return
        
        try:
            for line in iter(self.server_process.stdout.readline, ''):
                if not line:
                    break
                
                # Print server output
                print(f"[SERVER] {line.rstrip()}")
                
                # Check if server is ready
                if "Application startup complete" in line or "Uvicorn running on" in line:
                    self.server_ready.set()
                
                # Check for shutdown
                if self.shutdown_event.is_set():
                    break
                    
        except Exception as e:
            print(f"Error monitoring server output: {e}")
    
    def stop_server(self):
        """Stop the PlexiChat server."""
        if self.server_process:
            print("🛑 Stopping PlexiChat server...")
            self.shutdown_event.set()
            
            try:
                # Try graceful shutdown first
                self.server_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.server_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    print("⚠️  Forcing server shutdown...")
                    self.server_process.kill()
                    self.server_process.wait()
                
                print("✅ Server stopped")
                
            except Exception as e:
                print(f"Error stopping server: {e}")
            
            self.server_process = None
    
    def is_server_running(self) -> bool:
        """Check if the server is running."""
        return (
            self.server_process is not None and 
            self.server_process.poll() is None and
            self.server_ready.is_set()
        )
    
    async def run_tests(self, test_command: str, args: List[str] = None) -> int:
        """Run tests using the CLI test system."""
        if not self.is_server_running():
            print("❌ Server is not running. Start the server first.")
            return 1
        
        base_url = f"http://{self.host}:{self.port}"
        return await handle_test_command(test_command, args)
    
    def run_interactive_cli(self):
        """Run interactive CLI for testing and management."""
        print("\n" + "=" * 60)
        print("🎮 PlexiChat Interactive CLI")
        print("=" * 60)
        print("Available commands:")
        print("  test all                    - Run all tests")
        print("  test quick                  - Run quick tests")
        print("  test category <name>        - Run category tests")
        print("  test endpoint <method> <path> - Test specific endpoint")
        print("  test help                   - Show test help")
        print("  status                      - Show server status")
        print("  logs                        - Show recent logs")
        print("  quit / exit                 - Exit CLI")
        print("=" * 60)
        
        while True:
            try:
                command = input("\nplexichat> ").strip()
                
                if not command:
                    continue
                
                if command.lower() in ["quit", "exit", "q"]:
                    break
                
                # Handle commands
                if command == "status":
                    self._show_status()
                elif command == "logs":
                    self._show_logs()
                elif command.startswith("test "):
                    self._handle_test_command(command)
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'test help' for test commands or 'quit' to exit")
                    
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except EOFError:
                break
    
    def _show_status(self):
        """Show server status."""
        if self.is_server_running():
            print(f"✅ Server is running on {self.host}:{self.port}")
            print(f"🔗 URL: http://{self.host}:{self.port}")
            print(f"📚 API Docs: http://{self.host}:{self.port}/docs")
        else:
            print("❌ Server is not running")
    
    def _show_logs(self):
        """Show recent logs."""
        log_file = Path("logs/plexichat.log")
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    # Show last 20 lines
                    recent_lines = lines[-20:] if len(lines) > 20 else lines
                    print("\n📄 Recent logs:")
                    for line in recent_lines:
                        print(f"  {line.rstrip()}")
            except Exception as e:
                print(f"Error reading logs: {e}")
        else:
            print("No log file found")
    
    def _handle_test_command(self, command: str):
        """Handle test commands in the CLI."""
        parts = command.split()[1:]  # Remove 'test' prefix
        
        if not parts:
            print("Please specify a test command. Type 'test help' for options.")
            return
        
        test_command = parts[0]
        test_args = parts[1:] if len(parts) > 1 else []
        
        # Run the test command
        try:
            result = asyncio.run(self.run_tests(test_command, test_args))
            if result == 0:
                print("✅ Test command completed successfully")
            else:
                print("❌ Test command failed")
        except Exception as e:
            print(f"Error running test command: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PlexiChat Enhanced Runner - Start server and run tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_enhanced.py                           # Start server and enter CLI
  python run_enhanced.py --test all                # Start server and run all tests
  python run_enhanced.py --test quick              # Start server and run quick tests
  python run_enhanced.py --no-cli                  # Start server without CLI
  python run_enhanced.py --port 8080 --debug      # Start on port 8080 in debug mode
        """
    )
    
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host to bind to (default: localhost)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port to bind to (default: 8001)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    parser.add_argument(
        "--test",
        help="Run specific test after startup (e.g., 'all', 'quick', 'category security')"
    )
    
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Don't start interactive CLI"
    )
    
    args = parser.parse_args()
    
    # Create runner
    runner = PlexiChatRunner(args.host, args.port, args.debug)
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        print("\n🛑 Received shutdown signal...")
        runner.stop_server()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start server
        if not runner.start_server():
            print("❌ Failed to start server")
            return 1
        
        # Run specific test if requested
        if args.test:
            test_parts = args.test.split()
            test_command = test_parts[0]
            test_args = test_parts[1:] if len(test_parts) > 1 else []
            
            print(f"\n🧪 Running test: {args.test}")
            result = asyncio.run(runner.run_tests(test_command, test_args))
            
            if not args.no_cli:
                print("\nTest completed. Starting interactive CLI...")
                runner.run_interactive_cli()
            
            return result
        
        # Start interactive CLI if not disabled
        if not args.no_cli:
            runner.run_interactive_cli()
        else:
            print("Server running. Press Ctrl+C to stop.")
            # Keep the main thread alive
            try:
                while runner.is_server_running():
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        
        return 0
        
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    finally:
        runner.stop_server()


if __name__ == "__main__":
    sys.exit(main())
