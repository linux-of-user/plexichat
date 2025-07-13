import logging
import signal
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(text: str, color: str = Colors.WHITE):
    """Print colored text."""
    logger.info(f"{color}{text}{Colors.END}")

def print_success(text: str):
    """Print success message."""
    print_colored(f" {text}", Colors.GREEN)

def print_error(text: str):
    """Print error message."""
    print_colored(f" {text}", Colors.RED)

def print_warning(text: str):
    """Print warning message."""
    print_colored(f"  {text}", Colors.YELLOW)

def print_info(text: str):
    """Print info message."""
    print_colored(f"  {text}", Colors.BLUE)

def print_header(text: str):
    """Print section header."""
    print_colored(f"\n{'='*50}", Colors.CYAN)
    print_colored(f"{text.center(50)}", Colors.BOLD + Colors.CYAN)
    print_colored(f"{'='*50}", Colors.CYAN)

class CleanShutdown:
    """Clean shutdown manager for PlexiChat."""

    def __init__(self):
        self.processes_found = []
        self.ports_to_check = [8000, 8001, 8080, 3000]  # Common ports

    def find_api_processes(self):
        """Find all PlexiChat related processes."""
        print_info("Scanning for PlexiChat processes...")

        if not PSUTIL_AVAILABLE:
            print_warning("psutil not available - process scanning disabled")
            return []

        processes = []

        # Look for processes by name patterns
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])

                # Check if this is our process
                if any(pattern in cmdline.lower() for pattern in [
                    'app.main:app',
                    'enhanced_launch.py',
                    'run.py',
                    'chatapi'
                ]):
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': cmdline,
                        'process': proc
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Also check processes using our ports
        for port in self.ports_to_check:
            try:
                for conn in psutil.net_connections():
                    if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = ' '.join(proc.cmdline())

                            # Add if not already found
                            if not any(p['pid'] == conn.pid for p in processes):
                                processes.append({
                                    'pid': conn.pid,
                                    'name': proc.name(),
                                    'cmdline': cmdline,
                                    'process': proc,
                                    'port': port
                                })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception:
                continue

        self.processes_found = processes
        return processes

    def display_processes(self):
        """Display found processes."""
        if not self.processes_found:
            print_info("No Enhanced Chat API processes found")
            return

        print_info(f"Found {len(self.processes_found)} Enhanced Chat API processes:")

        for i, proc_info in enumerate(self.processes_found, 1):
            port_info = f" (Port: {proc_info['port']})" if 'port' in proc_info else ""
            print_colored(f"  {i}. PID {proc_info['pid']}: {proc_info['name']}{port_info}", Colors.YELLOW)
            print_colored(f"     Command: {proc_info['cmdline'][:80]}...", Colors.WHITE)

    def shutdown_process(self, proc_info, timeout=10):
        """Shutdown a single process gracefully."""
        pid = proc_info['pid']
        name = proc_info['name']

        try:
            process = proc_info['process']

            print_info(f"Shutting down {name} (PID: {pid})...")

            # Try graceful shutdown first
            if process.is_running():
                process.terminate()

                # Wait for graceful shutdown
                try:
                    process.wait(timeout=timeout)
                    print_success(f"Process {pid} terminated gracefully")
                    return True
                except psutil.TimeoutExpired:
                    print_warning(f"Process {pid} didn't respond to SIGTERM, force killing...")

                    # Force kill
                    try:
                        process.kill()
                        process.wait(timeout=5)
                        print_success(f"Process {pid} force killed")
                        return True
                    except psutil.TimeoutExpired:
                        print_error(f"Failed to kill process {pid}")
                        return False
            else:
                print_info(f"Process {pid} already terminated")
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print_error(f"Error accessing process {pid}: {e}")
            return False

    def shutdown_all(self, force=False):
        """Shutdown all found processes."""
        if not self.processes_found:
            print_info("No processes to shutdown")
            return True

        print_header("SHUTTING DOWN PROCESSES")

        success_count = 0
        total_count = len(self.processes_found)

        for proc_info in self.processes_found:
            if self.shutdown_process(proc_info, timeout=5 if force else 10):
                success_count += 1

        print_header("SHUTDOWN SUMMARY")
        print_success(f"Successfully shut down {success_count}/{total_count} processes")

        return success_count == total_count

    def check_ports(self):
        """Check if any ports are still in use."""
        if not PSUTIL_AVAILABLE:
            return []

        print_info("Checking for ports still in use...")
        ports_in_use = []

        for port in self.ports_to_check:
            try:
                for conn in psutil.net_connections():
                    if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                        ports_in_use.append(port)
                        print_warning(f"Port {port} still in use")
                        break
            except Exception:
                continue

        if not ports_in_use:
            print_success("All ports are free")

        return ports_in_use

    def cleanup_resources(self):
        """Clean up temporary files and resources."""
        print_header("CLEANING UP RESOURCES")

        # Clean up log files
        log_dir = Path("logs")
        if log_dir.exists():
            try:
                # Remove old log files (older than 7 days)
                import time
                current_time = time.time()
                for log_file in log_dir.glob("*.log"):
                    if current_time - log_file.stat().st_mtime > 7 * 24 * 3600:
                        log_file.unlink()
                        print_info(f"Removed old log file: {log_file.name}")
            except Exception as e:
                print_warning(f"Error cleaning log files: {e}")

        # Clean up temporary files
        temp_patterns = ["*.tmp", "*.temp", "*.cache"]
        for pattern in temp_patterns:
            for temp_file in Path(".").glob(pattern):
                try:
                    temp_file.unlink()
                    print_info(f"Removed temporary file: {temp_file.name}")
                except Exception:
                    pass

        print_success("Resource cleanup completed")

    def run(self, force=False, interactive=True):
        """Run the complete shutdown process."""
        print_header("PLEXICHAT CLEAN SHUTDOWN")
        print_info("Starting clean shutdown process...")

        # Find processes
        self.find_api_processes()
        self.display_processes()

        if not self.processes_found:
            print_info("No processes found to shutdown")
            self.cleanup_resources()
            return True

        # Ask for confirmation if interactive
        if interactive and not force:
            response = input("\nProceed with shutdown? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print_info("Shutdown cancelled")
                return False

        # Shutdown processes
        success = self.shutdown_all(force=force)

        # Wait a moment for processes to fully terminate
        time.sleep(2)

        # Check ports
        self.check_ports()

        # Cleanup resources
        self.cleanup_resources()

        print_header("SHUTDOWN COMPLETE")
        if success:
            print_success("All processes shut down successfully")
        else:
            print_warning("Some processes may still be running")

        return success

def main():
    """Main entry point for the shutdown script."""
    import argparse

    parser = argparse.ArgumentParser(description="Clean shutdown for PlexiChat")
    parser.add_argument("--force", action="store_true", help="Force kill processes")
    parser.add_argument("--non-interactive", action="store_true", help="Run without user interaction")

    args = parser.parse_args()

    shutdown_manager = CleanShutdown()
    return shutdown_manager.run(force=args.force, interactive=not args.non_interactive)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
