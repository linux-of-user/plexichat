#!/usr/bin/env python3
"""
Enhanced Chat API v2.0.0 - Clean Shutdown Script
Safely shutdown all running components.
"""

import sys
import os
import time
import signal
import subprocess
import psutil
from pathlib import Path

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
    print(f"{color}{text}{Colors.END}")

def print_success(text: str):
    """Print success message."""
    print_colored(f"✅ {text}", Colors.GREEN)

def print_error(text: str):
    """Print error message."""
    print_colored(f"❌ {text}", Colors.RED)

def print_warning(text: str):
    """Print warning message."""
    print_colored(f"⚠️  {text}", Colors.YELLOW)

def print_info(text: str):
    """Print info message."""
    print_colored(f"ℹ️  {text}", Colors.BLUE)

def print_header(text: str):
    """Print section header."""
    print_colored(f"\n{'='*50}", Colors.CYAN)
    print_colored(f"{text.center(50)}", Colors.BOLD + Colors.CYAN)
    print_colored(f"{'='*50}", Colors.CYAN)

class CleanShutdown:
    """Clean shutdown manager for Enhanced Chat API."""
    
    def __init__(self):
        self.processes_found = []
        self.ports_to_check = [8000, 8001, 8080, 3000]  # Common ports
        
    def find_api_processes(self):
        """Find all Enhanced Chat API related processes."""
        print_info("Scanning for Enhanced Chat API processes...")
        
        processes = []
        
        # Look for processes by name patterns
        name_patterns = [
            'uvicorn',
            'python.*run.py',
            'python.*enhanced_launch.py',
            'python.*cli.py',
            'python.*app.main',
            'chatapi',
            'enhanced-chat-api'
        ]
        
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
                
        except psutil.NoSuchProcess:
            print_info(f"Process {pid} no longer exists")
            return True
        except psutil.AccessDenied:
            print_error(f"Access denied to process {pid}")
            return False
        except Exception as e:
            print_error(f"Error shutting down process {pid}: {e}")
            return False
    
    def shutdown_all(self, force=False):
        """Shutdown all found processes."""
        if not self.processes_found:
            print_info("No processes to shutdown")
            return True
        
        print_info(f"Shutting down {len(self.processes_found)} processes...")
        
        success_count = 0
        timeout = 5 if force else 10
        
        for proc_info in self.processes_found:
            if self.shutdown_process(proc_info, timeout):
                success_count += 1
        
        if success_count == len(self.processes_found):
            print_success("All processes shutdown successfully")
            return True
        else:
            print_warning(f"Shutdown {success_count}/{len(self.processes_found)} processes")
            return False
    
    def check_ports(self):
        """Check if ports are still in use."""
        print_info("Checking if ports are free...")
        
        ports_in_use = []
        
        for port in self.ports_to_check:
            try:
                for conn in psutil.net_connections():
                    if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                        ports_in_use.append(port)
                        break
            except Exception:
                continue
        
        if ports_in_use:
            print_warning(f"Ports still in use: {', '.join(map(str, ports_in_use))}")
            return False
        else:
            print_success("All ports are free")
            return True
    
    def cleanup_resources(self):
        """Clean up any remaining resources."""
        print_info("Cleaning up resources...")
        
        # Clean up PID files if they exist
        pid_files = [
            'chatapi.pid',
            'uvicorn.pid',
            'server.pid'
        ]
        
        for pid_file in pid_files:
            if Path(pid_file).exists():
                try:
                    Path(pid_file).unlink()
                    print_info(f"Removed PID file: {pid_file}")
                except Exception as e:
                    print_warning(f"Failed to remove {pid_file}: {e}")
        
        # Clean up temporary files
        temp_patterns = [
            '*.tmp',
            '.uvicorn-*',
            '__pycache__/*'
        ]
        
        import glob
        for pattern in temp_patterns:
            for file_path in glob.glob(pattern, recursive=True):
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        import shutil
                        shutil.rmtree(file_path)
                except Exception:
                    pass
        
        print_success("Resource cleanup complete")
    
    def run(self, force=False, interactive=True):
        """Run the shutdown process."""
        print_header("ENHANCED CHAT API - CLEAN SHUTDOWN")
        
        # Find processes
        processes = self.find_api_processes()
        
        if not processes:
            print_success("No Enhanced Chat API processes found")
            self.check_ports()
            return True
        
        # Display processes
        self.display_processes()
        
        # Ask for confirmation if interactive
        if interactive and not force:
            print()
            response = input("Shutdown all processes? [Y/n]: ").strip().lower()
            if response and response not in ['y', 'yes']:
                print_info("Shutdown cancelled")
                return False
        
        # Shutdown processes
        success = self.shutdown_all(force)
        
        # Check ports
        time.sleep(1)
        self.check_ports()
        
        # Cleanup
        self.cleanup_resources()
        
        if success:
            print_success("Clean shutdown completed successfully")
        else:
            print_warning("Shutdown completed with some issues")
        
        return success

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Chat API v2.0.0 - Clean Shutdown Script"
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force shutdown without confirmation'
    )
    
    parser.add_argument(
        '--list',
        action='store_true',
        help='List processes without shutting down'
    )
    
    parser.add_argument(
        '--check-ports',
        action='store_true',
        help='Check port status only'
    )
    
    args = parser.parse_args()
    
    shutdown_manager = CleanShutdown()
    
    if args.list:
        print_header("ENHANCED CHAT API - PROCESS LIST")
        shutdown_manager.find_api_processes()
        shutdown_manager.display_processes()
        return 0
    
    if args.check_ports:
        print_header("ENHANCED CHAT API - PORT CHECK")
        shutdown_manager.check_ports()
        return 0
    
    # Run shutdown
    success = shutdown_manager.run(force=args.force, interactive=not args.force)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
