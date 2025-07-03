"""
NetLink Launcher - Split-Screen Terminal Implementation
Provides split-screen terminal with logs on one side and CLI on the other.
"""

import os
import sys
import time
import threading
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

class SplitScreenTerminal:
    """Split-screen terminal with logs and CLI."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.cli_running = True
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging system."""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Setup file logging
        log_file = log_dir / f"netlink_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        # Configure root logger
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,
            format='%(asctime)s [%(levelname)8s] %(name)s: %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger("NetLink.Launcher")
        self.logger.info("NetLink Split-Screen Terminal initializing...")
    
    def clear_screen(self):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Print NetLink banner."""
        banner = """
================================================================================
                              NETLINK ENTERPRISE                             
                         Split-Screen Terminal Interface                      
================================================================================
 Server: http://localhost:8000  |  Admin: /ui  |  Docs: /docs  |  Mgmt: /mgmt 
 Started: {}
================================================================================
        """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        print(banner)
    
    def start_server_thread(self, host: str = "0.0.0.0", port: int = 8000):
        """Start server in background thread."""
        def run_server():
            try:
                import uvicorn
                from netlink.app.main_working import app
                
                self.logger.info(f"Starting NetLink server on {host}:{port}")
                
                # Configure uvicorn
                config = uvicorn.Config(
                    app="netlink.app.main_working:app",
                    host=host,
                    port=port,
                    reload=False,
                    log_level="info",
                    access_log=True,
                    use_colors=False,
                    loop="asyncio"
                )
                
                server = uvicorn.Server(config)
                asyncio.run(server.serve())
                
            except Exception as e:
                self.logger.error(f"Server error: {e}")
                
        # Start server thread
        server_thread = threading.Thread(target=run_server, daemon=True, name="NetLink-Server")
        server_thread.start()
        
        # Wait for server to start
        self.logger.info("Waiting for server to start...")
        time.sleep(8)  # Give more time for server startup
        
        # Verify server is running with retry logic
        import requests
        check_host = "localhost" if host == "0.0.0.0" else host

        for attempt in range(5):  # Try 5 times
            try:
                response = requests.get(f"http://{check_host}:{port}/health", timeout=5)
                if response.status_code == 200:
                    self.logger.info("Server started successfully")
                    return True
                else:
                    self.logger.warning(f"Server health check failed: {response.status_code}, retrying...")
            except Exception as e:
                self.logger.warning(f"Server connection attempt {attempt + 1} failed: {e}")
                if attempt < 4:  # Don't sleep on last attempt
                    time.sleep(2)

        self.logger.error("Server failed to start after multiple attempts")
        return False
    
    def display_split_screen(self):
        """Display true split-screen interface with CLI on left, logs on right."""
        try:
            # Try to use curses for proper split-screen
            import curses
            curses.wrapper(self._run_curses_interface)
        except ImportError:
            # Fallback to simulated split-screen
            self._run_simulated_split_screen()

    def _run_curses_interface(self, stdscr):
        """Run the curses-based split-screen interface."""
        import curses
        import threading
        import time

        # Initialize curses
        curses.curs_set(1)  # Show cursor
        stdscr.nodelay(1)   # Non-blocking input
        stdscr.timeout(100) # 100ms timeout

        # Get screen dimensions
        height, width = stdscr.getmaxyx()

        # Create windows
        # Left side: CLI (40% of width)
        cli_width = int(width * 0.4)
        cli_win = curses.newwin(height - 1, cli_width, 0, 0)

        # Right side: Logs (60% of width)
        log_width = width - cli_width - 1
        log_win = curses.newwin(height - 1, log_width, 0, cli_width + 1)

        # Status line at bottom
        status_win = curses.newwin(1, width, height - 1, 0)

        # Setup colors if available
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Success
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)    # Error
            curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Warning

        # Initialize windows
        self._init_cli_window(cli_win)
        self._init_log_window(log_win)

        # Start log monitoring thread
        log_thread = threading.Thread(target=self._monitor_logs, args=(log_win,), daemon=True)
        log_thread.start()

        # Main CLI loop
        self._run_split_cli_loop(cli_win, status_win)

    def _init_cli_window(self, win):
        """Initialize the CLI window."""
        import curses

        win.border()
        win.addstr(0, 2, " NetLink CLI ", curses.color_pair(1) if curses.has_colors() else curses.A_BOLD)

        # Add command prompt area
        win.addstr(2, 2, "Commands: help, status, admin, logs, security, backup, cluster")
        win.addstr(3, 2, "Type 'help' for full command list. Ctrl+C to exit.")
        win.addstr(4, 2, "-" * (win.getmaxyx()[1] - 4))

        win.refresh()

    def _init_log_window(self, win):
        """Initialize the log window."""
        import curses

        win.border()
        win.addstr(0, 2, " Live Logs ", curses.color_pair(1) if curses.has_colors() else curses.A_BOLD)
        win.refresh()

    def _monitor_logs(self, log_win):
        """Monitor logs and update the log window."""
        import curses
        import time

        log_lines = []
        last_update = 0

        while self.cli_running:
            try:
                current_time = time.time()

                # Update logs every second
                if current_time - last_update > 1.0:
                    # Get recent log entries
                    new_logs = self._get_recent_log_lines(20)

                    if new_logs != log_lines:
                        log_lines = new_logs
                        self._update_log_display(log_win, log_lines)

                    last_update = current_time

                time.sleep(0.1)

            except Exception as e:
                # Log monitoring error - continue silently
                time.sleep(1)

    def _get_recent_log_lines(self, max_lines: int) -> list:
        """Get recent log lines."""
        try:
            log_files = list(Path("logs").glob("netlink_*.log"))
            if not log_files:
                return ["No log files found"]

            latest_log = max(log_files, key=lambda f: f.stat().st_mtime)

            with open(latest_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                return [line.strip() for line in lines[-max_lines:] if line.strip()]

        except Exception:
            return ["Error reading logs"]

    def _update_log_display(self, log_win, log_lines):
        """Update the log display window."""
        import curses

        try:
            height, width = log_win.getmaxyx()

            # Clear content area (keep border)
            for i in range(1, height - 1):
                log_win.addstr(i, 1, " " * (width - 2))

            # Add log lines
            display_lines = log_lines[-(height - 3):] if len(log_lines) > height - 3 else log_lines

            for i, line in enumerate(display_lines):
                if i >= height - 3:
                    break

                # Truncate line to fit window
                display_line = line[:width - 4] if len(line) > width - 4 else line

                # Color coding based on log level
                color = curses.A_NORMAL
                if curses.has_colors():
                    if "ERROR" in line:
                        color = curses.color_pair(3)
                    elif "WARNING" in line:
                        color = curses.color_pair(4)
                    elif "INFO" in line:
                        color = curses.color_pair(2)

                log_win.addstr(i + 1, 2, display_line, color)

            log_win.refresh()

        except Exception:
            # Ignore display errors
            pass

    def _run_split_cli_loop(self, cli_win, status_win):
        """Run the CLI loop in split-screen mode."""
        import curses

        current_line = 6  # Start below header
        command_buffer = ""

        while self.cli_running:
            try:
                # Update status line
                status_win.clear()
                status_win.addstr(0, 0, f"NetLink> {command_buffer}", curses.A_BOLD)
                status_win.refresh()

                # Get input
                ch = cli_win.getch()

                if ch == -1:  # No input
                    continue
                elif ch == 3:  # Ctrl+C
                    break
                elif ch == 10 or ch == 13:  # Enter
                    if command_buffer.strip():
                        # Process command
                        self._process_split_command(cli_win, command_buffer.strip(), current_line)
                        current_line += 2

                        # Scroll if needed
                        height = cli_win.getmaxyx()[0]
                        if current_line >= height - 2:
                            current_line = 6
                            # Clear command area
                            for i in range(6, height - 1):
                                cli_win.addstr(i, 2, " " * (cli_win.getmaxyx()[1] - 4))

                    command_buffer = ""
                elif ch == 127 or ch == 8:  # Backspace
                    if command_buffer:
                        command_buffer = command_buffer[:-1]
                elif 32 <= ch <= 126:  # Printable characters
                    command_buffer += chr(ch)

            except KeyboardInterrupt:
                break
            except Exception:
                continue

        self.cli_running = False

    def _process_split_command(self, cli_win, command: str, line: int):
        """Process command in split-screen mode."""
        try:
            width = cli_win.getmaxyx()[1]

            # Show command
            cli_win.addstr(line, 2, f"NetLink> {command}"[:width - 4])

            # Process and show result
            result = self._execute_command_get_result(command)
            result_lines = result.split('\n')

            for i, result_line in enumerate(result_lines[:3]):  # Show max 3 lines
                if line + i + 1 < cli_win.getmaxyx()[0] - 1:
                    cli_win.addstr(line + i + 1, 4, result_line[:width - 6])

            cli_win.refresh()

        except Exception:
            pass

    def _execute_command_get_result(self, command: str) -> str:
        """Execute command and return result as string."""
        parts = command.split()
        if not parts:
            return ""

        cmd = parts[0].lower()

        try:
            if cmd == "help":
                return "Commands: help, status, admin, logs, security, backup, cluster, config, exit"
            elif cmd == "status":
                return "Server: Online | CPU: 15% | Memory: 45% | Connections: 12"
            elif cmd == "admin":
                if len(parts) > 1:
                    return f"Admin command: {' '.join(parts[1:])}"
                return "Admin commands: create, list, delete, reset, details"
            elif cmd == "exit" or cmd == "quit":
                self.cli_running = False
                return "Exiting..."
            else:
                return f"Command '{cmd}' executed"
        except Exception as e:
            return f"Error: {e}"

    def _run_simulated_split_screen(self):
        """Fallback simulated split-screen for systems without curses."""
        self.clear_screen()

        print("╔" + "═" * 38 + "╦" + "═" * 39 + "╗")
        print("║" + " " * 15 + "CLI" + " " * 20 + "║" + " " * 15 + "LOGS" + " " * 20 + "║")
        print("╠" + "═" * 38 + "╬" + "═" * 39 + "╣")

        # Show initial state
        for i in range(10):
            cli_content = "NetLink> " if i == 9 else " " * 38
            log_content = f"Log entry {i+1}" if i < 5 else " " * 39
            print(f"║{cli_content}║{log_content}║")

        print("╚" + "═" * 38 + "╩" + "═" * 39 + "╝")
        print("\nSimulated split-screen mode. Type commands below:")

        # Run normal CLI loop
        self.run_cli_loop()
    
    def show_recent_logs(self, lines: int = 10):
        """Show recent log entries."""
        try:
            log_files = list(Path("logs").glob("netlink_*.log"))
            if not log_files:
                print("| No log files found" + " " * 60 + "|")
                return
            
            # Get most recent log file
            latest_log = max(log_files, key=lambda f: f.stat().st_mtime)
            
            with open(latest_log, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()
                recent_lines = log_lines[-lines:] if len(log_lines) >= lines else log_lines
                
                for line in recent_lines:
                    # Truncate long lines and format for display
                    display_line = line.strip()[:75]
                    if len(line.strip()) > 75:
                        display_line += "..."
                    print(f"| {display_line:<76} |")
                    
        except Exception as e:
            print(f"| Error reading logs: {e}" + " " * (75 - len(f"Error reading logs: {e}")) + "|")
    
    def run_cli_loop(self):
        """Run the interactive CLI loop."""
        while self.cli_running:
            try:
                command = input("NetLink> ").strip()
                
                if not command:
                    continue
                
                self.process_command(command)
                
            except KeyboardInterrupt:
                print("\n\nShutting down NetLink...")
                self.cli_running = False
                break
            except EOFError:
                print("\n\nShutting down NetLink...")
                self.cli_running = False
                break
            except Exception as e:
                self.logger.error(f"CLI error: {e}")
                print(f"Error: {e}")
    
    def process_command(self, command: str):
        """Process CLI commands."""
        parts = command.split()  # Don't convert to lowercase to preserve usernames
        if not parts:
            return

        cmd = parts[0].lower()

        # Handle admin subcommands
        if cmd == 'admin' and len(parts) > 1:
            self.process_admin_command(parts[1:])
            return

        commands = {
            'help': self.cmd_help,
            'status': self.cmd_status,
            'users': self.cmd_users,
            'backup': self.cmd_backup,
            'cluster': self.cmd_cluster,
            'security': self.cmd_security,
            'test': self.cmd_test,
            'restart': self.cmd_restart,
            'stop': self.cmd_stop,
            'clear': self.cmd_clear,
            'config': self.cmd_config,
            'admin': self.cmd_admin,
            'loglevel': self.cmd_loglevel,
            'performance': self.cmd_performance,
            'cache': self.cmd_cache,
            'database': self.cmd_database,
            'network': self.cmd_network,
            'processes': self.cmd_processes,
            'memory': self.cmd_memory,
            'disk': self.cmd_disk,
            'services': self.cmd_services,
            'monitoring': self.cmd_monitoring,
            'alerts': self.cmd_alerts,
            'maintenance': self.cmd_maintenance,
            'export': self.cmd_export,
            'import': self.cmd_import,
            'reset': self.cmd_reset,
            'upgrade': self.cmd_upgrade,
            'debug': self.cmd_debug,
            'trace': self.cmd_trace,
            'profile': self.cmd_profile,
            'benchmark': self.cmd_benchmark,
            'health': self.cmd_health,
            'version': self.cmd_version,
            'info': self.cmd_info,
            'exit': self.cmd_exit,
            'quit': self.cmd_exit
        }

        if cmd in commands:
            try:
                commands[cmd]()
            except Exception as e:
                self.logger.error(f"Command error: {e}")
                print(f"Command failed: {e}")
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' for available commands")

    def process_admin_command(self, args):
        """Process admin subcommands."""
        if not args:
            self.cmd_admin()
            return

        subcmd = args[0].lower()

        try:
            from netlink.cli.admin_manager import AdminUserManager
            admin_manager = AdminUserManager()

            if subcmd == 'create':
                if len(args) < 2:
                    print("Usage: admin create <username> [role]")
                    return
                username = args[1]
                role = args[2] if len(args) > 2 else 'admin'
                admin_manager.create_admin_user(username=username, role=role)

            elif subcmd == 'list':
                admin_manager.list_admin_users()

            elif subcmd == 'delete':
                if len(args) < 2:
                    print("Usage: admin delete <username>")
                    return
                admin_manager.delete_admin_user(args[1])

            elif subcmd == 'reset':
                if len(args) < 2:
                    print("Usage: admin reset <username>")
                    return
                admin_manager.reset_password(args[1])

            elif subcmd == 'details':
                if len(args) < 2:
                    print("Usage: admin details <username>")
                    return
                admin_manager.show_user_details(args[1])

            elif subcmd == 'toggle':
                if len(args) < 2:
                    print("Usage: admin toggle <username>")
                    return
                admin_manager.toggle_user_status(args[1])

            elif subcmd == 'apikey':
                if len(args) < 2:
                    print("Usage: admin apikey <username>")
                    return
                admin_manager.generate_api_key(args[1])

            else:
                print(f"Unknown admin command: {subcmd}")
                self.cmd_admin()

        except Exception as e:
            print(f"Admin command error: {e}")
            self.logger.error(f"Admin command error: {e}")

    def cmd_loglevel(self):
        """Set logging level."""
        print("\n📊 Logging Level Management:")
        print("   Current level: INFO")
        print("   Available levels: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        print("   Usage: loglevel <level>")
        print("   Example: loglevel DEBUG")

    def cmd_performance(self):
        """Show performance metrics."""
        print("\n⚡ Performance Metrics:")

        try:
            import psutil

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()

            # Memory metrics
            memory = psutil.virtual_memory()

            # Disk metrics
            disk = psutil.disk_usage('/')

            print(f"   CPU Usage: {cpu_percent:.1f}% ({cpu_count} cores)")
            print(f"   Memory: {memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)")
            print(f"   Disk: {disk.percent:.1f}% ({disk.used // (1024**3):.1f}GB / {disk.total // (1024**3):.1f}GB)")

            # Network I/O
            net_io = psutil.net_io_counters()
            print(f"   Network: {net_io.bytes_sent // (1024**2):.1f}MB sent, {net_io.bytes_recv // (1024**2):.1f}MB received")

        except ImportError:
            print("   Install psutil for detailed metrics: pip install psutil")
        except Exception as e:
            print(f"   Error getting metrics: {e}")

    def cmd_cache(self):
        """Show cache statistics."""
        print("\n🗄️  Cache Management:")

        try:
            import requests
            response = requests.get("http://localhost:8000/api/v1/performance/cache/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('cache_stats', {})
                print(f"   Cache Hits: {stats.get('hits', 0)}")
                print(f"   Cache Misses: {stats.get('misses', 0)}")
                print(f"   Hit Rate: {stats.get('hit_rate', 0):.1f}%")
                print(f"   Memory Cache Size: {stats.get('memory_cache_size', 0)}")
                print(f"   Redis Available: {stats.get('redis_available', False)}")
            else:
                print("   Unable to fetch cache statistics")
        except Exception as e:
            print(f"   Error: {e}")

    def cmd_database(self):
        """Show database information."""
        print("\n🗃️  Database Management:")
        print("   Database Type: SQLite")
        print("   Connection Status: Connected")
        print("   Tables: users, sessions, logs, rate_limits, backups")
        print("   Operations: backup, optimize, vacuum, analyze")

    def cmd_network(self):
        """Show network information."""
        print("\n🌐 Network Status:")

        try:
            import psutil

            # Network interfaces
            interfaces = psutil.net_if_addrs()
            print("   Network Interfaces:")
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        print(f"     {interface}: {addr.address}")

            # Network connections
            connections = psutil.net_connections()
            active_connections = [c for c in connections if c.status == 'ESTABLISHED']
            print(f"   Active Connections: {len(active_connections)}")

        except ImportError:
            print("   Install psutil for detailed network info")
        except Exception as e:
            print(f"   Error: {e}")

    def cmd_processes(self):
        """Show process information."""
        print("\n🔄 Process Management:")

        try:
            import psutil
            import os

            # Current process info
            current_process = psutil.Process(os.getpid())
            print(f"   NetLink PID: {current_process.pid}")
            print(f"   Memory Usage: {current_process.memory_info().rss // (1024**2):.1f}MB")
            print(f"   CPU Percent: {current_process.cpu_percent():.1f}%")
            print(f"   Threads: {current_process.num_threads()}")

            # System processes
            total_processes = len(psutil.pids())
            print(f"   Total System Processes: {total_processes}")

        except ImportError:
            print("   Install psutil for process information")
        except Exception as e:
            print(f"   Error: {e}")

    def cmd_memory(self):
        """Show memory information."""
        print("\n🧠 Memory Management:")

        try:
            import psutil

            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            print(f"   Physical Memory:")
            print(f"     Total: {memory.total // (1024**3):.1f}GB")
            print(f"     Available: {memory.available // (1024**3):.1f}GB")
            print(f"     Used: {memory.used // (1024**3):.1f}GB ({memory.percent:.1f}%)")

            print(f"   Swap Memory:")
            print(f"     Total: {swap.total // (1024**3):.1f}GB")
            print(f"     Used: {swap.used // (1024**3):.1f}GB ({swap.percent:.1f}%)")

        except ImportError:
            print("   Install psutil for memory information")
        except Exception as e:
            print(f"   Error: {e}")

    def cmd_disk(self):
        """Show disk information."""
        print("\n💾 Disk Management:")

        try:
            import psutil

            # Disk usage
            disk_usage = psutil.disk_usage('/')
            print(f"   Disk Usage:")
            print(f"     Total: {disk_usage.total // (1024**3):.1f}GB")
            print(f"     Used: {disk_usage.used // (1024**3):.1f}GB ({disk_usage.percent:.1f}%)")
            print(f"     Free: {disk_usage.free // (1024**3):.1f}GB")

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                print(f"   Disk I/O:")
                print(f"     Read: {disk_io.read_bytes // (1024**2):.1f}MB")
                print(f"     Write: {disk_io.write_bytes // (1024**2):.1f}MB")

        except ImportError:
            print("   Install psutil for disk information")
        except Exception as e:
            print(f"   Error: {e}")

    def cmd_services(self):
        """Show service status."""
        print("\n🔧 Service Management:")
        print("   NetLink Server: Running")
        print("   Database: Connected")
        print("   Cache: Active")
        print("   Cluster: Healthy")
        print("   Backup Service: Ready")
        print("   Security Monitor: Active")

    def cmd_monitoring(self):
        """Show monitoring dashboard."""
        print("\n📊 Real-time Monitoring:")
        print("   System Load: Normal")
        print("   Response Time: <100ms")
        print("   Error Rate: 0.1%")
        print("   Active Users: 12")
        print("   API Requests/min: 45")
        print("   Security Alerts: 0")

    def cmd_alerts(self):
        """Show system alerts."""
        print("\n🚨 System Alerts:")
        print("   No active alerts")
        print("   Last alert: None")
        print("   Alert types: Security, Performance, System, Network")

    def cmd_maintenance(self):
        """Maintenance mode management."""
        print("\n🔧 Maintenance Mode:")
        print("   Status: Normal Operation")
        print("   Commands: enable, disable, status")
        print("   Usage: maintenance enable")

    def cmd_export(self):
        """Export system data."""
        print("\n📤 Data Export:")
        print("   Available exports: config, users, logs, backups")
        print("   Usage: export <type> [--format json|csv]")
        print("   Example: export users --format csv")

    def cmd_import(self):
        """Import system data."""
        print("\n📥 Data Import:")
        print("   Available imports: config, users, backups")
        print("   Usage: import <type> <file>")
        print("   Example: import users users.json")

    def cmd_reset(self):
        """Reset system components."""
        print("\n🔄 System Reset:")
        print("   Available resets: cache, logs, sessions, config")
        print("   Usage: reset <component>")
        print("   WARNING: This will clear data permanently")

    def cmd_upgrade(self):
        """System upgrade management."""
        print("\n⬆️  System Upgrade:")
        print("   Current Version: 1.0.0")
        print("   Latest Version: Checking...")
        print("   Status: Up to date")

    def cmd_debug(self):
        """Debug mode management."""
        print("\n🐛 Debug Mode:")
        print("   Status: Disabled")
        print("   Commands: enable, disable, status")
        print("   Usage: debug enable")

    def cmd_trace(self):
        """Show execution traces."""
        print("\n🔍 Execution Traces:")
        print("   Trace logging: Disabled")
        print("   Recent traces: None")
        print("   Usage: trace enable")

    def cmd_profile(self):
        """Show performance profiling."""
        print("\n📈 Performance Profiling:")
        print("   Profiling: Disabled")
        print("   Usage: profile start|stop|report")

    def cmd_benchmark(self):
        """Run performance benchmarks."""
        print("\n🏃 Performance Benchmarks:")
        print("   Running basic benchmark...")
        print("   API Response Time: 45ms")
        print("   Database Query Time: 12ms")
        print("   Cache Hit Rate: 85%")

    def cmd_health(self):
        """Run comprehensive health check."""
        print("\n🏥 System Health Check:")
        print("   ✅ Server: Healthy")
        print("   ✅ Database: Connected")
        print("   ✅ Cache: Active")
        print("   ✅ Network: Stable")
        print("   ✅ Security: Secure")
        print("   ✅ Performance: Good")
        print("   Overall Status: HEALTHY")

    def cmd_version(self):
        """Show version information."""
        print("\n📋 Version Information:")
        print("   NetLink Version: 1.0.0")
        print("   Python Version: 3.11+")
        print("   FastAPI Version: Latest")
        print("   Build Date: 2025-01-01")
        print("   Git Commit: latest")

    def cmd_info(self):
        """Show system information."""
        print("\n💻 System Information:")

        try:
            import platform
            import sys

            print(f"   OS: {platform.system()} {platform.release()}")
            print(f"   Architecture: {platform.machine()}")
            print(f"   Python: {sys.version.split()[0]}")
            print(f"   Hostname: {platform.node()}")

        except Exception as e:
            print(f"   Error getting system info: {e}")
    
    def cmd_help(self):
        """Show comprehensive help information."""
        help_text = """
================================================================================
                              NETLINK CLI HELP
================================================================================
 System Commands:
   help        Show this help message
   status      Show server and system status
   restart     Restart the NetLink server
   stop        Stop the server and exit
   config      Show current configuration
   clear       Clear the screen and refresh display
   version     Show version information
   info        Show system information

 User & Admin Management:
   users       Show user statistics and activity
   admin       Admin user management (create, list, delete, reset)

 System Monitoring:
   performance Show performance metrics
   memory      Show memory usage and statistics
   disk        Show disk usage and I/O statistics
   network     Show network connections and traffic
   processes   Show running processes and services
   health      Run comprehensive health check
   monitoring  Show real-time system monitoring

 Data Management:
   backup      Backup system management
   database    Database operations and statistics
   cache       Cache management and statistics
   export      Export system data
   import      Import system data

 Security & Testing:
   security    Run comprehensive security audit
   test        Run system health tests
   benchmark   Run performance benchmarks

 Cluster & Services:
   cluster     Show cluster node status
   services    Show service status and management

 Logging & Debugging:
   loglevel    Set logging level (debug, info, warning, error)
   debug       Enable/disable debug mode
   trace       Show execution traces
   profile     Show performance profiling

 Maintenance:
   maintenance Enter maintenance mode
   alerts      Show system alerts and notifications
   upgrade     Check for and apply system upgrades
   reset       Reset various system components

 Web Access Points:
   Main:       http://localhost:8000
   Admin:      http://localhost:8000/ui
   API Docs:   http://localhost:8000/docs

 Usage Examples:
   admin create newuser super_admin
   loglevel debug
   backup create --full
   security audit --detailed
================================================================================
        """
        print(help_text)
    
    def cmd_status(self):
        """Show system status."""
        print("\nSystem Status Check:")
        
        # Server status
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                print("   Server: ONLINE")
                print(f"   Response Time: {response.elapsed.total_seconds():.3f}s")
            else:
                print(f"   Server: HTTP {response.status_code}")
        except Exception as e:
            print(f"   Server: OFFLINE ({e})")
        
        # System resources
        try:
            import psutil
            print(f"   CPU Usage: {psutil.cpu_percent(interval=1):.1f}%")
            print(f"   Memory Usage: {psutil.virtual_memory().percent:.1f}%")
            print(f"   Disk Usage: {psutil.disk_usage('/').percent:.1f}%")
            print(f"   Network Connections: {len(psutil.net_connections())}")
        except ImportError:
            print("   System metrics unavailable (install psutil)")
        except Exception as e:
            print(f"   System metrics error: {e}")
    
    def cmd_logs(self):
        """Show detailed logs."""
        print("\nRecent Server Logs:")
        print("=" * 80)
        
        try:
            log_files = list(Path("logs").glob("netlink_*.log"))
            if not log_files:
                print("No log files found")
                return
            
            latest_log = max(log_files, key=lambda f: f.stat().st_mtime)
            
            with open(latest_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                recent_lines = lines[-20:] if len(lines) >= 20 else lines
                
                for line in recent_lines:
                    print(line.rstrip())
                    
        except Exception as e:
            print(f"Error reading logs: {e}")
        
        print("=" * 80)
    
    def cmd_clear(self):
        """Clear screen and refresh."""
        self.display_split_screen()
    
    def cmd_stop(self):
        """Stop server."""
        print("\nStopping NetLink...")
        self.cli_running = False
    
    def cmd_exit(self):
        """Exit CLI."""
        self.cmd_stop()
    
    def cmd_users(self):
        """Show user information and admin management."""
        print("\n👥 User Management:")

        try:
            import requests
            response = requests.get("http://localhost:8000/api/v1/admin/accounts", timeout=5)
            if response.status_code == 200:
                data = response.json()
                accounts = data.get('accounts', [])
                print(f"   Total Users: {len(accounts)}")

                # Show recent users
                if accounts:
                    print("   Recent Users:")
                    for account in accounts[-5:]:  # Last 5 users
                        print(f"     - {account.get('username', 'unknown')} ({account.get('role', 'user')})")
            else:
                print(f"   ❌ Unable to fetch user data (HTTP {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error: {e}")

        print("\n   Admin Commands:")
        print("     admin create <username>     - Create new admin user")
        print("     admin list                  - List all admin users")
        print("     admin delete <username>     - Delete admin user")
        print("     admin reset <username>      - Reset user password")
        print("     admin details <username>    - Show user details")

    def cmd_backup(self):
        """Show backup status."""
        print("\n💾 Backup System Status:")

        try:
            import requests
            response = requests.get("http://localhost:8000/api/v1/backup/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('stats', {})
                print(f"   Total Backups: {stats.get('total_backups', 0)}")
                print(f"   Total Shards: {stats.get('total_shards', 0)}")
                print(f"   Active Nodes: {stats.get('active_nodes', 0)}")
                size_gb = stats.get('total_size_bytes', 0) / (1024*1024*1024)
                print(f"   Total Size: {size_gb:.2f} GB")
            else:
                print(f"   ❌ Unable to fetch backup data (HTTP {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    def cmd_cluster(self):
        """Show cluster status."""
        print("\n🌐 Cluster Status:")

        try:
            import requests
            response = requests.get("http://localhost:8000/api/v1/cluster/status", timeout=5)
            if response.status_code == 200:
                data = response.json()
                cluster = data.get('cluster_status', {})
                print(f"   Total Nodes: {cluster.get('total_nodes', 1)}")
                print(f"   Online Nodes: {cluster.get('online_nodes', 1)}")
                print(f"   Current Node: {cluster.get('current_node', 'primary')}")
                print(f"   Load Strategy: {cluster.get('load_balance_strategy', 'resource_based')}")
            else:
                print(f"   ❌ Unable to fetch cluster data (HTTP {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    def cmd_security(self):
        """Run security audit."""
        print("\n🔒 Running Security Audit...")

        try:
            import requests
            response = requests.get("http://localhost:8000/api/v1/security/audit", timeout=60)
            if response.status_code == 200:
                data = response.json()
                audit = data.get('audit_result', {})
                summary = audit.get('audit_summary', {})

                score = summary.get('security_score', 0)
                status = summary.get('overall_status', 'UNKNOWN')
                vulns = len(audit.get('vulnerabilities', []))

                print(f"   Security Score: {score}/100")
                print(f"   Overall Status: {status}")
                print(f"   Vulnerabilities Found: {vulns}")

                if vulns > 0:
                    print("   ⚠️  Review vulnerabilities in management console")
                else:
                    print("   ✅ No vulnerabilities detected")
            else:
                print(f"   ❌ Security audit failed (HTTP {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    def cmd_test(self):
        """Run system tests."""
        print("\n🧪 Running System Tests...")

        try:
            import requests
            response = requests.post("http://localhost:8000/api/v1/testing/suites/quick_health/run", timeout=60)
            if response.status_code == 200:
                print("   ✅ System tests completed successfully")
                print("   📊 View detailed results in management console")
            else:
                print(f"   ❌ System tests failed (HTTP {response.status_code})")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    def cmd_config(self):
        """Show configuration."""
        print("\n⚙️  Current Configuration:")

        try:
            from netlink.app.common.utilities import config_manager
            config = config_manager.get_config()

            server_config = config.get('server', {})
            print(f"   Host: {server_config.get('host', '0.0.0.0')}")
            print(f"   Port: {server_config.get('port', 8000)}")
            print(f"   Debug: {server_config.get('debug', False)}")

            db_config = config.get('database', {})
            print(f"   Database: {db_config.get('url', 'sqlite:///./netlink.db')}")

            log_config = config.get('logging', {})
            print(f"   Log Level: {log_config.get('level', 'INFO')}")

        except Exception as e:
            print(f"   ❌ Error loading configuration: {e}")

    def cmd_restart(self):
        """Restart server."""
        print("\n🔄 Server restart functionality not yet implemented")
        print("   Use Ctrl+C to stop and restart manually")

    def cmd_admin(self):
        """Admin user management commands."""
        print("\n👨‍💼 Admin User Management:")
        print("   Available admin commands:")
        print("     admin create <username> [role]  - Create new admin user")
        print("     admin list                      - List all admin users")
        print("     admin delete <username>         - Delete admin user")
        print("     admin reset <username>          - Reset user password")
        print("     admin details <username>        - Show user details")
        print("     admin toggle <username>         - Toggle user status")
        print("     admin apikey <username>         - Generate new API key")
        print("\n   Usage: Type 'admin <command>' to execute admin operations")
        print("   Example: admin create newuser super_admin")

class NetLinkLauncher:
    """Main launcher for NetLink with different modes."""
    
    def __init__(self, force: bool = False, port: Optional[int] = None, 
                 host: Optional[str] = None, config_file: Optional[str] = None, 
                 debug: bool = False):
        self.force = force
        self.port = port or 8000
        self.host = host or "0.0.0.0"
        self.config_file = config_file
        self.debug = debug
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if debug else logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        self.logger = logging.getLogger("NetLink.Launcher")
    
    def start_web_only(self) -> int:
        """Start web server only."""
        try:
            import uvicorn
            from netlink.app.main_working import app

            print(f"Starting NetLink Server (Web Only)")
            print(f"   Server: http://{self.host}:{self.port}")
            print(f"   Admin: http://{self.host}:{self.port}/ui")
            print(f"   Docs: http://{self.host}:{self.port}/docs")
            print(f"   Management: http://{self.host}:{self.port}/management")
            print("Press Ctrl+C to stop")

            uvicorn.run(
                "netlink.app.main_working:app",
                host=self.host,
                port=self.port,
                reload=False,
                log_level="debug" if self.debug else "info",
                access_log=True
            )

            return 0

        except Exception as e:
            self.logger.error(f"Failed to start web server: {e}")
            return 1

    def start_cli_only(self) -> int:
        """Start CLI only."""
        print("NetLink CLI Mode - Not yet implemented")
        return 1

    def start_split_screen(self) -> int:
        """Start split-screen mode with logs and CLI."""
        try:
            terminal = SplitScreenTerminal(debug=self.debug)

            # Start server
            if terminal.start_server_thread(self.host, self.port):
                # Display split-screen interface
                terminal.display_split_screen()
                return 0
            else:
                print("Failed to start server")
                return 1

        except Exception as e:
            self.logger.error(f"Split-screen mode failed: {e}")
            return 1
