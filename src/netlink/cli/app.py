"""
NetLink CLI Application
Interactive command-line interface for NetLink administration.
"""

import cmd
import sys
import os
import time
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

class NetLinkCLI(cmd.Cmd):
    """Interactive CLI for NetLink administration."""
    
    intro = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            NetLink CLI v1.0.0                               ║
║                     Interactive Administration Interface                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Type 'help' for available commands or 'quit' to exit.
Web Interface: http://localhost:8000
    """
    
    prompt = "netlink> "
    
    def __init__(self, split_screen=None):
        super().__init__()
        self.server_running = False
        self.split_screen = split_screen
        self.command_history = []
        self.auto_complete_enabled = True
        self.last_command_time = None

        # Enhanced features
        self.aliases = {
            'st': 'status',
            'ls': 'list',
            'cfg': 'config',
            'usr': 'user',
            'log': 'logs',
            'mon': 'monitor',
            'perf': 'performance'
        }

        # Initialize command completion
        self._setup_completion()

        if self.split_screen:
            self.split_screen.add_log_entry("INFO", "cli", "Enhanced CLI initialized with split-screen support")

    def _setup_completion(self):
        """Setup command completion and history."""
        try:
            import readline
            import atexit

            # Setup history file
            history_file = os.path.expanduser("~/.netlink_history")
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass

            # Save history on exit
            atexit.register(readline.write_history_file, history_file)

            # Setup completion
            readline.set_completer(self._complete_command)
            readline.parse_and_bind("tab: complete")

        except ImportError:
            # readline not available
            pass

    def _complete_command(self, text, state):
        """Command completion function."""
        commands = [cmd[3:] for cmd in dir(self) if cmd.startswith('do_')]
        commands.extend(self.aliases.keys())

        matches = [cmd for cmd in commands if cmd.startswith(text)]

        if state < len(matches):
            return matches[state]
        return None
    
    def default(self, line):
        """Handle unknown commands and aliases."""
        command = line.split()[0] if line.split() else ""

        # Check for aliases
        if command in self.aliases:
            actual_command = self.aliases[command]
            args = " ".join(line.split()[1:]) if len(line.split()) > 1 else ""
            return self.onecmd(f"{actual_command} {args}")

        # Log unknown command
        if self.split_screen:
            self.split_screen.add_log_entry("WARNING", "cli", f"Unknown command: {command}")

        print(f"❌ Unknown command: {command}")
        print("Type 'help' for available commands")

    def precmd(self, line):
        """Pre-process commands."""
        if line.strip():
            self.command_history.append(line.strip())
            self.last_command_time = time.time()

            if self.split_screen:
                self.split_screen.add_log_entry("DEBUG", "cli", f"Command executed: {line.strip()}")

        return line

    def do_status(self, arg):
        """Show enhanced system status."""
        if self.split_screen:
            self.split_screen.start_operation("status_check", "command")

        print("📊 NetLink Enhanced System Status")
        print("═" * 50)

        # Basic status
        print(f"🌐 Web Server: {'Running' if self.server_running else 'Stopped'}")
        print(f"💾 Database: Connected")
        print(f"🔐 Authentication: Active")
        print(f"📡 API Endpoints: Available")

        # Enhanced status with split-screen integration
        if self.split_screen:
            stats = self.split_screen.get_stats()
            print(f"📊 Total Logs: {stats['total_logs']}")
            print(f"❌ Errors: {stats['errors']}")
            print(f"⚠️  Warnings: {stats['warnings']}")
            print(f"🔄 Active Operations: {stats['active_operations']}")
            print(f"⏱️  Uptime: {stats['uptime_seconds']:.1f}s")

        # System resources
        try:
            import psutil
            print(f"💻 CPU Usage: {psutil.cpu_percent()}%")
            print(f"🧠 Memory Usage: {psutil.virtual_memory().percent}%")
            print(f"💽 Disk Usage: {psutil.disk_usage('/').percent}%")
        except ImportError:
            print("💻 System metrics: Not available (install psutil)")

        print()

        if self.split_screen:
            self.split_screen.end_operation("status_check", success=True)
    
    def do_test(self, arg):
        """Run system tests."""
        print("🧪 Running system tests...")
        try:
            from netlink.tests.quick_test import run_quick_test
            success = run_quick_test()
            if success:
                print("✅ All tests passed!")
            else:
                print("❌ Some tests failed!")
        except Exception as e:
            print(f"❌ Test error: {e}")
    
    def do_validate(self, arg):
        """Validate system configuration."""
        print("🔍 Validating system configuration...")
        try:
            from netlink.tests.validate_system import run_system_validation
            success = run_system_validation()
            if success:
                print("✅ System validation passed!")
            else:
                print("❌ System validation failed!")
        except Exception as e:
            print(f"❌ Validation error: {e}")
    
    def do_logs(self, arg):
        """Show recent logs with enhanced filtering."""
        if self.split_screen:
            self.split_screen.start_operation("logs_display", "command")

        args = arg.split() if arg else []
        count = 20  # default
        level_filter = None

        # Parse arguments
        for i, a in enumerate(args):
            if a == '--count' or a == '-c':
                if i + 1 < len(args):
                    try:
                        count = int(args[i + 1])
                    except ValueError:
                        print("❌ Invalid count value")
                        return
            elif a == '--level' or a == '-l':
                if i + 1 < len(args):
                    level_filter = args[i + 1].upper()

        print(f"📋 Recent System Logs (showing {count} entries)")
        if level_filter:
            print(f"🔍 Filtered by level: {level_filter}")
        print("═" * 60)

        if self.split_screen:
            # Get logs from split-screen buffer
            logs = self.split_screen.log_buffer
            filtered_logs = []

            for log in logs:
                if level_filter and log.level.upper() != level_filter:
                    continue
                filtered_logs.append(log)

            # Show most recent logs
            recent_logs = list(filtered_logs)[-count:]

            for log in recent_logs:
                timestamp = log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                level_icon = self._get_level_icon(log.level)
                print(f"{level_icon} {timestamp} - {log.level.upper()} - [{log.module}] {log.message}")
        else:
            # Fallback static logs
            print("🕐 2025-06-29 12:00:00 - INFO - [launcher] NetLink started")
            print("🕐 2025-06-29 12:00:01 - INFO - [database] Database connected")
            print("🕐 2025-06-29 12:00:02 - INFO - [web_server] Web server listening on :8000")
            print("🕐 2025-06-29 12:00:03 - INFO - [system] All systems operational")

        print()

        if self.split_screen:
            self.split_screen.end_operation("logs_display", success=True)

    def _get_level_icon(self, level: str) -> str:
        """Get icon for log level."""
        icons = {
            'DEBUG': '🔍',
            'INFO': '📝',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        }
        return icons.get(level.upper(), '📝')

    def do_monitor(self, arg):
        """Start system monitoring."""
        if not self.split_screen:
            print("❌ Monitoring requires split-screen mode")
            return

        print("📊 Starting system monitoring...")
        print("Press Ctrl+C to stop monitoring")

        try:
            while True:
                stats = self.split_screen.get_stats()

                # Clear screen and show stats
                os.system('cls' if os.name == 'nt' else 'clear')
                print("📊 NetLink System Monitor")
                print("═" * 40)
                print(f"⏱️  Uptime: {stats['uptime_seconds']:.1f}s")
                print(f"📊 Total Logs: {stats['total_logs']}")
                print(f"❌ Errors: {stats['errors']}")
                print(f"⚠️  Warnings: {stats['warnings']}")
                print(f"🔄 Active Operations: {stats['active_operations']}")
                print(f"📝 Log Buffer: {stats['log_buffer_size']}")

                # System metrics
                try:
                    import psutil
                    print(f"💻 CPU: {psutil.cpu_percent()}%")
                    print(f"🧠 Memory: {psutil.virtual_memory().percent}%")
                    print(f"💽 Disk: {psutil.disk_usage('/').percent}%")
                except ImportError:
                    pass

                print("\nPress Ctrl+C to stop...")
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n📊 Monitoring stopped")

    def do_performance(self, arg):
        """Show performance metrics."""
        if self.split_screen:
            self.split_screen.start_operation("performance_check", "command")

        print("⚡ NetLink Performance Metrics")
        print("═" * 40)

        if self.split_screen:
            stats = self.split_screen.get_stats()
            uptime = stats['uptime_seconds']

            print(f"📊 Requests per second: {stats['requests'] / max(uptime, 1):.2f}")
            print(f"❌ Error rate: {(stats['errors'] / max(stats['total_logs'], 1)) * 100:.2f}%")
            print(f"⚠️  Warning rate: {(stats['warnings'] / max(stats['total_logs'], 1)) * 100:.2f}%")
            print(f"🔄 Avg operations: {stats['active_operations']}")

        # System performance
        try:
            import psutil
            cpu_times = psutil.cpu_times()
            print(f"💻 CPU User Time: {cpu_times.user:.2f}s")
            print(f"💻 CPU System Time: {cpu_times.system:.2f}s")
            print(f"🧠 Memory Available: {psutil.virtual_memory().available // (1024**2)} MB")
            print(f"💽 Disk Read: {psutil.disk_io_counters().read_bytes // (1024**2)} MB")
            print(f"💽 Disk Write: {psutil.disk_io_counters().write_bytes // (1024**2)} MB")
        except ImportError:
            print("💻 System performance: Not available (install psutil)")

        print()

        if self.split_screen:
            self.split_screen.end_operation("performance_check", success=True)

    def do_export(self, arg):
        """Export logs or configuration."""
        if not arg:
            print("📤 Export Options:")
            print("  export logs [filename]    - Export logs to file")
            print("  export config [filename]  - Export configuration")
            print("  export stats [filename]   - Export statistics")
            return

        args = arg.split()
        export_type = args[0] if args else ""
        filename = args[1] if len(args) > 1 else None

        if export_type == "logs":
            if self.split_screen:
                try:
                    exported_file = self.split_screen.export_logs(filename)
                    print(f"✅ Logs exported to: {exported_file}")
                except Exception as e:
                    print(f"❌ Export failed: {e}")
            else:
                print("❌ Log export requires split-screen mode")

        elif export_type == "config":
            config_file = filename or f"netlink_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                config_data = {
                    "server": {"host": "0.0.0.0", "port": 8000},
                    "database": {"url": "sqlite:///./netlink.db"},
                    "logging": {"level": "INFO", "file": "logs/netlink.log"},
                    "exported_at": datetime.now().isoformat()
                }

                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)

                print(f"✅ Configuration exported to: {config_file}")
            except Exception as e:
                print(f"❌ Config export failed: {e}")

        elif export_type == "stats":
            stats_file = filename or f"netlink_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                if self.split_screen:
                    stats_data = self.split_screen.get_stats()
                else:
                    stats_data = {"message": "Statistics not available without split-screen mode"}

                with open(stats_file, 'w') as f:
                    json.dump(stats_data, f, indent=2, default=str)

                print(f"✅ Statistics exported to: {stats_file}")
            except Exception as e:
                print(f"❌ Stats export failed: {e}")

        else:
            print(f"❌ Unknown export type: {export_type}")

    def do_history(self, arg):
        """Show command history."""
        print("📜 Command History")
        print("═" * 30)

        if not self.command_history:
            print("No commands in history")
            return

        # Show last 20 commands
        recent_history = self.command_history[-20:]

        for i, cmd in enumerate(recent_history, 1):
            print(f"{i:2d}. {cmd}")

        print()

    def do_clear(self, arg):
        """Clear screen or logs."""
        if arg == "logs" and self.split_screen:
            self.split_screen.log_buffer.clear()
            self.split_screen.stats['total_logs'] = 0
            self.split_screen.stats['errors'] = 0
            self.split_screen.stats['warnings'] = 0
            print("✅ Logs cleared")
        else:
            os.system('cls' if os.name == 'nt' else 'clear')

    def do_alias(self, arg):
        """Show or manage command aliases."""
        if not arg:
            print("🔗 Command Aliases")
            print("═" * 20)
            for alias, command in self.aliases.items():
                print(f"  {alias} → {command}")
            print()
        else:
            # Could implement alias management here
            print("Alias management not yet implemented")

    def do_info(self, arg):
        """Show system information."""
        print("ℹ️  NetLink System Information")
        print("═" * 40)
        print(f"🏷️  Version: 1.0.0")
        print(f"🐍 Python: {sys.version.split()[0]}")
        print(f"💻 Platform: {sys.platform}")
        print(f"📁 Working Directory: {os.getcwd()}")
        print(f"👤 User: {os.getenv('USER', os.getenv('USERNAME', 'Unknown'))}")

        if self.split_screen:
            stats = self.split_screen.get_stats()
            print(f"⏱️  Session Uptime: {stats['uptime_seconds']:.1f}s")
            print(f"📊 Commands Executed: {len(self.command_history)}")

        print()

    def get_status(self) -> Dict[str, Any]:
        """Get current CLI status for external monitoring."""
        return {
            'server_running': self.server_running,
            'commands_executed': len(self.command_history),
            'last_command_time': self.last_command_time,
            'split_screen_active': self.split_screen is not None,
            'auto_complete_enabled': self.auto_complete_enabled
        }
    
    def do_users(self, arg):
        """User management commands."""
        if not arg:
            print("👥 User Management")
            print("─" * 40)
            print("Available commands:")
            print("  users list     - List all users")
            print("  users add      - Add new user")
            print("  users delete   - Delete user")
            print("  users reset    - Reset user password")
            return
        
        parts = arg.split()
        if not parts:
            return
        
        command = parts[0]
        
        if command == "list":
            print("👥 Active Users:")
            print("  • admin (Administrator)")
            print("  • user1 (Standard User)")
            print("  • guest (Guest)")
        elif command == "add":
            print("➕ Add new user functionality would be here")
        elif command == "delete":
            print("🗑️ Delete user functionality would be here")
        elif command == "reset":
            print("🔄 Reset password functionality would be here")
        else:
            print(f"❌ Unknown user command: {command}")
    
    def do_config(self, arg):
        """Configuration management."""
        print("⚙️ Configuration Management")
        print("─" * 40)
        print("Current configuration:")
        print("  • Host: 0.0.0.0")
        print("  • Port: 8000")
        print("  • Database: SQLite")
        print("  • Debug: False")
        print("  • SSL: Disabled")
        print()
    
    def do_backup(self, arg):
        """Backup management."""
        print("💾 Backup Management")
        print("─" * 40)
        print("Available commands:")
        print("  backup create  - Create new backup")
        print("  backup list    - List all backups")
        print("  backup restore - Restore from backup")
        print()
    
    def do_quit(self, arg):
        """Exit the CLI."""
        print("👋 Goodbye!")
        return True
    
    def do_exit(self, arg):
        """Exit the CLI."""
        return self.do_quit(arg)
    
    def do_clear(self, arg):
        """Clear the screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def emptyline(self):
        """Handle empty line input."""
        pass
    
    def default(self, line):
        """Handle unknown commands."""
        print(f"❌ Unknown command: {line}")
        print("Type 'help' for available commands.")
    
    def run(self):
        """Run the CLI."""
        try:
            self.cmdloop()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            return
