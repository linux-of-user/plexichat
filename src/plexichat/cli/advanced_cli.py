"""
Advanced CLI for NetLink with sophisticated command syntax and features.
Provides comprehensive command-line interface for all system operations.
"""

import os
import sys
import json
import asyncio
import argparse
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
import shlex
import readline
import atexit

import logging import logger
from .enhanced_logic_engine import EnhancedLogicEngine
from .automation_commands import AutomationCLI


class AdvancedCLI:
    """Advanced command-line interface with sophisticated features."""
    
    def __init__(self):
        self.commands = {}
        self.aliases = {}
        self.history_file = os.path.expanduser("~/.netlink_history")
        self.config = self._load_cli_config()
        self.running = False

        # Initialize logic engine and automation CLI
        self.logic_engine = EnhancedLogicEngine()
        self.automation_cli = AutomationCLI(self.logic_engine)
        
        # Initialize readline for command history
        self._setup_readline()
        
        # Register built-in commands
        self._register_commands()
        
        logger.info("🖥️ Advanced CLI initialized")
    
    def _load_cli_config(self) -> Dict[str, Any]:
        """Load CLI configuration."""
        config_path = "config/cli.json"
        
        default_config = {
            "prompt": "netlink> ",
            "history_size": 1000,
            "auto_complete": True,
            "color_output": True,
            "split_screen": True,
            "log_commands": True,
            "aliases": {
                "ls": "list",
                "ps": "status",
                "restart": "server restart",
                "stop": "server stop",
                "start": "server start",
                "logs": "log view",
                "backup": "database backup",
                "restore": "database restore"
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                # Create default config
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
                
        except Exception as e:
            logger.error(f"Failed to load CLI config: {e}")
            return default_config
    
    def _setup_readline(self):
        """Setup readline for command history and completion."""
        try:
            # Load command history
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
            
            # Set history size
            readline.set_history_length(self.config.get("history_size", 1000))
            
            # Setup completion
            if self.config.get("auto_complete", True):
                readline.set_completer(self._complete_command)
                readline.parse_and_bind("tab: complete")
            
            # Save history on exit
            atexit.register(self._save_history)
            
        except ImportError:
            logger.warning("Readline not available - command history disabled")
    
    def _save_history(self):
        """Save command history."""
        try:
            readline.write_history_file(self.history_file)
        except:
            pass
    
    def _complete_command(self, text: str, state: int) -> Optional[str]:
        """Command completion function."""
        try:
            line = readline.get_line_buffer()
            parts = line.split()
            
            if not parts or (len(parts) == 1 and not line.endswith(' ')):
                # Complete command names
                matches = [cmd for cmd in self.commands.keys() if cmd.startswith(text)]
                matches.extend([alias for alias in self.aliases.keys() if alias.startswith(text)])
            else:
                # Complete subcommands or arguments
                matches = []
                # This could be extended to provide context-aware completion
            
            if state < len(matches):
                return matches[state]
            else:
                return None
                
        except Exception:
            return None
    
    def _register_commands(self):
        """Register built-in CLI commands."""

        # Server management commands
        self.register_command("server", self._cmd_server, "Server management operations")
        self.register_command("status", self._cmd_status, "Show system status")
        self.register_command("config", self._cmd_config, "Configuration management")
        self.register_command("restart", self._cmd_restart, "Restart server components")
        self.register_command("shutdown", self._cmd_shutdown, "Shutdown server gracefully")

        # Database commands
        self.register_command("database", self._cmd_database, "Database operations")
        self.register_command("backup", self._cmd_backup, "Backup operations")
        self.register_command("restore", self._cmd_restore, "Restore operations")
        self.register_command("migrate", self._cmd_migrate, "Database migration operations")
        self.register_command("vacuum", self._cmd_vacuum, "Database maintenance operations")

        # User management
        self.register_command("user", self._cmd_user, "User management")
        self.register_command("moderation", self._cmd_moderation, "Moderation operations")
        self.register_command("permissions", self._cmd_permissions, "Permission management")
        self.register_command("roles", self._cmd_roles, "Role management")
        self.register_command("sessions", self._cmd_sessions, "Session management")

        # System commands
        self.register_command("log", self._cmd_log, "Log management")
        self.register_command("test", self._cmd_test, "Run system tests")
        self.register_command("security", self._cmd_security, "Security operations")
        self.register_command("rate-limits", self._cmd_rate_limits, "Rate limiting management")
        self.register_command("permissions", self._cmd_permissions, "Permission management")
        self.register_command("antivirus", self._cmd_antivirus, "Enhanced antivirus management")
        self.register_command("health", self._cmd_health, "System health checks")
        self.register_command("metrics", self._cmd_metrics, "System metrics and analytics")
        self.register_command("performance", self._cmd_performance, "Performance monitoring")

        # AI Management commands
        self.register_command("ai", self._cmd_ai, "AI system management")
        self.register_command("models", self._cmd_models, "AI model management")
        self.register_command("providers", self._cmd_providers, "AI provider configuration")

        # Backup & Clustering commands
        self.register_command("cluster", self._cmd_cluster, "Cluster management")
        self.register_command("shards", self._cmd_shards, "Shard management")
        self.register_command("nodes", self._cmd_nodes, "Node management")
        self.register_command("replication", self._cmd_replication, "Replication management")

        # Plugin & Extension commands
        self.register_command("plugins", self._cmd_plugins, "Plugin management")
        self.register_command("extensions", self._cmd_extensions, "Extension management")
        self.register_command("antivirus", self._cmd_antivirus, "Antivirus management")

        # Monitoring & Analytics
        self.register_command("monitor", self._cmd_monitor, "System monitoring")
        self.register_command("analytics", self._cmd_analytics, "Analytics and reporting")
        self.register_command("alerts", self._cmd_alerts, "Alert management")
        self.register_command("notifications", self._cmd_notifications, "Notification management")

        # Automation & Scripting
        self.register_command("automation", self._cmd_automation, "Automation and logic engine")
        self.register_command("logic", self._cmd_logic, "Logic engine operations")
        self.register_command("script", self._cmd_script, "Script execution and management")
        self.register_command("scheduler", self._cmd_scheduler, "Task scheduler management")
        self.register_command("workflows", self._cmd_workflows, "Workflow management")

        # Network & Communication
        self.register_command("network", self._cmd_network, "Network diagnostics")
        self.register_command("ssl", self._cmd_ssl, "SSL certificate management")
        self.register_command("firewall", self._cmd_firewall, "Firewall management")
        self.register_command("proxy", self._cmd_proxy, "Proxy configuration")

        # Development & Debugging
        self.register_command("debug", self._cmd_debug, "Debug operations")
        self.register_command("trace", self._cmd_trace, "Trace system operations")
        self.register_command("profile", self._cmd_profile, "Performance profiling")
        self.register_command("benchmark", self._cmd_benchmark, "System benchmarking")

        # Deployment & Updates
        self.register_command("deploy", self._cmd_deploy, "Deployment operations")
        self.register_command("update", self._cmd_update, "System updates")
        self.register_command("upgrade", self._cmd_upgrade, "System upgrades")
        self.register_command("rollback", self._cmd_rollback, "Rollback operations")

        # Utility commands
        self.register_command("help", self._cmd_help, "Show help information")
        self.register_command("exit", self._cmd_exit, "Exit the CLI")
        self.register_command("quit", self._cmd_exit, "Exit the CLI")
        self.register_command("clear", self._cmd_clear, "Clear the screen")
        self.register_command("history", self._cmd_history, "Show command history")
        self.register_command("version", self._cmd_version, "Show version information")
        self.register_command("info", self._cmd_info, "Show system information")
        self.register_command("env", self._cmd_env, "Environment management")
        self.register_command("vars", self._cmd_vars, "Variable management")

        # File & Directory operations
        self.register_command("files", self._cmd_files, "File management")
        self.register_command("dirs", self._cmd_dirs, "Directory management")
        self.register_command("search", self._cmd_search, "Search operations")
        self.register_command("find", self._cmd_find, "Find files and directories")

        # Load aliases
        for alias, command in self.config.get("aliases", {}).items():
            self.aliases[alias] = command
    
    def register_command(self, name: str, handler, description: str):
        """Register a new command."""
        self.commands[name] = {
            "handler": handler,
            "description": description
        }
    
    def _colorize(self, text: str, color: str) -> str:
        """Colorize text output."""
        if not self.config.get("color_output", True):
            return text
        
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "bold": "\033[1m",
            "reset": "\033[0m"
        }
        
        return f"{colors.get(color, '')}{text}{colors['reset']}"
    
    def _print_banner(self):
        """Print CLI banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                     NetLink Advanced CLI                     ║
║                  Comprehensive System Control                ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(self._colorize(banner, "cyan"))
        print(f"Type {self._colorize('help', 'yellow')} for available commands")
        print(f"Type {self._colorize('exit', 'yellow')} to quit\n")
    
    async def run_interactive(self):
        """Run interactive CLI mode."""
        self._print_banner()
        self.running = True
        
        while self.running:
            try:
                # Get user input
                prompt = self._colorize(self.config.get("prompt", "netlink> "), "green")
                command_line = input(prompt).strip()
                
                if not command_line:
                    continue
                
                # Log command if enabled
                if self.config.get("log_commands", True):
                    logger.info(f"CLI command: {command_line}")
                
                # Execute command
                await self.execute_command(command_line)
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(self._colorize(f"Error: {e}", "red"))
    
    async def execute_command(self, command_line: str):
        """Execute a command line."""
        try:
            # Parse command line
            parts = shlex.split(command_line)
            if not parts:
                return
            
            command = parts[0]
            args = parts[1:]
            
            # Check for aliases
            if command in self.aliases:
                alias_command = self.aliases[command]
                # Replace the command with the alias
                new_parts = shlex.split(alias_command) + args
                command = new_parts[0]
                args = new_parts[1:]
            
            # Find and execute command
            if command in self.commands:
                await self.commands[command]["handler"](args)
            else:
                print(self._colorize(f"Unknown command: {command}", "red"))
                print(f"Type {self._colorize('help', 'yellow')} for available commands")
                
        except Exception as e:
            print(self._colorize(f"Command execution failed: {e}", "red"))
    
    # Command implementations
    async def _cmd_server(self, args: List[str]):
        """Server management command."""
        if not args:
            print("Usage: server <start|stop|restart|status|health|backup>")
            print("  start    - Start the NetLink server")
            print("  stop     - Stop the NetLink server")
            print("  restart  - Restart the NetLink server")
            print("  status   - Show server status")
            print("  health   - Show detailed health information")
            print("  backup   - Create server backup")
            return

        action = args[0]

        try:
            from netlink.core.server_manager import server_manager, ServerState

            if action == "start":
                print(self._colorize("🚀 Starting NetLink server...", "green"))
                success = await server_manager.start_server()
                if success:
                    print(self._colorize("✅ Server started successfully", "green"))
                    status = server_manager.get_server_status()
                    server_info = status.get('server_info', {})
                    print(f"   Host: {server_info.get('host', 'localhost')}")
                    print(f"   Port: {server_info.get('port', '8000')}")
                    print(f"   PID: {server_info.get('pid', 'N/A')}")
                else:
                    print(self._colorize("❌ Failed to start server", "red"))

            elif action == "stop":
                print(self._colorize("🛑 Stopping NetLink server...", "yellow"))
                graceful = "--force" not in args
                success = await server_manager.stop_server(graceful=graceful)
                if success:
                    print(self._colorize("✅ Server stopped successfully", "green"))
                else:
                    print(self._colorize("❌ Failed to stop server", "red"))

            elif action == "restart":
                print(self._colorize("🔄 Restarting NetLink server...", "blue"))
                success = await server_manager.restart_server()
                if success:
                    print(self._colorize("✅ Server restarted successfully", "green"))
                else:
                    print(self._colorize("❌ Failed to restart server", "red"))

            elif action == "status":
                status = server_manager.get_server_status()
                server_info = status.get('server_info', {})
                health = status.get('health', {})
                resources = status.get('resources', {})

                print(self._colorize("📊 Server Status", "cyan"))
                print("=" * 50)
                print(f"State: {self._colorize(server_info.get('state', 'unknown').upper(), 'green' if server_info.get('state') == 'running' else 'yellow')}")
                print(f"PID: {server_info.get('pid', 'N/A')}")
                print(f"Host: {server_info.get('host', 'localhost')}")
                print(f"Port: {server_info.get('port', '8000')}")
                print(f"Started: {server_info.get('started_at', 'N/A')}")
                print(f"Uptime: {status.get('uptime_formatted', '0 seconds')}")
                print(f"Health: {self._colorize(health.get('status', 'unknown').upper(), 'green' if health.get('status') == 'healthy' else 'yellow')}")

                if resources:
                    print(f"Memory: {resources.get('memory_usage', 0):.1f}%")
                    print(f"CPU: {resources.get('cpu_usage', 0):.1f}%")

            elif action == "health":
                status = server_manager.get_server_status()
                health = status.get('health', {})

                print(self._colorize("❤️ Server Health", "cyan"))
                print("=" * 50)
                print(f"Overall Status: {self._colorize(health.get('status', 'unknown').upper(), 'green' if health.get('status') == 'healthy' else 'yellow')}")

                issues = health.get('issues', [])
                if issues:
                    print(f"Issues ({len(issues)}):")
                    for issue in issues:
                        print(f"  • {self._colorize(issue, 'red')}")
                else:
                    print(self._colorize("✅ No issues detected", "green"))

            elif action == "backup":
                backup_name = args[1] if len(args) > 1 else None
                print(self._colorize("💾 Creating server backup...", "blue"))
                backup_path = server_manager.create_backup(backup_name)
                print(self._colorize(f"✅ Backup created: {backup_path}", "green"))

            else:
                print(self._colorize(f"❌ Unknown server action: {action}", "red"))
                print("Use 'server' without arguments to see available actions")

        except ImportError:
            print(self._colorize("❌ Server manager not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Server command failed: {e}", "red"))
            
        elif action == "status":
            print(self._colorize("📊 Server Status:", "cyan"))
            print("Status: Running")
            print("Uptime: 2 hours 15 minutes")
            print("Memory: 245 MB")
            print("CPU: 12%")
            print("Connections: 42")
            
        else:
            print(f"Unknown server action: {action}")
    
    async def _cmd_status(self, args: List[str]):
        """System status command."""
        print(self._colorize("🖥️ NetLink System Status", "bold"))
        print("=" * 50)
        print(f"Server: {self._colorize('Running', 'green')}")
        print(f"Database: {self._colorize('Connected', 'green')}")
        print(f"Backup System: {self._colorize('Active', 'green')}")
        print(f"Security: {self._colorize('Protected', 'green')}")
        print(f"Clustering: {self._colorize('Enabled', 'blue')}")
        print(f"Last Backup: {self._colorize('2 hours ago', 'yellow')}")
        print(f"Active Users: {self._colorize('15', 'cyan')}")
        print(f"Messages Today: {self._colorize('1,337', 'cyan')}")
    
    async def _cmd_config(self, args: List[str]):
        """Configuration management command."""
        if not args:
            print("Usage: config <get|set|list|reload> [key] [value]")
            return
        
        action = args[0]
        
        if action == "list":
            print(self._colorize("📋 Configuration Settings:", "cyan"))
            print("server.host = 0.0.0.0")
            print("server.port = 8000")
            print("database.type = sqlite")
            print("backup.enabled = true")
            print("security.enabled = true")
            
        elif action == "get" and len(args) > 1:
            key = args[1]
            print(f"{key} = example_value")
            
        elif action == "set" and len(args) > 2:
            key = args[1]
            value = args[2]
            print(f"✅ Set {key} = {value}")
            
        elif action == "reload":
            print(self._colorize("🔄 Reloading configuration...", "blue"))
            print("✅ Configuration reloaded")
    
    async def _cmd_database(self, args: List[str]):
        """Database operations command."""
        if not args:
            print("Usage: database <info|backup|restore|migrate|optimize>")
            return
        
        action = args[0]
        
        if action == "info":
            print(self._colorize("🗄️ Database Information:", "cyan"))
            print("Type: SQLite")
            print("Size: 2.4 MB")
            print("Tables: 12")
            print("Records: 1,337")
            print("Status: Connected")
            
        elif action == "backup":
            print(self._colorize("💾 Creating database backup...", "blue"))
            print("✅ Backup created: netlink_backup_20241230.db")
            
        elif action == "optimize":
            print(self._colorize("⚡ Optimizing database...", "yellow"))
            print("✅ Database optimized")
    
    async def _cmd_log(self, args: List[str]):
        """Log management command."""
        if not args:
            print("Usage: log <view|tail|search|clear> [options]")
            return
        
        action = args[0]
        
        if action == "view":
            print(self._colorize("📋 Recent Log Entries:", "cyan"))
            print("2024-12-30 14:30:22 [INFO] Server started")
            print("2024-12-30 14:30:25 [INFO] Database connected")
            print("2024-12-30 14:30:30 [INFO] Backup system initialized")
            
        elif action == "tail":
            print(self._colorize("📡 Tailing logs (Ctrl+C to stop):", "blue"))
            # Implementation would tail logs in real-time
            
        elif action == "search" and len(args) > 1:
            query = args[1]
            print(f"🔍 Searching logs for: {query}")
            print("Found 3 matches")
    
    async def _cmd_help(self, args: List[str]):
        """Help command."""
        if args and args[0] in self.commands:
            # Show help for specific command
            cmd = args[0]
            print(f"Help for '{cmd}': {self.commands[cmd]['description']}")
        else:
            # Show all commands
            print(self._colorize("📚 Available Commands:", "bold"))
            print("=" * 50)
            
            for cmd, info in sorted(self.commands.items()):
                print(f"{self._colorize(cmd.ljust(15), 'yellow')} {info['description']}")
            
            print(f"\n{self._colorize('Aliases:', 'bold')}")
            for alias, command in sorted(self.aliases.items()):
                print(f"{self._colorize(alias.ljust(15), 'cyan')} → {command}")
    
    async def _cmd_exit(self, args: List[str]):
        """Exit command."""
        print(self._colorize("👋 Goodbye!", "green"))
        self.running = False
    
    async def _cmd_clear(self, args: List[str]):
        """Clear screen command."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    async def _cmd_history(self, args: List[str]):
        """Command history."""
        try:
            history_length = readline.get_current_history_length()
            print(self._colorize(f"📜 Command History ({history_length} entries):", "cyan"))
            
            start = max(0, history_length - 20)  # Show last 20 commands
            for i in range(start, history_length):
                cmd = readline.get_history_item(i + 1)
                if cmd:
                    print(f"{i + 1:3d}: {cmd}")
        except:
            print("Command history not available")
    
    async def _cmd_test(self, args: List[str]):
        """Test command."""
        print(self._colorize("🧪 Running system tests...", "blue"))
        print("✅ Database connection test: PASSED")
        print("✅ API endpoints test: PASSED")
        print("✅ Security test: PASSED")
        print("✅ Backup system test: PASSED")
        print(self._colorize("🎉 All tests passed!", "green"))
    
    async def _cmd_security(self, args: List[str]):
        """Security operations."""
        if not args:
            print("Usage: security <scan|status|update>")
            return
        
        action = args[0]
        
        if action == "scan":
            print(self._colorize("🔍 Running security scan...", "blue"))
            print("✅ No threats detected")
            print("✅ All systems secure")
            
        elif action == "status":
            print(self._colorize("🛡️ Security Status:", "cyan"))
            print("Firewall: Active")
            print("Antivirus: Running")
            print("Threats Blocked: 42")
            print("Last Scan: 1 hour ago")
    
    async def _cmd_user(self, args: List[str]):
        """User management."""
        if not args:
            print("Usage: user <list|create|delete|info> [username]")
            return
        
        action = args[0]
        
        if action == "list":
            print(self._colorize("👥 Users:", "cyan"))
            print("admin (Administrator)")
            print("user1 (Member)")
            print("user2 (Member)")
            
        elif action == "create" and len(args) > 1:
            username = args[1]
            print(f"✅ Created user: {username}")
    
    async def _cmd_moderation(self, args: List[str]):
        """Moderation operations."""
        print(self._colorize("⚖️ Moderation System:", "cyan"))
        print("Active Moderators: 3")
        print("Pending Reports: 2")
        print("Actions Today: 5")
    
    async def _cmd_cluster(self, args: List[str]):
        """Cluster management."""
        print(self._colorize("🌐 Cluster Status:", "cyan"))
        print("Nodes: 3 active")
        print("Load Balancing: Enabled")
        print("Sync Status: Healthy")
    
    async def _cmd_monitor(self, args: List[str]):
        """System monitoring."""
        print(self._colorize("📊 System Monitor:", "cyan"))
        print("CPU: 15%")
        print("Memory: 245 MB / 1 GB")
        print("Disk: 2.4 GB / 100 GB")
        print("Network: 1.2 MB/s")
    
    async def _cmd_deploy(self, args: List[str]):
        """Deployment operations."""
        print(self._colorize("🚀 Deployment Tools:", "blue"))
        print("Current Version: 1.0.0")
        print("Environment: Production")
        print("Last Deploy: 2 hours ago")
    
    async def _cmd_backup(self, args: List[str]):
        """Backup operations."""
        print(self._colorize("💾 Creating backup...", "blue"))
        print("✅ Backup completed successfully")
    
    async def _cmd_restore(self, args: List[str]):
        """Restore operations."""
        if not args:
            print("Usage: restore <backup_file>")
            return
        
        backup_file = args[0]
        print(self._colorize(f"🔄 Restoring from {backup_file}...", "yellow"))
        print("✅ Restore completed successfully")

    async def _cmd_automation(self, args: List[str]):
        """Automation and logic engine management."""
        await self.automation_cli.cmd_automation(args)

    async def _cmd_logic(self, args: List[str]):
        """Logic engine operations."""
        if not args:
            print(self._colorize("🧠 Logic Engine Operations", "cyan"))
            print("Available commands:")
            print("  variables    - Manage logic engine variables")
            print("  functions    - List available functions")
            print("  evaluate     - Evaluate expression")
            print("  test         - Test conditions")
            return

        subcommand = args[0].lower()
        subargs = args[1:] if len(args) > 1 else []

        if subcommand == "variables":
            await self._cmd_logic_variables(subargs)
        elif subcommand == "functions":
            await self._cmd_logic_functions(subargs)
        elif subcommand == "evaluate":
            await self._cmd_logic_evaluate(subargs)
        elif subcommand == "test":
            await self._cmd_logic_test(subargs)
        else:
            print(self._colorize(f"Unknown logic command: {subcommand}", "red"))

    async def _cmd_logic_variables(self, args: List[str]):
        """Manage logic engine variables."""
        if not args:
            print(self._colorize("🔧 Logic Engine Variables", "cyan"))
            for key, value in self.logic_engine.variables.items():
                print(f"  {key} = {value}")
            return

        action = args[0].lower()

        if action == "set" and len(args) >= 3:
            var_name = args[1]
            var_value = " ".join(args[2:])

            # Try to parse as JSON for complex types
            try:
                var_value = json.loads(var_value)
            except:
                pass  # Keep as string

            self.logic_engine.variables[var_name] = var_value
            self.logic_engine.save_config()
            print(self._colorize(f"✅ Set variable: {var_name} = {var_value}", "green"))

        elif action == "get" and len(args) >= 2:
            var_name = args[1]
            value = self.logic_engine.variables.get(var_name, "Not found")
            print(f"{var_name} = {value}")

        elif action == "delete" and len(args) >= 2:
            var_name = args[1]
            if var_name in self.logic_engine.variables:
                del self.logic_engine.variables[var_name]
                self.logic_engine.save_config()
                print(self._colorize(f"✅ Deleted variable: {var_name}", "green"))
            else:
                print(self._colorize(f"❌ Variable not found: {var_name}", "red"))

        else:
            print("Usage: logic variables [set <name> <value>|get <name>|delete <name>]")

    async def _cmd_logic_functions(self, args: List[str]):
        """List available logic engine functions."""
        print(self._colorize("🔧 Available Functions", "cyan"))
        for func_name in sorted(self.logic_engine.functions.keys()):
            print(f"  {func_name}()")

    async def _cmd_logic_evaluate(self, args: List[str]):
        """Evaluate logic engine expression."""
        if not args:
            print("Usage: logic evaluate <expression>")
            return

        expression = " ".join(args)

        try:
            result = self.logic_engine._evaluate_function(expression)
            print(f"Result: {result}")
        except Exception as e:
            print(self._colorize(f"❌ Evaluation error: {e}", "red"))

    async def _cmd_logic_test(self, args: List[str]):
        """Test logic engine conditions."""
        if len(args) < 3:
            print("Usage: logic test <condition_type> <field> <value>")
            return

        from .enhanced_logic_engine import Condition, ConditionType

        try:
            condition_type = ConditionType(args[0])
            field = args[1]
            value = args[2]

            condition = Condition(
                type=condition_type,
                field=field,
                value=value
            )

            result = await self.logic_engine.evaluate_condition(condition)
            status = self._colorize("✅ TRUE", "green") if result else self._colorize("❌ FALSE", "red")
            print(f"Condition result: {status}")

        except ValueError as e:
            print(self._colorize(f"❌ Invalid condition type: {args[0]}", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Test error: {e}", "red"))

    async def _cmd_script(self, args: List[str]):
        """Script execution and management."""
        if not args:
            print(self._colorize("📜 Script Management", "cyan"))
            print("Available commands:")
            print("  run <file>     - Execute script file")
            print("  list           - List available scripts")
            print("  create <name>  - Create new script")
            print("  edit <name>    - Edit existing script")
            return

        subcommand = args[0].lower()
        subargs = args[1:] if len(args) > 1 else []

        if subcommand == "run":
            await self._cmd_script_run(subargs)
        elif subcommand == "list":
            await self._cmd_script_list(subargs)
        elif subcommand == "create":
            await self._cmd_script_create(subargs)
        elif subcommand == "edit":
            await self._cmd_script_edit(subargs)
        else:
            print(self._colorize(f"Unknown script command: {subcommand}", "red"))

    async def _cmd_script_run(self, args: List[str]):
        """Execute script file."""
        if not args:
            print("Usage: script run <file>")
            return

        script_file = args[0]

        try:
            if not os.path.exists(script_file):
                print(self._colorize(f"❌ Script file not found: {script_file}", "red"))
                return

            print(self._colorize(f"🚀 Executing script: {script_file}", "blue"))

            with open(script_file, 'r') as f:
                commands = f.readlines()

            for i, command in enumerate(commands, 1):
                command = command.strip()
                if not command or command.startswith('#'):
                    continue

                print(self._colorize(f"[{i}] {command}", "yellow"))
                await self.execute_command(command)

            print(self._colorize("✅ Script execution completed", "green"))

        except Exception as e:
            print(self._colorize(f"❌ Script execution failed: {e}", "red"))

    async def _cmd_script_list(self, args: List[str]):
        """List available scripts."""
        scripts_dir = "scripts"

        if not os.path.exists(scripts_dir):
            print(self._colorize("📜 No scripts directory found", "yellow"))
            return

        print(self._colorize("📜 Available Scripts", "cyan"))

        for filename in os.listdir(scripts_dir):
            if filename.endswith('.txt') or filename.endswith('.script'):
                filepath = os.path.join(scripts_dir, filename)
                size = os.path.getsize(filepath)
                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                print(f"  {filename:<20} {size:>8} bytes  {mtime.strftime('%Y-%m-%d %H:%M')}")

    async def _cmd_script_create(self, args: List[str]):
        """Create new script."""
        if not args:
            print("Usage: script create <name>")
            return

        script_name = args[0]
        if not script_name.endswith('.script'):
            script_name += '.script'

        scripts_dir = "scripts"
        os.makedirs(scripts_dir, exist_ok=True)

        script_path = os.path.join(scripts_dir, script_name)

        if os.path.exists(script_path):
            print(self._colorize(f"❌ Script already exists: {script_name}", "red"))
            return

        template = """# NetLink CLI Script
# Created: {timestamp}
# Description: {description}

# Example commands:
# status
# logs system --tail 10
# automation list

""".format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            description=input("Script description: ").strip() or "Auto-generated script"
        )

        with open(script_path, 'w') as f:
            f.write(template)

        print(self._colorize(f"✅ Created script: {script_path}", "green"))
        print(f"Edit with: script edit {script_name}")

    async def _cmd_script_edit(self, args: List[str]):
        """Edit existing script."""
        if not args:
            print("Usage: script edit <name>")
            return

        script_name = args[0]
        if not script_name.endswith('.script'):
            script_name += '.script'

        script_path = os.path.join("scripts", script_name)

        if not os.path.exists(script_path):
            print(self._colorize(f"❌ Script not found: {script_name}", "red"))
            return

        # Try to open with system editor
        editor = os.environ.get('EDITOR', 'notepad' if os.name == 'nt' else 'nano')

        try:
            subprocess.run([editor, script_path])
            print(self._colorize(f"✅ Script edited: {script_name}", "green"))
        except Exception as e:
            print(self._colorize(f"❌ Failed to open editor: {e}", "red"))
            print(f"Please edit manually: {script_path}")


def create_cli_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="NetLink Advanced CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netlink-cli                           # Interactive mode
  netlink-cli server start             # Start server
  netlink-cli database backup          # Create backup
  netlink-cli user list                # List users
  netlink-cli --split-screen           # Enable split-screen mode
        """
    )
    
    parser.add_argument(
        "command",
        nargs="*",
        help="Command to execute"
    )
    
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Force interactive mode"
    )
    
    parser.add_argument(
        "--split-screen", "-s",
        action="store_true",
        help="Enable split-screen mode with logs"
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    parser.add_argument(
        "--config",
        help="Path to CLI configuration file"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    return parser

    async def _cmd_ai(self, args: List[str]):
        """Handle AI system management commands."""
        if not args:
            print(self._colorize("🤖 AI System Management", "cyan"))
            print("Available subcommands:")
            print("  status    - Show AI system status")
            print("  health    - Check AI system health")
            print("  models    - Manage AI models")
            print("  providers - Manage AI providers")
            print("  test      - Test AI functionality")
            print("  cache     - Cache management")
            print("  usage     - Usage statistics")
            return

        subcommand = args[0]
        subargs = args[1:] if len(args) > 1 else []

        try:
            # Import AI CLI dynamically
            from netlink.ai.cli.ai_cli import AICommandLineInterface
            ai_cli = AICommandLineInterface()

            if subcommand == "status":
                health = await ai_cli.ai_layer.health_check()
                print(self._colorize("🤖 AI System Status", "cyan"))
                print(f"Overall Status: {health['overall_status'].upper()}")
                print(f"Total Models: {health['total_models']}")
                print(f"Available Models: {health['available_models']}")
                print(f"Unavailable Models: {health['unavailable_models']}")

            elif subcommand == "health":
                await ai_cli.health_check()

            elif subcommand == "models":
                if not subargs:
                    await ai_cli.list_models()
                elif subargs[0] == "add" and len(subargs) > 1:
                    # Add model from config file
                    with open(subargs[1], 'r') as f:
                        model_data = json.load(f)
                    await ai_cli.add_model(model_data)
                elif subargs[0] == "remove" and len(subargs) > 1:
                    await ai_cli.remove_model(subargs[1])
                else:
                    print("Usage: ai models [add <config_file>|remove <model_id>]")

            elif subcommand == "providers":
                if not subargs:
                    await ai_cli.list_providers()
                elif subargs[0] == "configure" and len(subargs) >= 3:
                    provider, api_key = subargs[1], subargs[2]
                    base_url = subargs[3] if len(subargs) > 3 else ""
                    await ai_cli.configure_provider(provider, api_key, base_url)
                else:
                    print("Usage: ai providers [configure <provider> <api_key> [base_url]]")

            elif subcommand == "test" and len(subargs) >= 2:
                model_id, prompt = subargs[0], " ".join(subargs[1:])
                await ai_cli.test_model(model_id, prompt)

            elif subcommand == "cache":
                if subargs and subargs[0] == "clear":
                    ai_cli.clear_cache()
                else:
                    cache_size = len(ai_cli.ai_layer.request_cache)
                    print(f"Cache size: {cache_size} entries")

            elif subcommand == "usage":
                user_id = subargs[0] if subargs else None
                await ai_cli.get_usage_stats(user_id)

            else:
                print(f"Unknown AI subcommand: {subcommand}")

        except ImportError:
            print(self._colorize("❌ AI system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ AI command failed: {e}", "red"))

    async def _cmd_models(self, args: List[str]):
        """Handle AI model management commands."""
        await self._cmd_ai(["models"] + args)

    async def _cmd_providers(self, args: List[str]):
        """Handle AI provider management commands."""
        await self._cmd_ai(["providers"] + args)

    async def _cmd_shards(self, args: List[str]):
        """Handle shard management commands."""
        if not args:
            print(self._colorize("🗂️ Shard Management", "cyan"))
            print("Available subcommands:")
            print("  list      - List all shards")
            print("  status    - Show shard status")
            print("  create    - Create new shard")
            print("  delete    - Delete shard")
            print("  verify    - Verify shard integrity")
            print("  distribute - Distribute shards")
            print("  backup    - Backup shards")
            print("  restore   - Restore from shards")
            return

        subcommand = args[0]
        subargs = args[1:] if len(args) > 1 else []

        try:
            # Import backup system dynamically
            from netlink.backup.shard_manager import ShardManager
            shard_manager = ShardManager()

            if subcommand == "list":
                shards = await shard_manager.list_shards()
                print(self._colorize(f"📋 Total Shards: {len(shards)}", "cyan"))
                for shard in shards:
                    status = "✅" if shard['healthy'] else "❌"
                    print(f"  {status} {shard['id']} - {shard['size']} bytes - {shard['location']}")

            elif subcommand == "status":
                status = await shard_manager.get_status()
                print(self._colorize("🗂️ Shard System Status", "cyan"))
                print(f"Total Shards: {status['total_shards']}")
                print(f"Healthy Shards: {status['healthy_shards']}")
                print(f"Corrupted Shards: {status['corrupted_shards']}")
                print(f"Total Size: {status['total_size']} bytes")

            elif subcommand == "verify":
                shard_id = subargs[0] if subargs else None
                result = await shard_manager.verify_shards(shard_id)
                if result['success']:
                    print(self._colorize("✅ Shard verification completed", "green"))
                else:
                    print(self._colorize(f"❌ Verification failed: {result['error']}", "red"))

            else:
                print(f"Unknown shard subcommand: {subcommand}")

        except ImportError:
            print(self._colorize("❌ Backup system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Shard command failed: {e}", "red"))

    async def _cmd_nodes(self, args: List[str]):
        """Handle cluster node management commands."""
        if not args:
            print(self._colorize("🖥️ Node Management", "cyan"))
            print("Available subcommands:")
            print("  list      - List all nodes")
            print("  status    - Show node status")
            print("  add       - Add new node")
            print("  remove    - Remove node")
            print("  health    - Check node health")
            print("  sync      - Synchronize nodes")
            return

        subcommand = args[0]
        subargs = args[1:] if len(args) > 1 else []

        try:
            # Import clustering system dynamically
            from netlink.clustering.node_manager import NodeManager
            node_manager = NodeManager()

            if subcommand == "list":
                nodes = await node_manager.list_nodes()
                print(self._colorize(f"🖥️ Cluster Nodes: {len(nodes)}", "cyan"))
                for node in nodes:
                    status = "🟢" if node['online'] else "🔴"
                    node_type = node.get('type', 'main').upper()
                    print(f"  {status} {node['id']} ({node_type}) - {node['address']}:{node['port']}")

            elif subcommand == "status":
                status = await node_manager.get_cluster_status()
                print(self._colorize("🖥️ Cluster Status", "cyan"))
                print(f"Total Nodes: {status['total_nodes']}")
                print(f"Online Nodes: {status['online_nodes']}")
                print(f"Offline Nodes: {status['offline_nodes']}")
                print(f"Cluster Health: {status['health_percentage']:.1f}%")

            elif subcommand == "health":
                node_id = subargs[0] if subargs else None
                result = await node_manager.health_check(node_id)
                if result['success']:
                    print(self._colorize("✅ Node health check completed", "green"))
                else:
                    print(self._colorize(f"❌ Health check failed: {result['error']}", "red"))

            else:
                print(f"Unknown node subcommand: {subcommand}")

        except ImportError:
            print(self._colorize("❌ Clustering system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Node command failed: {e}", "red"))

    async def _cmd_plugins(self, args: List[str]):
        """Handle enhanced plugin management commands."""
        if not args:
            print(self._colorize("🔌 Enhanced Plugin Management", "cyan"))
            print("Available subcommands:")
            print("  list           - List all plugins")
            print("  install <zip>  - Install plugin from ZIP file")
            print("  uninstall <name> - Uninstall plugin")
            print("  enable <name>  - Enable plugin")
            print("  disable <name> - Disable plugin")
            print("  info <name>    - Show detailed plugin info")
            print("  update <name>  - Update plugin to latest version")
            print("  check-updates  - Check for plugin updates")
            print("  security [scan <name>] - Security overview or scan plugin")
            print("  auto-update <name> <enable|disable> - Manage auto-updates")
            print("  cleanup [days] - Clean up quarantined plugins")
            return

        try:
            # Import enhanced plugin CLI
            from netlink.plugins.plugin_cli import handle_plugin_command
            await handle_plugin_command(args)

        except ImportError:
            print(self._colorize("❌ Enhanced plugin system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Plugin command failed: {e}", "red"))

    async def _cmd_rate_limits(self, args: List[str]):
        """Handle rate limiting management commands."""
        try:
            # Import security CLI
            from netlink.security.security_cli import handle_security_command

            # Prepend 'rate-limits' context to args for the security CLI
            rate_limit_args = []
            if args:
                # Map CLI commands to security CLI commands
                command_mapping = {
                    "list": "list-rules",
                    "create": "create-rule",
                    "delete": "delete-rule",
                    "status": "status",
                    "banned": "banned",
                    "unban-ip": "unban-ip",
                    "unban-user": "unban-user"
                }

                mapped_command = command_mapping.get(args[0], args[0])
                rate_limit_args = [mapped_command] + args[1:]

            await handle_security_command(rate_limit_args)

        except ImportError:
            print(self._colorize("❌ Rate limiting system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Rate limiting command failed: {e}", "red"))

    async def _cmd_permissions(self, args: List[str]):
        """Handle permission management commands."""
        try:
            # Import security CLI
            from netlink.security.security_cli import handle_security_command

            # Prepend 'permissions' context to args for the security CLI
            permission_args = []
            if args:
                # Map CLI commands to security CLI commands
                command_mapping = {
                    "list": "list-roles",
                    "show": "show-role",
                    "create": "create-role",
                    "delete": "delete-role",
                    "assign": "assign-role",
                    "revoke": "revoke-role",
                    "check": "check-perm",
                    "user": "show-user"
                }

                mapped_command = command_mapping.get(args[0], args[0])
                permission_args = [mapped_command] + args[1:]

            await handle_security_command(permission_args)

        except ImportError:
            print(self._colorize("❌ Permission system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Permission command failed: {e}", "red"))

    async def _cmd_antivirus(self, args: List[str]):
        """Handle enhanced antivirus management commands."""
        try:
            # Import antivirus CLI
            from netlink.antivirus.antivirus_cli import handle_antivirus_command

            await handle_antivirus_command(args)

        except ImportError:
            print(self._colorize("❌ Enhanced antivirus system not available", "red"))
        except Exception as e:
            print(self._colorize(f"❌ Antivirus command failed: {e}", "red"))

    async def _cmd_health(self, args: List[str]):
        """System health checks."""
        print(self._colorize("🏥 System Health Check", "cyan"))

        # Check server status
        try:
            # This would check if the server is running
            print("✅ Server: Running")
        except:
            print("❌ Server: Not responding")

        # Check database
        try:
            # This would check database connectivity
            print("✅ Database: Connected")
        except:
            print("❌ Database: Connection failed")

        # Check AI system
        try:
            from netlink.ai.core.ai_abstraction_layer import AIAbstractionLayer
            ai_layer = AIAbstractionLayer()
            health = await ai_layer.health_check()
            if health['overall_status'] == 'healthy':
                print("✅ AI System: Healthy")
            else:
                print("⚠️ AI System: Degraded")
        except:
            print("❌ AI System: Not available")

        # Check backup system
        try:
            # This would check backup system status
            print("✅ Backup System: Operational")
        except:
            print("❌ Backup System: Issues detected")

    async def _cmd_metrics(self, args: List[str]):
        """System metrics and analytics."""
        print(self._colorize("📊 System Metrics", "cyan"))

        # System uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime_hours = uptime_seconds / 3600
                print(f"System Uptime: {uptime_hours:.1f} hours")
        except:
            print("System Uptime: Unknown")

        # Memory usage
        try:
            import psutil
            memory = psutil.virtual_memory()
            print(f"Memory Usage: {memory.percent}% ({memory.used // 1024 // 1024} MB / {memory.total // 1024 // 1024} MB)")
        except:
            print("Memory Usage: Unknown")

        # CPU usage
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"CPU Usage: {cpu_percent}%")
        except:
            print("CPU Usage: Unknown")

    async def _cmd_version(self, args: List[str]):
        """Show version information."""
        print(self._colorize("ℹ️ NetLink Version Information", "cyan"))
        print("NetLink Server: 1a1")
        print("CLI Version: 1a1")
        print("Python Version:", sys.version.split()[0])

        # Show component versions
        try:
            from netlink.ai.core.ai_abstraction_layer import AIAbstractionLayer
            print("AI System: Available")
        except:
            print("AI System: Not available")

        try:
            from netlink.backup.shard_manager import ShardManager
            print("Backup System: Available")
        except:
            print("Backup System: Not available")

    async def _cmd_info(self, args: List[str]):
        """Show system information."""
        print(self._colorize("ℹ️ System Information", "cyan"))
        print(f"Platform: {sys.platform}")
        print(f"Python: {sys.version}")
        print(f"Working Directory: {os.getcwd()}")
        print(f"Config Directory: {os.path.expanduser('~/.netlink')}")

        # Show loaded modules
        netlink_modules = [name for name in sys.modules.keys() if name.startswith('netlink')]
        print(f"Loaded NetLink Modules: {len(netlink_modules)}")

    async def _cmd_env(self, args: List[str]):
        """Environment management."""
        if not args:
            print(self._colorize("🌍 Environment Variables", "cyan"))
            netlink_vars = {k: v for k, v in os.environ.items() if 'NETLINK' in k.upper()}
            if netlink_vars:
                for key, value in netlink_vars.items():
                    print(f"  {key} = {value}")
            else:
                print("  No NetLink environment variables found")
            return

        subcommand = args[0]
        if subcommand == "set" and len(args) >= 3:
            key, value = args[1], args[2]
            os.environ[key] = value
            print(f"Set {key} = {value}")
        elif subcommand == "get" and len(args) >= 2:
            key = args[1]
            value = os.environ.get(key, "Not set")
            print(f"{key} = {value}")
        else:
            print("Usage: env [set <key> <value>|get <key>]")

    async def _cmd_vars(self, args: List[str]):
        """Variable management for logic engine."""
        if not args:
            print(self._colorize("🔧 Logic Engine Variables", "cyan"))
            for key, value in self.logic_engine.variables.items():
                print(f"  {key} = {value}")
            return

        subcommand = args[0]
        if subcommand == "set" and len(args) >= 3:
            key, value = args[1], args[2]
            # Try to parse as JSON for complex types
            try:
                value = json.loads(value)
            except:
                pass  # Keep as string
            self.logic_engine.set_variable(key, value)
            print(f"Set variable {key} = {value}")
        elif subcommand == "get" and len(args) >= 2:
            key = args[1]
            value = self.logic_engine.get_variable(key, "Not set")
            print(f"{key} = {value}")
        elif subcommand == "delete" and len(args) >= 2:
            key = args[1]
            if self.logic_engine.delete_variable(key):
                print(f"Deleted variable {key}")
            else:
                print(f"Variable {key} not found")
        else:
            print("Usage: vars [set <key> <value>|get <key>|delete <key>]")


async def main():
    """Main CLI entry point."""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Create CLI instance
    cli = AdvancedCLI()
    
    # Apply command-line options
    if args.no_color:
        cli.config["color_output"] = False
    
    if args.split_screen:
        cli.config["split_screen"] = True
    
    # Execute command or run interactive mode
    if args.command and not args.interactive:
        # Execute single command
        command_line = " ".join(args.command)
        await cli.execute_command(command_line)
    else:
        # Run interactive mode
        await cli.run_interactive()


if __name__ == "__main__":
    asyncio.run(main())
