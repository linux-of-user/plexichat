# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalCall=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportIndexIssue=false
# pyright: reportGeneralTypeIssues=false
import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

try:
    import keyboard
    HAS_KEYBOARD = True
except ImportError:
    keyboard = None
    HAS_KEYBOARD = False
import psutil
import logging

"""
Enhanced Split-Screen Console Interface
Provides advanced split-screen functionality with real-time updates, interactive features, and improved layout.


# Rich library imports (optional)
try:
    from rich.align import Align
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

@dataclass
class LogEntry:
    """Enhanced log entry with additional metadata."""
        timestamp: datetime
    level: str
    module: str
    message: str
    thread_id: str
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    duration: Optional[float] = None
    extra_data: Optional[Dict[str, Any]] = None

@dataclass
class SystemMetrics:
    System performance metrics."""
        cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    disk_percent: float
    active_connections: int
    requests_per_minute: int
    error_rate: float
    uptime: timedelta

class EnhancedSplitScreen:
    """Enhanced split-screen console interface with advanced features."""
        def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.console = Console() if RICH_AVAILABLE else None
        self.layout = None
        self.live_display = None
        self.active = False
        self.update_thread = None

        # Data storage
        self.log_buffer = deque(maxlen=1000)
        self.metrics_history = deque(maxlen=100)
        self.command_history = deque(maxlen=50)
        self.active_operations = {}

        # Statistics
        self.stats = {
            'total_logs': 0,
            'errors': 0,
            'warnings': 0,
            'requests': 0,
            'start_time': datetime.now(),
            'last_error': None,
            'peak_memory': 0,
            'peak_cpu': 0
        }

        # Configuration
        self.config = {
            'refresh_rate': 4,  # Hz
            'max_log_lines': 15,
            'show_thread_info': True,
            'show_performance_graph': True,
            'auto_scroll': True,
            'highlight_errors': True,
            'show_system_metrics': True
        }

        # Interactive features
        self.command_queue = queue.Queue()
        self.input_mode = False
        self.current_filter = None

        if not RICH_AVAILABLE:
            self.logger.info("Warning: Rich library not available. Split-screen functionality will be limited.")

    def start(self):
        """Start the enhanced split-screen interface."""
        if not RICH_AVAILABLE:
            self._start_fallback_mode()
            return

        if self.active:
            return

        self.active = True
        self.layout = self._create_enhanced_layout()

        self.live_display = Live(
            self.layout,
            console=self.console,
            refresh_per_second=self.config['refresh_rate'],
            screen=True
        )

        # Start update thread
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        if self.update_thread and hasattr(self.update_thread, "start"):
            self.update_thread.start()

        # Start input handler
        input_thread = threading.Thread(target=self._input_handler, daemon=True)
        if input_thread and hasattr(input_thread, "start"): input_thread.start()

        if self.logger:
            self.logger.info("Enhanced split-screen interface started")

    def stop(self):
        """Stop the split-screen interface."""
        self.active = False
        if self.live_display:
            if self.live_display and hasattr(self.live_display, "stop"):
                self.live_display.stop()
        if self.logger:
            self.logger.info("Enhanced split-screen interface stopped")

    def _create_enhanced_layout(self):
        """Create the enhanced split-screen layout."""
        if not RICH_AVAILABLE:
            return None

        layout = Layout()

        # Main structure
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main"),
            Layout(name="input", size=3)
        )

        # Main area split
        layout["main"].split_row(
            Layout(name="left_panel", ratio=2),
            Layout(name="right_panel", ratio=1)
        )

        # Left panel split
        layout["left_panel"].split_column(
            Layout(name="logs", ratio=3),
            Layout(name="operations", ratio=1)
        )

        # Right panel split
        layout["right_panel"].split_column(
            Layout(name="metrics", ratio=1),
            Layout(name="system", ratio=1),
            Layout(name="commands", ratio=1)
        )

        return layout

    def _update_loop(self):
        """Main update loop for the display."""
        if not RICH_AVAILABLE or not self.live_display:
            return

        try:
            with self.live_display:
                while self.active:
                    self._update_display()
                    time.sleep(1.0 / self.config['refresh_rate'])
        except KeyboardInterrupt:
            self.active = False
        except Exception as e:
            if self.logger:
                self.logger.error(f"Split-screen update error: {e}", exc_info=True)

    def _update_display(self):
        """Update all display components."""
        if not RICH_AVAILABLE or not self.layout or not self.live_display:
            return

        try:
            # Update header
            self._update_header()

            # Update logs panel
            self._update_logs_panel()

            # Update operations panel
            self._update_operations_panel()

            # Update metrics panel
            self._update_metrics_panel()

            # Update system panel
            self._update_system_panel()

            # Update commands panel
            self._update_commands_panel()

            # Update input panel
            self._update_input_panel()

        except Exception as e:
            if self.logger:
                self.logger.error(f"Display update error: {e}")

    def _update_header(self):
        """Update the header panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        uptime = datetime.now() - self.stats['start_time']
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds

        status_text = (
            f"[bold blue]PlexiChat Enhanced Console[/bold blue] | "
            f"Uptime: {uptime_str} | "
            f"Logs: {self.stats['total_logs']} | "
            f"Errors: {self.stats['errors']} | "
            f"Requests: {self.stats['requests']}"
        )

        if self.current_filter:
            status_text += f" | Filter: {self.current_filter}"

        self.layout["header"].update(Panel(
            Align.center(status_text),
            style="blue",
            title="System Status"
        ))

    def _update_logs_panel(self):
        """Update the logs display panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        log_table = Table(show_header=True, header_style="bold magenta", expand=True)
        log_table.add_column("Time", style="dim", width=12)
        log_table.add_column("Level", width=8)
        log_table.add_column("Module", width=15)
        log_table.add_column("Message", ratio=1)

        # Get recent logs
        recent_logs = list(self.log_buffer)[-self.config['max_log_lines']:]

        for entry in recent_logs:
            level_style = self._get_level_style(entry.level)
            message = entry.message

            # Truncate long messages
            if len(message) > 80:
                message = message[:77] + "..."

            # Highlight errors
            if entry.level.upper() in ['ERROR', 'CRITICAL'] and self.config['highlight_errors']:
                message = f"[bold red]{message}[/bold red]"

            log_table.add_row(
                entry.timestamp.strftime('%H:%M:%S'),
                f"[{level_style}]{entry.level}[/{level_style}]",
                entry.module,
                message
            )

        self.layout["logs"].update(Panel(
            log_table,
            title="Recent Logs",
            border_style="green"
        ))

    def _update_operations_panel(self):
        """Update the operations panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        operations_table = Table(show_header=True, header_style="bold cyan", expand=True)
        operations_table.add_column("ID", style="dim", width=10)
        operations_table.add_column("Type", width=12)
        operations_table.add_column("Status", width=10)
        operations_table.add_column("Duration", width=12)

        for op_id, operation in self.active_operations.items():
            duration = "N/A"
            if operation.get('start_time'):
                duration = str(datetime.now() - operation['start_time']).split('.')[0]

            status_style = "green" if operation.get('success') else "yellow"
            operations_table.add_row(
                op_id[:8],
                operation.get('type', 'unknown'),
                f"[{status_style}]{operation.get('status', 'running')}[/{status_style}]",
                duration
            )

        self.layout["operations"].update(Panel(
            operations_table,
            title="Active Operations",
            border_style="cyan"
        ))

    def _get_level_style(self, level: str) -> str:
        """Get the style for a log level.
        level_styles = {
            'DEBUG': 'dim',
            'INFO': 'blue',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold red'
        }
        return level_styles.get(level.upper(), 'white')

    def add_log_entry(self, level: str, module: str, message: str, **kwargs):
        """Add a log entry to the display."""
        entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            module=module,
            message=message,
            thread_id=str(threading.get_ident()),
            **kwargs
        )

        self.log_buffer.append(entry)
        self.stats['total_logs'] += 1

        if level.upper() in ['ERROR', 'CRITICAL']:
            self.stats['errors'] += 1
            self.stats['last_error'] = entry
        elif level.upper() == 'WARNING':
            self.stats['warnings'] += 1

    def start_operation(self, operation_id: str, operation_type: str = "request"):
        """Start tracking an operation.
        self.active_operations[operation_id] = {
            'type': operation_type,
            'status': 'running',
            'start_time': datetime.now(),
            'success': None
        }

    def end_operation(self, operation_id: str, success: bool = True):
        """End tracking an operation."""
        if operation_id in self.active_operations:
            self.active_operations[operation_id]['status'] = 'completed'
            self.active_operations[operation_id]['success'] = success

    def _start_fallback_mode(self):
        Start fallback mode without Rich library."""
        logger = logging.getLogger(__name__)
        logger.info("=" * 80)
        logger.info("PlexiChat Enhanced Console - Fallback Mode")
        logger.info("=" * 80)
        logger.info("Rich library not available. Running in basic mode.")
        logger.info("Press Ctrl+C to exit.")
        logger.info("=" * 80)

        self.active = True

        # Start input handler
        input_thread = threading.Thread(target=self._input_handler, daemon=True)
        if input_thread and hasattr(input_thread, "start"): input_thread.start()

        # Fallback display loop
        self._fallback_loop()

    def _fallback_loop(self):
        """Fallback display loop without Rich library."""
        logger = logging.getLogger(__name__)

        while self.active:
            try:
                # Simple console output
                recent_logs = list(self.log_buffer)[-5:]  # Show last 5 logs
# SECURITY: os.system() removed - use subprocess.run() instead'cls' if os.name == 'nt' else 'clear')
                logger = logging.getLogger(__name__)
                logger.info(f"PlexiChat Console - Logs: {self.stats['total_logs']} | Errors: {self.stats['errors']}")
                logger.info("-" * 80)

                for entry in recent_logs:
                    logger.info(f"[{entry.timestamp.strftime('%H:%M:%S')}] {entry.level}: {entry.message}")

                logger.info("-" * 80)
                logger.info("Press 'q' to quit, 'c' to clear logs")

                time.sleep(2)  # Update every 2 seconds

            except KeyboardInterrupt:
                self.active = False
            except Exception as e:
                logger.error(f"Fallback loop error: {e}")
                time.sleep(1)

    def _update_metrics_panel(self):
        """Update the metrics panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        try:
            # Get current system metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()

            # Update peak values
            self.stats['peak_cpu'] = max(self.stats['peak_cpu'], cpu_percent)
            self.stats['peak_memory'] = max(self.stats['peak_memory'], memory.percent)

            metrics_table = Table(show_header=False, expand=True)
            metrics_table.add_column("Metric", style="bold")
            metrics_table.add_column("Value", style="blue")

            metrics_table.add_row("CPU Usage", f"{cpu_percent:.1f}%")
            metrics_table.add_row("Memory Usage", f"{memory.percent:.1f}%")
            metrics_table.add_row("Peak CPU", f"{self.stats['peak_cpu']:.1f}%")
            metrics_table.add_row("Peak Memory", f"{self.stats['peak_memory']:.1f}%")
            metrics_table.add_row("Active Operations", str(len(self.active_operations)))

            self.layout["metrics"].update(Panel(
                metrics_table,
                title="System Metrics",
                border_style="green"
            ))

        except Exception:
            self.layout["metrics"].update(Panel(
                "[dim]psutil not available\nInstall with: pip install psutil[/dim]",
                title="System Metrics",
                border_style="dim"
            ))

    def _update_system_panel(self):
        """Update the system information panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        try:
            # Network and disk info
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            system_table = Table(show_header=False, expand=True)
            system_table.add_column("Item", style="bold")
            system_table.add_column("Value", style="blue")

            system_table.add_row("Disk Usage", f"{disk.percent:.1f}%")
            system_table.add_row("Disk Free", f"{disk.free // (1024**3):.1f} GB")
            system_table.add_row("Network Sent", f"{network.bytes_sent // (1024**2):.1f} MB")
            system_table.add_row("Network Recv", f"{network.bytes_recv // (1024**2):.1f} MB")

            # Process info
            process = psutil.Process()
            system_table.add_row("Process PID", str(process.pid))
            system_table.add_row("Threads", str(process.num_threads()))

            self.layout["system"].update(Panel(
                system_table,
                title="System Info",
                border_style="blue"
            ))

        except Exception:
            self.layout["system"].update(Panel(
                "[dim]System info unavailable[/dim]",
                title="System Info",
                border_style="dim"
            ))

    def _update_commands_panel(self):
        """Update the commands/help panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        commands_text = Text()
        commands_text.append("Available Commands:\n", style="bold")
        commands_text.append(" ", style="dim")
        commands_text.append("f", style="bold green")
        commands_text.append(" - Filter logs\n", style="dim")
        commands_text.append(" ", style="dim")
        commands_text.append("c", style="bold green")
        commands_text.append(" - Clear logs\n", style="dim")
        commands_text.append(" ", style="dim")
        commands_text.append("s", style="bold green")
        commands_text.append(" - Show stats\n", style="dim")
        commands_text.append(" ", style="dim")
        commands_text.append("r", style="bold green")
        commands_text.append(" - Refresh rate\n", style="dim")
        commands_text.append(" ", style="dim")
        commands_text.append("q", style="bold red")
        commands_text.append(" - Quit\n", style="dim")

        if self.command_history:
            commands_text.append("\nRecent Commands:\n", style="bold")
            for cmd in list(self.command_history)[-3:]:
                commands_text.append(f" {cmd}\n", style="dim cyan")

        self.layout["commands"].update(Panel(
            commands_text,
            title="Commands",
            border_style="magenta"
        ))

    def _update_input_panel(self):
        """Update the input panel."""
        if not RICH_AVAILABLE or not self.layout:
            return

        if self.input_mode:
            input_text = "[bold yellow]Input Mode Active[/bold yellow] - Type command and press Enter"
        else:
            input_text = "[dim]Press any key for commands, 'q' to quit[/dim]"

        self.layout["input"].update(Panel(
            Align.center(input_text),
            style="yellow" if self.input_mode else "dim",
            title="Input"
        ))

    def _input_handler(self):
        """Handle keyboard input for interactive features.
        if not HAS_KEYBOARD:
            # Keyboard module not available, use basic input
            while self.active:
                try:
                    # This is a simplified version - in practice you'd want better input handling
                    time.sleep(1)
                except KeyboardInterrupt:
                    self.active = False
            return

        try:
            while self.active:
                try:
                    event = keyboard.read_event()
                    if event.event_type == keyboard.KEY_DOWN:
                        self._handle_key_press(event.name)
                except Exception:
                    # Fallback if keyboard module not available
                    time.sleep(1)
        except Exception:
            # Fallback for any other errors
            while self.active:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    self.active = False

    def _handle_key_press(self, key: str):
        """Handle individual key presses."""
        if key == 'q':
            self.active = False
        elif key == 'c':
            self.log_buffer.clear()
            self.stats['total_logs'] = 0
            self.stats['errors'] = 0
            self.stats['warnings'] = 0
        elif key == 'f':
            self.input_mode = True
            # In a real implementation, you'd handle filter input
        elif key == 's':
            self._show_detailed_stats()
        elif key == 'r':
            # Toggle refresh rate
            self.config['refresh_rate'] = 8 if self.config['refresh_rate'] == 4 else 4

    def _show_detailed_stats(self):
        Show detailed statistics."""
        uptime = datetime.now() - self.stats['start_time']

        stats_info = {
            'uptime': str(uptime).split('.')[0],
            'total_logs': self.stats['total_logs'],
            'errors': self.stats['errors'],
            'warnings': self.stats['warnings'],
            'requests': self.stats['requests'],
            'peak_cpu': f"{self.stats['peak_cpu']:.1f}%",
            'peak_memory': f"{self.stats['peak_memory']:.1f}%",
            'active_operations': len(self.active_operations),
            'log_buffer_size': len(self.log_buffer)
        }

        if self.logger:
            self.logger.info("Detailed statistics", extra={'stats': stats_info})

    def set_config(self, **config_updates):
        """Update configuration from plexichat.core.config import settings
settings."""
        self.config.update(config_updates)
        if self.logger:
            self.logger.info(f"Configuration updated: {config_updates}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics.
        return {
            **self.stats,
            'active_operations': len(self.active_operations),
            'log_buffer_size': len(self.log_buffer),
            'uptime_seconds': (datetime.now() - self.stats['start_time']).total_seconds()
        }

    def export_logs(self, filename: Optional[str] = None) -> str:
        """Export current logs to file."""
        if not filename:
            filename = f"plexichat_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("PlexiChat Console Logs Export\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Total Entries: {len(self.log_buffer)}\n")
                f.write("=" * 80 + "\n\n")

                for entry in self.log_buffer:
                    f.write(f"[{entry.timestamp.isoformat()}] {entry.level.upper()}: {entry.message}\n")
                    if entry.extra_data:
                        f.write(f"  Extra: {entry.extra_data}\n")
                    f.write("\n")

            if self.logger:
                self.logger.info(f"Logs exported to {filename}")

            return filename

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to export logs: {e}")
            raise
