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

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

import logging

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
    # Define dummy classes if rich is not available
    Align = Console = Layout = Live = Panel = Table = Text = object

"""
Enhanced Split-Screen Console Interface
Provides advanced split-screen functionality with real-time updates, interactive features, and improved layout.
"""

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
    """System performance metrics."""
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
        self.layout = self._create_enhanced_layout() if RICH_AVAILABLE else None
        self.live_display: Optional[Live] = None
        self.active = False
        self.update_thread = None
        self.log_buffer = deque(maxlen=1000)
        self.metrics_history = deque(maxlen=100)
        self.stats = {
            'total_logs': 0, 'errors': 0, 'warnings': 0,
            'requests': 0, 'start_time': datetime.now(),
            'last_error': None, 'peak_memory': 0, 'peak_cpu': 0
        }
        self.config = {
            'refresh_rate': 2, 'max_log_lines': 15,
            'show_thread_info': True, 'highlight_errors': True
        }

    def start(self):
        """Start the enhanced split-screen interface."""
        if not RICH_AVAILABLE:
            self.logger.warning("Rich library not installed. Split-screen view is disabled.")
            return

        if self.active:
            return

        self.active = True
        self.live_display = Live(self.layout, console=self.console, screen=True, refresh_per_second=self.config['refresh_rate'])
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        self.logger.info("Enhanced split-screen interface started.")

    def stop(self):
        """Stop the split-screen interface."""
        self.active = False
        if self.update_thread:
            self.update_thread.join()
        if self.live_display:
            self.live_display.stop()
        self.logger.info("Enhanced split-screen interface stopped.")

    def _create_enhanced_layout(self) -> Optional[Layout]:
        """Create the enhanced split-screen layout."""
        if not RICH_AVAILABLE:
            return None
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(ratio=1, name="main"),
            Layout(size=3, name="footer")
        )
        layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2))
        layout["side"].split(Layout(name="metrics"), Layout(name="stats"))
        return layout

    def _update_loop(self):
        """Main update loop for the display."""
        if not self.live_display: return
        with self.live_display:
            while self.active:
                self._update_display()
                time.sleep(1 / self.config['refresh_rate'])

    def _update_display(self):
        """Update all display components."""
        if not self.layout: return
        self.layout["header"].update(self._get_header_panel())
        self.layout["body"].update(self._get_logs_panel())
        self.layout["metrics"].update(self._get_metrics_panel())
        self.layout["stats"].update(self._get_stats_panel())
        self.layout["footer"].update(self._get_footer_panel())

    def _get_header_panel(self) -> Panel:
        uptime = str(datetime.now() - self.stats['start_time']).split('.')[0]
        header_text = f"[bold blue]PlexiChat Console[/] | Uptime: {uptime} | Logs: {self.stats['total_logs']}"
        return Panel(Align.center(header_text, vertical="middle"), title="Status", border_style="green")

    def _get_logs_panel(self) -> Panel:
        log_table = Table(show_header=True, header_style="bold magenta", expand=True)
        log_table.add_column("Time", style="dim", width=8)
        log_table.add_column("Level", width=8)
        log_table.add_column("Message")

        log_entries = list(self.log_buffer)[-self.config['max_log_lines']:]
        for entry in log_entries:
            level_style = self._get_level_style(entry.level)
            log_table.add_row(
                entry.timestamp.strftime('%H:%M:%S'),
                f"[{level_style}]{entry.level}[/]",
                entry.message
            )
        return Panel(log_table, title="Logs", border_style="cyan")

    def _get_metrics_panel(self) -> Panel:
        content = ""
        if HAS_PSUTIL and psutil:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            content = f"CPU: {cpu}%\nMemory: {mem.percent}%"
        else:
            content = "psutil not installed"
        return Panel(content, title="Metrics", border_style="yellow")

    def _get_stats_panel(self) -> Panel:
        stats_text = (
            f"Total Logs: {self.stats['total_logs']}\n"
            f"Errors: {self.stats['errors']}\n"
            f"Warnings: {self.stats['warnings']}"
        )
        return Panel(stats_text, title="Statistics", border_style="magenta")

    def _get_footer_panel(self) -> Panel:
        return Panel("Press 'q' to quit", style="dim")

    def _get_level_style(self, level: str) -> str:
        """Get the style for a log level."""
        return {'DEBUG': 'dim', 'INFO': 'blue', 'WARNING': 'yellow', 'ERROR': 'red', 'CRITICAL': 'bold red'}.get(level.upper(), 'white')

    def add_log_entry(self, level: str, module: str, message: str, **kwargs):
        """Add a log entry to the display."""
        entry = LogEntry(timestamp=datetime.now(), level=level, module=module, message=message, thread_id=str(threading.get_ident()), **kwargs)
        self.log_buffer.append(entry)
        self.stats['total_logs'] += 1
        if level.upper() in ['ERROR', 'CRITICAL']:
            self.stats['errors'] += 1
        elif level.upper() == 'WARNING':
            self.stats['warnings'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        self.stats['uptime_seconds'] = (datetime.now() - self.stats['start_time']).total_seconds()
        return self.stats

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    console_manager = EnhancedSplitScreen()
    console_manager.start()
    try:
        for i in range(20):
            console_manager.add_log_entry("INFO", "main", f"Log entry #{i}")
            if i % 5 == 0:
                console_manager.add_log_entry("WARNING", "main", f"This is a warning at step {i}")
            time.sleep(0.5)
        console_manager.add_log_entry("ERROR", "main", "An error occurred!")
        time.sleep(5)
    finally:
        console_manager.stop()
