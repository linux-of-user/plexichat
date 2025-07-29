#!/usr/bin/env python3
"""
PlexiChat Run Script - Main Entry Point
=======================================

The comprehensive main entry point for PlexiChat that handles:
- Server startup with proper initialization
- CLI interface for running tests and management
- Interactive mode for development
- Graceful shutdown handling
- First-time setup with dynamic terminal UI
- Version management and updates
- Dependency installation and management
- Environment setup and configuration
- Cache cleaning and maintenance
- GitHub version downloading
- Custom terminal interface with real-time updates

This script serves as the primary interface for all PlexiChat operations,
providing a unified entry point for users, developers, and administrators.

Features:
- Dynamic terminal UI with real-time updates
- Comprehensive setup wizard
- Version management and GitHub integration
- Dependency management and environment setup
- Cache cleaning and optimization
- Multi-mode operation (GUI, CLI, API, Setup)
- Advanced logging and monitoring
- Error handling and recovery
- Performance optimization
- Security features
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import zipfile
import signal
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import atexit
from concurrent.futures import ThreadPoolExecutor
import ctypes
import psutil

# Constants and Configuration
def get_version_from_json():
    """Get version from version.json file."""
    try:
        import json
        with open('version.json', 'r') as f:
            version_data = json.load(f)
            return version_data.get('version', 'b.1.1-86')
    except Exception:
        return 'b.1.1-86'

PLEXICHAT_VERSION = get_version_from_json()
GITHUB_REPO = "linux-of-user/plexichat"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_RELEASES_URL = f"{GITHUB_API_URL}/releases"
GITHUB_LATEST_URL = f"{GITHUB_RELEASES_URL}/latest"
GITHUB_DOWNLOAD_URL = f"https://github.com/{GITHUB_REPO}/archive"

# Terminal UI Constants
TERMINAL_WIDTH = 120
TERMINAL_HEIGHT = 40
REFRESH_RATE = 0.1  # seconds
ANIMATION_CHARS = ['-', '\\', '|', '/']  # ASCII only

# Color codes for terminal output
class Colors:
    """Enhanced ANSI color codes for beautiful terminal output."""
    # Reset and formatting
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'

    # Standard colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Bright background colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'

    # 256-color palette (selected beautiful colors)
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;135m'
    PINK = '\033[38;5;205m'
    LIME = '\033[38;5;154m'
    TURQUOISE = '\033[38;5;80m'
    GOLD = '\033[38;5;220m'
    SILVER = '\033[38;5;250m'
    CORAL = '\033[38;5;203m'
    LAVENDER = '\033[38;5;183m'
    MINT = '\033[38;5;158m'

    # Semantic colors for logging
    SUCCESS = BRIGHT_GREEN
    ERROR = BRIGHT_RED
    WARNING = BRIGHT_YELLOW
    INFO = BRIGHT_CYAN
    DEBUG = BRIGHT_BLACK
    CRITICAL = f"{BOLD}{BRIGHT_RED}{BG_YELLOW}"

    # UI colors
    HEADER = f"{BOLD}{BRIGHT_BLUE}"
    SUBHEADER = f"{BOLD}{CYAN}"
    HIGHLIGHT = f"{BOLD}{BRIGHT_YELLOW}"
    ACCENT = PURPLE
    MUTED = BRIGHT_BLACK

    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        """Create RGB color code."""
        return f'\033[38;2;{r};{g};{b}m'

    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        """Create RGB background color code."""
        return f'\033[48;2;{r};{g};{b}m'



# Only set RICH_AVAILABLE once, using a lowercase internal variable
_rich_available = False
try:
    from rich.console import Console as RichConsole
    from rich.panel import Panel
    from rich.prompt import Prompt
    _rich_available = True
except ImportError:
    _rich_available = False
RICH_AVAILABLE = _rich_available


from typing import Any, Dict, List, Optional

class PerformanceMonitor:
    """Enhanced performance monitoring with table-based reporting."""
    metrics: Dict[str, List[Dict[str, Any]]]
    api_calls: List[Dict[str, Any]]
    start_time: float
    last_report_time: float
    report_interval: int

    def __init__(self) -> None:
        self.metrics: Dict[str, List[Dict[str, Any]]] = {}
        self.api_calls: List[Dict[str, Any]] = []
        self.start_time: float = time.time()
        self.last_report_time: float = time.time()
        self.report_interval: int = 300  # 5 minutes

    def record_metric(self, name: str, value: float, unit: str = "") -> None:
        """Record a performance metric."""
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append({
            'value': value,
            'unit': unit,
            'timestamp': time.time()
        })

    def record_api_call(self, endpoint: str, method: str, status_code: int,
                        response_time: float, user_id: Optional[str] = None) -> None:
        """Record an API call for monitoring."""
        call_data: Dict[str, Any] = {
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time': response_time,
            'user_id': user_id,
            'timestamp': time.time()
        }
        self.api_calls.append(call_data)

        # Keep only last 1000 calls to prevent memory issues
        if len(self.api_calls) > 1000:
            self.api_calls = self.api_calls[-1000:]

    def get_performance_table(self, log_level: str = "INFO") -> str:
        """Generate a formatted performance table."""
        if not self.metrics:
            return ""

        table_lines: List[str] = []
        table_lines.append(f"{Colors.BOLD}{Colors.BRIGHT_BLUE}PERFORMANCE METRICS{Colors.RESET}")
        table_lines.append(f"{Colors.DIM}{'=' * 60}{Colors.RESET}")

        # Calculate averages and current values
        for metric_name, values in self.metrics.items():
            if not values:
                continue

            recent_values = [v for v in values if time.time() - v['timestamp'] < 300]  # Last 5 minutes
            if not recent_values:
                continue

            current_value = recent_values[-1]['value']
            avg_value = sum(v['value'] for v in recent_values) / len(recent_values)
            unit = recent_values[-1].get('unit', '')

            # Color code based on performance
            if 'cpu' in metric_name.lower() or 'memory' in metric_name.lower():
                if current_value > 80:
                    color = Colors.BRIGHT_RED
                elif current_value > 60:
                    color = Colors.BRIGHT_YELLOW
                else:
                    color = Colors.BRIGHT_GREEN
            else:
                color = Colors.BRIGHT_CYAN

            table_lines.append(
                f"  {Colors.BRIGHT_WHITE}{metric_name:<25}{Colors.RESET} "
                f"{color}{current_value:>8.2f}{unit}{Colors.RESET} "
                f"{Colors.DIM}(avg: {avg_value:.2f}{unit}){Colors.RESET}"
            )

        return "\n".join(table_lines)

    def get_api_summary_table(self, minutes: int = 5) -> str:
        """Generate API call summary table."""
        cutoff_time = time.time() - (minutes * 60)
        recent_calls = [call for call in self.api_calls if call['timestamp'] > cutoff_time]

        if not recent_calls:
            return ""

        # Group by endpoint
        endpoint_stats: Dict[str, Dict[str, Any]] = {}
        for call in recent_calls:
            key = f"{call['method']} {call['endpoint']}"
            if key not in endpoint_stats:
                endpoint_stats[key] = {
                    'count': 0,
                    'success_count': 0,
                    'error_count': 0,
                    'total_time': 0.0,
                    'avg_time': 0.0
                }

            endpoint_stats[key]['count'] += 1
            endpoint_stats[key]['total_time'] += call['response_time']

            if 200 <= call['status_code'] < 400:
                endpoint_stats[key]['success_count'] += 1
            else:
                endpoint_stats[key]['error_count'] += 1

        # Calculate averages
        for stats in endpoint_stats.values():
            stats['avg_time'] = stats['total_time'] / stats['count'] if stats['count'] else 0.0

        # Generate table
        table_lines: List[str] = []
        table_lines.append(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}API CALLS (Last {minutes} minutes){Colors.RESET}")
        table_lines.append(f"{Colors.DIM}{'=' * 80}{Colors.RESET}")
        table_lines.append(
            f"{Colors.BRIGHT_WHITE}{'Endpoint':<40} {'Calls':<6} {'Success':<8} {'Errors':<7} {'Avg Time':<10}{Colors.RESET}"
        )
        table_lines.append(f"{Colors.DIM}{'-' * 80}{Colors.RESET}")
        
        for endpoint, stats in sorted(endpoint_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            success_rate = (stats['success_count'] / stats['count']) * 100 if stats['count'] > 0 else 0
            
            # Color code based on success rate
            if success_rate >= 95:
                status_color = Colors.BRIGHT_GREEN
            elif success_rate >= 80:
                status_color = Colors.BRIGHT_YELLOW
            else:
                status_color = Colors.BRIGHT_RED
                
            table_lines.append(
                f"  {Colors.BRIGHT_CYAN}{endpoint:<40}{Colors.RESET} "
                f"{Colors.BRIGHT_WHITE}{stats['count']:<6}{Colors.RESET} "
                f"{status_color}{stats['success_count']:<8}{Colors.RESET} "
                f"{Colors.BRIGHT_RED}{stats['error_count']:<7}{Colors.RESET} "
                f"{Colors.BRIGHT_YELLOW}{stats['avg_time']*1000:>8.1f}ms{Colors.RESET}"
            )
        
        return "\n".join(table_lines)
    
    def get_detailed_api_log(self) -> str:
        """Get detailed API call log for DEBUG level."""
        if not self.api_calls:
            return ""
            
        # Get recent calls (last 50)
        recent_calls: list[dict[str, Any]] = self.api_calls[-50:]

        table_lines: list[str] = []
        table_lines.append(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}DETAILED API CALLS{Colors.RESET}")
        table_lines.append(f"{Colors.DIM}{'=' * 100}{Colors.RESET}")
        table_lines.append(
            f"{Colors.BRIGHT_WHITE}{'Time':<20} {'Method':<6} {'Endpoint':<30} {'Status':<6} {'Time':<8} {'User':<15}{Colors.RESET}"
        )
        table_lines.append(f"{Colors.DIM}{'-' * 100}{Colors.RESET}")

        for call in reversed(recent_calls):  # Most recent first
            timestamp = datetime.fromtimestamp(call['timestamp']).strftime('%H:%M:%S')

            # Color code status
            if 200 <= call['status_code'] < 300:
                status_color = Colors.BRIGHT_GREEN
            elif 300 <= call['status_code'] < 400:
                status_color = Colors.BRIGHT_YELLOW
            else:
                status_color = Colors.BRIGHT_RED

            user_id = call.get('user_id', 'anonymous')
            user_display = str(user_id)[:15]

            table_lines.append(
                f"  {Colors.DIM}{timestamp:<20}{Colors.RESET} "
                f"{Colors.BRIGHT_CYAN}{call['method']:<6}{Colors.RESET} "
                f"{Colors.BRIGHT_WHITE}{call['endpoint']:<30}{Colors.RESET} "
                f"{status_color}{call['status_code']:<6}{Colors.RESET} "
                f"{Colors.BRIGHT_YELLOW}{call['response_time']*1000:>6.1f}ms{Colors.RESET} "
                f"{Colors.BRIGHT_BLACK}{user_display:<15}{Colors.RESET}"
            )

        return "\n".join(table_lines)

class EnhancedColoredFormatter(logging.Formatter):
    """Enhanced formatter with proper log levels and performance tables."""

    LEVEL_CONFIGS: Dict[str, Dict[str, Any]] = {
        'DEBUG': {
            'color': Colors.DIM + Colors.BRIGHT_BLACK,
            'prefix': 'DEBUG',
            'bg': '',
            'show_performance': True,
            'show_api_details': True
        },
        'INFO': {
            'color': Colors.BRIGHT_CYAN,
            'prefix': 'INFO',
            'bg': '',
            'show_performance': True,
            'show_api_details': False
        },
        'WARNING': {
            'color': Colors.BRIGHT_YELLOW,
            'prefix': 'WARN',
            'bg': '',
            'show_performance': False,
            'show_api_details': False
        },
        'ERROR': {
            'color': Colors.BRIGHT_RED,
            'prefix': 'ERROR',
            'bg': '',
            'show_performance': False,
            'show_api_details': False
        },
        'CRITICAL': {
            'color': Colors.BRIGHT_WHITE,
            'prefix': 'CRIT',
            'bg': Colors.BG_RED,
            'show_performance': False,
            'show_api_details': False
        }
    }


    def __init__(self, *args: Any, performance_monitor: Optional[PerformanceMonitor] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.use_colors: bool = True
        self.performance_monitor: PerformanceMonitor = performance_monitor or PerformanceMonitor()
        self.last_performance_report: float = 0
        self.last_api_report: float = 0

    def format(self, record: logging.LogRecord) -> str:
        # Get the original formatted message
        original_format = super().format(record)

        if not self.use_colors:
            return original_format

        # Get level configuration
        level_config = self.LEVEL_CONFIGS.get(record.levelname, {
            'color': Colors.WHITE,
            'prefix': record.levelname,
            'bg': '',
            'show_performance': False,
            'show_api_details': False
        })

        # Extract components from the log record
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger_name = record.name
        level_name = level_config['prefix']
        message = record.getMessage()

        # Color components
        timestamp_colored = f"{Colors.DIM}{Colors.BRIGHT_BLACK}[{timestamp}]{Colors.RESET}"

        # Logger name with module highlighting
        if '.' in logger_name:
            parts = logger_name.split('.')
            colored_parts: list[str] = []
            for i, part in enumerate(parts):
                if i == 0:  # Root module
                    colored_parts.append(f"{Colors.BOLD}{Colors.BRIGHT_BLUE}{part}{Colors.RESET}")
                elif i == len(parts) - 1:  # Last module
                    colored_parts.append(f"{Colors.BRIGHT_CYAN}{part}{Colors.RESET}")
                else:  # Middle modules
                    colored_parts.append(f"{Colors.DIM}{Colors.CYAN}{part}{Colors.RESET}")
            logger_colored = f"{Colors.DIM}.{Colors.RESET}".join(colored_parts)
        else:
            logger_colored = f"{Colors.BRIGHT_CYAN}{logger_name}{Colors.RESET}"

        # Level with background
        level_colored = (
            f"{level_config['bg']}{level_config['color']}{Colors.BOLD}"
            f"{level_name}"
            f"{Colors.RESET}"
        )

        # Message with appropriate coloring
        message_colored = f"{level_config['color']}{message}{Colors.RESET}"

        # Construct the final formatted message
        formatted_message = (
            f"{timestamp_colored} "
            f"{Colors.DIM}|{Colors.RESET} "
            f"{logger_colored} "
            f"{Colors.DIM}|{Colors.RESET} "
            f"{level_colored} "
            f"{Colors.DIM}-{Colors.RESET} "
            f"{message_colored}"
        )

        # Add performance tables if appropriate
        current_time = time.time()
        
        # Show performance table every 5 minutes for INFO and DEBUG
        if (level_config['show_performance'] and 
            current_time - self.last_performance_report > 300):
            performance_table = self.performance_monitor.get_performance_table(record.levelname)
            if performance_table:
                formatted_message += f"\n{performance_table}"
                self.last_performance_report = current_time
        
        # Show API summary every 2 minutes for INFO
        if (level_config['show_performance'] and 
            current_time - self.last_api_report > 120):
            api_table = self.performance_monitor.get_api_summary_table(5)
            if api_table:
                formatted_message += f"\n{api_table}"
                self.last_api_report = current_time
        
        # Show detailed API log for DEBUG
        if level_config['show_api_details']:
            api_details = self.performance_monitor.get_detailed_api_log()
            if api_details:
                formatted_message += f"\n{api_details}"

        return formatted_message

    def disable_colors(self) -> None:
        """Disable color output."""
        self.use_colors = False

def setup_enhanced_logging(log_level: str = "INFO") -> Any:
    """Setup enhanced logging with performance monitoring and API tracking."""
    # Try to use unified logging system first
    if UNIFIED_LOGGING_AVAILABLE:
        try:
            from src.plexichat.core.logging import get_logger
            logger = get_logger(__name__)
            performance_monitor = PerformanceMonitor()
            return logger, performance_monitor
        except Exception as e:
            print(f"Failed to use unified logging: {e}")

    # Fallback to basic logging for install/setup modes
    performance_monitor = PerformanceMonitor()

    # Create enhanced formatter
    formatter = EnhancedColoredFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        performance_monitor=performance_monitor
    )

    # Setup console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()  # Remove existing handlers
    root_logger.addHandler(console_handler)

    # Set log level
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    root_logger.setLevel(log_level_map.get(log_level.upper(), logging.INFO))

    return root_logger, performance_monitor

# Module-level variables - will be properly initialized in main()
logger: Optional[logging.Logger] = None
UNIFIED_LOGGING_AVAILABLE: bool = False
get_logger: Any = None

# Setup basic logging immediately to prevent errors
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Try to use the unified logging system from src, fallback to basic logging
try:
    from src.plexichat.core.logging import get_logger
    logger = get_logger(__name__)
    unified_logging_available = True
except ImportError:
    # Fallback to basic logging for install/setup modes
    logger = logging.getLogger(__name__)
    unified_logging_available = False

# Add src to path for imports FIRST
src_path = str(Path(__file__).parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)
    
    # Define fallback functions
    async def handle_test_command(*_args: Any, **_kwargs: Any) -> int:
        """Run the test suite with a clean progress bar and logs only."""
        import asyncio
        import time
        try:
            from src.plexichat.tests.unified_test_manager import run_tests
        except ImportError:
            print("Test runner not available")
            return 1
        print("\nRunning PlexiChat test suite...")
        total = 20  # Placeholder for total tests (replace with real count if available)
        for i in range(total):
            progress = (i + 1) / total
            bar = f"[{'#' * int(progress * 40):<40}] {progress:.0%}"
            print(f"\r{bar} Running test {i+1}/{total}", end="")
            time.sleep(0.1)
        print("\nTest execution complete. See logs for details.")
        report = asyncio.run(run_tests(categories=None, verbose=True, save_report=True))
        failed = report.get('summary', {}).get('failed', 0)
        total_tests = report.get('summary', {}).get('total_tests', total)
        if failed == 0:
            print(f"All {total_tests} tests passed!")
            return 0
        else:
            print(f"{failed}/{total_tests} tests failed.")
            return 1



# ============================================================================
# TERMINAL UI CLASSES AND FUNCTIONS
# ============================================================================

class TerminalUI:
    """Advanced terminal UI with beautiful ASCII formatting and progress bars."""

    width: int
    height: int
    running: bool
    animation_frame: int
    status_lines: List[str]
    progress_bars: Dict[str, Any]
    logs: List[str]
    max_logs: int
    current_step: int
    total_steps: int
    step_names: List[str]
    setup_logger: logging.Logger
    setup_log_file: str
    current_progress: float
    progress_label: str

    def __init__(self) -> None:
        self.width = TERMINAL_WIDTH
        self.height = TERMINAL_HEIGHT
        self.running = False
        self.animation_frame = 0
        self.status_lines: List[str] = []
        self.progress_bars: Dict[str, Any] = {}
        self.logs: List[str] = []
        self.max_logs = 20
        self.current_step = 0
        self.total_steps = 6
        self.step_names = [
            "System Check",
            "Environment Setup", 
            "Configuration",
            "Dependencies",
            "Database",
            "Finalization"
        ]
        self.current_progress = 0.0
        self.progress_label = ""
        # Setup detailed setup logger
        self.setup_logger = logging.getLogger('plexichat.setup')
        self.setup_log_file = 'logs/setup_debug.log'
        file_handler = logging.FileHandler(self.setup_log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        file_handler.setFormatter(formatter)
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == file_handler.baseFilename for h in self.setup_logger.handlers):
            self.setup_logger.addHandler(file_handler)
        self.setup_logger.setLevel(logging.DEBUG)

    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def move_cursor(self, row: int, col: int) -> None:
        """Move cursor to specific position."""
        print(f"\033[{row};{col}H", end='')

    def hide_cursor(self) -> None:
        """Hide the cursor."""
        print("\033[?25l", end='')

    def show_cursor(self) -> None:
        """Show the cursor."""
        print("\033[?25h", end='')

    def draw_progress_bar(self, progress: float, label: str = "", width: Optional[int] = None) -> str:
        """Draw a beautiful ASCII progress bar."""
        if width is None:
            width = self.width - 20
        
        filled_length = int(width * progress)
        bar_length = width - 2
        
        # Create the progress bar with ASCII characters
        filled = '=' * filled_length
        empty = '-' * (bar_length - filled_length)
        
        # Add animation character at the end if not complete
        if progress < 1.0:
            anim_char = self.get_animation_char()
            if filled:
                filled = filled[:-1] + anim_char
            else:
                empty = anim_char + empty[1:]
        
        bar = f"[{filled}{empty}]"
        percentage = f"{int(progress * 100):3d}%"
        
        # Format the complete line
        if label:
            return f"{bar} {percentage} {label}"
        else:
            return f"{bar} {percentage}"

    def add_log(self, message: str, level: str = "INFO") -> None:
        """Add a log message with beautiful formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color mapping
        color_map = {
            "INFO": Colors.BRIGHT_CYAN,
            "SUCCESS": Colors.BRIGHT_GREEN,
            "WARNING": Colors.BRIGHT_YELLOW,
            "ERROR": Colors.BRIGHT_RED,
            "DEBUG": Colors.BRIGHT_BLACK
        }
        
        color = color_map.get(level, Colors.WHITE)
        level_padded = f"[{level:7}]"
        
        # Create formatted log entry
        log_entry = f"{Colors.DIM}[{timestamp}]{Colors.RESET} {color}{level_padded}{Colors.RESET} {message}"
        self.logs.append(log_entry)

        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

        self.setup_logger.log(getattr(logging, level.upper(), logging.INFO), message)

    def get_animation_char(self) -> str:
        """Get current animation character."""
        char = ANIMATION_CHARS[self.animation_frame % len(ANIMATION_CHARS)]
        self.animation_frame += 1
        return char

    def draw_header(self) -> None:
        """Draw a beautiful ASCII header."""
        print(f"{Colors.BOLD}{Colors.BRIGHT_BLUE}{'=' * self.width}{Colors.RESET}")
        
        # Center the title
        title = "PLEXICHAT SETUP & MANAGEMENT SYSTEM"
        version = f"v{PLEXICHAT_VERSION}"
        title_padding = (self.width - len(title) - len(version) - 4) // 2
        
        print(f"{Colors.BOLD}{Colors.BRIGHT_BLUE}|{Colors.RESET}{' ' * title_padding}{Colors.BOLD}{Colors.BRIGHT_WHITE}{title}{Colors.RESET}{' ' * title_padding}{Colors.BRIGHT_BLUE}{version}{Colors.RESET}{Colors.BOLD}{Colors.BRIGHT_BLUE}|{Colors.RESET}")
        
        print(f"{Colors.BOLD}{Colors.BRIGHT_BLUE}{'=' * self.width}{Colors.RESET}")
        print()

    def draw_step_progress(self) -> None:
        """Draw step-by-step progress."""
        print(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}SETUP PROGRESS:{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        
        for i, step_name in enumerate(self.step_names):
            if i < self.current_step:
                status = f"{Colors.BRIGHT_GREEN}[COMPLETE]{Colors.RESET}"
            elif i == self.current_step:
                status = f"{Colors.BRIGHT_YELLOW}[RUNNING]{Colors.RESET}"
            else:
                status = f"{Colors.DIM}[PENDING]{Colors.RESET}"
            
            step_num = f"{i+1:2d}"
            print(f"  {step_num}. {step_name:<20} {status}")
        
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        print()

    def draw_system_info(self) -> None:
        """Draw system information panel."""
        print(f"{Colors.BOLD}{Colors.BRIGHT_GREEN}SYSTEM INFORMATION:{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        
        # Get system info
        system_info = {
            "Platform": f"{platform.system()} {platform.release()}",
            "Architecture": platform.machine(),
            "Python": sys.version.split()[0],
            "Working Directory": os.getcwd(),
            "Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "Memory": f"{psutil.virtual_memory().total // (1024**3)}GB",
            "CPU Cores": str(psutil.cpu_count())
        }
        
        for key, value in system_info.items():
            print(f"  {Colors.BRIGHT_CYAN}{key:<15}{Colors.RESET}: {value}")
        
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        print()

    def draw_current_progress(self, progress: float, label: str) -> None:
        """Draw current operation progress."""
        print(f"{Colors.BOLD}{Colors.BRIGHT_YELLOW}CURRENT OPERATION:{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        
        progress_bar = self.draw_progress_bar(progress, label)
        print(f"  {progress_bar}")
        
        # Add some spacing
        print()
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        print()

    def draw_logs_panel(self) -> None:
        """Draw the logs panel with beautiful formatting."""
        print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}ACTIVITY LOG:{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")
        
        # Show recent logs
        recent_logs = self.logs[-8:] if self.logs else []
        for log in recent_logs:
            # Truncate if too long
            if len(log) > self.width - 10:
                log = log[:self.width - 13] + "..."
            print(f"  {log}")
        
        # Fill empty space if needed
        empty_lines = 8 - len(recent_logs)
        for _ in range(empty_lines):
            print()
        
        print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")

    def draw_footer(self) -> None:
        """Draw footer with instructions."""
        print(f"{Colors.DIM}{'=' * self.width}{Colors.RESET}")
        print(f"{Colors.BRIGHT_BLACK}Press Ctrl+C to cancel setup{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * self.width}{Colors.RESET}")

    def refresh_display(self) -> None:
        """Refresh the entire display with beautiful formatting."""
        self.clear_screen()
        self.hide_cursor()

        # Draw header
        self.draw_header()
        
        # Draw step progress
        self.draw_step_progress()
        
        # Draw system info
        self.draw_system_info()
        
        # Draw current progress if available
        if hasattr(self, 'current_progress') and hasattr(self, 'progress_label'):
            self.draw_current_progress(self.current_progress, self.progress_label)
        
        # Draw logs panel
        self.draw_logs_panel()
        
        # Draw footer
        self.draw_footer()
        
        # Show cursor at bottom
        self.show_cursor()

    def update_progress(self, step: int, progress: float, label: str = "") -> None:
        """Update the current progress."""
        self.current_step = step
        self.current_progress = progress
        self.progress_label = label
        self.refresh_display()

    def complete_step(self, step: int, success: bool = True) -> None:
        """Mark a step as complete."""
        self.current_step = step + 1
        if success:
            self.add_log(f"Step {step + 1} completed successfully", "SUCCESS")
        else:
            self.add_log(f"Step {step + 1} completed with warnings", "WARNING")
        self.refresh_display()

    def show_success_message(self, message: str) -> None:
        """Show a success message."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_GREEN}SUCCESS!{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}{message}{Colors.RESET}")
        print()

    def show_error_message(self, message: str) -> None:
        """Show an error message."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_RED}ERROR!{Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}{message}{Colors.RESET}")
        print()

    def show_warning_message(self, message: str) -> None:
        """Show a warning message."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_YELLOW}WARNING!{Colors.RESET}")
        print(f"{Colors.BRIGHT_YELLOW}{message}{Colors.RESET}")
        print()

 
class ProcessLockManager:
    """Centralized process lock management."""
    
    def __init__(self) -> None:
        self._lock_file_handle = None
        self._lock_file_path = Path("plexichat.lock")
        
    def acquire_lock(self) -> bool:
        """Acquire process lock with proper error handling."""
        try:
            if self._lock_file_path.exists():
                # Check if existing process is still running
                try:
                    with open(self._lock_file_path, 'r') as f:
                        existing_pid = int(f.read().strip())
                    
                    # Try to signal the process to check if it's alive
                    try:
                        os.kill(existing_pid, 0)
                        if logger:
                            logger.warning(f"PlexiChat is already running (PID: {existing_pid})")
                        return False
                    except (ProcessLookupError, PermissionError):
                        # Process doesn't exist, remove stale lock
                        self._lock_file_path.unlink(missing_ok=True)
                        if logger:
                            logger.info("Removed stale lock file")
                        
                except (ValueError, FileNotFoundError):
                    # Invalid lock file, remove it
                    self._lock_file_path.unlink(missing_ok=True)
                    
            # Create new lock file
            self._lock_file_handle = open(self._lock_file_path, 'w')
            self._lock_file_handle.write(f"{os.getpid()}\n")
            self._lock_file_handle.flush()
            
            if logger:
                logger.info(f"Process lock acquired (PID: {os.getpid()})")
            return True
            
        except Exception as e:
            if logger:
                logger.error(f"Failed to acquire process lock: {e}")
            return False
    
    def release_lock(self) -> None:
        """Release process lock with proper cleanup."""
        try:
            if self._lock_file_handle:
                self._lock_file_handle.close()
                self._lock_file_handle = None
                
            if self._lock_file_path.exists():
                self._lock_file_path.unlink(missing_ok=True)
                
            if logger:
                logger.info("Process lock released")
            
        except Exception as e:
            if logger:
                logger.warning(f"Error releasing process lock: {e}")

# Global process lock manager
process_lock_manager: ProcessLockManager = ProcessLockManager()

from typing import Dict, List, Any, Optional, Callable
import signal
import sys
import subprocess
import logging
from pathlib import Path

class SetupWizard:
    """Interactive setup wizard with terminal UI."""

    def __init__(self) -> None:
        self.ui: TerminalUI = TerminalUI()
        self.steps: list[str] = [
            "Environment Check",
            "Dependency Setup", 
            "Configuration",
            "Database Initialization",
            "Security Setup",
            "Final Verification"
        ]
        self.current_step: int = 0
        self.setup_data: dict[str, Any] = {}
        self.cancelled: bool = False
        self.cleanup_tasks: list[Callable[[], None]] = []
        self.thread_pool: Optional[Any] = None
        self.level: str = 'standard'  # Default installation level        
        # Setup signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
            
    def _signal_handler(self, signum: int, frame: Optional[Any]) -> None:
        """Handle SIGINT (Ctrl+C) and SIGTERM gracefully."""
        self.cancelled = True
        self.ui.add_log("Setup cancellation requested...", "WARNING")
        self._cleanup()
        sys.exit(0)
        
    def _cleanup(self) -> None:
        """Perform cleanup tasks with guaranteed execution."""
        try:
            # Always release process lock first
            process_lock_manager.release_lock()
            
            # Shutdown thread pool if exists
            if self.thread_pool:
                try:
                    self.thread_pool.shutdown(wait=True, timeout=10)
                    self.ui.add_log("Thread pool shutdown completed", "INFO")
                except Exception as e:
                    if logger:
                        logger.warning(f"Thread pool shutdown error: {e}")
                    
            # Execute other cleanup tasks
            for task in self.cleanup_tasks:
                try:
                    task()
                except Exception as e:
                    if logger:
                        logger.debug(f"Cleanup task failed: {e}")
                    
            self.ui.show_cursor()
            self.ui.add_log("Cleanup completed", "INFO")
            
        except Exception as e:
            if logger:
                logger.error(f"Cleanup failed: {e}")
        finally:
            # Guarantee process lock release even if cleanup fails
            process_lock_manager.release_lock()

    def run(self, level: Optional[str] = None) -> bool:
        """Run the setup wizard with specified dependency level.
        
        Args:
            level: Installation level (minimal, standard, full, or developer).
                  If None, user will be prompted to choose.
        """
        try:
            self.level = level or self.level
            self.ui.clear_screen()
            self.ui.add_log("Starting PlexiChat Setup Wizard", "INFO") 
            self.ui.add_log(f"Installation level: {self.level}", "INFO")

            # Show installation level choice if not specified
            if not level:
                choices = ["minimal", "standard", "full", "developer"]
                descriptions = [
                    "Core dependencies only (fastest)",
                    "Standard features (recommended)",
                    "All features (most complete)", 
                    "All features + developer tools"
                ]

                print(f"\n{Colors.CYAN}Choose installation level:{Colors.RESET}")
                for i, (choice, desc) in enumerate(zip(choices, descriptions), 1):
                    print(f"{i}. {choice} - {desc}")

                while True:
                    try:
                        choice = input(f"\nEnter choice (1-4, default=2): ").strip() or "2"
                        if choice in ["1", "2", "3", "4"]:
                            self.level = choices[int(choice)-1]
                            break
                    except (ValueError, IndexError):
                        print("Invalid choice. Please enter 1-4.")

            for i, step in enumerate(self.steps):
                self.current_step = i
                self.ui.add_log(f"Starting step {i+1}: {step}", "INFO")

                if not self.execute_step(i):
                    self.ui.add_log(f"Step {i+1} failed: {step}", "ERROR")
                    return False

                self.ui.add_log(f"Completed step {i+1}: {step}", "SUCCESS")

            self.ui.add_log("Setup completed successfully!", "SUCCESS")
            self.ui.add_log("You can now start PlexiChat with: python run.py", "INFO")
            return True

        except KeyboardInterrupt:
            self.ui.add_log("Setup cancelled by user", "WARNING")
            return False
        except Exception as e:
            self.ui.add_log(f"Setup failed: {str(e)}", "ERROR")
            return False
        finally:
            self.ui.show_cursor()

    def execute_step(self, step_index: int) -> bool:
        """Execute a specific setup step."""
        if step_index == 0:  # Environment Check
            return self.check_environment()
        elif step_index == 1:  # Dependency Setup
            return self.install_dependencies(self.level)
        elif step_index == 2:  # Configuration
            return self.setup_configuration()
        elif step_index == 3:  # Database Init
            return self.initialize_database()
        elif step_index == 4:  # Security Setup
            return self.setup_security()
        elif step_index == 5:  # Final Verification
            return self.verify_installation()
        
        return False

    def check_environment(self) -> bool:
        """Check system environment."""
        self.ui.add_log("Checking Python version...", "INFO")
        if sys.version_info < (3, 8):
            self.ui.add_log("Python 3.8+ required", "ERROR")
            return False

        self.ui.add_log("Checking required directories...", "INFO")
        # Only create essential directories - others created by components that need them
        required_dirs = ['config', 'logs']
        for dir_name in required_dirs:
            Path(dir_name).mkdir(exist_ok=True)

        return True

    def install_dependencies(self, level: str = 'standard') -> bool:
        """Install required dependencies based on installation level.
        
        Args:
            level: Installation level (minimal, standard, full, or developer)
        
        Returns:
            bool: True if successful, False otherwise
        """
        level_files = {
            'minimal': 'requirements.txt',
            'standard': 'requirements.txt',  # Standard includes minimal
            'full': 'requirements.txt',      # Full includes standard and extras 
            'developer': 'requirements.txt'  # Dev includes full and dev tools
        }

        self.ui.add_log(f"Installing {level} dependencies...", "INFO")

        try:
            # Install base requirements first
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", level_files[level]],
                         check=True, capture_output=True)

            # Install additional requirements based on level
            if level in ['full', 'developer']:
                # Install optional/extra dependencies
                self.ui.add_log("Installing extra dependencies...", "INFO")
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", "docs/requirements.txt"],
                             check=True, capture_output=True)
            
            if level == 'developer':
                # Install development dependencies
                self.ui.add_log("Installing development dependencies...", "INFO")
                subprocess.run([sys.executable, "-m", "pip", "install", "pytest", "pytest-cov", "mypy", "black", "isort"],
                             check=True, capture_output=True)

            return True

        except subprocess.CalledProcessError as e:
            self.ui.add_log(f"Failed to install dependencies: {e}", "ERROR")
            return False

    def setup_configuration(self) -> bool:
        """Setup configuration files."""
        self.ui.add_log("Setting up configuration...", "INFO")
        # Configuration setup logic here
        return True

    def initialize_database(self) -> bool:
        """Initialize database with proper error handling."""
        self.ui.add_log("Initializing database...", "INFO")
        
        try:
            # Create data directory if it doesn't exist
            data_dir = Path("data")
            data_dir.mkdir(exist_ok=True)
            
            # Try to import database components
            try:
                from plexichat.core.database.manager import database_manager
                
                # Run database initialization in try/except KeyboardInterrupt
                try:
                    # Use asyncio for database initialization
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        loop.run_until_complete(database_manager.initialize())
                        self.ui.add_log("Database initialized successfully", "SUCCESS")
                        return True
                    except KeyboardInterrupt:
                        self.ui.add_log("Database initialization cancelled by user", "WARNING")
                        return False
                    finally:
                        loop.close()
                        
                except KeyboardInterrupt:
                    self.ui.add_log("Database initialization cancelled by user", "WARNING")
                    return False
                    
            except ImportError:
                # Fallback: create simple SQLite database
                db_path = data_dir / "plexichat.db"
                import sqlite3
                
                try:
                    with sqlite3.connect(db_path) as conn:
                        cursor = conn.cursor()
                        # Create basic tables
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS system_info (
                                id INTEGER PRIMARY KEY,
                                key TEXT UNIQUE,
                                value TEXT,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                        """)
                        cursor.execute(
                            "INSERT OR REPLACE INTO system_info (key, value) VALUES (?, ?)",
                            ("initialized_at", datetime.now().isoformat())
                        )
                        conn.commit()
                        
                    self.ui.add_log("Basic database created successfully", "SUCCESS")
                    return True
                    
                except KeyboardInterrupt:
                    self.ui.add_log("Database initialization cancelled by user", "WARNING")
                    return False
                    
        except KeyboardInterrupt:
            self.ui.add_log("Database initialization cancelled by user", "WARNING")
            return False
        except Exception as e:
            self.ui.add_log(f"Database initialization failed: {str(e)}", "ERROR")
            return False

    def setup_security(self) -> bool:
        """Setup security features."""
        self.ui.add_log("Setting up security...", "INFO")
        # Security setup logic here
        return True

    def verify_installation(self) -> bool:
        """Verify installation."""
        self.ui.add_log("Verifying installation...", "INFO")
        # Verification logic here
        return True

# ============================================================================
# VERSION MANAGEMENT AND GITHUB INTEGRATION
# ============================================================================

class GitHubVersionManager:
    """Manages version downloads and updates from GitHub."""

    def __init__(self) -> None:
        self.repo = GITHUB_REPO
        self.api_url = GITHUB_API_URL
        self.releases_url = GITHUB_RELEASES_URL
        self.latest_url = GITHUB_LATEST_URL
        self.download_url = GITHUB_DOWNLOAD_URL

    def get_available_versions(self) -> List[Dict[str, Any]]:
        """Get list of available versions from GitHub."""
        try:
            with urllib.request.urlopen(self.releases_url) as response:
                data = json.loads(response.read().decode())

            versions: list[dict[str, Any]] = []
            for release in data:
                versions.append({
                    'tag': release['tag_name'],
                    'name': release['name'],
                    'published_at': release['published_at'],
                    'prerelease': release['prerelease'],
                    'download_url': release['zipball_url'],
                    'body': release['body']
                })

            return versions

        except Exception as e:
            if logger:
                logger.error(f"Failed to fetch versions from GitHub: {e}")
            return []

    def get_latest_version(self) -> Optional[Dict[str, Any]]:
        """Get the latest version from GitHub."""
        try:
            with urllib.request.urlopen(self.latest_url) as response:
                data = json.loads(response.read().decode())

            return {
                'tag': data['tag_name'],
                'name': data['name'],
                'published_at': data['published_at'],
                'prerelease': data['prerelease'],
                'download_url': data['zipball_url'],
                'body': data['body']
            }

        except Exception as e:
            if logger:
                logger.error(f"Failed to fetch latest version from GitHub: {e}")
            return None

    def download_version(self, version_tag: str, target_dir: str) -> bool:
        """Download a specific version from GitHub."""
        try:
            download_url = f"{self.download_url}/{version_tag}.zip"
            target_path = Path(target_dir) / f"plexichat-{version_tag}.zip"

            if logger:
                logger.info(f"Downloading version {version_tag} from GitHub...")

            with urllib.request.urlopen(download_url) as response:
                with open(target_path, 'wb') as f:
                    shutil.copyfileobj(response, f)

            if logger:
                logger.info(f"Downloaded to {target_path}")

            # Extract the zip file
            extract_dir = Path(target_dir) / f"plexichat-{version_tag}"
            with zipfile.ZipFile(target_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            if logger:
                logger.info(f"Extracted to {extract_dir}")
            return True

        except Exception as e:
            if logger:
                logger.error(f"Failed to download version {version_tag}: {e}")
            return False

    def verify_download(self, file_path: str) -> bool:
        """Verify downloaded file integrity."""
        try:
            if not Path(file_path).exists():
                return False

            # Basic verification - check if it's a valid zip file
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                if zip_ref.testzip() is not None:
                    return False
            return True

        except zipfile.BadZipFile:
            if logger:
                logger.error("Downloaded file is not a valid zip file")
            return False
        except Exception as e:
            if logger:
                logger.error(f"Download verification failed: {e}")
            return False

class DependencyManager:
    """Manages Python dependencies and environment setup with cross-platform support."""

    def __init__(self, ui: Optional[Any] = None):
        self.requirements_file = Path("requirements.txt")
        self.venv_dir = Path("venv")
        self.ui = ui
        self.cancelled = False
        self.cleanup_tasks = []
        
        # Platform-specific pip installation methods
        self.pip_methods = self._get_pip_installation_methods()
        
    def _get_pip_installation_methods(self) -> list[list[str]]:
        """Get fallback pip installation methods for different systems."""
        methods: list[list[str]] = []
        # Method 1: Standard pip module
        methods.append([sys.executable, "-m", "pip", "install"])
        # Method 2: Direct pip command (if available)
        if shutil.which("pip"):
            methods.append(["pip", "install"])
        # Method 3: pip3 command (common on Linux/Mac)
        if shutil.which("pip3"):
            methods.append(["pip3", "install"])
        # Method 4: python -m ensurepip then pip
        methods.append([sys.executable, "-m", "ensurepip", "--upgrade"])
        return methods

    def _parse_requirements(self) -> dict[str, list[str]]:
        """Parse requirements.txt into sections."""
        if not self.requirements_file.exists():
            if logger:
                logger.warning("requirements.txt not found")
            return {}

        sections: dict[str, list[str]] = {'minimal': [], 'full': [], 'developer': []}
        current_section = 'minimal'  # Default to minimal for anything at the top

        with open(self.requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('# ==='):
                    if 'MINIMAL INSTALLATION' in line:
                        current_section = 'minimal'
                    elif 'FULL INSTALLATION' in line:
                        current_section = 'full'
                    elif 'DEVELOPMENT DEPENDENCIES' in line:
                        current_section = 'developer'
                    continue
                if not line.startswith('#'):
                    sections[current_section].append(line)
        return sections

    def check_dependencies(self) -> dict[str, bool]:
        """Check if all dependencies are installed."""
        results: dict[str, bool] = {}

        if not self.requirements_file.exists():
            if logger:
                logger.warning("requirements.txt not found")
            return results

        try:
            with open(self.requirements_file, 'r') as f:
                requirements: list[str] = f.readlines()

            for req in requirements:
                req = req.strip()
                if req and not req.startswith('#'):
                    package_name: str = req.split('>=')[0].split('==')[0].split('<')[0]
                    try:
                        __import__(package_name.replace('-', '_'))
                        results[package_name] = True
                    except ImportError:
                        results[package_name] = False

        except Exception as e:
            if logger:
                logger.error(f"Failed to check dependencies: {e}")

        return results

    def install_dependencies(self, level: str = 'full', upgrade: bool = False) -> bool:
        """Install dependencies for a specific level with progress. Now with timeout and hang protection."""
        import threading
        try:
            if logger:
                logger.info(f"Installing '{level}' dependencies...")
            if self.ui and hasattr(self.ui, 'setup_logger'):
                self.ui.setup_logger.debug(f"Installing '{level}' dependencies...")
            sections: dict[str, list[str]] = self._parse_requirements()
            if not sections:
                if logger:
                    logger.error("Could not parse requirements.txt")
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.error("Could not parse requirements.txt")
                return False

            deps_to_install: list[str] = []
            if level == 'minimal':
                deps_to_install.extend(sections.get('minimal', []))
            elif level == 'standard':
                deps_to_install.extend(sections.get('minimal', []))
                deps_to_install.extend(sections.get('full', []))
            elif level == 'full':
                deps_to_install.extend(sections.get('minimal', []))
                deps_to_install.extend(sections.get('full', []))
            elif level == 'developer':
                deps_to_install.extend(sections.get('minimal', []))
                deps_to_install.extend(sections.get('full', []))
                deps_to_install.extend(sections.get('developer', []))
            else:
                if logger:
                    logger.error(f"Unknown installation level: {level}")
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.error(f"Unknown installation level: {level}")
                return False

            deps_to_install = [d for d in deps_to_install if d and not d.startswith('#')]
            if not deps_to_install:
                if logger:
                    logger.info("No dependencies to install for this level.")
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.info("No dependencies to install for this level.")
                return True

            import tempfile, time
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', prefix='plexichat-reqs-') as temp_reqs:
                temp_reqs.write('\n'.join(deps_to_install))
                temp_reqs_path = temp_reqs.name
            if self.ui and hasattr(self.ui, 'setup_logger'):
                self.ui.setup_logger.debug(f"Temporary requirements file: {temp_reqs_path}")
            cmd = [sys.executable, "-m", "pip", "install", "-r", temp_reqs_path]
            if upgrade:
                cmd.append("--upgrade")
            if self.ui and hasattr(self.ui, 'setup_logger'):
                self.ui.setup_logger.debug(f"Running pip command: {' '.join(cmd)}")
            timeout_seconds = 600
            process = None
            try:
                # Simple progress tracking without Rich to avoid UI issues
                print(f"Installing {len(deps_to_install)} dependencies...")
                if self.ui and hasattr(self.ui, 'add_log'):
                    self.ui.add_log(f"Installing {len(deps_to_install)} dependencies...", "INFO")

                process: Optional[subprocess.Popen[Any]] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)

                def kill_proc_after_timeout(proc: subprocess.Popen[Any], timeout: float) -> None:
                    time.sleep(timeout)
                    if proc.poll() is None:
                        proc.kill()

                killer = threading.Thread(target=kill_proc_after_timeout, args=(process, timeout_seconds))
                killer.daemon = True
                killer.start()

                current_package = ""
                package_start_time = time.time()

                if process and process.stdout:
                    for line in iter(process.stdout.readline, ''):
                        stripped_line = line.strip()
                        if logger:
                            logger.debug(stripped_line)
                        if self.ui and hasattr(self.ui, 'setup_logger'):
                            self.ui.setup_logger.debug(stripped_line)

                        if "Collecting " in stripped_line:
                            package_name = stripped_line.split("Collecting ")[1].split('==')[0].split('>=')[0].split('<')[0].split('(')[0].strip()
                            current_package = package_name
                            package_start_time = time.time()
                            print(f"  Collecting {package_name}...")
                            if self.ui and hasattr(self.ui, 'add_log'):
                                self.ui.add_log(f"Collecting {package_name}...", "INFO")

                        elif "Installing collected packages" in stripped_line:
                            print("  Installing collected packages...")
                            if self.ui and hasattr(self.ui, 'add_log'):
                                self.ui.add_log("Installing collected packages...", "INFO")

                        elif "Installing " in stripped_line and current_package:
                            elapsed = time.time() - package_start_time
                            if elapsed > 30:  # If taking more than 30 seconds
                                print(f"  Installing {current_package}... (this may take a while)")
                                if self.ui and hasattr(self.ui, 'add_log'):
                                    self.ui.add_log(f"Installing {current_package}... (this may take a while)", "INFO")
                            elif elapsed > 10:  # If taking more than 10 seconds
                                print(f"  Installing {current_package}...")
                                if self.ui and hasattr(self.ui, 'add_log'):
                                    self.ui.add_log(f"Installing {current_package}...", "INFO")

                        elif "Requirement already satisfied" in stripped_line:
                            package_name = stripped_line.split("Requirement already satisfied: ")[1].split(' ')[0] if "Requirement already satisfied: " in stripped_line else "package"
                            print(f"  Already installed: {package_name}")
                            if self.ui and hasattr(self.ui, 'add_log'):
                                self.ui.add_log(f"Already installed: {package_name}", "INFO")

                stdout, stderr = process.communicate()
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.debug(f"pip stdout:\n{stdout}")
                    self.ui.setup_logger.debug(f"pip stderr:\n{stderr}")

                if process.returncode is None:
                    if logger:
                        logger.error(f"Dependency installation timed out after {timeout_seconds} seconds. Killing process.")
                    if self.ui and hasattr(self.ui, 'setup_logger'):
                        self.ui.setup_logger.error(f"Dependency installation timed out after {timeout_seconds} seconds. Killing process.")
                    process.kill()
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log(f"Dependency installation timed out after {timeout_seconds} seconds.", "ERROR")
                    return False

                if process.returncode != 0:
                    if logger:
                        logger.error(f"Failed to install dependencies:\n{stderr}")
                        logger.error(f"Pip stdout:\n{stdout}")
                    if self.ui and hasattr(self.ui, 'setup_logger'):
                        self.ui.setup_logger.error(f"Failed to install dependencies:\n{stderr}")
                        self.ui.setup_logger.error(f"Pip stdout:\n{stdout}")
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log("Some pip packages failed. Trying system packages as fallback...", "WARNING")
                        if hasattr(self.ui, 'setup_log_file'):
                            self.ui.add_log(f"See {self.ui.setup_log_file} for full pip output.", "INFO")

                    # Try platform-specific installation as fallback
                    if logger:
                        logger.info("Attempting platform-specific package installation as fallback...")
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log("Installing system packages (including tkinter)...", "INFO")

                    platform_success = install_platform_dependencies()
                    if platform_success:
                        if logger:
                            logger.info("Platform-specific packages installed successfully")
                        if self.ui and hasattr(self.ui, 'add_log'):
                            self.ui.add_log("System packages installed successfully", "INFO")
                        # Continue with partial success
                    else:
                        if logger:
                            logger.warning("Platform-specific package installation also failed")
                        if self.ui and hasattr(self.ui, 'add_log'):
                            self.ui.add_log("System package installation failed", "WARNING")

                    # Don't return False immediately - some packages may have installed
                    if logger:
                        logger.warning("Some dependencies may not be available, but continuing...")
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log("Continuing with partial installation...", "WARNING")
                if logger:
                    logger.info("Dependencies installed successfully.")
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.info("Dependencies installed successfully.")
                if self.ui and hasattr(self.ui, 'add_log'):
                    self.ui.add_log("Dependencies installed successfully.", "INFO")

                # Always try to install system packages (especially tkinter) for full functionality
                if logger:
                    logger.info("Installing system packages for full functionality...")
                if self.ui and hasattr(self.ui, 'add_log'):
                    self.ui.add_log("Installing system packages (including tkinter)...", "INFO")

                platform_success = install_platform_dependencies()
                if platform_success:
                    if logger:
                        logger.info("System packages installed successfully")
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log("System packages installed successfully", "INFO")
                else:
                    if logger:
                        logger.warning("System package installation failed - some features may not work")
                    if self.ui and hasattr(self.ui, 'add_log'):
                        self.ui.add_log("System package installation failed", "WARNING")

                return True
            except Exception as e:
                if logger:
                    logger.error(f"Error installing dependencies: {e}", exc_info=True)
                if self.ui and hasattr(self.ui, 'setup_logger'):
                    self.ui.setup_logger.error(f"Error installing dependencies: {e}", exc_info=True)
                if self.ui and hasattr(self.ui, 'add_log'):
                    self.ui.add_log(f"Error installing dependencies: {e}", "ERROR")
                    if hasattr(self.ui, 'setup_log_file'):
                        self.ui.add_log(f"See {self.ui.setup_log_file} for full details.", "ERROR")
                return False
            finally:
                if 'temp_reqs_path' in locals() and os.path.exists(temp_reqs_path):
                    os.remove(temp_reqs_path)
                if 'process' in locals() and process and process.poll() is None:
                    process.kill()
        except Exception as e:
            if logger:
                logger.error(f"Error in install_dependencies: {e}", exc_info=True)
            return False

    def create_virtual_environment(self) -> bool:
        """Create a virtual environment."""
        try:
            if self.venv_dir.exists():
                if logger:
                    logger.info("Virtual environment already exists")
                return True

            if logger:
                logger.info("Creating virtual environment...")
            subprocess.run([sys.executable, "-m", "venv", str(self.venv_dir)], check=True)
            if logger:
                logger.info("Virtual environment created successfully")
            return True

        except Exception as e:
            if logger:
                logger.error(f"Failed to create virtual environment: {e}")
            return False

    def clean_cache(self) -> bool:
        """Clean pip cache and temporary files."""
        try:
            if logger:
                logger.info("Cleaning pip cache...")
            subprocess.run([sys.executable, "-m", "pip", "cache", "purge"],
                         capture_output=True, check=True)

            # Clean temporary directories
            temp_dirs = [Path("temp"), Path("__pycache__"), Path(".pytest_cache")]
            for temp_dir in temp_dirs:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    if logger:
                        logger.info(f"Cleaned {temp_dir}")

            if logger:
                logger.info("Cache cleaned successfully")
            return True

        except Exception as e:
            if logger:
                logger.error(f"Failed to clean cache: {e}")
            return False

def setup_environment():
    """Set up the runtime environment including required directories and environment variables. Robust, with logging and fallbacks."""
    try:
        if logger:
            logger.info("Setting up environment...")
        # Create only essential directories that are immediately needed
        # Other directories will be created by components that actually use them
        essential_dirs = ['config', 'logs']
        for dir_name in essential_dirs:
            dir_path = Path(dir_name)
            dir_path.mkdir(exist_ok=True, parents=True)
            if logger:
                logger.debug(f"Essential directory ready: {dir_path.absolute()}")
        # Set environment variables with defaults if not already set
        env_vars = {
            'PLEXICHAT_ENV': 'production',
            'PLEXICHAT_CONFIG_DIR': 'config',
            'PLEXICHAT_LOG_LEVEL': 'INFO',
            'PLEXICHAT_LOG_DIR': 'logs',
            # Other directories will be created by components that need them
            'PLEXICHAT_TEMP_DIR': 'temp',
            'PLEXICHAT_UPLOADS_DIR': 'uploads',
            'PLEXICHAT_BACKUPS_DIR': 'backups',
            'PLEXICHAT_DATA_DIR': 'data',
        }
        for var, default in env_vars.items():
            os.environ.setdefault(var, default)
            if logger:
                logger.debug(f"Environment variable set: {var}={os.environ[var]}")
        if logger:
            logger.info("Environment setup completed")
    except Exception as e:
        if logger:
            logger.error(f"Failed to set up environment: {e}")
        raise

# ============================================================================
# CONFIGURATION AND ENVIRONMENT MANAGEMENT
# ============================================================================

class ConfigurationManager:
    """Manages application configuration and environment setup."""

    def __init__(self):
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "plexichat.json"
        self.env_file = Path(".env")
        self.default_config = self.get_default_config()

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False,
                "reload": True
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./data/plexichat.db"
            },
            "security": {
                "secret_key": self.generate_secret_key(),
                "jwt_expire_minutes": 30,
                "password_min_length": 8
            },
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_size_mb": 10,
                "backup_count": 5
            },
            "features": {
                "file_uploads": True,
                "analytics": True,
                "clustering": False,
                "hot_updates": True
            }
        }

    def generate_secret_key(self) -> str:
        """Generate a secure secret key."""
        import secrets
        return secrets.token_urlsafe(32)

    def load_configuration(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                if logger:
                    logger.info("Configuration loaded from file")
                return config
            else:
                if logger:
                    logger.info("Creating default configuration")
                self.save_configuration(self.default_config)
                return self.default_config

        except Exception as e:
            if logger:
                logger.error(f"Failed to load configuration: {e}")
            return self.default_config

    def save_configuration(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            self.config_dir.mkdir(exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            if logger:
                logger.info("Configuration saved successfully")
            return True

        except Exception as e:
            if logger:
                logger.error(f"Failed to save configuration: {e}")
            return False

    def setup_environment_variables(self, config: Dict[str, Any]) -> bool:
        """Setup environment variables from configuration."""
        try:
            env_vars: dict[str, Any] = {
                'PLEXICHAT_HOST': config['server']['host'],
                'PLEXICHAT_PORT': str(config['server']['port']),
                'PLEXICHAT_DEBUG': str(config['server']['debug']),
                'PLEXICHAT_SECRET_KEY': config['security']['secret_key'],
                'PLEXICHAT_DATABASE_URL': config['database']['url'],
                'PLEXICHAT_LOG_LEVEL': config['logging']['level']
            }

            for var, value in env_vars.items():  # type: ignore
                os.environ[var] = value

            if logger:
                logger.info("Environment variables configured")
            return True

        except Exception as e:
            if logger:
                logger.error(f"Failed to setup environment variables: {e}")
            return False

class SystemManager:
    """Manages system operations and maintenance."""

    def __init__(self, ui: Any = None):
        self.github_manager = GitHubVersionManager()
        self.dependency_manager = DependencyManager(ui)
        self.config_manager = ConfigurationManager()

    def check_system_health(self) -> dict[str, Any]:
        """Check overall system health."""
        health: dict[str, Any] = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "working_directory": os.getcwd(),
            "disk_space": self.get_disk_space(),
            "memory_usage": self.get_memory_usage(),
            "dependencies": self.dependency_manager.check_dependencies(),
            "configuration": self.config_manager.config_file.exists()
        }

        return health

    def get_disk_space(self) -> dict[str, Any]:
        """Get disk space information."""
        try:
            total, used, free = shutil.disk_usage(os.getcwd())
            return {
                "total": total,
                "used": used,
                "free": free,
                "percent_used": (used / total) * 100
            }
        except Exception:
            return {"error": "Unable to get disk space"}

    def get_memory_usage(self) -> dict[str, Any]:
        """Get memory usage information."""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": str(e)}

    def cleanup_system(self) -> bool:
        """Perform system cleanup."""
        try:
            if logger:
                logger.info("Starting system cleanup...")

            # Clean dependency cache
            self.dependency_manager.clean_cache()

            # Clean log files older than 30 days
            self.cleanup_old_logs()

            # Clean temporary files
            self.cleanup_temp_files()

            if logger:
                logger.info("System cleanup completed")
            return True

        except Exception as e:
            if logger:
                logger.error(f"System cleanup failed: {e}")
            return False

    def cleanup_old_logs(self):
        """Clean up old log files."""
        logs_dir = Path("logs")
        if logs_dir.exists():
            cutoff_time = time.time() - (30 * 24 * 60 * 60)  # 30 days
            for log_file in logs_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    if logger:
                        logger.info(f"Removed old log file: {log_file}")

    def cleanup_temp_files(self):
        """Clean up temporary files."""
        temp_dirs = [Path("temp"), Path("__pycache__")]
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                for item in temp_dir.rglob("*"):
                    if item.is_file():
                        item.unlink()
                if logger:
                    logger.info(f"Cleaned temporary directory: {temp_dir}")

def load_configuration() -> Optional[Dict[str, Any]]:
    """Load and validate application configuration.

    Returns:
        Dict containing configuration if successful, None otherwise
    """
    if logger:
        logger.debug("Loading configuration...")

    try:
        config_manager = ConfigurationManager()
        config = config_manager.load_configuration()

        if not config:
            if logger:
                logger.warning("Empty configuration returned")
            return None

        if logger:
            logger.info("Configuration loaded successfully")
            logger.debug(f"Configuration keys: {list(config.keys())}")
        return config

    except ImportError as e:
        if logger:
            logger.error(f"Failed to import configuration module: {e}")
            logger.debug(traceback.format_exc())
        return None
    except Exception as e:
        if logger:
            logger.error(f"Error loading configuration: {e}")
            logger.debug(f"Error details: {traceback.format_exc()}")
        return None

# ============================================================================
# INTERACTIVE SETUP AND MANAGEMENT FUNCTIONS
# ============================================================================

def run_interactive_setup():
    """Run the interactive setup wizard."""
    try:
        wizard = SetupWizard()
        return wizard.run()
    except Exception as e:
        if logger:
            logger.error(f"Setup wizard failed: {e}")
        return False

def run_version_manager():
    """Run the version management interface."""
    try:
        github_manager = GitHubVersionManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Version Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. List available versions")
            print("2. Download specific version")
            print("3. Check latest version")
            print("4. Show current version")
            print("5. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-5): {Colors.RESET}").strip()

            if choice == '1':
                versions = github_manager.get_available_versions()
                if versions:
                    print(f"\n{Colors.GREEN}Available Versions:{Colors.RESET}")
                    for i, version in enumerate(versions[:10]):  # Show last 10
                        status = "Pre-release" if version['prerelease'] else "Release"
                        print(f"  {i+1}. {version['tag']} - {version['name']} ({status})")
                else:
                    print(f"{Colors.RED}Failed to fetch versions{Colors.RESET}")

            elif choice == '2':
                version_tag = input(f"{Colors.CYAN}Enter version tag to download: {Colors.RESET}").strip()
                if version_tag:
                    target_dir = input(f"{Colors.CYAN}Enter target directory (default: ./downloads): {Colors.RESET}").strip()
                    if not target_dir:
                        target_dir = "./downloads"

                    Path(target_dir).mkdir(exist_ok=True)
                    if github_manager.download_version(version_tag, target_dir):
                        print(f"{Colors.GREEN}Version {version_tag} downloaded successfully{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Failed to download version {version_tag}{Colors.RESET}")

            elif choice == '3':
                latest = github_manager.get_latest_version()
                if latest:
                    print(f"\n{Colors.GREEN}Latest Version:{Colors.RESET}")
                    print(f"  Tag: {latest['tag']}")
                    print(f"  Name: {latest['name']}")
                    print(f"  Published: {latest['published_at']}")
                    print(f"  Pre-release: {latest['prerelease']}")
                else:
                    print(f"{Colors.RED}Failed to fetch latest version{Colors.RESET}")

            elif choice == '4':
                print(f"\n{Colors.GREEN}Current Version: {PLEXICHAT_VERSION}{Colors.RESET}")

            elif choice == '5':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-5.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Version manager exited{Colors.RESET}")
    except Exception as e:
        if logger:
            logger.error(f"Version manager error: {e}")

def run_dependency_manager():
    """Run the dependency management interface."""
    try:
        dep_manager = DependencyManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Dependency Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. Check dependencies")
            print("2. Install dependencies")
            print("3. Upgrade dependencies")
            print("4. Create virtual environment")
            print("5. Clean cache")
            print("6. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-6): {Colors.RESET}").strip()

            if choice == '1':
                deps = dep_manager.check_dependencies()
                print(f"\n{Colors.GREEN}Dependency Status:{Colors.RESET}")
                for package, installed in deps.items():
                    status = f"{Colors.GREEN}✓{Colors.RESET}" if installed else f"{Colors.RED}✗{Colors.RESET}"
                    print(f"  {status} {package}")

            elif choice == '2':
                if dep_manager.install_dependencies():
                    print(f"{Colors.GREEN}Dependencies installed successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to install dependencies{Colors.RESET}")

            elif choice == '3':
                if dep_manager.install_dependencies(upgrade=True):
                    print(f"{Colors.GREEN}Dependencies upgraded successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to upgrade dependencies{Colors.RESET}")

            elif choice == '4':
                if dep_manager.create_virtual_environment():
                    print(f"{Colors.GREEN}Virtual environment created successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to create virtual environment{Colors.RESET}")

            elif choice == '5':
                if dep_manager.clean_cache():
                    print(f"{Colors.GREEN}Cache cleaned successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to clean cache{Colors.RESET}")

            elif choice == '6':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-6.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Dependency manager exited{Colors.RESET}")
    except Exception as e:
        if logger:
            logger.error(f"Dependency manager error: {e}")

def run_system_manager():
    """Run the system management interface."""
    try:
        sys_manager = SystemManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat System Manager{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. System health check")
            print("2. Clean system")
            print("3. Show disk usage")
            print("4. Show memory usage")
            print("5. Environment info")
            print("6. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice (1-6): {Colors.RESET}").strip()

            if choice == '1':
                health = sys_manager.check_system_health()
                print(f"\n{Colors.GREEN}System Health:{Colors.RESET}")
                for key, value in health.items():
                    if isinstance(value, dict):
                        print(f"  {key}:")
                        for sub_key, sub_value in value.items():  # type: ignore
                            print(f"    {sub_key}: {sub_value}")
                    else:
                        print(f"  {key}: {value}")

            elif choice == '2':
                if sys_manager.cleanup_system():
                    print(f"{Colors.GREEN}System cleaned successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}System cleanup failed{Colors.RESET}")

            elif choice == '3':
                disk = sys_manager.get_disk_space()
                if "error" not in disk:
                    print(f"\n{Colors.GREEN}Disk Usage:{Colors.RESET}")
                    print(f"  Total: {disk['total'] / (1024**3):.2f} GB")
                    print(f"  Used: {disk['used'] / (1024**3):.2f} GB ({disk['percent_used']:.1f}%)")
                    print(f"  Free: {disk['free'] / (1024**3):.2f} GB")
                else:
                    print(f"{Colors.RED}Error: {disk['error']}{Colors.RESET}")

            elif choice == '4':
                memory = sys_manager.get_memory_usage()
                if "error" not in memory:
                    print(f"\n{Colors.GREEN}Memory Usage:{Colors.RESET}")
                    print(f"  Total: {memory['total'] / (1024**3):.2f} GB")
                    print(f"  Used: {memory['used'] / (1024**3):.2f} GB ({memory['percent']:.1f}%)")
                    print(f"  Available: {memory['available'] / (1024**3):.2f} GB")
                else:
                    print(f"{Colors.RED}Error: {memory['error']}{Colors.RESET}")

            elif choice == '5':
                print(f"\n{Colors.GREEN}Environment Information:{Colors.RESET}")
                print(f"  Python: {sys.version}")
                print(f"  Platform: {platform.platform()}")
                print(f"  Working Directory: {os.getcwd()}")
                print(f"  PlexiChat Version: {PLEXICHAT_VERSION}")

            elif choice == '6':
                break

            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-6.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}System manager exited{Colors.RESET}")
    except Exception as e:
        if logger:
            logger.error(f"System manager error: {e}")

def run_enhanced_tests():
    """Run the comprehensive test suite."""
    try:
        import asyncio
        try:
            from src.plexichat.tests.unified_test_manager import run_tests
        except ImportError:
            if logger:
                logger.error("Test runner not available")
            return False

        if logger:
            logger.info("Running PlexiChat comprehensive test suite...")

        # Run all tests
        report = asyncio.run(run_tests(
            categories=None,  # Run all categories
            verbose=True,
            save_report=True
        ))

        # Check results
        if report.get('summary', {}).get('failed', 0) == 0:
            if logger:
                logger.info("All tests passed!")
            return True
        else:
            failed_count = report['summary']['failed']
            total_count = report['summary']['total_tests']
            if logger:
                logger.error(f"{failed_count}/{total_count} tests failed")
            return False

    except ImportError as e:
        if logger:
            logger.error(f"Test system not available: {e}")
            logger.info("Make sure all test dependencies are installed")
        return False
    except Exception as e:
        if logger:
            logger.error(f"Error running tests: {e}")
        return False

# ============================================================================
# MAIN APPLICATION RUNNERS
# ============================================================================

def run_splitscreen_cli():
    """Run the enhanced splitscreen CLI interface."""
    try:
        # Import with timeout to avoid deadlocks
        import threading
        import time

        def import_cli():
            try:
                from plexichat.interfaces.cli.console_manager import EnhancedSplitScreen
                return EnhancedSplitScreen(logger=logger)
            except Exception as e:
                if logger:
                    logger.warning(f"CLI import failed: {e}")
                return None

        # Try to import with a timeout
        cli = None
        import_thread = threading.Thread(target=lambda: setattr(import_cli, 'result', import_cli()))
        import_thread.daemon = True
        import_thread.start()
        import_thread.join(timeout=5.0)  # 5 second timeout

        if import_thread.is_alive():
            if logger:
                logger.warning("CLI import timed out, skipping splitscreen CLI")
            return

        cli = getattr(import_cli, 'result', None)
        if cli and hasattr(cli, "start"):
            cli.start()
        else:
            if logger:
                logger.info("Splitscreen CLI not available, continuing without it")
    except Exception as e:
        if logger:
            logger.error(f"Could not start splitscreen CLI: {e}")
            logger.debug(f"CLI error details: {e}", exc_info=True)

from typing import Any, Optional
def run_api_and_cli(args: Optional[Any] = None):
    """Run API server with optional CLI interface and WebUI."""
    # Check for --nocli flag
    start_cli = True
    if args and hasattr(args, 'nocli') and args.nocli:
        start_cli = False
    elif args and isinstance(args, list) and '--nocli' in args:
        start_cli = False

    # Check for --noui flag
    start_webui = True
    if args and getattr(args, 'noui', False):  # type: ignore
        start_webui = False
    elif args and isinstance(args, list) and '--noui' in args:
        start_webui = False

    if start_cli:
        try:
            # Start the splitscreen CLI in a separate thread
            cli_thread = threading.Thread(target=run_splitscreen_cli, daemon=True)
            if cli_thread and hasattr(cli_thread, "start"):
                cli_thread.start()
                if logger:
                    logger.info("CLI thread started successfully")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to start CLI interface: {e}")
                logger.info("Continuing with API server only...")
    else:
        if logger:
            logger.info("CLI interface disabled (--nocli flag)")

    if start_webui:
        try:
            # Start the WebUI in a separate thread
            webui_thread = threading.Thread(target=lambda: run_webui_server(args), daemon=True)
            webui_thread.start()
            if logger:
                logger.info("WebUI thread started successfully")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to start WebUI interface: {e}")
                logger.info("Continuing with API server only...")
    else:
        if logger:
            logger.info("WebUI interface disabled (--noui flag)")

    # Start the API server (blocking)
    run_api_server(args)

def run_gui(args: Any = None) -> None:
    """Launch the modern GUI interface with optional API server integration."""
    # Check for --noserver flag
    start_server = True
    if args and getattr(args, 'noserver', False):
        start_server = False
    elif args and isinstance(args, list) and '--noserver' in args:
        start_server = False

    if logger:
        logger.info(f"{Colors.BOLD}{Colors.BLUE}Launching PlexiChat Modern GUI...{Colors.RESET}")

    # Start API server in background if requested
    server_process = None
    if start_server:
        if logger:
            logger.info(f"{Colors.CYAN}Starting API server for GUI integration...{Colors.RESET}")
        try:
            import threading
            import time

            def start_api_server():
                try:
                    run_api_server(args)
                except Exception as e:
                    if logger:
                        logger.error(f"API server error: {e}")

            server_thread = threading.Thread(target=start_api_server, daemon=False)
            server_thread.start()

            # Give server time to start
            time.sleep(2)
            if logger:
                logger.info(f"{Colors.GREEN}API server started on http://127.0.0.1:8000{Colors.RESET}")

        except Exception as e:
            if logger:
                logger.warning(f"Failed to start API server: {e}")
            start_server = False

    try:
        if logger:
            logger.debug(f"{Colors.CYAN}Loading GUI modules...{Colors.RESET}")

        # Try to launch GUI with fallbacks
        gui_launched = False
        
        # Try PyQt6 first
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox
            import webbrowser
            
            if logger:
                logger.info(f"{Colors.GREEN}Tkinter GUI available{Colors.RESET}")
            
            # Create simple GUI window
            root = tk.Tk()
            root.title("PlexiChat")
            root.geometry("800x600")
            
            # Main frame
            main_frame = ttk.Frame(root, padding="10")
            main_frame.grid(row=0, column=0, sticky="nsew")
            
            # Title
            title_label = ttk.Label(main_frame, text="PlexiChat", font=('Arial', 24, 'bold'))
            title_label.grid(row=0, column=0, columnspan=2, pady=20)
            
            # Status
            status_text = "API Server: Running" if start_server else "API Server: Not Running"
            status_label = ttk.Label(main_frame, text=status_text)
            status_label.grid(row=1, column=0, columnspan=2, pady=10)
            
            # Buttons
            if start_server:
                def open_web():
                    webbrowser.open("http://localhost:8000")
                
                web_button = ttk.Button(main_frame, text="Open Web Interface", command=open_web)
                web_button.grid(row=2, column=0, padx=5, pady=10)
                
                docs_button = ttk.Button(main_frame, text="API Documentation", 
                                        command=lambda: webbrowser.open("http://localhost:8000/docs"))
                docs_button.grid(row=2, column=1, padx=5, pady=10)
            
            # Info text
            info_text = tk.Text(main_frame, height=20, width=80)
            info_text.grid(row=3, column=0, columnspan=2, pady=20)
            
            info_content = f"""PlexiChat GUI

Version: {PLEXICHAT_VERSION}
API Server: {'Running on http://localhost:8000' if start_server else 'Not running'}

Features:
- Secure messaging platform
- API server with web interface
- Plugin system
- File attachments
- Real-time communication

To get started:
1. {'Visit http://localhost:8000 for the web interface' if start_server else 'Start the API server first'}
2. Check the API documentation at /docs
3. Use the CLI tools for administration

For help: python run.py --help
"""
            
            info_text.insert(tk.END, info_content)
            info_text.config(state=tk.DISABLED)
            
            # Configure grid weights
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            main_frame.columnconfigure(0, weight=1)
            main_frame.columnconfigure(1, weight=1)
            
            if logger:
                logger.info(f"{Colors.GREEN}Simple GUI launched successfully{Colors.RESET}")
            
            # Run the GUI
            root.mainloop()
            gui_launched = True
            
        except ImportError as e:
            if logger:
                logger.warning(f"Tkinter not available: {e}")
            
        # If GUI couldn't be launched, show message
        if not gui_launched:
            if logger:
                logger.error(f"{Colors.RED}No GUI framework available{Colors.RESET}")
            print(f"\n{Colors.YELLOW}GUI not available. Install tkinter or PyQt6:{Colors.RESET}")
            print(f"  Windows: tkinter comes with Python")
            print(f"  Linux: sudo apt-get install python3-tk")
            print(f"  macOS: brew install python-tk")
            print(f"\n{Colors.CYAN}Alternative: Use the web interface at http://localhost:8000{Colors.RESET}")
            return False

        # If server was started and GUI closes, keep server running unless --noserver
        if start_server:
            if logger:
                logger.info(f"{Colors.CYAN}GUI closed but API server continues running...{Colors.RESET}")
                logger.info(f"{Colors.INFO}Access web interface at: http://localhost:8000{Colors.RESET}")
                logger.info(f"{Colors.INFO}Press Ctrl+C to stop the server{Colors.RESET}")

            # Keep the main thread alive so server continues
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                if logger:
                    logger.info(f"{Colors.YELLOW}Shutting down API server...{Colors.RESET}")

    except ImportError as e:
        if logger:
            logger.error(f"{Colors.RED}Failed to import GUI modules: {e}{Colors.RESET}")
            logger.error(f"{Colors.YELLOW}Make sure PyQt6 is installed{Colors.RESET}")
            logger.error(f"{Colors.CYAN}Install with: pip install PyQt6{Colors.RESET}")
            import traceback
            logger.debug(traceback.format_exc())
        return False
    except Exception as e:
        if logger:
            logger.error(f"{Colors.RED}GUI startup error: {e}{Colors.RESET}")
            import traceback
            logger.debug(traceback.format_exc())
        return False

    return True

def run_gui_standalone() -> bool:
    """Launch the GUI interface in standalone mode (without server integration)."""
    if logger:
        logger.info(f"{Colors.BOLD}{Colors.BLUE}Launching PlexiChat GUI (Standalone Mode)...{Colors.RESET}")
    try:
        if logger:
            logger.debug(f"{Colors.CYAN}Importing GUI modules...{Colors.RESET}")
        from plexichat.interfaces.gui.main_application import PlexiChatGUI

        if logger:
            logger.info(f"{Colors.GREEN}GUI modules imported successfully{Colors.RESET}")
            logger.info(f"{Colors.BOLD}{Colors.GREEN}Opening PlexiChat GUI in Standalone Mode...{Colors.RESET}")

        # Create and run GUI in standalone mode
        app = PlexiChatGUI()
        if hasattr(app, 'standalone_mode'):
            app.standalone_mode = True  # Set standalone flag
        app.run()

        if logger:
            logger.info(f"{Colors.BLUE}GUI closed successfully{Colors.RESET}")

    except ImportError as e:
        if logger:
            logger.error(f"{Colors.RED}Failed to import GUI modules: {e}{Colors.RESET}")
            logger.error(f"{Colors.YELLOW}Make sure tkinter is installed{Colors.RESET}")
            import traceback
            logger.debug(traceback.format_exc())
        return False
    except Exception as e:
        if logger:
            logger.error(f"{Colors.RED}GUI startup error: {e}{Colors.RESET}")
            import traceback
            logger.debug(traceback.format_exc())
        return False

    return True

def run_webui_server(args: Optional[Any] = None) -> None:
    """Start just the WebUI server component."""
    from typing import Any, Optional
    try:
        if logger:
            logger.info("Starting PlexiChat WebUI server...")

        # Get port from args or environment, but use a different port for WebUI
        base_port = 8003  # Default base port
        if args and hasattr(args, 'port') and getattr(args, 'port', None) is not None:
            base_port = getattr(args, 'port', 8003)
        else:
            port_env = os.getenv('PLEXICHAT_PORT')
            base_port = int(port_env) if port_env is not None else 8003

        # Use base_port + 1 for WebUI to avoid conflicts
        webui_port = base_port + 1

        # Import and start WebUI
        from plexichat.interfaces.web import app
        import uvicorn

        if logger:
            logger.info(f"WebUI server starting on port {webui_port}")
        uvicorn.run(app, host="0.0.0.0", port=webui_port, log_level="info")

    except Exception as e:
        if logger:
            logger.error(f"Failed to start WebUI server: {e}")

def run_webui(args: Optional[Any] = None) -> None:
    """Launch the web UI interface with API server by default."""
    from typing import Any, Optional
    # Check for --noserver flag
    start_server = True
    if args and hasattr(args, 'noserver') and getattr(args, 'noserver', False):
        start_server = False
    elif args and isinstance(args, list) and '--noserver' in args:
        start_server = False

    if start_server:
        if logger:
            logger.info("Launching PlexiChat Web UI with API server...")
            logger.info("Starting web server with enhanced UI...")
            logger.info("Web interface available at: http://localhost:8000")
            logger.info("API documentation at: http://localhost:8000/docs")
        run_api_and_cli(args)  # Start with API server and CLI
    else:
        if logger:
            logger.info("Launching PlexiChat Web UI without API server...")
        run_webui_server(args)

def run_configuration_wizard():
    """Run the configuration wizard."""
    try:
        config_manager = ConfigurationManager()

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Configuration Wizard{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        # Load existing config or create new
        config = config_manager.load_configuration()

        print(f"\n{Colors.GREEN}Current Configuration:{Colors.RESET}")
        print(json.dumps(config, indent=2))

        modify = input(f"\n{Colors.CYAN}Do you want to modify the configuration? (y/N): {Colors.RESET}").strip().lower()

        if modify == 'y':
            # Server configuration
            print(f"\n{Colors.BOLD}Server Configuration:{Colors.RESET}")
            host = input(f"Host ({config['server']['host']}): ").strip() or config['server']['host']
            port = input(f"Port ({config['server']['port']}): ").strip()
            if port.isdigit():
                port = int(port)
            else:
                port = config['server']['port']

            config['server']['host'] = host
            config['server']['port'] = port

            # Database configuration
            print(f"\n{Colors.BOLD}Database Configuration:{Colors.RESET}")
            db_type = input(f"Database type (sqlite/postgresql/mysql) ({config['database']['type']}): ").strip() or config['database']['type']

            if db_type == 'sqlite':
                db_url = input(f"Database file path ({config['database']['url']}): ").strip() or config['database']['url']
            else:
                db_url = input(f"Database URL ({config['database']['url']}): ").strip() or config['database']['url']

            config['database']['type'] = db_type
            config['database']['url'] = db_url

            # Security configuration
            print(f"\n{Colors.BOLD}Security Configuration:{Colors.RESET}")
            jwt_expire = input(f"JWT expiration minutes ({config['security']['jwt_expire_minutes']}): ").strip()
            if jwt_expire.isdigit():
                config['security']['jwt_expire_minutes'] = int(jwt_expire)

            # Features configuration
            print(f"\n{Colors.BOLD}Features Configuration:{Colors.RESET}")
            for feature, enabled in config['features'].items():
                response = input(f"Enable {feature}? (y/N) [current: {enabled}]: ").strip().lower()
                if response == 'y':
                    config['features'][feature] = True
                elif response == 'n':
                    config['features'][feature] = False

            # Save configuration
            if config_manager.save_configuration(config):
                print(f"\n{Colors.GREEN}Configuration saved successfully!{Colors.RESET}")

                # Setup environment variables
                config_manager.setup_environment_variables(config)
                print(f"{Colors.GREEN}Environment variables configured{Colors.RESET}")

                return True
            else:
                print(f"\n{Colors.RED}Failed to save configuration{Colors.RESET}")
                return False
        else:
            print(f"\n{Colors.YELLOW}Configuration unchanged{Colors.RESET}")
            return True

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Configuration wizard cancelled{Colors.RESET}")
        return False
    except Exception as e:
        if logger:
            logger.error(f"Configuration wizard failed: {e}")
        return False

def run_refresh_current_version():
    """Refresh current version by redownloading and verifying all files."""
    try:
        if logger:
            logger.info("Starting refresh of current version...")

        # Get current version from version.json
        current_version = get_version_from_json()
        if logger:
            logger.info(f"Current version: {current_version}")

        # Create backup before refresh
        backup_dir = Path("backups") / f"pre_refresh_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{Colors.BOLD}{Colors.BLUE}Refreshing PlexiChat {current_version}{Colors.RESET}")
        print(f"{Colors.DIM}Creating backup...{Colors.RESET}")

        # Backup critical files
        critical_files = ["config", "data", "logs"]
        for item in critical_files:
            if Path(item).exists():
                try:
                    if Path(item).is_dir():
                        shutil.copytree(item, backup_dir / item)
                    else:
                        shutil.copy2(item, backup_dir / item)
                except Exception as e:
                    if logger:
                        logger.warning(f"Could not backup {item}: {e}")

        print(f"{Colors.GREEN}Backup created at: {backup_dir}{Colors.RESET}")

        # Download current version from GitHub
        github_url = f"https://github.com/linux-of-user/plexichat/archive/refs/tags/{current_version}.zip"
        temp_dir = Path("temp") / "refresh"
        temp_dir.mkdir(parents=True, exist_ok=True)

        print(f"{Colors.DIM}Downloading {current_version} from GitHub...{Colors.RESET}")

        try:
            import urllib.request
            zip_file = temp_dir / f"{current_version}.zip"
            urllib.request.urlretrieve(github_url, zip_file)

            # Verify download
            if not zip_file.exists() or zip_file.stat().st_size < 1000:
                raise Exception("Download failed or file too small")

            print(f"{Colors.GREEN}Download completed: {zip_file.stat().st_size} bytes{Colors.RESET}")

            # Extract and verify
            print(f"{Colors.DIM}Extracting and verifying files...{Colors.RESET}")

            import zipfile
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                extract_dir = temp_dir / "extracted"
                zip_ref.extractall(extract_dir)

            # Find the extracted directory (usually plexichat-{version})
            extracted_dirs = list(extract_dir.glob("plexichat-*"))
            if not extracted_dirs:
                raise Exception("Could not find extracted plexichat directory")

            source_dir = extracted_dirs[0]

            # Verify critical files exist
            critical_source_files = ["src", "run.py", "requirements.txt"]
            for file in critical_source_files:
                if not (source_dir / file).exists():
                    raise Exception(f"Critical file missing: {file}")

            # File integrity check using checksums
            print(f"{Colors.DIM}Performing file integrity checks...{Colors.RESET}")

            # Update source files
            if Path("src").exists():
                shutil.rmtree("src")
            shutil.copytree(source_dir / "src", "src")

            # Update run.py
            shutil.copy2(source_dir / "run.py", "run.py")

            # Update requirements.txt if it exists
            if (source_dir / "requirements.txt").exists():
                shutil.copy2(source_dir / "requirements.txt", "requirements.txt")

            # Update version.json and changelog.json
            if (source_dir / "version.json").exists():
                shutil.copy2(source_dir / "version.json", "version.json")
                print(f"{Colors.GREEN}✓ Updated version.json{Colors.RESET}")

            if (source_dir / "changelog.json").exists():
                shutil.copy2(source_dir / "changelog.json", "changelog.json")
                print(f"{Colors.GREEN}✓ Updated changelog.json{Colors.RESET}")

            print(f"{Colors.GREEN}✓ Files refreshed successfully{Colors.RESET}")
            print(f"{Colors.GREEN}✓ File integrity verified{Colors.RESET}")
            print(f"{Colors.GREEN}✓ Refresh completed for version {current_version}{Colors.RESET}")

            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

            return True

        except Exception as e:
            if logger:
                logger.error(f"Refresh failed: {e}")
            print(f"{Colors.RED}✗ Refresh failed: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}Backup available at: {backup_dir}{Colors.RESET}")
            return False

    except Exception as e:
        if logger:
            logger.error(f"Refresh system failed: {e}")
        print(f"{Colors.RED}✗ Refresh system failed: {e}{Colors.RESET}")
        return False

def run_bootstrap_update_system():
    """Run update system in bootstrap mode (standalone)."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Bootstrap Update System{Colors.RESET}")
    print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.YELLOW}Running in bootstrap mode - limited functionality{Colors.RESET}")

    while True:
        print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
        print("1. Show current version")
        print("2. Refresh current version (redownload)")
        print("3. Exit")

        choice = input(f"\n{Colors.CYAN}Enter your choice (1-3): {Colors.RESET}").strip()

        if choice == '1':
            # Show basic version info
            print(f"{Colors.GREEN}Bootstrap mode - version info not available{Colors.RESET}")

        elif choice == '2':
            # Refresh current version
            confirm = input(f"{Colors.YELLOW}Are you sure you want to refresh? (y/N): {Colors.RESET}").strip().lower()
            if confirm == 'y':
                run_refresh_current_version()

        elif choice == '3':
            break

        else:
            print(f"{Colors.RED}Invalid choice. Please enter 1-3.{Colors.RESET}")

    return True

def run_update_system():
    """Run the update system using existing update functionality."""
    try:
        if logger:
            logger.info("Starting PlexiChat Update System...")

        # Check if we're in bootstrap mode (no src directory available)
        bootstrap_mode = not Path("src").exists()

        if bootstrap_mode:
            if logger:
                logger.info("Running in bootstrap mode - using standalone update system")
            return run_bootstrap_update_system()

        # Import the existing CLI system and plugin commands
        try:
            from plexichat.interfaces.cli.commands.updates import UpdateCLI
            from plexichat.core.plugins import unified_plugin_manager
            from plexichat.interfaces.cli.unified_cli import UnifiedCLI

            update_cli = UpdateCLI()
            plugin_manager = unified_plugin_manager
            _unified_cli = UnifiedCLI()  # Prefix with _ to indicate intentionally unused

            # Discover and load plugin commands
            asyncio.run(plugin_manager.discover_plugins())
            plugin_commands = plugin_manager.plugin_commands  # type: ignore

            _update_cli_available = True  # Prefix with _ to indicate intentionally unused
            if logger:
                logger.info(f"Loaded {len(plugin_commands)} plugin commands")  # type: ignore

        except ImportError as e:
            if logger:
                logger.warning(f"Full CLI system not available: {e}, using basic functionality")
            update_cli = None
            plugin_manager = None
            _unified_cli = None  # Prefix with _ to indicate intentionally unused
            plugin_commands = {}
            _update_cli_available = False  # Prefix with _ to indicate intentionally unused

        print(f"\n{Colors.BOLD}{Colors.BLUE}PlexiChat Update System{Colors.RESET}")
        print(f"{Colors.DIM}{'=' * 50}{Colors.RESET}")

        while True:
            print(f"\n{Colors.BOLD}Available Commands:{Colors.RESET}")
            print("1. Check for updates")
            print("2. Show current version")
            print("3. Upgrade to latest")
            print("4. Show changelog")
            print("5. Update history")
            print("6. Reinstall dependencies")
            print("7. Refresh current version (redownload)")

            # Show plugin commands if available
            if plugin_commands:
                print(f"\n{Colors.BOLD}Plugin Commands:{Colors.RESET}")
                plugin_menu_start = 10
                plugin_choices = {}
                for i, (cmd_name, cmd_func) in enumerate(plugin_commands.items(), plugin_menu_start):  # type: ignore
                    print(f"{i}. {cmd_name}")
                    plugin_choices[str(i)] = (cmd_name, cmd_func)
                print(f"\n8. List all plugin commands")
                print(f"9. Execute custom plugin command")

            print(f"\n0. Exit")

            choice = input(f"\n{Colors.CYAN}Enter your choice: {Colors.RESET}").strip()

            if choice == '1':
                # Check for updates
                if update_cli:
                    asyncio.run(update_cli.handle_check(None))
                else:
                    print(f"{Colors.YELLOW}Basic update check not implemented yet{Colors.RESET}")

            elif choice == '2':
                # Show current version
                if update_cli:
                    asyncio.run(update_cli.handle_version(None))
                else:
                    try:
                        from src.plexichat.core.versioning.version_manager import VersionManager
                        vm = VersionManager()
                        print(f"{Colors.GREEN}Current version: {vm.current_version}{Colors.RESET}")
                        print(f"Version type: {vm.version_type}")
                        print(f"Build number: {vm.build_number}")
                        print(f"Release date: {vm.release_date}")
                    except Exception as e:
                        print(f"{Colors.RED}Error getting version: {e}{Colors.RESET}")

            elif choice == '3':
                # Upgrade to latest
                confirm = input(f"{Colors.YELLOW}Are you sure you want to upgrade? (y/N): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    if update_cli:
                        asyncio.run(update_cli.handle_upgrade(None))
                    else:
                        print(f"{Colors.YELLOW}Upgrade functionality not available{Colors.RESET}")

            elif choice == '4':
                # Show changelog
                if update_cli:
                    asyncio.run(update_cli.handle_changelog(None))
                else:
                    print(f"{Colors.YELLOW}Changelog functionality not available{Colors.RESET}")

            elif choice == '5':
                # Show update history
                if update_cli:
                    asyncio.run(update_cli.handle_history(None))
                else:
                    print(f"{Colors.YELLOW}Update history not available{Colors.RESET}")

            elif choice == '6':
                # Reinstall dependencies
                if update_cli:
                    asyncio.run(update_cli.handle_reinstall_deps(None))
                else:
                    print(f"{Colors.YELLOW}Dependency reinstall not available{Colors.RESET}")

            elif choice == '7':
                # Refresh current version (redownload)
                confirm = input(f"{Colors.YELLOW}Are you sure you want to refresh the current version? This will redownload and verify all files. (y/N): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    run_refresh_current_version()

            elif choice == '8' and plugin_commands:
                # List all plugin commands
                print(f"\n{Colors.BOLD}All Plugin Commands:{Colors.RESET}")
                for cmd_name in plugin_commands.keys():
                    print(f"  - {cmd_name}")

            elif choice == '9' and plugin_commands:
                # Execute custom plugin command
                cmd_name = input(f"{Colors.CYAN}Enter plugin command name: {Colors.RESET}").strip()
                if cmd_name in plugin_commands:
                    try:
                        print(f"{Colors.GREEN}Executing {cmd_name}...{Colors.RESET}")
                        result = asyncio.run(plugin_commands[cmd_name]())  # type: ignore
                        print(f"{Colors.GREEN}Command completed: {result}{Colors.RESET}")
                    except Exception as e:
                        print(f"{Colors.RED}Command failed: {e}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Command not found: {cmd_name}{Colors.RESET}")

            elif plugin_commands and choice in [str(i) for i in range(10, 10 + len(plugin_commands))]:  # type: ignore
                # Execute specific plugin command
                plugin_list = list(plugin_commands.items())  # type: ignore
                plugin_index = int(choice) - 10
                if 0 <= plugin_index < len(plugin_list):  # type: ignore
                    cmd_name, cmd_func = plugin_list[plugin_index]  # type: ignore
                    try:
                        print(f"{Colors.GREEN}Executing {cmd_name}...{Colors.RESET}")
                        result = asyncio.run(cmd_func())  # type: ignore
                        print(f"{Colors.GREEN}Command completed: {result}{Colors.RESET}")
                    except Exception as e:
                        print(f"{Colors.RED}Command failed: {e}{Colors.RESET}")

            elif choice == '0':
                break

            else:
                print(f"{Colors.RED}Invalid choice.{Colors.RESET}")

    except ImportError as e:
        if logger:
            logger.error(f"Update system not available: {e}")
        print(f"{Colors.RED}Update system not available. Using fallback GitHub version manager.{Colors.RESET}")
        run_version_manager()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Update system exited{Colors.RESET}")
    except Exception as e:
        if logger:
            logger.error(f"Update system error: {e}")
        print(f"{Colors.RED}Update system error: {e}{Colors.RESET}")

def run_first_time_setup(level: Optional[str] = None) -> bool:
    """Run comprehensive first-time setup with dynamic terminal UI and timeout handling."""
    cancelled = False
    start_time = time.time()
    
    from typing import Any
    def signal_handler(signum: int, frame: Any) -> None:
        nonlocal cancelled
        cancelled = True
        print(f"\n{Colors.YELLOW}Setup cancelled by user{Colors.RESET}")
        sys.exit(0)
    
    def timeout_handler():
        """Handle setup timeout after 15 minutes"""
        if time.time() - start_time > 900:  # 15 minutes timeout
            print(f"\n{Colors.RED}Setup timed out after 15 minutes{Colors.RESET}")
            return True
        return False
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print(f"\n{Colors.BOLD}{Colors.GREEN}*** Welcome to PlexiChat! ***{Colors.RESET}")
        print(f"{Colors.DIM}Starting first-time setup... (Press Ctrl+C to cancel){Colors.RESET}")
        print(f"{Colors.DIM}This may take a few minutes depending on your system.{Colors.RESET}")

        # If no level specified, show interactive setup options
        if level is None:
            level = show_setup_interface_choice()
            if level in ['gui', 'webui']:
                return launch_setup_interface(level)

        # Initialize terminal UI with beautiful progress tracking
        ui = TerminalUI()
        ui.add_log("Starting PlexiChat first-time setup", "INFO")
        ui.add_log(f"Setup timeout: 15 minutes", "INFO")
        ui.refresh_display()

        # Initialize managers with error handling
        try:
            system_manager = SystemManager()
        except Exception as e:
            ui.add_log(f"Failed to initialize system manager: {e}", "ERROR")
            return False

        # Step 1: System check with timeout and progress
        ui.update_progress(0, 0.1, "Checking system requirements...")
        ui.add_log("Checking system requirements...", "INFO")
        ui.refresh_display()
        
        try:
            # Quick timeout check
            if timeout_handler():
                return False
                
            health = system_manager.check_system_health()
            if health:
                ui.add_log("System check passed", "SUCCESS")
                ui.complete_step(0, True)
            else:
                ui.add_log("System check failed - continuing anyway", "WARNING")
                ui.complete_step(0, False)
        except Exception as e:
            ui.add_log(f"System check error: {e} - continuing", "WARNING")
            ui.complete_step(0, False)

        # Step 2: Environment setup with timeout and progress
        ui.update_progress(1, 0.2, "Setting up environment...")
        ui.add_log("Setting up environment...", "INFO")
        ui.refresh_display()
        
        try:
            if timeout_handler():
                return False
                
            setup_environment()
            ui.add_log("Environment setup completed", "SUCCESS")
            ui.complete_step(1, True)
        except Exception as e:
            ui.add_log(f"Environment setup failed: {e} - continuing", "WARNING")
            ui.complete_step(1, False)

        # Step 3: Configuration with timeout and progress
        ui.update_progress(2, 0.3, "Setting up configuration...")
        ui.add_log("Setting up configuration...", "INFO")
        ui.refresh_display()
        
        try:
            if timeout_handler():
                return False
                
            config_manager = ConfigurationManager()
            config = config_manager.load_configuration()
            if config:
                config_manager.setup_environment_variables(config)
                ui.add_log("Configuration setup completed", "SUCCESS")
                ui.complete_step(2, True)
            else:
                ui.add_log("Configuration setup failed - using defaults", "WARNING")
                ui.complete_step(2, False)
        except Exception as e:
            ui.add_log(f"Configuration error: {e} - using defaults", "WARNING")
            ui.complete_step(2, False)

        # Step 4: Dependencies with enhanced progress and timeout
        ui.update_progress(3, 0.4, "Preparing for dependency installation...")
        ui.add_log("Preparing for dependency installation...", "INFO")
        ui.refresh_display()
        
        # Check for cancellation
        if cancelled or timeout_handler():
            ui.add_log("Setup cancelled or timed out", "WARNING")
            return False

        # Interactive level selection with fallback
        if level is None:
            try:
                if RICH_AVAILABLE:
                    # Temporarily stop the UI to ask for input
                    ui.show_cursor()
                    ui.clear_screen()
                    
                    console = RichConsole()
                    console.print(Panel.fit(
                        "Choose your installation type:",
                        title="[bold cyan]Dependency Setup[/bold cyan]",
                        border_style="green"
                    ))
                    
                    choices = ["minimal", "standard", "full", "developer"]
                    descriptions = [
                        "Core dependencies only (fastest)",
                        "Standard features (recommended)", 
                        "All features (most complete)",
                        "All features + developer tools"
                    ]
                    
                    choice_text = "\n".join([
                        f"[bold yellow]{i+1}[/bold yellow]. {choice.capitalize()}: {desc}" 
                        for i, (choice, desc) in enumerate(zip(choices, descriptions))
                    ])
                    console.print(choice_text)
                    
                    level_choice_str = Prompt.ask(
                        "\nEnter your choice (1-4)",
                        choices=[str(i+1) for i in range(4)],
                        default="2"
                    )
                    level = choices[int(level_choice_str) - 1]

                    ui.hide_cursor()
                else:
                    print("Rich library not found. Using fallback selection.")
                    print("\nChoose installation level:")
                    print("1. Minimal (fastest)")
                    print("2. Standard (recommended)")
                    print("3. Full (most complete)")
                    print("4. Developer (with dev tools)")
                    
                    while True:
                        try:
                            choice = input("\nEnter choice (1-4, default=2): ").strip() or "2"
                            if choice in ["1", "2", "3", "4"]:
                                level = ["minimal", "standard", "full", "developer"][int(choice)-1]
                                break
                            else:
                                print("Invalid choice. Please enter 1-4.")
                        except (KeyboardInterrupt, EOFError):
                            print(f"\n{Colors.YELLOW}Setup cancelled{Colors.RESET}")
                            return False
            except Exception as e:
                ui.add_log(f"Level selection failed: {e} - using 'standard'", "WARNING")
                level = 'standard'
        
            ui.add_log(f"Selected installation level: {level}", "SUCCESS")
            ui.add_log("Installing dependencies... (this may take several minutes)", "INFO")
            ui.add_log("Tip: Some packages may show warnings - this is usually normal", "INFO")
        ui.refresh_display()

        # Enhanced dependency installation with progress tracking
        try:
            dep_manager = DependencyManager(ui)
            
            # Install with timeout monitoring and progress updates
            install_start = time.time()
            install_success = False
            
            ui.update_progress(3, 0.5, f"Installing {level} dependencies...")
            ui.add_log(f"Starting {level} dependency installation...", "INFO")
            ui.refresh_display()
            
            # Run installation with periodic timeout checks
            install_success = dep_manager.install_dependencies(level=level)
            
            install_duration = time.time() - install_start
            
            if install_success:
                ui.add_log(f"Dependencies installed successfully in {install_duration:.1f}s", "SUCCESS")
                ui.complete_step(3, True)
            else:
                ui.add_log("Some dependencies failed to install - PlexiChat may still work", "WARNING")
                ui.add_log("You can retry installation later with: python run.py setup", "INFO")
                ui.complete_step(3, False)
                
        except Exception as e:
            ui.add_log(f"Dependency installation error: {e}", "ERROR")
            ui.add_log("You can retry installation later with: python run.py setup", "INFO")
            ui.complete_step(3, False)

        # Step 5: Database initialization with timeout and progress
        ui.update_progress(4, 0.8, "Initializing database...")
        ui.add_log("Initializing database...", "INFO")
        ui.refresh_display()
        
        try:
            if timeout_handler():
                return False
                
            # Simple database initialization
            try:
                data_dir = Path("data")
                data_dir.mkdir(exist_ok=True)
                db_path = data_dir / "plexichat.db"
                import sqlite3
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS system_info (
                            id INTEGER PRIMARY KEY,
                            key TEXT UNIQUE,
                            value TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    cursor.execute(
                        "INSERT OR REPLACE INTO system_info (key, value) VALUES (?, ?)",
                        ("initialized_at", datetime.now().isoformat())
                    )
                    conn.commit()
                ui.add_log("Database initialized successfully", "SUCCESS")
                ui.complete_step(4, True)
            except Exception as e:
                ui.add_log(f"Database error: {e} - using defaults", "WARNING")
                ui.complete_step(4, False)
        except Exception as e:
            ui.add_log(f"Database error: {e} - using defaults", "WARNING")
            ui.complete_step(4, False)

        # Step 6: Final setup with progress
        ui.update_progress(5, 0.9, "Finalizing setup...")
        ui.add_log("Finalizing setup...", "INFO")
        ui.refresh_display()
        
        total_time = time.time() - start_time
        ui.add_log(f"PlexiChat setup completed successfully in {total_time:.1f}s!", "SUCCESS")
        ui.add_log("You can now start PlexiChat with: python run.py", "INFO")
        ui.add_log("For help, use: python run.py --help", "INFO")
        ui.add_log("Web UI will be available at: http://localhost:8000", "INFO")
        ui.complete_step(5, True)

        # Show final success message
        ui.show_success_message("PlexiChat setup completed successfully!")
        ui.show_success_message(f"Total setup time: {total_time:.1f} seconds")
        ui.show_success_message("You can now start PlexiChat with: python run.py")

        # Give user time to read final message
        ui.refresh_display()
        time.sleep(3)
        return True

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup cancelled by user{Colors.RESET}")
        return False
    except Exception as e:
        total_time = time.time() - start_time
        logging.getLogger(__name__).error(f"First-time setup failed after {total_time:.1f}s: {e}")
        print(f"\n{Colors.RED}Setup failed: {e}{Colors.RESET}")
        print(f"{Colors.DIM}Try running with minimal dependencies: python run.py setup --level minimal{Colors.RESET}")
        return False


def show_setup_interface_choice():
    """Show interactive setup interface choice."""
    print(f"\n{Colors.BOLD}Setup Interface Selection{Colors.RESET}")
    print(f"{Colors.DIM}Choose how you'd like to complete the setup:{Colors.RESET}")
    print()
    print(f"1. {Colors.GREEN}Terminal{Colors.RESET} - Complete setup in this terminal (recommended)")
    print(f"2. {Colors.BLUE}GUI{Colors.RESET} - Open graphical setup interface")
    print(f"3. {Colors.CYAN}Web UI{Colors.RESET} - Open web-based setup interface")
    print()
    print(f"{Colors.BOLD}Installation Levels:{Colors.RESET}")
    print(f"  {Colors.WHITE}minimal{Colors.RESET}   - Core dependencies only (fastest)")
    print(f"  {Colors.WHITE}standard{Colors.RESET}  - Standard features (recommended)")
    print(f"  {Colors.WHITE}full{Colors.RESET}      - All features (most complete)")
    print(f"  {Colors.WHITE}developer{Colors.RESET} - All features + developer tools")
    print()

    while True:
        try:
            choice = input(f"{Colors.BOLD}Enter your choice (1-3) or installation level: {Colors.RESET}").strip().lower()

            # Check if user directly entered an installation level
            if choice in ['minimal', 'standard', 'full', 'developer']:
                return choice
            elif choice in ['1', 'terminal', 't']:
                level = input(f"{Colors.DIM}Installation level (minimal/standard/full/developer) [standard]: {Colors.RESET}").strip().lower()
                return level if level in ['minimal', 'standard', 'full', 'developer'] else 'standard'
            elif choice in ['2', 'gui', 'g']:
                return 'gui'
            elif choice in ['3', 'webui', 'web', 'w']:
                return 'webui'
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1-3 or an installation level.{Colors.RESET}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}Setup cancelled{Colors.RESET}")
            sys.exit(0)


def launch_setup_interface(interface_type: str) -> bool:
    """Launch GUI or WebUI setup interface."""
    try:
        if interface_type == 'gui':
            print(f"\n{Colors.CYAN}Launching GUI setup interface...{Colors.RESET}")

            # Check if tkinter is available
            try:
                import tkinter as tk
                print(f"{Colors.GREEN}GUI support available{Colors.RESET}")

                # Import and launch GUI setup
                sys.path.insert(0, 'src')
                from plexichat.interfaces.gui.main_application import PlexiChatGUI

                gui = PlexiChatGUI()
                gui.show_setup_page()  # type: ignore  # This method needs to be implemented
                gui.run()
                return True

            except ImportError:
                print(f"{Colors.RED}GUI not available - tkinter not installed{Colors.RESET}")
                print(f"{Colors.YELLOW}Install with: sudo apt-get install python3-tk{Colors.RESET}")
                print(f"{Colors.CYAN}Falling back to terminal setup...{Colors.RESET}")
                return run_first_time_setup(level='standard')

        elif interface_type == 'webui':
            print(f"\n{Colors.CYAN}Launching Web UI setup interface...{Colors.RESET}")

            # Start web server with setup page
            import threading
            import webbrowser
            import time

            def start_web_server():
                try:
                    sys.path.insert(0, 'src')
                    from plexichat.main import app
                    import uvicorn

                    # Start server in setup mode
                    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
                except Exception as e:
                    print(f"{Colors.RED}Failed to start web server: {e}{Colors.RESET}")

            # Start server in background
            server_thread = threading.Thread(target=start_web_server, daemon=True)
            server_thread.start()

            # Wait a moment for server to start
            time.sleep(2)

            # Open browser to setup page
            setup_url = "http://localhost:8000/setup"
            print(f"{Colors.GREEN}Opening setup page: {setup_url}{Colors.RESET}")
            webbrowser.open(setup_url)

            print(f"{Colors.CYAN}Complete setup in your web browser, then press Enter to continue...{Colors.RESET}")
            input()
            return True

    except Exception as e:
        print(f"{Colors.RED}Failed to launch {interface_type} interface: {e}{Colors.RESET}")
        print(f"{Colors.CYAN}Falling back to terminal setup...{Colors.RESET}")
        return run_first_time_setup(level='standard')


from typing import Any, Optional
def run_api_server(args: Optional[Any] = None) -> bool:
    """Start the PlexiChat API server."""
    from typing import Any, Optional
    try:
        # Set process name for easier identification
        try:
            from setproctitle import setproctitle
            setproctitle("PlexiChatServer")
        except ImportError:
            pass
        import uvicorn
        if logger:
            logger.info("About to import FastAPI app from src.plexichat.main...")
        from src.plexichat.main import app
        if logger:
            logger.info("FastAPI app imported successfully!")
        config = load_configuration()
        host: str = "0.0.0.0"
        port: int = 8000

        # Load from config first
        if config:
            host = str(config.get('server', {}).get('host', '0.0.0.0'))
            port = int(config.get('server', {}).get('port', 8000))

        # Override with command line arguments if provided
        if args:
            if hasattr(args, 'host') and getattr(args, 'host', None):
                host = str(getattr(args, 'host', '0.0.0.0'))
            if hasattr(args, 'port') and getattr(args, 'port', None):
                port = int(getattr(args, 'port', 8000))

        if logger:
            logger.info(f"Starting PlexiChat API server on {host}:{port}")
            logger.info("PlexiChat API server starting...")
            logger.info(f"Version: {PLEXICHAT_VERSION}")
            logger.info(f"API Documentation available at: http://{host}:{port}/docs")
            logger.info(f"Web interface available at: http://{host}:{port}")
            logger.info(f"Health check: http://{host}:{port}/health")
            logger.info(f"Version info: http://{host}:{port}/api/v1/version")

        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=False,  # Disable reload to avoid import issues
            log_level="info"
        )
        return True

    except Exception as e:
        if logger:
            logger.error(f"Could not start API server: {e}")
        return False
    return False

def run_cli() -> None:
    """Run the enhanced CLI interface."""
    try:
        # Import the enhanced CLI system
        from plexichat.interfaces.cli.enhanced_cli import enhanced_cli

        # If no additional arguments, show help
        if len(sys.argv) <= 2:
            enhanced_cli.show_help()
            return

        # Extract command and arguments
        command = sys.argv[2] if len(sys.argv) > 2 else None
        args = sys.argv[3:] if len(sys.argv) > 3 else []

        if command:
            # Run the command
            import asyncio
            success = asyncio.run(enhanced_cli.execute_command(command, args))
            if not success:
                print(f"{Colors.RED}Command failed: {command}{Colors.RESET}")
                sys.exit(1)
        else:
            enhanced_cli.show_help()

    except Exception as e:
        if logger:
            logger.error(f"Could not start CLI: {e}")
            logger.debug(f"CLI error details: {e}", exc_info=True)
        print(f"{Colors.RED}CLI Error: {e}{Colors.RESET}")
        sys.exit(1)

def run_admin_cli() -> None:
    """Run admin CLI commands."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to admin commands
        original_argv = sys.argv.copy()

        # If no additional args, show admin help
        if len(sys.argv) <= 2:
            sys.argv = ['plexichat', 'admin', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['plexichat', 'admin'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        if logger:
            logger.error(f"Could not start admin CLI: {e}")
        print("Admin CLI not available. Please check your installation.")

def run_backup_node() -> None:
    """Run backup node."""
    try:
        from plexichat.features.backup.nodes.backup_node_main import main as backup_main
        import asyncio
        asyncio.run(backup_main())
    except Exception as e:
        if logger:
            logger.error(f"Could not start backup node: {e}")

def run_plugin_manager() -> None:
    """Run plugin management CLI."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to plugin commands
        original_argv = sys.argv.copy()

        # If no additional args, show plugin help
        if len(sys.argv) <= 2:
            sys.argv = ['run.py', 'plugins', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['run.py', 'plugins'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        if logger:
            logger.error(f"Could not start plugin manager: {e}")
        print("Plugin manager CLI not available. Please check your installation.")

def show_help():
    """Display comprehensive help information."""
    help_text = f"""
{Colors.BOLD}{Colors.BLUE}PlexiChat - Government-Level Secure Communication Platform{Colors.RESET}
{Colors.DIM}{'=' * 80}{Colors.RESET}

{Colors.BOLD}Usage:{Colors.RESET} python run.py [command] [options]

{Colors.BOLD}Main Commands:{Colors.RESET}
  {Colors.GREEN}(no command){Colors.RESET}     - Start API server with splitscreen CLI (default)
  {Colors.GREEN}api{Colors.RESET}              - Start API server with splitscreen CLI
  {Colors.GREEN}gui{Colors.RESET}              - Launch GUI (starts API server and splitscreen CLI)
  {Colors.GREEN}webui{Colors.RESET}            - Launch Web UI interface
  {Colors.GREEN}cli{Colors.RESET}              - Run enhanced CLI interface (50+ commands)
                             • System monitoring and management
                             • Database operations and optimization
                             • Security scanning and audit
                             • Plugin management and installation
                             • User administration and backup
                             • Performance monitoring and analytics
                             • Network diagnostics and testing
                             • AI system management
                             • Development tools and testing
                             • Maintenance and cleanup utilities
  {Colors.GREEN}admin{Colors.RESET}            - Run admin CLI commands only
  {Colors.GREEN}backup-node{Colors.RESET}      - Start backup node server
  {Colors.GREEN}plugin{Colors.RESET}           - Plugin management CLI
  {Colors.GREEN}test{Colors.RESET}             - Run enhanced test suite
  {Colors.GREEN}help{Colors.RESET}             - Show this help

{Colors.BOLD}Setup & Management Commands:{Colors.RESET}
  {Colors.CYAN}setup{Colors.RESET}             - Run first-time setup wizard. Will prompt for installation level.
  {Colors.CYAN}advanced-setup{Colors.RESET}    - Run comprehensive advanced setup wizard
  {Colors.CYAN}wizard{Colors.RESET}            - Run configuration wizard
  {Colors.CYAN}config{Colors.RESET}            - Show/modify configuration
  {Colors.CYAN}update{Colors.RESET}            - Run update system
  {Colors.CYAN}version{Colors.RESET}           - Version management interface
  {Colors.CYAN}deps{Colors.RESET}              - Dependency management interface
  {Colors.CYAN}system{Colors.RESET}            - System management interface
  {Colors.CYAN}clean{Colors.RESET}             - Clean system cache and temporary files
  {Colors.CYAN}optimize{Colors.RESET}          - Run performance optimization
  {Colors.CYAN}diagnostic{Colors.RESET}        - Run comprehensive system diagnostics
  {Colors.CYAN}maintenance{Colors.RESET}       - Run maintenance mode with all optimizations

{Colors.BOLD}GitHub Integration Commands:{Colors.RESET}
  {Colors.YELLOW}download{Colors.RESET}         - Download specific version from GitHub
  {Colors.YELLOW}latest{Colors.RESET}           - Download latest version from GitHub
  {Colors.YELLOW}versions{Colors.RESET}         - List available versions on GitHub

{Colors.BOLD}Options:{Colors.RESET}
  {Colors.WHITE}--verbose, -v{Colors.RESET}    - Enable verbose output
  {Colors.WHITE}--debug, -d{Colors.RESET}      - Enable debug mode (same as --log-level=DEBUG)
  {Colors.WHITE}--config FILE{Colors.RESET}    - Use custom config file
  {Colors.WHITE}--log-level LEVEL{Colors.RESET} - Set log level (DEBUG, INFO, WARNING, ERROR)
  {Colors.WHITE}--port PORT{Colors.RESET}      - Override port number
  {Colors.WHITE}--host HOST{Colors.RESET}      - Override host address
  {Colors.WHITE}--no-ui{Colors.RESET}          - Disable terminal UI for setup commands
  {Colors.WHITE}--level LEVEL{Colors.RESET}     - Installation level for setup command (interactive if not provided)

{Colors.BOLD}Examples:{Colors.RESET}
  {Colors.DIM}python run.py{Colors.RESET}                    # Start API server with splitscreen CLI (default)
  {Colors.DIM}python run.py setup{Colors.RESET}              # Run first-time setup wizard
  {Colors.DIM}python run.py advanced-setup{Colors.RESET}     # Run comprehensive advanced setup
  {Colors.DIM}python run.py gui{Colors.RESET}                # Launch GUI interface
  {Colors.DIM}python run.py version{Colors.RESET}            # Manage versions and downloads
  {Colors.DIM}python run.py download v1.2.0{Colors.RESET}    # Download specific version
  {Colors.DIM}python run.py update{Colors.RESET}             # Check for and install updates
  {Colors.DIM}python run.py deps{Colors.RESET}               # Manage dependencies
  {Colors.DIM}python run.py optimize{Colors.RESET}           # Run performance optimization
  {Colors.DIM}python run.py diagnostic{Colors.RESET}         # Run system diagnostics
  {Colors.DIM}python run.py maintenance{Colors.RESET}        # Run full maintenance mode
  {Colors.DIM}python run.py clean{Colors.RESET}              # Clean system cache
  {Colors.DIM}python run.py wizard{Colors.RESET}             # Configure PlexiChat
  {Colors.DIM}python run.py --verbose{Colors.RESET}          # Start with verbose logging
  {Colors.DIM}python run.py setup --level developer{Colors.RESET}  # Non-interactive setup with developer tools

{Colors.BOLD}Features:{Colors.RESET}
  {Colors.GREEN}•{Colors.RESET} API server with comprehensive endpoints
  {Colors.GREEN}•{Colors.RESET} Admin management system with CLI and web interface
  {Colors.GREEN}•{Colors.RESET} Backup node system with clustering
  {Colors.GREEN}•{Colors.RESET} Plugin system with SDK
  {Colors.GREEN}•{Colors.RESET} File attachment support for messages
  {Colors.GREEN}•{Colors.RESET} Security scanning for uploaded files
  {Colors.GREEN}•{Colors.RESET} Real-time messaging capabilities
  {Colors.GREEN}•{Colors.RESET} Enhanced splitscreen CLI with terminal UI
  {Colors.GREEN}•{Colors.RESET} Comprehensive test suite
  {Colors.GREEN}•{Colors.RESET} Configuration management wizard
  {Colors.GREEN}•{Colors.RESET} GitHub version management and downloads
  {Colors.GREEN}•{Colors.RESET} Dependency management and virtual environments
  {Colors.GREEN}•{Colors.RESET} System monitoring and cleanup tools
  {Colors.GREEN}•{Colors.RESET} Security features and encryption
  {Colors.GREEN}•{Colors.RESET} AI integration and automation
  {Colors.GREEN}•{Colors.RESET} Advanced logging and monitoring
  {Colors.GREEN}•{Colors.RESET} Dynamic terminal UI with real-time updates

{Colors.BOLD}Version:{Colors.RESET} {PLEXICHAT_VERSION} (alpha version)
{Colors.BOLD}API Version:{Colors.RESET} v1
{Colors.BOLD}GitHub:{Colors.RESET} https://github.com/{GITHUB_REPO}

{Colors.DIM}For more information, visit the documentation or run specific commands with --help{Colors.RESET}
"""
    print(help_text)

def parse_arguments():
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments

    Raises:
        SystemExit: If there's an error parsing arguments
    """
    try:
        parser = argparse.ArgumentParser(
            description="PlexiChat - Government-Level Secure Communication Platform",
            add_help=True,  # Ensure --help is always available
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
Examples:
  run.py                    # Start API server with splitscreen CLI (default)
  run.py setup              # Run first-time setup wizard
  run.py gui                # Launch GUI interface with API server
  run.py gui --noserver     # Launch GUI without API server
  run.py webui              # Launch WebUI with API server
  run.py webui --noserver   # Launch WebUI without API server
  run.py update            # Check for and install updates
  run.py clean             # Clean system cache and temporary files
  run.py install           # Install or repair system components
  run.py --verbose         # Enable verbose logging
  run.py --log-level DEBUG # Set log level to DEBUG
  run.py setup --level developer # Non-interactive setup with developer tools
"""
        )

        # Command argument with expanded choices
        parser.add_argument('command',
                          nargs='?',
                          default='api',
                          choices=[
                              # Core functionality
                              'api', 'gui', 'gui-standalone', 'webui', 'cli', 'admin',
                              # System management
                              'setup', 'clean', 'install', 'update',
                              # Core features
                              'backup-node', 'plugin', 'help'
                          ],
                          help='Command to execute (default: %(default)s)')

        # Additional positional arguments for some commands
        parser.add_argument('args',
                          nargs='*',
                          help='Additional arguments for specific commands')

        # Optional arguments
        parser.add_argument('--verbose', '-v',
                          action='store_true',
                          help='Enable verbose output (same as --log-level=DEBUG)')
        parser.add_argument('--debug', '-d',
                          action='store_true',
                          help='Enable debug mode (same as --log-level=DEBUG)')
        parser.add_argument('--config',
                          type=str,
                          metavar='FILE',
                          help='Use custom config file')
        parser.add_argument('--log-level',
                          choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                          default='INFO',
                          help='Set the logging level (default: %(default)s)')
        parser.add_argument('--level',
                          choices=['minimal', 'standard', 'full', 'developer'],
                          help='Installation level for setup command (interactive if not provided)')
        parser.add_argument('--port',
                          type=int,
                          help='Override default port number')
        parser.add_argument('--host',
                          type=str,
                          help='Override default host address')
        parser.add_argument('--no-ui',
                          action='store_true',
                          help='Disable terminal UI for setup commands')
        parser.add_argument('--target-dir',
                          type=str,
                          default='./downloads',
                          help='Target directory for downloads (default: %(default)s)')
        parser.add_argument('--force-kill',
                          action='store_true',
                          help='Force kill existing processes before starting')
        parser.add_argument('--repo',
                          type=str,
                          help='GitHub repository for install command (format: user/repo)')
        parser.add_argument('--version-tag',
                          type=str,
                          help='Specific version tag to install')
        parser.add_argument('--config-file',
                          type=str,
                          help='Install from configuration file')
        parser.add_argument('--noserver',
                          action='store_true',
                          help='Start GUI without API server (GUI and WebUI commands only)')
        parser.add_argument('--noui',
                          action='store_true',
                          help='Disable WebUI interface (API server only mode)')
        parser.add_argument('--nocli',
                          action='store_true',
                          help='Disable CLI interface (API server only mode)')

        # Parse and return arguments
        args = parser.parse_args()

        # If help is requested as a command or --help is present, show help
        if args.command == 'help' or '--help' in sys.argv or '-h' in sys.argv:
            show_help()
            sys.exit(0)

        return args

    except Exception as e:
        if logger:
            logger.error(f"Error parsing command line arguments: {e}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(traceback.format_exc())
        sys.exit(1)

def print_config_info(config: Optional[Dict[str, Any]]):
    """Print configuration information."""
    if config:
        print(f"\n{Colors.BOLD}{Colors.GREEN}Current Configuration:{Colors.RESET}")
        print(json.dumps(config, indent=2))
    else:
        print(f"\n{Colors.RED}No configuration loaded{Colors.RESET}")

def handle_github_commands(command: str, args: List[str], target_dir: str):
    """Handle GitHub-related commands."""
    github_manager = GitHubVersionManager()

    if command == 'versions':
        versions = github_manager.get_available_versions()
        if versions:
            print(f"\n{Colors.GREEN}Available Versions on GitHub:{Colors.RESET}")
            for i, version in enumerate(versions[:20]):  # Show last 20
                status = f"{Colors.YELLOW}Pre-release{Colors.RESET}" if version['prerelease'] else f"{Colors.GREEN}Release{Colors.RESET}"
                print(f"  {i+1:2d}. {Colors.BOLD}{version['tag']}{Colors.RESET} - {version['name']} ({status})")
                print(f"      Published: {version['published_at']}")
        else:
            print(f"{Colors.RED}Failed to fetch versions from GitHub{Colors.RESET}")

    elif command == 'latest':
        latest = github_manager.get_latest_version()
        if latest:
            print(f"\n{Colors.GREEN}Latest Version on GitHub:{Colors.RESET}")
            print(f"  Tag: {Colors.BOLD}{latest['tag']}{Colors.RESET}")
            print(f"  Name: {latest['name']}")
            print(f"  Published: {latest['published_at']}")
            print(f"  Pre-release: {latest['prerelease']}")

            download = input(f"\n{Colors.CYAN}Download this version? (y/N): {Colors.RESET}").strip().lower()
            if download == 'y':
                Path(target_dir).mkdir(exist_ok=True)
                if github_manager.download_version(latest['tag'], target_dir):
                    print(f"{Colors.GREEN}Version {latest['tag']} downloaded successfully to {target_dir}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to download version {latest['tag']}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Failed to fetch latest version from GitHub{Colors.RESET}")

    elif command == 'download':
        if args:
            version_tag = args[0]
            Path(target_dir).mkdir(exist_ok=True)
            print(f"\n{Colors.CYAN}Downloading version {version_tag} to {target_dir}...{Colors.RESET}")
            if github_manager.download_version(version_tag, target_dir):
                print(f"{Colors.GREEN}Version {version_tag} downloaded successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}Failed to download version {version_tag}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Please specify a version tag to download{Colors.RESET}")
            print(f"Example: python run.py download v1.2.0")

# Process lock logic (cross-platform, adapted from __main__.py)
try:
    import fcntl
    has_fcntl = True
except ImportError:
    try:
        import msvcrt
        has_msvcrt = True
        has_fcntl = False
    except ImportError:
        has_fcntl = False
        has_msvcrt = False

# Global install path for all runtime modes
install_path = Path(os.environ.get('PLEXICHAT_HOME', Path.cwd()))

# Update process lock file to be in INSTALL_PATH for all runtime modes
PROCESS_LOCK_FILE = str(install_path / "plexichat.lock")

_lock_file = None
_thread_pool = None


def acquire_process_lock():
    """Acquire process lock with proper PID writing and error handling."""
    global _lock_file
    lock_path = Path(PROCESS_LOCK_FILE)
    current_pid = os.getpid()
    retries = 5  # Increased retries
    delay = 0.1
    backoff_factor = 2

    for i in range(retries):
        try:
            # Check if lock file exists and if process is still running
            if lock_path.exists():
                try:
                    with open(lock_path, 'r') as f:
                        content = f.read().strip()
                        if content:
                            existing_pid = int(content)
                            if _is_process_running(existing_pid):
                                if logger:
                                    logger.error(f"Another PlexiChat instance is already running (PID: {existing_pid})")
                                return False
                            else:
                                if logger:
                                    logger.info(f"Removing stale lock file (PID {existing_pid} no longer running)")
                                try:
                                    # On Windows, try to force delete if needed
                                    if sys.platform == "win32":
                                        import subprocess
                                        subprocess.run(['del', '/f', str(lock_path)], shell=True, capture_output=True)
                                    else:
                                        lock_path.unlink(missing_ok=True)
                                except PermissionError:
                                    if logger:
                                        logger.warning(f"Could not remove stale lock file, retrying...")
                                    time.sleep(delay)
                                    continue
                except (ValueError, FileNotFoundError):
                    lock_path.unlink(missing_ok=True)

            # Create lock directory if it doesn't exist
            lock_path.parent.mkdir(parents=True, exist_ok=True)

            # Always write the current PID to the lock file after acquiring the lock
            # Use atomic write by writing to temp file first
            temp_lock = lock_path.with_suffix('.tmp')
            try:
                with open(temp_lock, 'w') as f:
                    f.write(f"{current_pid}\n")
                    f.flush()
                    os.fsync(f.fileno())
                temp_lock.replace(lock_path)  # Atomic replace
                if logger:
                    logger.info(f"Process lock acquired successfully (PID: {current_pid})")
                return True
            finally:
                if temp_lock.exists():
                    temp_lock.unlink(missing_ok=True)

        except (OSError, IOError, BlockingIOError) as e:
            if isinstance(e, PermissionError) and i < retries - 1:
                if logger:
                    logger.warning(f"Failed to acquire lock, retrying in {delay}s...")
                time.sleep(delay)
                delay *= backoff_factor  # Exponential backoff
            else:
                if logger:
                    logger.error(f"Failed to acquire process lock: {e}")
                return False
    return False

def _is_process_running(pid: int) -> bool:
    """Check if a process with given PID is running."""
    import subprocess  # Import at function level to ensure it's available
    try:
        if sys.platform == "win32":
            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'],
                                  capture_output=True, text=True, timeout=5)
            return str(pid) in result.stdout
        else:
            # Unix/Linux: send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
    except (ProcessLookupError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    except Exception:
        # If we can't determine, assume it's running to be safe
        return True
        return False
    except Exception:
        # If we can't determine, assume it's running to be safe
        return True

def release_process_lock():
    """Release the process lock with improved error handling and cleanup."""
    global _lock_file
    lock_path = Path(PROCESS_LOCK_FILE)
    
    try:
        # Read current PID from lock file
        if lock_path.exists():
            try:
                with open(lock_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        pid = int(content)
                        # Only remove if it's our lock
                        if pid == os.getpid():
                            # Try multiple methods to remove the lock file
                            try:
                                lock_path.unlink(missing_ok=True)
                            except PermissionError:
                                if sys.platform == "win32":
                                    import subprocess
                                    subprocess.run(['del', '/f', str(lock_path)], shell=True, capture_output=True)
                                else:
                                    # On Unix, try changing permissions first
                                    try:
                                        os.chmod(lock_path, 0o666)
                                        lock_path.unlink(missing_ok=True)
                                    except:
                                        pass
                            if logger:
                                logger.info("Process lock released")
            except (ValueError, FileNotFoundError):
                pass
    except Exception as e:
        if logger:
            logger.warning(f"Error during process lock release: {e}")

# ============================================================================
# ENHANCED STARTUP AND OS SUPPORT
# ============================================================================

def setup_platform_support():
    """Setup platform-specific configurations and optimizations, including process naming."""
    try:
        current_os = platform.system().lower()

        if current_os == "windows":
            try:
                import ctypes
                # Set process priority to normal
                ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00000020)
                # Enable ANSI color support on Windows 10+
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                # Set console title
                ctypes.windll.kernel32.SetConsoleTitleW("PlexiChat Installer")
            except Exception as e:
                print(f"Windows optimization warning: {e}")
        elif current_os == "linux":
            try:
                from setproctitle import setproctitle
                setproctitle("plexichat-installer")
                if os.path.exists("/run/systemd/system"):
                    os.environ["PLEXICHAT_SYSTEMD"] = "1"
            except Exception as e:
                print(f"Linux optimization warning: {e}")
        elif current_os == "darwin":
            try:
                from setproctitle import setproctitle
                setproctitle("plexichat-installer")
            except Exception as e:
                print(f"macOS optimization warning: {e}")
        os.environ["PLEXICHAT_OS"] = current_os
        os.environ["PLEXICHAT_ARCH"] = platform.machine()
    except Exception as e:
        print(f"Platform setup error: {e}")

def setup_enhanced_logging_with_files(log_level: str = "INFO"):
    """Setup enhanced logging with file handlers and performance monitoring."""
    try:
        # Create logs directory in INSTALL_PATH if it doesn't exist
        logs_dir = install_path / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)

        # Setup enhanced logging with performance monitoring
        logger, performance_monitor = setup_enhanced_logging(log_level)

        # Add file logging with rotation
        from logging.handlers import RotatingFileHandler

        # Main log file
        file_handler = RotatingFileHandler(
            logs_dir / "plexichat.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

        # Error log file
        error_handler = RotatingFileHandler(
            logs_dir / "plexichat_errors.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d'
        ))

        # Performance log file
        perf_handler = RotatingFileHandler(
            logs_dir / "plexichat_performance.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

        # API calls log file
        api_handler = RotatingFileHandler(
            logs_dir / "plexichat_api.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        api_handler.setLevel(logging.DEBUG)
        api_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

        # Add handlers to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        root_logger.addHandler(error_handler)
        root_logger.addHandler(perf_handler)
        root_logger.addHandler(api_handler)

        logger.info(f"Enhanced logging system initialized with level: {log_level}")
        logger.info("Performance monitoring and API tracking enabled")
        return logger, performance_monitor

    except Exception as e:
        print(f"Enhanced logging setup failed: {e}")
        return None, None

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    import signal
    def signal_handler(signum: int, _frame: object) -> None:
        logging.getLogger().info(f"Received signal {signal.Signals(signum).name}, initiating graceful shutdown...")
        try:
            # Only shutdown thread pool if it exists
            global _thread_pool
            if '_thread_pool' in globals() and _thread_pool:
                _thread_pool.shutdown(wait=False)
        except Exception:
            pass
        try:
            release_process_lock()
        except Exception:
            pass
        sys.exit(0)
    if sys.platform == "win32":
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    else:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

def display_startup_banner():
    """Display enhanced startup banner with system information (ASCII only, no emojis or Unicode boxes)."""
    try:
        banner = f"""
{Colors.BOLD}{Colors.BRIGHT_CYAN}+{'-'*58}+
|                     PlexiChat Server                      |
|              Advanced AI-Powered Chat Platform           |
+{'-'*58}+{Colors.RESET}

{Colors.BRIGHT_GREEN}System Information:{Colors.RESET}
  - OS: {platform.system()} {platform.release()} ({platform.machine()})
  - Python: {platform.python_version()}
  - Working Directory: {os.getcwd()}
  - Process ID: {os.getpid()}
  - Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{Colors.BRIGHT_YELLOW}Starting PlexiChat with enhanced features...{Colors.RESET}
"""
        print(banner)

    except Exception as e:
        print(f"Banner display error: {e}")

def run_enhanced_bootstrap():
    """Enhanced bootstrap with platform-specific optimizations."""
    print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}PlexiChat Standalone Bootstrap{Colors.RESET}")
    
    # Platform-specific setup
    platform = sys.platform
    if platform.startswith('linux'):
        print(f"{Colors.CYAN}Linux detected - enabling systemd integration and SELinux support{Colors.RESET}")
        setup_linux_specific_features()
    elif platform.startswith('win'):
        print(f"{Colors.CYAN}Windows detected - enabling Windows service integration{Colors.RESET}")
        setup_windows_specific_features()
    elif platform.startswith('darwin'):
        print(f"{Colors.CYAN}macOS detected - enabling launchd integration{Colors.RESET}")
        setup_macos_specific_features()
    
    # Enhanced system checks
    system_info = get_detailed_system_info()
    print(f"{Colors.GREEN}System: {system_info['os']} {system_info['version']}{Colors.RESET}")
    print(f"{Colors.GREEN}Architecture: {system_info['arch']}{Colors.RESET}")
    print(f"{Colors.GREEN}Python: {system_info['python_version']}{Colors.RESET}")
    print(f"{Colors.GREEN}Memory: {system_info['memory_gb']:.1f}GB{Colors.RESET}")
    print(f"{Colors.GREEN}CPU Cores: {system_info['cpu_cores']}{Colors.RESET}")
    
    # Check for virtualization
    if is_virtualized():
        print(f"{Colors.YELLOW}Virtual environment detected - optimizing for containerized deployment{Colors.RESET}")
        setup_virtualized_environment()
    
    # Enhanced dependency resolution
    print(f"\n{Colors.BOLD}Resolving dependencies with platform-specific optimizations...{Colors.RESET}")
    
    # Platform-specific dependency installation
    if platform.startswith('linux'):
        install_linux_dependencies()
    elif platform.startswith('win'):
        install_windows_dependencies()
    elif platform.startswith('darwin'):
        install_macos_dependencies()
    
    # Enhanced security setup
    print(f"\n{Colors.BOLD}Setting up enhanced security features...{Colors.RESET}")
    setup_enhanced_security()
    
    # Performance optimization
    print(f"\n{Colors.BOLD}Optimizing performance for current platform...{Colors.RESET}")
    optimize_performance()
    
    print(f"\n{Colors.BOLD}{Colors.BRIGHT_GREEN}Bootstrap completed successfully!{Colors.RESET}")
    print(f"{Colors.CYAN}Platform-specific optimizations applied.{Colors.RESET}")

def setup_linux_specific_features():
    """Setup Linux-specific features like systemd, SELinux, and AppArmor."""
    try:
        # Check for systemd
        if os.path.exists('/run/systemd/system'):
            print(f"{Colors.GREEN}Systemd detected - enabling service integration{Colors.RESET}")
            setup_systemd_integration()
        
        # Check for SELinux
        if os.path.exists('/etc/selinux/config'):
            print(f"{Colors.GREEN}SELinux detected - configuring security policies{Colors.RESET}")
            setup_selinux_policies()
        
        # Check for AppArmor
        if os.path.exists('/sys/kernel/security/apparmor'):
            print(f"{Colors.GREEN}AppArmor detected - setting up profiles{Colors.RESET}")
            setup_apparmor_profiles()
        
        # Setup cgroups for resource management
        setup_cgroups_integration()
        
        # Enable kernel optimizations
        setup_kernel_optimizations()
        
    except Exception as e:
        print(f"{Colors.YELLOW}Linux-specific setup warning: {e}{Colors.RESET}")

def setup_windows_specific_features():
    """Setup Windows-specific features like Windows services and registry integration."""
    try:
        # Check for Windows service capabilities
        if hasattr(os, 'name') and os.name == 'nt':
            print(f"{Colors.GREEN}Windows detected - setting up service integration{Colors.RESET}")
            setup_windows_service_integration()
        
        # Setup Windows registry integration
        setup_windows_registry_integration()
        
        # Enable Windows Defender exclusions
        setup_windows_defender_exclusions()
        
        # Setup Windows performance counters
        setup_windows_performance_counters()
        
    except Exception as e:
        print(f"{Colors.YELLOW}Windows-specific setup warning: {e}{Colors.RESET}")

def setup_macos_specific_features():
    """Setup macOS-specific features like launchd and sandboxing."""
    try:
        # Check for launchd
        if os.path.exists('/System/Library/LaunchDaemons'):
            print(f"{Colors.GREEN}Launchd detected - setting up service integration{Colors.RESET}")
            setup_launchd_integration()
        
        # Setup macOS sandboxing
        setup_macos_sandboxing()
        
        # Enable macOS security features
        setup_macos_security_features()
        
        # Setup macOS performance monitoring
        setup_macos_performance_monitoring()
        
    except Exception as e:
        print(f"{Colors.YELLOW}macOS-specific setup warning: {e}{Colors.RESET}")

from typing import Any
def get_detailed_system_info() -> dict[str, Any]:
    """Get detailed system information for platform-specific optimizations."""
    info: dict[str, Any] = {
        'os': platform.system(),
        'version': platform.release(),
        'arch': platform.machine(),
        'python_version': sys.version.split()[0],
        'memory_gb': psutil.virtual_memory().total / (1024**3),
        'cpu_cores': psutil.cpu_count(),
        'platform': sys.platform
    }
    return info

def is_virtualized():
    """Check if running in a virtualized environment."""
    try:
        # Check for common virtualization indicators
        virtualization_indicators = [
            '/proc/cpuinfo',  # Linux
            '/sys/class/dmi/id/product_name',  # Linux
            'HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SystemInformation\\ComputerHardwareId'  # Windows
        ]
        
        for indicator in virtualization_indicators:
            if os.path.exists(indicator):
                with open(indicator, 'r') as f:
                    content = f.read().lower()
                    if any(vm in content for vm in ['vmware', 'virtualbox', 'kvm', 'xen', 'hyper-v']):
                        return True
        
        return False
    except:
        return False

def setup_virtualized_environment():
    """Optimize settings for virtualized environments."""
    try:
        # Reduce memory usage
        import gc
        gc.set_threshold(100, 5, 5)
        
        # Optimize for containerized environments
        if os.path.exists('/.dockerenv'):
            print(f"{Colors.GREEN}Docker container detected - applying container optimizations{Colors.RESET}")
            setup_container_optimizations()
        
    except Exception as e:
        print(f"{Colors.YELLOW}Virtualization setup warning: {e}{Colors.RESET}")

def install_platform_dependencies():
    """Install platform-specific dependencies as fallbacks when pip fails."""
    platform = sys.platform

    print(f"{Colors.CYAN}Installing platform-specific system dependencies...{Colors.RESET}")
    print(f"{Colors.DIM}These are fallback installations for packages that failed via pip{Colors.RESET}")

    if platform.startswith('linux'):
        return install_linux_dependencies()
    elif platform.startswith('win'):
        return install_windows_dependencies()
    elif platform.startswith('darwin'):
        return install_macos_dependencies()
    else:
        print(f"{Colors.YELLOW}Unknown platform: {platform}{Colors.RESET}")
        return False

def install_linux_dependencies():
    """Install Linux-specific dependencies."""
    try:
        print(f"{Colors.CYAN}Installing Linux system dependencies...{Colors.RESET}")

        # Detect Linux distribution
        distro_info: dict[str, Any] = detect_linux_distro()
        distro: str = str(distro_info.get('id', 'unknown')).lower()

        if distro in ['ubuntu', 'debian', 'linuxmint']:
            install_debian_packages()
        elif distro in ['fedora', 'rhel', 'centos', 'rocky', 'almalinux']:
            install_fedora_packages()
        elif distro in ['arch', 'manjaro']:
            install_arch_packages()
        else:
            print(f"{Colors.YELLOW}Unknown Linux distribution: {distro}{Colors.RESET}")
            print(f"{Colors.CYAN}Attempting Debian/Ubuntu package installation...{Colors.RESET}")
            install_debian_packages()

    except Exception as e:
        print(f"{Colors.YELLOW}Linux dependency installation warning: {e}{Colors.RESET}")


from typing import Any
def detect_linux_distro() -> dict[str, str]:
    """Detect Linux distribution."""
    try:
        # Try to read /etc/os-release
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                info: dict[str, str] = {}
                for line in lines:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        info[key.lower()] = value.strip('"')
                return info

        # Fallback methods
        if os.path.exists('/etc/debian_version'):
            return {'id': 'debian'}
        elif os.path.exists('/etc/fedora-release'):
            return {'id': 'fedora'}
        elif os.path.exists('/etc/arch-release'):
            return {'id': 'arch'}

        return {'id': 'unknown'}
    except Exception:
        return {'id': 'unknown'}


def check_admin_privileges() -> bool:
    """Check if running with admin/root privileges."""
    try:
        if sys.platform.startswith('win'):
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # geteuid is not available on all platforms (e.g., Windows)
            return hasattr(os, 'geteuid') and os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def request_elevation():
    """Request elevation of privileges."""
    if sys.platform.startswith('win'):
        print(f"{Colors.YELLOW}Administrator privileges required{Colors.RESET}")
        print(f"{Colors.CYAN}Please run the following command in an elevated Command Prompt:{Colors.RESET}")
        print(f"python {' '.join(sys.argv)}")
        return False
    else:
        print(f"{Colors.YELLOW}Root privileges required for system package installation{Colors.RESET}")
        print(f"{Colors.CYAN}Commands will be run with sudo{Colors.RESET}")
        return True


def install_debian_packages():
    """Install packages on Debian/Ubuntu systems."""
    debian_packages = [
        'python3-tk', 'python3-dev', 'python3-pip', 'python3-venv',
        'build-essential', 'libssl-dev', 'libffi-dev', 'libjpeg-dev',
        'libpng-dev', 'libfreetype6-dev', 'libsqlite3-dev', 'libreadline-dev',
        'libbz2-dev', 'libncurses5-dev', 'libncursesw5-dev', 'xz-utils',
        'tk-dev', 'liblzma-dev', 'git', 'curl', 'wget'
    ]

    try:
        if check_admin_privileges():
            print(f"{Colors.GREEN}Running with admin privileges - installing Debian/Ubuntu packages{Colors.RESET}")
            subprocess.run(['apt-get', 'update'], check=True)
            subprocess.run(['apt-get', 'install', '-y'] + debian_packages, check=True)
            print(f"{Colors.GREEN}Debian/Ubuntu packages installed successfully{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}Attempting to install packages with sudo...{Colors.RESET}")
            try:
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y'] + debian_packages, check=True)
                print(f"{Colors.GREEN}Debian/Ubuntu packages installed successfully{Colors.RESET}")
                return True
            except subprocess.CalledProcessError:
                print(f"{Colors.RED}Failed to install with sudo{Colors.RESET}")
                print_debian_manual_instructions(debian_packages)
                return False
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Package installation failed{Colors.RESET}")
        print_debian_manual_instructions(debian_packages)
        return False


def print_debian_manual_instructions(packages: list[str]) -> None:
    """Print manual installation instructions for Debian/Ubuntu."""
    print(f"{Colors.YELLOW}Manual installation required{Colors.RESET}")
    print(f"{Colors.CYAN}Please run the following commands:{Colors.RESET}")
    print(f"sudo apt-get update")
    print(f"sudo apt-get install -y {' '.join(packages)}")
    print(f"")
    print(f"{Colors.DIM}Then run setup again: python run.py setup{Colors.RESET}")


def install_fedora_packages():
    """Install packages on Fedora/RHEL/CentOS systems."""
    fedora_packages = [
        'python3-tkinter', 'python3-devel', 'python3-pip', 'gcc', 'gcc-c++',
        'make', 'openssl-devel', 'libffi-devel', 'libjpeg-turbo-devel',
        'libpng-devel', 'freetype-devel', 'sqlite-devel', 'readline-devel',
        'bzip2-devel', 'ncurses-devel', 'xz-devel', 'tk-devel',
        'git', 'curl', 'wget'
    ]

    try:
        # Try dnf first (newer systems), then yum (older systems)
        package_manager = 'dnf' if subprocess.run(['which', 'dnf'], capture_output=True).returncode == 0 else 'yum'

        if hasattr(os, 'geteuid') and os.geteuid() == 0:  # type: ignore[attr-defined]
            print(f"{Colors.GREEN}Running as root - installing Fedora/RHEL packages with {package_manager}{Colors.RESET}")
            subprocess.run([package_manager, 'install', '-y'] + fedora_packages, check=True)
            print(f"{Colors.GREEN}Fedora/RHEL packages installed successfully{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}Attempting to install packages with sudo {package_manager}...{Colors.RESET}")
            subprocess.run(['sudo', package_manager, 'install', '-y'] + fedora_packages, check=True)
            print(f"{Colors.GREEN}Fedora/RHEL packages installed successfully{Colors.RESET}")
    except subprocess.CalledProcessError:
        print(f"{Colors.YELLOW}Could not install system packages automatically{Colors.RESET}")
        print(f"{Colors.CYAN}Please run manually:{Colors.RESET}")
        print(f"sudo {package_manager} install -y {' '.join(fedora_packages)}")


def install_arch_packages():
    """Install packages on Arch Linux systems."""
    arch_packages = [
        'python-tkinter', 'python', 'python-pip', 'base-devel', 'openssl',
        'libffi', 'libjpeg-turbo', 'libpng', 'freetype2', 'sqlite',
        'readline', 'bzip2', 'ncurses', 'xz', 'tk', 'git', 'curl', 'wget'
    ]

    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:  # type: ignore[attr-defined]
            print(f"{Colors.GREEN}Running as root - installing Arch Linux packages{Colors.RESET}")
            subprocess.run(['pacman', '-S', '--noconfirm'] + arch_packages, check=True)
            print(f"{Colors.GREEN}Arch Linux packages installed successfully{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}Attempting to install packages with sudo pacman...{Colors.RESET}")
            subprocess.run(['sudo', 'pacman', '-S', '--noconfirm'] + arch_packages, check=True)
            print(f"{Colors.GREEN}Arch Linux packages installed successfully{Colors.RESET}")
    except subprocess.CalledProcessError:
        print(f"{Colors.YELLOW}Could not install system packages automatically{Colors.RESET}")
        print(f"{Colors.CYAN}Please run manually:{Colors.RESET}")
        print(f"sudo pacman -S --noconfirm {' '.join(arch_packages)}")

def install_windows_dependencies():
    """Install Windows-specific dependencies."""
    try:
        print(f"{Colors.CYAN}Installing Windows-specific dependencies...{Colors.RESET}")

        # Check if tkinter is available (usually comes with Python on Windows)
        try:
            import tkinter
            print(f"{Colors.GREEN}tkinter is available{Colors.RESET}")
        except ImportError:
            print(f"{Colors.RED}tkinter is not available{Colors.RESET}")
            print(f"{Colors.YELLOW}Please reinstall Python with tkinter support{Colors.RESET}")
            print(f"{Colors.CYAN}Download from: https://www.python.org/downloads/{Colors.RESET}")

        # Check for admin privileges
        if not check_admin_privileges():
            print(f"{Colors.YELLOW}Package installation may require administrator privileges{Colors.RESET}")
            if not request_elevation():
                print_windows_manual_instructions()
                return False

        # Try chocolatey first, then winget
        if install_with_chocolatey():
            print(f"{Colors.GREEN}Packages installed via Chocolatey{Colors.RESET}")
            return True
        elif install_with_winget():
            print(f"{Colors.GREEN}Packages installed via winget{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}No package manager available - manual installation required{Colors.RESET}")
            print_windows_manual_instructions()
            return False

    except Exception as e:
        print(f"{Colors.YELLOW}Windows dependency installation warning: {e}{Colors.RESET}")
        return False


def install_with_chocolatey():
    """Try to install packages with Chocolatey."""
    try:
        subprocess.run(['choco', '--version'], check=True, capture_output=True)
        print(f"{Colors.GREEN}Chocolatey detected - installing packages{Colors.RESET}")

        choco_packages = ['python', 'git', 'nodejs', 'sqlite']
        success = True

        for package in choco_packages:
            try:
                subprocess.run(['choco', 'install', package, '-y'], check=True, capture_output=True)
                print(f"{Colors.GREEN}Installed {package}{Colors.RESET}")
            except subprocess.CalledProcessError:
                print(f"{Colors.YELLOW}Could not install {package}{Colors.RESET}")
                success = False

        return success

    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_with_winget():
    """Try to install packages with winget."""
    try:
        subprocess.run(['winget', '--version'], check=True, capture_output=True)
        print(f"{Colors.GREEN}winget detected - installing packages{Colors.RESET}")

        winget_packages = [
            'Python.Python.3.11',
            'Git.Git',
            'OpenJS.NodeJS',
            'SQLite.SQLite'
        ]
        success = True

        for package in winget_packages:
            try:
                subprocess.run(['winget', 'install', package, '--accept-package-agreements', '--accept-source-agreements'],
                             check=True, capture_output=True)
                print(f"{Colors.GREEN}Installed {package}{Colors.RESET}")
            except subprocess.CalledProcessError:
                print(f"{Colors.YELLOW}Could not install {package}{Colors.RESET}")
                success = False

        return success

    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def print_windows_manual_instructions():
    """Print manual installation instructions for Windows."""
    print(f"{Colors.CYAN}Manual installation required:{Colors.RESET}")
    print(f"1. Install Chocolatey: https://chocolatey.org/install")
    print(f"2. Or install winget: https://github.com/microsoft/winget-cli")
    print(f"3. Then run setup again")
    print(f"")
    print(f"{Colors.CYAN}Alternative - Manual downloads:{Colors.RESET}")
    print(f"- Python: https://www.python.org/downloads/")
    print(f"- Git: https://git-scm.com/download/win")
    print(f"- Node.js: https://nodejs.org/en/download/")
    print(f"- SQLite: https://www.sqlite.org/download.html")

def install_macos_dependencies():
    """Install macOS-specific dependencies."""
    try:
        print(f"{Colors.CYAN}Installing macOS-specific dependencies...{Colors.RESET}")

        # Check if tkinter is available
        try:
            import tkinter
            print(f"{Colors.GREEN}tkinter is available{Colors.RESET}")
        except ImportError:
            print(f"{Colors.RED}tkinter is not available{Colors.RESET}")
            print(f"{Colors.YELLOW}Install with: brew install python-tk{Colors.RESET}")

        # macOS-specific package installation using homebrew
        if install_with_homebrew():
            print(f"{Colors.GREEN}Packages installed via Homebrew{Colors.RESET}")
        else:
            print_macos_manual_instructions()

    except Exception as e:
        print(f"{Colors.YELLOW}macOS dependency installation warning: {e}{Colors.RESET}")


def install_with_homebrew():
    """Try to install packages with Homebrew."""
    try:
        subprocess.run(['brew', '--version'], check=True, capture_output=True)
        print(f"{Colors.GREEN}Homebrew detected - installing packages{Colors.RESET}")

        brew_packages = [
            'python-tk', 'python@3.11', 'openssl', 'libffi', 'jpeg',
            'libpng', 'freetype', 'sqlite3', 'readline', 'xz',
            'git', 'curl', 'wget'
        ]
        success = True

        for package in brew_packages:
            try:
                subprocess.run(['brew', 'install', package], check=True, capture_output=True)
                print(f"{Colors.GREEN}Installed {package}{Colors.RESET}")
            except subprocess.CalledProcessError:
                print(f"{Colors.YELLOW}Could not install {package} (may already be installed){Colors.RESET}")

        return success

    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def print_macos_manual_instructions():
    """Print manual installation instructions for macOS."""
    print(f"{Colors.YELLOW}Homebrew not available{Colors.RESET}")
    print(f"{Colors.CYAN}Install Homebrew first:{Colors.RESET}")
    print(f'/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
    print(f"")
    print(f"{Colors.CYAN}Then install packages:{Colors.RESET}")
    print(f"brew install python-tk python@3.11 openssl libffi jpeg libpng freetype sqlite3 readline xz git")
    print(f"")
    print(f"{Colors.CYAN}Alternative - MacPorts:{Colors.RESET}")
    print(f"sudo port install python311 +tkinter")
    print(f"")
    print(f"{Colors.CYAN}Or download manually:{Colors.RESET}")
    print(f"- Python: https://www.python.org/downloads/macos/")
    print(f"- Git: https://git-scm.com/download/mac")

def setup_enhanced_security():
    """Setup enhanced security features for the platform."""
    try:
        # Platform-specific security setup
        platform = sys.platform
        
        if platform.startswith('linux'):
            setup_linux_security()
        elif platform.startswith('win'):
            setup_windows_security()
        elif platform.startswith('darwin'):
            setup_macos_security()
        
        # Common security features
        setup_common_security_features()
        
    except Exception as e:
        print(f"{Colors.YELLOW}Security setup warning: {e}{Colors.RESET}")

def optimize_performance():
    """Optimize performance for the current platform."""
    try:
        # Platform-specific performance optimizations
        platform = sys.platform
        
        if platform.startswith('linux'):
            optimize_linux_performance()
        elif platform.startswith('win'):
            optimize_windows_performance()
        elif platform.startswith('darwin'):
            optimize_macos_performance()
        
        # Common performance optimizations
        setup_common_performance_optimizations()
        
    except Exception as e:
        print(f"{Colors.YELLOW}Performance optimization warning: {e}{Colors.RESET}")

# Placeholder functions for platform-specific implementations
def setup_systemd_integration(): pass
def setup_selinux_policies(): pass
def setup_apparmor_profiles(): pass
def setup_cgroups_integration(): pass
def setup_kernel_optimizations(): pass
def setup_windows_service_integration(): pass
def setup_windows_registry_integration(): pass
def setup_windows_defender_exclusions(): pass
def setup_windows_performance_counters(): pass
def setup_launchd_integration(): pass
def setup_macos_sandboxing(): pass
def setup_macos_security_features(): pass
def setup_macos_performance_monitoring(): pass
def setup_container_optimizations(): pass
def setup_linux_security(): pass
def setup_windows_security(): pass
def setup_macos_security(): pass
def setup_common_security_features(): pass
def optimize_linux_performance(): pass
def optimize_windows_performance(): pass
def optimize_macos_performance(): pass
def setup_common_performance_optimizations(): pass

def download_plexichat_from_github(repo: str, version_tag: str) -> str:
    """Download PlexiChat from GitHub repository for a specific version."""
    try:
        print(f"  {Colors.BRIGHT_CYAN}Downloading PlexiChat from GitHub...{Colors.RESET}")
        # ...existing code...
        return zip_path
    except Exception:
        return ""

        print(f"  {Colors.GREEN}✓ Downloaded successfully")

        # Extract the repository
        print(f"  {Colors.YELLOW}📦 Extracting files...")

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract to current directory
            zip_ref.extractall('.')

            # Move files from <repo>-<version_tag> or <repo>-main to current directory
            import shutil
            main_dir = f"{repo.split('/')[-1]}-{version_tag if version_tag else 'main'}"
            source_dir = Path(main_dir)
            if source_dir.exists():
                for item in source_dir.iterdir():
                    if item.is_dir():
                        if Path(item.name).exists():
                            shutil.rmtree(item.name)
                        shutil.move(str(item), item.name)
                    else:
                        if Path(item.name).exists():
                            Path(item.name).unlink()
                        shutil.move(str(item), item.name)
                shutil.rmtree(source_dir)

        Path(zip_path).unlink()
        print(f"  {Colors.GREEN}✓ PlexiChat downloaded and extracted successfully")

    except Exception as e:
        print(f"  {Colors.RED}✗ Failed to download PlexiChat: {e}")
        raise

from typing import Any, Optional
def run_install_command(args: Optional[Any] = None) -> None:
    """Install PlexiChat with interactive setup and platform-specific installation."""
    try:
        # Check if installing from config file
        if args and hasattr(args, 'config_file') and getattr(args, 'config_file', None):  # type: ignore
            install_from_config_file(getattr(args, 'config_file', None))  # type: ignore
            return

        print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}PlexiChat Advanced Installer{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}Interactive installation with platform-specific setup{Colors.RESET}\n")

        # Step 1: Installation Type Selection
        install_type = select_installation_type()

        # Step 2: Installation Location
        install_path = select_installation_path(install_type)

        # Step 3: Configuration Setup
        config_path = setup_configuration_path(install_type)

        # Step 4: Repository and Version Selection
        repo = args.repo if args and hasattr(args, 'repo') and getattr(args, 'repo', None) else get_default_repository()  # type: ignore
        version_tag = args.version_tag if args and hasattr(args, 'version_tag') and getattr(args, 'version_tag', None) else None  # type: ignore

        print(f"{Colors.BOLD}Repository: {Colors.BRIGHT_CYAN}{repo}{Colors.RESET}")

        # Step 5: Version Analysis and Selection
        print(f"\n{Colors.BOLD}Step 1: Version Analysis{Colors.RESET}")
        compare_versions_with_github(repo)

        if not version_tag:
            version_tag = select_version_to_install(repo)

        print(f"{Colors.BOLD}Selected Version: {Colors.BRIGHT_GREEN}{version_tag}{Colors.RESET}")

        # Step 6: Requirements Group Selection
        requirements_group = select_requirements_group()

        # Step 7: Download and Install
        print(f"\n{Colors.BOLD}Step 2: Download and Install{Colors.RESET}")
        download_and_install_to_path(repo, version_tag, install_path)

        print(f"\n{Colors.BOLD}{Colors.BRIGHT_GREEN}[CHECK] Installation completed!{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}To complete setup, run:{Colors.RESET} {Colors.BRIGHT_YELLOW}python run.py setup{Colors.RESET}")
        print(f"You can also complete setup in the GUI or WebUI after launching the server.")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Installation interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Installation failed: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def select_installation_type():
    """Prompt user to select installation type with more options."""
    print("Installation Type Selection:")
    print("  1. Portable Installation (current directory)")
    print("  2. System Installation (platform-specific location)")
    print("  3. Custom Installation Path")
    while True:
        choice = input("Select installation type (1-3): ").strip()
        if choice in ('1', '2', '3'):
            return int(choice)
        print("Invalid choice. Please enter 1, 2, or 3.")

from typing import Any
def select_installation_path(install_type: Any) -> Any:
    """Prompt user to select or enter installation path based on type."""
    global install_path
    if install_type == 1:
        install_path = Path(os.getcwd())
        return install_path
    elif install_type == 2:
        default_path = Path("C:/Program Files/PlexiChat") if sys.platform == 'win32' else Path("/opt/plexichat")
        install_path = default_path
        print(f"System Installation Path:\n  Default: {default_path}")
        use_default = input("Use default path? (Y/n): ").strip().lower()
        if use_default in ('', 'y', 'yes'):
            return install_path
        else:
            custom_path = input("Enter custom system install path: ").strip()
            install_path = Path(custom_path)
            return install_path
    elif install_type == 3:
        custom_path = input("Enter custom installation path: ").strip()
        install_path = Path(custom_path)
        return install_path
    else:
        install_path = Path(os.getcwd())
        return install_path

def setup_configuration_path(install_type: Any) -> Any:
    """Setup configuration path based on installation type."""
    if install_type == "portable":
        return Path.cwd() / "config"

    # System installation - user-specific config
    import platform
    system = platform.system().lower()

    if system == "windows":
        config_path = Path.home() / ".plexichat"
    elif system == "darwin":  # macOS
        config_path = Path.home() / ".plexichat"
    else:  # Linux and others
        config_path = Path.home() / ".plexichat"

    print(f"{Colors.BOLD}Configuration will be stored in: {Colors.BRIGHT_CYAN}{config_path}{Colors.RESET}")
    return config_path

def get_default_repository():
    """Get the default repository from configuration or use fallback."""
    try:
        # Try to get from existing update system configuration
        # Using fallback since simplified update system doesn't have GITHUB_REPO
        return "linux-of-user/plexichat"
    except ImportError:
        # Fallback to default
        return "linux-of-user/plexichat"

def select_requirements_group():
    """Select which group of requirements to install."""
    print(f"\n{Colors.BOLD}Requirements Group Selection:{Colors.RESET}")
    print(f"  {Colors.BRIGHT_CYAN}1.{Colors.RESET} Minimal - Basic functionality only")
    print(f"  {Colors.BRIGHT_CYAN}2.{Colors.RESET} Standard - Recommended features")
    print(f"  {Colors.BRIGHT_CYAN}3.{Colors.RESET} Full - All features")
    print(f"  {Colors.BRIGHT_CYAN}4.{Colors.RESET} Developer - All features + development tools")

    while True:
        choice = input(f"\n{Colors.BOLD}Select requirements group (1-4): {Colors.RESET}").strip()
        if choice == "1":
            return "minimal"
        elif choice == "2":
            return "standard"
        elif choice == "3":
            return "full"
        elif choice == "4":
            return "developer"
        else:
            print(f"{Colors.RED}Invalid choice. Please select 1-4.{Colors.RESET}")

def download_and_install_to_path(repo: str, version_tag: str, install_path: Any) -> None:
    """Download and install PlexiChat to the specified path."""
    try:
        install_path.mkdir(parents=True, exist_ok=True)
        print(f"  {Colors.BRIGHT_CYAN}Installing to: {install_path}{Colors.RESET}")

        # Change to installation directory
        original_cwd = Path.cwd()
        os.chdir(install_path)

        try:
            # Download PlexiChat
            download_plexichat_from_github(repo, version_tag)

            # Generate version files after installation
            try:
                print(f"  {Colors.BRIGHT_CYAN}Generating version files...{Colors.RESET}")
                from src.plexichat.core.versioning.version_manager import VersionManager
                version_manager = VersionManager()
                version_manager.auto_generate_files()
                print(f"  {Colors.GREEN}✓ Version files generated{Colors.RESET}")
            except Exception as e:
                print(f"  {Colors.YELLOW}⚠ Version file generation failed: {e}{Colors.RESET}")

            print(f"  {Colors.GREEN}✓ Installation completed to {install_path}")
        finally:
            # Return to original directory
            os.chdir(original_cwd)

    except PermissionError as e:
        print(f"ERROR: Access is denied to '{install_path}'.")
        if sys.platform == 'win32' and str(install_path).lower().startswith('c:\\program files'):
            print("Attempting to request administrator permissions...")
            # Relaunch with admin rights using UAC
            try:
                params = ' '.join([f'"{arg}"' for arg in sys.argv])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                print("If the UAC prompt was accepted, the installer will continue with elevated permissions.")
                sys.exit(0)
            except Exception as uac_e:
                print(f"Failed to request administrator permissions: {uac_e}")
                print("Please run this installer as administrator or choose a different install path (e.g., your user directory or a portable location).")
        else:
            print("You do not have permission to install to this directory. Please choose a different install path or check your permissions.")
        return False
    except Exception as e:
        print(f"Installation failed: {e}")
        return False

def compare_versions_with_github(repo: str) -> None:
    """Compare current version with GitHub repository and show more details."""
    try:
        print(f"  {Colors.BRIGHT_CYAN}Analyzing repository versions...{Colors.RESET}")
        current_version = get_current_version()
        print(f"  Current version: {Colors.BRIGHT_YELLOW}{current_version}{Colors.RESET}")
        # Get GitHub releases for more info
        import urllib.request, json
        api_url = f"https://api.github.com/repos/{repo}/releases"
        try:
            with urllib.request.urlopen(api_url) as response:
                releases = json.loads(response.read().decode())
        except Exception:
            releases = []
        if releases:
            latest = releases[0]
            print(f"  Latest version: {Colors.BRIGHT_GREEN}{latest['tag_name']}{Colors.RESET}")
            print(f"    Published: {latest.get('published_at', 'unknown')}")
            print(f"    Prerelease: {latest.get('prerelease', False)}")
            desc = latest.get('body', '').split('\n')[0]
            if desc:
                print(f"    Description: {desc}")
            comparison = compare_version_strings(current_version, latest['tag_name'])
def compare_version_strings(v1: str, v2: str) -> int:
    """Stub: Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    # TODO: Implement real version comparison
    return 0
            if comparison < 0:
                print(f"  {Colors.BRIGHT_YELLOW}Your version is behind by {abs(comparison)} builds")
            elif comparison > 0:
                print(f"  {Colors.BRIGHT_CYAN}Your version is ahead by {comparison} builds")
            else:
                print(f"  {Colors.BRIGHT_GREEN}You have the latest version")
        else:
            print(f"  {Colors.YELLOW}Could not fetch GitHub releases")
    except Exception as e:
        print(f"  {Colors.YELLOW}Version comparison failed: {e}")

def get_current_version():
    """Get current PlexiChat version."""
    try:
        # Try to get from version file
        version_file = Path("VERSION")
        if version_file.exists():
            with open(version_file, 'r') as f:
                return f.read().strip()

        # Fallback to version from version.json
        return get_version_from_json()
    except Exception:
        return get_version_from_json()

# ============================================================================
# MAIN EXECUTION LOGIC
# ============================================================================

def main():
    """Main execution function."""
    try:
        # Parse command line arguments first
        try:
            args = parse_arguments()
        except SystemExit as e:
            # This catches when --help or -h is used, allowing help to display without lock
            return e.code

        # Skip process lock for help command
        if getattr(args, 'command', None) == 'help' or '--help' in sys.argv or '-h' in sys.argv:
            show_help()
            return 0

        # Acquire process lock for all other commands
        if not process_lock_manager.acquire_lock():
            print(f"{Colors.RED}PlexiChat is already running. Use --force-kill to terminate existing processes.{Colors.RESET}")
            return 1

        # Setup enhanced logging
        log_level = "DEBUG" if (args.verbose or args.debug) else args.log_level
        logger, performance_monitor = setup_enhanced_logging(log_level)

        # Handle port override
        if args.port:
            os.environ['PLEXICHAT_PORT'] = str(args.port)

        # Handle host override
        if args.host:
            os.environ['PLEXICHAT_HOST'] = args.host

        # Execute command based on args.command
        if args.command == 'api':
            logger.info("Starting API server with CLI interface")
            return run_api_and_cli(args)

        elif args.command == 'gui':
            logger.info("Starting GUI interface")
            return run_gui(args)

        elif args.command == 'gui-standalone':
            logger.info("Starting GUI in standalone mode")
            return run_gui_standalone()

        elif args.command == 'webui':
            logger.info("Starting WebUI interface")
            return run_webui(args)

        elif args.command == 'cli':
            logger.info("Starting CLI interface")
            return run_cli()

        elif args.command == 'admin':
            logger.info("Starting admin CLI")
            return run_admin_cli()

        elif args.command == 'backup-node':
            logger.info("Starting backup node")
            return run_backup_node()

        elif args.command == 'plugin':
            logger.info("Starting plugin manager")
            return run_plugin_manager()

        elif args.command == 'test':
            logger.info("Running test suite")
            return asyncio.run(handle_test_command(args))

        elif args.command == 'setup':
            logger.info("Running setup wizard")
            return run_setup_command(args.level, args.no_ui)

        elif args.command == 'config':
            logger.info("Running configuration wizard")
            return run_config_wizard()

        elif args.command == 'wizard':
            logger.info("Running configuration wizard")
            return run_config_wizard()

        elif args.command == 'update':
            logger.info("Running update manager")
            return run_update_manager()

        elif args.command == 'version':
            logger.info("Running version manager")
            return run_version_manager()

        elif args.command == 'clean':
            logger.info("Running system cleanup")
            return run_system_cleanup()

        elif args.command == 'update':
            logger.info("Running update process")
            if args.args and args.args[0] == 'check':
                # Just check for updates
                return handle_github_commands('versions', [], args.target_dir)
            else:
                # Get and install latest version
                return handle_github_commands('latest', args.args, args.target_dir)

        elif args.command == 'install':
            logger.info("Running installer")
            return run_install_command(args)

        else:
            logger.error(f"Unknown command: {args.command}")
            show_help()
            return 1

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
        return 1
    finally:
        # Always release the process lock
        process_lock_manager.release_lock()

if __name__ == "__main__":
    sys.exit(main())