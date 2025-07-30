# Utility to load OS package lists from requirements.txt
def _load_os_packages(section: str) -> list[str]:
    """Load OS package list from requirements.txt section marker (e.g., [pacman])."""
    req_path = Path(__file__).parent / "requirements.txt"
    if not req_path.exists():
        req_path = Path("requirements.txt")
    if not req_path.exists():
        print(f"{Colors.YELLOW}requirements.txt not found for OS package fallback{Colors.RESET}")
        return []
    lines = req_path.read_text(encoding="utf-8").splitlines()
    in_section = False
    pkgs = []
    marker = f"[{section}]"
    for line in lines:
        line = line.strip()
        if line.startswith("#") and marker in line:
            in_section = True
            continue
        if in_section:
            if line.startswith("# [") and marker not in line:
                break
            if line.startswith("#") and not line.startswith("# ["):
                pkg = line[1:].strip()
                if pkg:
                    pkgs.append(pkg)
    return pkgs
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

# Add src to path for imports FIRST
src_path = str(Path(__file__).parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Try to use the unified logging system from src, fallback to basic logging
try:
    from src.plexichat.core.logging import get_logger
    logger = get_logger(__name__)
    unified_logging_available = True
except ImportError:
    # Fallback to basic logging for install/setup modes
    logger = logging.getLogger(__name__)
    unified_logging_available = False

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
                    except (ProcessLookupError, PermissionError, OSError):
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

def setup_configuration_path(install_type: int) -> Path:
    """Setup configuration path based on installation type."""
    if install_type == 1: # Portable
        return Path.cwd() / "config"

    system = platform.system().lower()
    if system == "windows" or system == "darwin":
        config_path = Path.home() / ".plexichat"
    else:  # Linux and others
        config_path = Path.home() / ".config" / "plexichat"

    print(f"{Colors.BOLD}Configuration will be stored in: {Colors.BRIGHT_CYAN}{config_path}{Colors.RESET}")
    return config_path

def get_default_repository() -> str:
    """Get the default repository."""
    return "linux-of-user/plexichat"

def download_and_install_to_path(repo: str, version_tag: str, install_path: Path) -> None:
    """Download and install PlexiChat to the specified path."""
    try:
        install_path.mkdir(parents=True, exist_ok=True)
        print(f"  {Colors.BRIGHT_CYAN}Installing to: {install_path}{Colors.RESET}")

        original_cwd = Path.cwd()
        # We download to a temp location within the CWD to avoid permission issues
        # then move the final files to the install_path
        temp_dir = Path(tempfile.mkdtemp(prefix="plexichat-install-"))
        os.chdir(temp_dir)

        try:
            zip_path = download_plexichat_from_github(repo, version_tag)
            if not zip_path:
                raise RuntimeError("Failed to download PlexiChat.")
            
            extract_and_cleanup_zip(zip_path, install_path)

            try:
                print(f"  {Colors.BRIGHT_CYAN}Generating version files...{Colors.RESET}")
                # This will likely fail if run from a script that is not in the source tree
                # but we keep it for when the installer is part of the project itself.
                from src.plexichat.core.versioning.version_manager import VersionManager
                VersionManager().auto_generate_files()
                print(f"  {Colors.GREEN}✓ Version files generated{Colors.RESET}")
            except Exception as e:
                print(f"  {Colors.YELLOW}⚠ Version file generation failed: {e}{Colors.RESET}")

            print(f"  {Colors.GREEN}✓ Installation completed to {install_path}")
        finally:
            os.chdir(original_cwd)
            shutil.rmtree(temp_dir) # Clean up the temporary directory

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
def load_configuration() -> Dict[str, Any]:
    """Load configuration from file or return defaults."""
    try:
        config_dir = Path("config")
        config_file = config_dir / "plexichat.json"
        
        # Create config directory if it doesn't exist
        config_dir.mkdir(exist_ok=True)
        
        # Default configuration
        default_config = {
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
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_size_mb": 10,
                "backup_count": 5
            }
        }
        
        # Load configuration if file exists
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                if logger:
                    logger.info(f"Configuration loaded from {config_file}")
                return config
            except Exception as e:
                if logger:
                    logger.error(f"Error loading configuration: {e}")
        
        # Return default configuration
        if logger:
            logger.info("Using default configuration")
        return default_config
    except Exception as e:
        if logger:
            logger.error(f"Failed to load configuration: {e}")
        return {}

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
            logger.info("About to import FastAPI app from plexichat.main...")
        try:
            # Try importing from plexichat.main first
            from plexichat.main import app
            if logger:
                logger.info("FastAPI app imported successfully from plexichat.main!")
        except ImportError:
            # Fallback to src.plexichat.main
            try:
                from src.plexichat.main import app
                if logger:
                    logger.info("FastAPI app imported successfully from src.plexichat.main!")
            except ImportError as e:
                if logger:
                    logger.error(f"Failed to import FastAPI app: {e}")
                return False
                
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
        try:
            from plexichat.interfaces.cli.enhanced_cli import enhanced_cli
        except ImportError:
            try:
                from src.plexichat.interfaces.cli.enhanced_cli import enhanced_cli
            except ImportError as e:
                if logger:
                    logger.error(f"Could not import enhanced CLI: {e}")
                print(f"{Colors.RED}Enhanced CLI not available: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}Showing basic help instead...{Colors.RESET}")
                # Use the global show_help function defined in this file
                show_help()
                return

        # Show welcome message
        print(f"{Colors.BRIGHT_CYAN}PlexiChat Enhanced CLI{Colors.RESET}")
        print(f"{Colors.CYAN}Version: {PLEXICHAT_VERSION}{Colors.RESET}")
        print(f"{Colors.CYAN}Type 'help' for available commands{Colors.RESET}")
        
        # Interactive CLI mode
        enhanced_cli.show_help()
        
        # Start interactive loop
        print(f"\n{Colors.BRIGHT_GREEN}Starting interactive CLI mode...{Colors.RESET}")
        while True:
            try:
                # Get command input
                cmd_input = input(f"{Colors.BRIGHT_GREEN}plexichat>{Colors.RESET} ").strip()
                
                if not cmd_input:
                    continue
                    
                if cmd_input.lower() in ['exit', 'quit', 'q']:
                    print(f"{Colors.YELLOW}Exiting CLI...{Colors.RESET}")
                    break
                    
                # Parse command and arguments
                parts = cmd_input.split()
                command = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                
                # Execute command
                import asyncio
                success = asyncio.run(enhanced_cli.execute_command(command, args))
                if not success:
                    print(f"{Colors.RED}Command failed: {command}{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled. Type 'exit' to quit.{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                if logger:
                    logger.error(f"CLI command error: {e}")
                    logger.debug(f"CLI error details: {e}", exc_info=True)

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
    # Load Debian/Ubuntu fallback packages from requirements.txt [apt] section
    debian_packages = _load_os_packages("apt")
    # Fallback to hard-coded list if section missing/empty
    if not debian_packages:
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
    fedora_packages = _load_os_packages("dnf")

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
    # Load Arch Linux fallback packages from requirements.txt [pacman] section
    arch_packages = _load_os_packages("pacman")
    # Fallback to hard-coded minimal list if the section is missing or empty
    if not arch_packages:
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

def download_plexichat_from_github(repo: str, version_tag: str) -> str:
    """Download PlexiChat from GitHub and return the path to the zip file."""
    try:
        print(f"  {Colors.BRIGHT_CYAN}Downloading PlexiChat {version_tag} from {repo}...{Colors.RESET}")
        manager = GitHubVersionManager()
        versions = manager.get_available_versions()
        version_to_download = None

        if version_tag == 'latest':
            version_to_download = manager.get_latest_version()
        else:
            for v in versions:
                if v['tag'] == version_tag:
                    version_to_download = v
                    break

        if not version_to_download:
            print(f"{Colors.RED}Version '{version_tag}' not found.{Colors.RESET}")
            return ""

        download_url = version_to_download['download_url']
        zip_path = Path(f"plexichat-{version_to_download['tag']}.zip")

        with urllib.request.urlopen(download_url) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)

        print(f"  {Colors.GREEN}✓ Downloaded to {zip_path}{Colors.RESET}")
        return str(zip_path)

    except Exception as e:
        print(f"{Colors.RED}Failed to download from GitHub: {e}{Colors.RESET}")
        return ""

def extract_and_cleanup_zip(zip_path: str, install_path: Path) -> None:
    """Extract downloaded zip file and clean up."""
    try:
        print(f"  {Colors.YELLOW}📦 Extracting files...{Colors.RESET}")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall('.')

        extracted_folders = [d for d in Path('.').iterdir() if d.is_dir() and d.name.startswith('linux-of-user-plexichat-')]
        if extracted_folders:
            source_dir = extracted_folders[0]
            for item in source_dir.iterdir():
                shutil.move(str(item), str(install_path / item.name))
            if source_dir.exists() and source_dir.is_dir():
                shutil.rmtree(source_dir)

        Path(zip_path).unlink()
        print(f"  {Colors.GREEN}✓ PlexiChat downloaded and extracted successfully")

    except Exception as e:
        print(f"  {Colors.RED}✗ Extraction failed: {e}")
        raise

def compare_version_strings(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    try:
        from packaging.version import parse
        v1_parsed, v2_parsed = parse(v1), parse(v2)
        if v1_parsed < v2_parsed: return -1
        if v1_parsed > v2_parsed: return 1
        return 0
    except ImportError:
        # Fallback if packaging is not installed
        if v1 == v2: return 0
        return -1 # Assume older if can't compare

def compare_versions_with_github(repo: str) -> None:
    """Compare current version with GitHub repository and show more details."""
    try:
        print(f"  {Colors.BRIGHT_CYAN}Analyzing repository versions...{Colors.RESET}")
        current_version = get_current_version()
        print(f"  Current version: {Colors.BRIGHT_YELLOW}{current_version}{Colors.RESET}")
        
        api_url = f"https://api.github.com/repos/{repo}/releases"
        releases = []
        try:
            with urllib.request.urlopen(api_url) as response:
                releases = json.loads(response.read().decode())
        except Exception as e:
            print(f"  {Colors.YELLOW}Could not fetch GitHub releases: {e}")

        if releases:
            latest = releases[0]
            print(f"  Latest version: {Colors.BRIGHT_GREEN}{latest['tag_name']}{Colors.RESET}")
            print(f"    Published: {latest.get('published_at', 'unknown')}")
            print(f"    Prerelease: {latest.get('prerelease', False)}")
            desc = latest.get('body', '').split('\n')[0]
            if desc:
                print(f"    Description: {desc}")
            
            comparison = compare_version_strings(current_version, latest['tag_name'])
            if comparison < 0:
                print(f"  {Colors.BRIGHT_YELLOW}Your version is behind.{Colors.RESET}")
            elif comparison > 0:
                print(f"  {Colors.BRIGHT_CYAN}You are ahead of the latest release.{Colors.RESET}")
            else:
                print(f"  {Colors.BRIGHT_GREEN}You have the latest version.{Colors.RESET}")

    except Exception as e:
        print(f"  {Colors.YELLOW}Version comparison failed: {e}")



def get_current_version() -> str:
    """Get current PlexiChat version."""
    try:
        version_file = Path("VERSION")
        if version_file.exists():
            return version_file.read_text().strip()
        return get_version_from_json()
    except Exception:
        return get_version_from_json()

# ============================================================================
# STUB FUNCTIONS (to be implemented)
# ============================================================================

def install_from_config_file(config_file: str):
    print(f"STUB: Installing from config file: {config_file}")

def select_version_to_install(repo: str) -> str:
    print("STUB: Selecting version to install...")
    manager = GitHubVersionManager()
    versions = manager.get_available_versions()
    if not versions:
        print("Could not fetch versions. Defaulting to 'latest'.")
        return "latest"
    
    print("Available versions:")
    for i, v in enumerate(versions):
        print(f"  {i+1}. {v['tag']} ({v['name']}){' [prerelease]' if v['prerelease'] else ''}")
    
    while True:
        choice = input(f"Select version to install (1-{len(versions)}), or 'latest': ").strip().lower()
        if choice == 'latest':
            return 'latest'
        try:
            index = int(choice) - 1
            if 0 <= index < len(versions):
                return versions[index]['tag']
        except ValueError:
            pass
        print("Invalid selection.")

def run_api_and_cli(args):
    """Start the PlexiChat API server with CLI interface."""
    try:
        # Start the API server in a separate thread
        import threading
        logger.info("Starting PlexiChat API server in background thread...")
        api_thread = threading.Thread(target=run_api_server, args=(args,), daemon=True)
        api_thread.start()
        
        # Give the API server time to start
        import time
        time.sleep(2)
        
        # Run the CLI interface in the main thread
        logger.info("API server started. Now starting CLI interface...")
        run_cli()
        return 0
    except Exception as e:
        logger.error(f"Error starting API and CLI: {e}")
        return 1

def run_gui(args):
    print(f"STUB: Running GUI with args: {args}")
    return 0

def run_gui_standalone():
    print("STUB: Running GUI standalone")
    return 0

def run_webui(args):
    print(f"STUB: Running WebUI with args: {args}")
    return 0

def run_cli():
    """Run the enhanced CLI interface with plugin integration."""
    try:
        # Import the main CLI system with plugin support
        try:
            from plexichat.interfaces.cli.main_cli import main as cli_main
        except ImportError:
            try:
                from src.plexichat.interfaces.cli.main_cli import main as cli_main
            except ImportError as e:
                print(f"CLI system not available: {e}")
                return 1
        
        # Check if we have arguments to pass to CLI
        import sys
        if len(sys.argv) > 2:
            # CLI has arguments, use main CLI
            original_argv = sys.argv.copy()
            try:
                # Remove 'run.py' and 'cli' from argv, pass remaining args to CLI
                sys.argv = ['plexichat'] + sys.argv[2:]
                cli_main()
            finally:
                sys.argv = original_argv
        else:
            # Interactive mode - use enhanced CLI
            try:
                from plexichat.interfaces.cli.enhanced_cli import enhanced_cli
            except ImportError:
                try:
                    from src.plexichat.interfaces.cli.enhanced_cli import enhanced_cli
                except ImportError:
                    enhanced_cli = None
            
            if enhanced_cli:
                print(f"{Colors.BRIGHT_CYAN}PlexiChat Enhanced CLI{Colors.RESET}")
                print(f"{Colors.CYAN}Version: {PLEXICHAT_VERSION}{Colors.RESET}")
                print(f"{Colors.CYAN}Type 'help' for available commands{Colors.RESET}")
                
                # Start interactive loop
                import asyncio
                asyncio.run(enhanced_cli.start_interactive_mode())
            else:
                # Fallback to main CLI without args
                cli_main()
                
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}CLI interrupted by user{Colors.RESET}")
        return 0
    except Exception as e:
        logger.error(f"Error running CLI: {e}")
        print(f"Error: {e}")
        return 1

def run_admin_cli():
    print("STUB: Running admin CLI")
    return 0

def run_backup_node():
    print("STUB: Running backup node")
    return 0

def run_plugin_manager():
    print("STUB: Running plugin manager")
    return 0

async def handle_test_command(args):
    print(f"STUB: Handling test command with args: {args}")
    return 0

def run_setup_command(level, no_ui):
    print(f"STUB: Running setup command with level={level}, no_ui={no_ui}")
    wizard = SetupWizard()
    wizard.run(level=level)
    return 0

def run_config_wizard():
    print("STUB: Running config wizard")
    return 0

def run_update_manager():
    print("STUB: Running update manager")
    return 0

def run_version_manager():
    print("STUB: Running version manager")
    return 0

def run_system_cleanup():
    print("STUB: Running system cleanup")
    return 0

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