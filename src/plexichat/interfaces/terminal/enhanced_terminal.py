# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
#!/usr/bin/env python3
"""
Enhanced Terminal Interface for PlexiChat
=========================================

Provides a tmux-like terminal interface with:
- Resizable panes
- Split screen functionality
- Real-time log monitoring
- Interactive CLI
- System status display
- Performance metrics
"""

import os
import sys
import time
import threading
import queue
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime

# Platform-specific imports
try:
    import msvcrt  # Windows
except ImportError:
    msvcrt = None
try:
    import termios  # Unix
    import tty
except ImportError:
    termios = None
    tty = None
HAS_TERMINAL = msvcrt is not None or (termios is not None and tty is not None)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class Pane:
    """Represents a terminal pane."""
    
    def __init__(self, x: int, y: int, width: int, height: int, title: str = ""):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.title = title
        self.content = []
        self.scroll_offset = 0
        self.active = False
        self.border = True
    
    def add_content(self, line: str):
        """Add content to the pane."""
        self.content.append(line)
        if len(self.content) > self.height - 2:  # Account for borders
            self.content.pop(0)
    
    def clear_content(self):
        """Clear pane content."""
        self.content = []
        self.scroll_offset = 0
    
    def scroll_up(self):
        """Scroll pane content up."""
        if self.scroll_offset > 0:
            self.scroll_offset -= 1
    
    def scroll_down(self):
        """Scroll pane content down."""
        max_scroll = max(0, len(self.content) - (self.height - 2))
        if self.scroll_offset < max_scroll:
            self.scroll_offset += 1

class EnhancedTerminal:
    """Enhanced terminal interface with resizable panes."""
    
    def __init__(self):
        self.width = 0
        self.height = 0
        self.panes = []
        self.active_pane = 0
        self.running = False
        self.input_queue = queue.Queue()
        self.log_queue = queue.Queue()
        
        # Initialize terminal
        self.init_terminal()
        
        # Create default panes
        self.create_default_panes()
    
    def init_terminal(self):
        """Initialize terminal settings."""
        if not HAS_TERMINAL:
            logger.warning("Terminal features not available on this platform")
            return
        
        # Get terminal size
        try:
            import shutil
            size = shutil.get_terminal_size()
            self.width = size.columns
            self.height = size.lines
        except Exception:
            self.width = 80
            self.height = 24
        
        # Set up terminal for raw input
        if os.name == 'posix':
            if termios is not None and tty is not None:
                self.old_settings = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin.fileno())
    
    def create_default_panes(self):
        """Create default pane layout."""
        # Calculate pane dimensions
        pane_width = self.width // 2
        pane_height = self.height - 2  # Account for status bar
        
        # Left pane - Logs
        self.panes.append(Pane(0, 0, pane_width, pane_height, "Logs"))
        
        # Right pane - CLI
        self.panes.append(Pane(pane_width, 0, pane_width, pane_height, "CLI"))
        
        # Set active pane
        self.panes[0].active = True
    
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get current terminal size."""
        try:
            import shutil
            size = shutil.get_terminal_size()
            return size.columns, size.lines
        except Exception:
            return 80, 24
    
    def resize_panes(self):
        """Resize panes based on terminal size."""
        new_width, new_height = self.get_terminal_size()
        
        if new_width != self.width or new_height != self.height:
            self.width = new_width
            self.height = new_height
            
            # Recalculate pane dimensions
            pane_width = self.width // 2
            pane_height = self.height - 2
            
            # Update pane dimensions
            if len(self.panes) >= 2:
                self.panes[0].width = pane_width
                self.panes[0].height = pane_height
                self.panes[1].x = pane_width
                self.panes[1].width = pane_width
                self.panes[1].height = pane_height
    
    def draw_pane(self, pane: Pane):
        """Draw a single pane."""
        # Draw border
        if pane.border:
            border_char = "═" if pane.active else "─"
            corner_char = "╔" if pane.active else "┌"
            
            # Top border
            print(f"\033[{pane.y};{pane.x}H{corner_char}{border_char * (pane.width - 2)}╗")
            
            # Side borders
            for i in range(1, pane.height - 1):
                side_char = "║" if pane.active else "│"
                print(f"\033[{pane.y + i};{pane.x}H{side_char}")
                print(f"\033[{pane.y + i};{pane.x + pane.width - 1}H{side_char}")
            
            # Bottom border
            print(f"\033[{pane.y + pane.height - 1};{pane.x}H╚{border_char * (pane.width - 2)}╝")
        
        # Draw title
        if pane.title:
            title = f" {pane.title} "
            title_x = pane.x + (pane.width - len(title)) // 2
            print(f"\033[{pane.y};{title_x}H{title}")
        
        # Draw content
        content_start = pane.y + 1
        content_end = pane.y + pane.height - 1
        
        for i, line in enumerate(pane.content[pane.scroll_offset:]):
            if content_start + i >= content_end:
                break
            
            # Truncate line to fit pane width
            if len(line) > pane.width - 2:
                line = line[:pane.width - 5] + "..."
            
            print(f"\033[{content_start + i};{pane.x + 1}H{line}")
    
    def draw_status_bar(self):
        """Draw status bar at bottom of terminal."""
        status_y = self.height - 1
        
        # Clear status bar
        print(f"\033[{status_y};1H{' ' * self.width}")
        
        # Status information
        status_info = [
            f"Pane: {self.active_pane + 1}/{len(self.panes)}",
            f"Size: {self.width}x{self.height}",
            f"Time: {datetime.now().strftime('%H:%M:%S')}"
        ]
        
        if PSUTIL_AVAILABLE and psutil:
            try:
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                status_info.extend([
                    f"CPU: {cpu_percent:.1f}%",
                    f"RAM: {memory.percent:.1f}%"
                ])
            except Exception:
                # psutil might fail on some systems
                pass
        
        status_line = " | ".join(status_info)
        status_x = max(0, (self.width - len(status_line)) // 2)
        print(f"\033[{status_y};{status_x + 1}H{status_line}")
    
    def draw_screen(self):
        """Draw the entire screen."""
        # Clear screen
        print("\033[2J")
        
        # Draw each pane
        for pane in self.panes:
            self.draw_pane(pane)
        
        # Draw status bar
        self.draw_status_bar()
        
        # Position cursor in active pane
        active_pane = self.panes[self.active_pane]
        cursor_x = active_pane.x + 1
        cursor_y = active_pane.y + active_pane.height - 2
        print(f"\033[{cursor_y};{cursor_x}H")
    
    def handle_input(self):
        """Handle keyboard input."""
        if not HAS_TERMINAL:
            return
        
        try:
            if os.name == 'nt':  # Windows
                if msvcrt:
                    if msvcrt.kbhit():
                        key = msvcrt.getch()
                        # Convert bytes to string for Windows
                        if isinstance(key, bytes):
                            key = key.decode('utf-8', errors='ignore')
                        self.process_key(key)
            else:  # Unix
                if sys.stdin.readable():
                    key = sys.stdin.read(1)
                    self.process_key(key)
        except Exception as e:
            logger.error(f"Error handling input: {e}")
    
    def process_key(self, key: str):
        """Process a single key press."""
        if key == '\x1b':  # Escape sequence
            # Handle arrow keys and other special keys
            pass
        elif key == '\t':  # Tab
            self.switch_pane()
        elif key == 'q':  # Quit
            self.running = False
        elif key == 'j':  # Scroll down
            self.panes[self.active_pane].scroll_down()
        elif key == 'k':  # Scroll up
            self.panes[self.active_pane].scroll_up()
        elif key == 'h':  # Previous pane
            self.previous_pane()
        elif key == 'l':  # Next pane
            self.next_pane()
        elif key == 'r':  # Refresh
            self.refresh_screen()
    
    def switch_pane(self):
        """Switch to next pane."""
        self.panes[self.active_pane].active = False
        self.active_pane = (self.active_pane + 1) % len(self.panes)
        self.panes[self.active_pane].active = True
    
    def previous_pane(self):
        """Switch to previous pane."""
        self.panes[self.active_pane].active = False
        self.active_pane = (self.active_pane - 1) % len(self.panes)
        self.panes[self.active_pane].active = True
    
    def next_pane(self):
        """Switch to next pane."""
        self.switch_pane()
    
    def refresh_screen(self):
        """Refresh the screen."""
        self.resize_panes()
        self.draw_screen()
    
    def add_log_message(self, message: str):
        """Add a log message to the logs pane."""
        if self.panes:
            timestamp = datetime.now().strftime('%H:%M:%S')
            formatted_message = f"[{timestamp}] {message}"
            self.panes[0].add_content(formatted_message)
    
    def add_cli_output(self, output: str):
        """Add output to the CLI pane."""
        if len(self.panes) > 1:
            self.panes[1].add_content(output)
    
    def run(self):
        """Run the enhanced terminal interface."""
        self.running = True
        
        # Start input handling thread
        input_thread = threading.Thread(target=self.input_loop, daemon=True)
        if input_thread and hasattr(input_thread, "start"): input_thread.start()
        
        # Start log monitoring thread
        log_thread = threading.Thread(target=self.log_monitor_loop, daemon=True)
        if log_thread and hasattr(log_thread, "start"): log_thread.start()
        
        # Main loop
        try:
            while self.running:
                self.refresh_screen()
                time.sleep(0.1)  # 10 FPS refresh rate
        except KeyboardInterrupt:
            self.running = False
        finally:
            if self and hasattr(self, "cleanup"): self.cleanup()
    
    def input_loop(self):
        """Input handling loop."""
        while self.running:
            self.handle_input()
            time.sleep(0.01)
    
    def log_monitor_loop(self):
        """Log monitoring loop."""
        log_file = Path("logs/plexichat.log")
        
        if not log_file.exists():
            log_file.parent.mkdir(exist_ok=True)
            log_file.touch()
        
        last_position = log_file.stat().st_size if log_file.exists() else 0
        
        while self.running:
            try:
                if log_file.exists():
                    current_size = log_file.stat().st_size
                    
                    if current_size > last_position:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_position)
                            new_lines = f.readlines()
                            
                            for line in new_lines:
                                line = line.strip()
                                if line:
                                    self.add_log_message(line)
                        
                        last_position = current_size
                
                time.sleep(0.2)  # Check every 200ms
            except Exception as e:
                logger.error(f"Error monitoring logs: {e}")
                time.sleep(1)
    
    def cleanup(self):
        """Restore terminal settings on exit."""
        if os.name == 'posix':
            if termios is not None and hasattr(self, 'old_settings'):
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)
        
        # Clear screen
        print("\033[2J")
        print("\033[H")

class TerminalManager:
    """Manages terminal sessions and panes."""
    
    def __init__(self):
        self.terminals = {}
        self.current_terminal = None
    
    def create_terminal(self, name: str) -> EnhancedTerminal:
        """Create a new terminal session."""
        terminal = EnhancedTerminal()
        self.terminals[name] = terminal
        return terminal
    
    def get_terminal(self, name: str) -> Optional[EnhancedTerminal]:
        """Get a terminal session by name."""
        return self.terminals.get(name)
    
    def list_terminals(self) -> List[str]:
        """List all terminal sessions."""
        return list(self.terminals.keys())
    
    def switch_terminal(self, name: str) -> bool:
        """Switch to a different terminal session."""
        if name in self.terminals:
            self.current_terminal = name
            return True
        return False

# Global terminal manager
terminal_manager = TerminalManager()

def start_enhanced_terminal():
    """Start the enhanced terminal interface."""
    terminal = EnhancedTerminal()
    terminal.run()

if __name__ == '__main__':
    start_enhanced_terminal() 
