"""
CLI Terminal Component for PlexiChat GUI

Integrates the enhanced CLI system into the GUI with a full-featured terminal interface.


import tkinter as tk
from tkinter import ttk, scrolledtext, font, messagebox
import threading
import asyncio
import subprocess
import sys
import os
import time
from typing import List, Dict, Optional, Callable
from datetime import datetime
from pathlib import Path
import logging

try:
    from plexichat.interfaces.cli.enhanced_cli import enhanced_cli
except ImportError:
    enhanced_cli = None

logger = logging.getLogger(__name__)


class CLITerminal(ttk.Frame):
    """
    Advanced CLI Terminal widget for GUI integration.
    
    Features:
    - Full CLI command execution
    - Command history and auto-completion
    - Syntax highlighting
    - Real-time output streaming
    - Multiple terminal tabs
    - Command shortcuts and aliases
    - Export/import command history
    """
        def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.parent = parent
        self.command_history = []
        self.history_index = -1
        self.current_command = ""
        self.is_running_command = False
        
        # Terminal colors and styling
        self.colors = {
            'bg': '#1e1e1e',
            'fg': '#ffffff',
            'prompt': '#00ff00',
            'command': '#ffff00',
            'output': '#ffffff',
            'error': '#ff0000',
            'success': '#00ff00',
            'warning': '#ffaa00',
            'info': '#00aaff'
        }
        
        self.setup_ui()
        self.setup_bindings()
        self.load_command_history()
        
        # Start with welcome message
        self.display_welcome()
    
    def setup_ui(self):
        """Setup the terminal UI components."""
        # Configure grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Main frame
        main_frame = ttk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Terminal header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Label(header_frame, text="PlexiChat CLI Terminal", 
                font=('Consolas', 12, 'bold')).pack(side=tk.LEFT)
        
        # Terminal controls
        controls_frame = ttk.Frame(header_frame)
        controls_frame.pack(side=tk.RIGHT)
        
        ttk.Button(controls_frame, text="Clear", 
                command=self.clear_terminal, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(controls_frame, text="History", 
                command=self.show_history, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(controls_frame, text="Help", 
                command=self.show_help, width=8).pack(side=tk.LEFT, padx=2)
        
        # Terminal output area
        terminal_frame = ttk.Frame(main_frame)
        terminal_frame.grid(row=1, column=0, sticky="nsew")
        terminal_frame.grid_rowconfigure(0, weight=1)
        terminal_frame.grid_columnconfigure(0, weight=1)
        
        # Output text widget
        self.output_text = scrolledtext.ScrolledText(
            terminal_frame,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            font=('Consolas', 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure text tags for colors
        self.setup_text_tags()
        
        # Command input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=2, column=0, sticky="ew", pady=(5, 0))
        input_frame.grid_columnconfigure(1, weight=1)
        
        # Prompt label
        self.prompt_label = ttk.Label(input_frame, text="plexichat>", 
                                    foreground=self.colors['prompt'],
                                    font=('Consolas', 10, 'bold'))
        self.prompt_label.grid(row=0, column=0, padx=(0, 5))
        
        # Command entry
        self.command_entry = ttk.Entry(
            input_frame,
            font=('Consolas', 10),
            foreground=self.colors['command']
        )
        self.command_entry.grid(row=0, column=1, sticky="ew")
        self.command_entry.focus()
        
        # Execute button
        ttk.Button(input_frame, text="Execute", 
                command=self.execute_command, width=10).grid(row=0, column=2, padx=(5, 0))
    
    def setup_text_tags(self):
        """Setup text tags for syntax highlighting."""
        self.output_text.tag_configure("prompt", foreground=self.colors['prompt'], font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("command", foreground=self.colors['command'], font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("output", foreground=self.colors['output'])
        self.output_text.tag_configure("error", foreground=self.colors['error'], font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("success", foreground=self.colors['success'], font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("warning", foreground=self.colors['warning'], font=('Consolas', 10, 'bold'))
        self.output_text.tag_configure("info", foreground=self.colors['info'], font=('Consolas', 10, 'bold'))
    
    def setup_bindings(self):
        """Setup keyboard bindings.
        self.command_entry.bind('<Return>', lambda e: self.execute_command())
        self.command_entry.bind('<Up>', self.history_up)
        self.command_entry.bind('<Down>', self.history_down)
        self.command_entry.bind('<Tab>', self.auto_complete)
        self.command_entry.bind('<Control-c>', self.interrupt_command)
        self.command_entry.bind('<Control-l>', lambda e: self.clear_terminal())
    
    def display_welcome(self):
        """Display welcome message."""
        welcome_text = f
PlexiChat Enhanced CLI Terminal
==============================
Welcome to the PlexiChat command-line interface!

Available commands: status, health, test-run, plugin-list, and many more...
Type 'help' to see all available commands.
Type 'cli help' to see CLI-specific help.

Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System ready.

"""
        self.append_output(welcome_text, "info")
        self.append_output("plexichat> ", "prompt")
    
    def append_output(self, text: str, tag: str = "output"):
        """Append text to the output area with specified tag.
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text, tag)
        self.output_text.config(state=tk.DISABLED)
        self.output_text.see(tk.END)
    
    def execute_command(self):
        """Execute the current command."""
        if self.is_running_command:
            return
        
        command = self.command_entry.get().strip()
        if not command:
            return
        
        # Add to history
        if command not in self.command_history:
            self.command_history.append(command)
            self.save_command_history()
        
        self.history_index = -1
        
        # Display command
        self.append_output(f"{command}\n", "command")
        
        # Clear input
        self.command_entry.delete(0, tk.END)
        
        # Execute command in background
        self.is_running_command = True
        threading.Thread(target=self._execute_command_thread, args=(command,), daemon=True).start()
    
    def _execute_command_thread(self, command: str):
        """Execute command in background thread."""
        try:
            # Handle special commands
            if command == "help":
                self._show_cli_help()
            elif command == "clear":
                self.after(0, self.clear_terminal)
            elif command == "history":
                self._show_command_history()
            elif command.startswith("cli "):
                # Execute CLI command
                cli_command = command[4:]  # Remove "cli " prefix
                self._execute_cli_command(cli_command)
            else:
                # Try to execute as CLI command directly
                self._execute_cli_command(command)
        
        except Exception as e:
            self.after(0, lambda: self.append_output(f"Error: {str(e)}\n", "error"))
        
        finally:
            self.is_running_command = False
            self.after(0, lambda: self.append_output("plexichat> ", "prompt"))
    
    def _execute_cli_command(self, command: str):
        """Execute a CLI command using the enhanced CLI system."""
        try:
            if enhanced_cli:
                # Parse command and arguments
                parts = command.split()
                if not parts:
                    return
                
                cmd_name = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                
                # Execute command
                result = asyncio.run(enhanced_cli.execute_command(cmd_name, args))
                
                if result:
                    self.after(0, lambda: self.append_output("Command completed successfully.\n", "success"))
                else:
                    self.after(0, lambda: self.append_output("Command failed or not found.\n", "error"))
            else:
                # Fallback to subprocess execution
                self._execute_subprocess_command(f"python run.py cli {command}")
        
        except Exception as e:
            self.after(0, lambda: self.append_output(f"CLI Error: {str(e)}\n", "error"))
    
    def _execute_subprocess_command(self, command: str):
        """Execute command using subprocess."""
        try:
            # Change to the correct directory
            cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            
            result = subprocess.run(
                command.split(),
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout:
                self.after(0, lambda: self.append_output(result.stdout, "output"))
            
            if result.stderr:
                self.after(0, lambda: self.append_output(result.stderr, "error"))
            
            if result.returncode == 0:
                self.after(0, lambda: self.append_output("Command completed successfully.\n", "success"))
            else:
                self.after(0, lambda: self.append_output(f"Command failed with exit code {result.returncode}\n", "error"))
        
        except subprocess.TimeoutExpired:
            self.after(0, lambda: self.append_output("Command timed out.\n", "error"))
        except Exception as e:
            self.after(0, lambda: self.append_output(f"Subprocess error: {str(e)}\n", "error"))

    def _show_cli_help(self):
        """Show CLI help information.
        help_text = """
Available Commands:
==================

System Commands:
- status          Show system status
- health          Show health check
- version         Show version information
- config          Show configuration

Testing Commands:
- test-run        Run all tests
- test-endpoint   Test specific endpoint
- test-suite      Run test suites
- test-load       Load testing
- test-security   Security testing

Plugin Commands:
- plugin-list     List all plugins
- plugin-enable   Enable a plugin
- plugin-disable  Disable a plugin
- plugin-install  Install a plugin

Database Commands:
- db-status       Database status
- db-migrate      Run migrations
- db-backup       Backup database

Admin Commands:
- user-list       List users
- user-create     Create user
- logs            View logs
- metrics         Show metrics

Special Commands:
- help            Show this help
- clear           Clear terminal
- history         Show command history
- exit            Exit terminal

Usage Examples:
- status
- test-run --verbose
- plugin-list
- user-create --username test --email test@example.com

"""
        self.after(0, lambda: self.append_output(help_text, "info"))

    def _show_command_history(self):
        """Show command history."""
        if not self.command_history:
            self.after(0, lambda: self.append_output("No command history available.\n", "info"))
            return

        history_text = "Command History:\n"
        history_text += "================\n"
        for i, cmd in enumerate(self.command_history[-20:], 1):  # Show last 20 commands
            history_text += f"{i:2d}. {cmd}\n"
        history_text += "\n"

        self.after(0, lambda: self.append_output(history_text, "info"))

    def history_up(self, event):
        """Navigate up in command history.
        if not self.command_history:
            return

        if self.history_index == -1:
            self.current_command = self.command_entry.get()
            self.history_index = len(self.command_history) - 1
        elif self.history_index > 0:
            self.history_index -= 1

        if 0 <= self.history_index < len(self.command_history):
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])

    def history_down(self, event):
        """Navigate down in command history."""
        if not self.command_history or self.history_index == -1:
            return

        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        else:
            self.history_index = -1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.current_command)

    def auto_complete(self, event):
        Auto-complete command."""
        current_text = self.command_entry.get()
        if not current_text:
            return

        # Common commands for auto-completion
        commands = [
            "status", "health", "version", "config", "help", "clear", "history",
            "test-run", "test-endpoint", "test-suite", "test-load", "test-security",
            "plugin-list", "plugin-enable", "plugin-disable", "plugin-install",
            "db-status", "db-migrate", "db-backup",
            "user-list", "user-create", "logs", "metrics"
        ]

        matches = [cmd for cmd in commands if cmd.startswith(current_text)]

        if len(matches) == 1:
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, matches[0])
        elif len(matches) > 1:
            # Show possible completions
            completions = "Possible completions: " + ", ".join(matches) + "\n"
            self.append_output(completions, "info")

    def interrupt_command(self, event):
        """Interrupt current command (Ctrl+C)."""
        if self.is_running_command:
            self.append_output("\n^C Command interrupted\n", "warning")
            self.is_running_command = False
            self.append_output("plexichat> ", "prompt")

    def clear_terminal(self):
        """Clear the terminal output.
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.display_welcome()

    def show_history(self):
        """Show command history in a popup."""
        if not self.command_history:
            tk.messagebox.showinfo("Command History", "No command history available.")
            return

        # Create history window
        history_window = tk.Toplevel(self)
        history_window.title("Command History")
        history_window.geometry("600x400")

        # History listbox
        frame = ttk.Frame(history_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        listbox = tk.Listbox(frame, font=('Consolas', 10))
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)

        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate history
        for cmd in self.command_history:
            listbox.insert(tk.END, cmd)

        # Buttons
        button_frame = ttk.Frame(history_window)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        def use_command():
            selection = listbox.curselection()
            if selection:
                cmd = listbox.get(selection[0])
                self.command_entry.delete(0, tk.END)
                self.command_entry.insert(0, cmd)
                history_window.destroy()

        ttk.Button(button_frame, text="Use Command", command=use_command).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", command=history_window.destroy).pack(side=tk.RIGHT)

    def show_help(self):
        """Show help in a popup.
        help_text = """
PlexiChat CLI Terminal Help
===========================

Keyboard Shortcuts:
- Enter: Execute command
- Up/Down arrows: Navigate command history
- Tab: Auto-complete command
- Ctrl+C: Interrupt current command
- Ctrl+L: Clear terminal

Command Categories:
- System: status, health, version, config
- Testing: test-run, test-endpoint, test-suite
- Plugins: plugin-list, plugin-enable, plugin-disable
- Database: db-status, db-migrate, db-backup
- Admin: user-list, user-create, logs, metrics

Tips:
- Type 'help' for command list
- Use 'cli <command>' to run CLI commands
- Commands support arguments and options
- History is automatically saved
"""

        tk.messagebox.showinfo("CLI Terminal Help", help_text)

    def load_command_history(self):
        """Load command history from file."""
        try:
            history_file = Path.home() / ".plexichat" / "cli_history.txt"
            if history_file.exists():
                with open(history_file, 'r') as f:
                    self.command_history = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to load command history: {e}")

    def save_command_history(self):
        """Save command history to file."""
        try:
            history_dir = Path.home() / ".plexichat"
            history_dir.mkdir(exist_ok=True)

            history_file = history_dir / "cli_history.txt"
            with open(history_file, 'w') as f:
                # Save last 1000 commands
                for cmd in self.command_history[-1000:]:
                    f.write(f"{cmd}\n")
        except Exception as e:
            logger.warning(f"Failed to save command history: {e}")
