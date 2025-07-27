# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
GUI Database Setup Wizard

Desktop GUI version of the database setup wizard using tkinter with:
- Modern interface design
- Step-by-step navigation
- Real-time validation
- Connection testing
- Progress tracking
- Help and documentation
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import asyncio
import threading
from typing import Any, Dict, List, Optional
import json

from plexichat.interfaces.web.components.enhanced_database_wizard import (
    EnhancedDatabaseWizard, DatabaseType, WizardStep
)


class DatabaseSetupGUI:
    """GUI Database Setup Wizard."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.wizard = EnhancedDatabaseWizard()
        self.current_step_frame = None

        self.setup_main_window()
        self.create_widgets()
        self.start_wizard()

    def setup_main_window(self):
        """Setup main window properties."""
        self.root.title("PlexiChat Database Setup Wizard")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Configure style
        style = ttk.Style()
        style.theme_use('clam')

        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 12))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Warning.TLabel', foreground='orange')

    def create_widgets(self):
        """Create main GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))

        self.title_label = ttk.Label(
            header_frame,
            text="Database Setup Wizard",
            style='Title.TLabel'
        )
        self.title_label.grid(row=0, column=0, sticky=tk.W)

        self.progress_label = ttk.Label(
            header_frame,
            text="Step 1 of 16",
            style='Subtitle.TLabel'
        )
        self.progress_label.grid(row=0, column=1, sticky=tk.E)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            header_frame,
            length=400,
            mode='determinate'
        )
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        # Sidebar for navigation
        sidebar_frame = ttk.LabelFrame(main_frame, text="Steps", padding="10")
        sidebar_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 20))

        self.steps_listbox = tk.Listbox(sidebar_frame, height=15, width=25)
        self.steps_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Populate steps
        steps = [
            "Welcome",
            "Database Selection",
            "Connection Config",
            "Authentication",
            "Performance Tuning",
            "Security Config",
            "Advanced Features",
            "Connection Test",
            "Schema Setup",
            "Data Migration",
            "Optimization",
            "Backup Config",
            "Monitoring Setup",
            "Review Summary",
            "Deployment",
            "Complete"
        ]

        for i, step in enumerate(steps):
            self.steps_listbox.insert(tk.END, f"{i+1}. {step}")

        # Main content area
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.rowconfigure(0, weight=1)

        # Navigation buttons
        nav_frame = ttk.Frame(main_frame)
        nav_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(20, 0))

        self.back_button = ttk.Button(
            nav_frame,
            text="<- Back",
            command=self.go_back,
            state='disabled'
        )
        self.back_button.grid(row=0, column=0, sticky=tk.W)

        self.next_button = ttk.Button(
            nav_frame,
            text="Next ->",
            command=self.go_next
        )
        self.next_button.grid(row=0, column=2, sticky=tk.E)

        self.cancel_button = ttk.Button(
            nav_frame,
            text="Cancel",
            command=self.cancel_wizard
        )
        self.cancel_button.grid(row=0, column=1, padx=20)

        nav_frame.columnconfigure(1, weight=1)

    def start_wizard(self):
        """Start the wizard and show welcome step."""
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.wizard.start_wizard())
            self.root.after(0, lambda: self.show_welcome_step(result))

        thread = threading.Thread(target=run_async)
        thread.daemon = True
        if thread and hasattr(thread, "start"): thread.start()

    def show_welcome_step(self, wizard_result: Dict[str, Any]):
        """Show welcome step."""
        self.clear_content()
        self.update_progress(1, 16)
        self.steps_listbox.selection_set(0)

        # Welcome content
        welcome_frame = ttk.Frame(self.content_frame)
        welcome_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=20, pady=20)
        welcome_frame.columnconfigure(0, weight=1)

        # Title
        title = ttk.Label(
            welcome_frame,
            text="Welcome to PlexiChat Database Setup",
            style='Title.TLabel'
        )
        title.grid(row=0, column=0, pady=(0, 20))

        # Description
        desc_text = """This wizard will guide you through setting up your database for PlexiChat.

Features:
* Support for 20+ database types
* Guided configuration with best practices
* Connection testing and validation
* Performance optimization recommendations
* Security configuration assistance
* Migration and backup setup

Estimated time: 10-30 minutes depending on complexity."""

        desc_label = ttk.Label(welcome_frame, text=desc_text, justify=tk.LEFT)
        desc_label.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        # Available databases
        db_frame = ttk.LabelFrame(welcome_frame, text="Supported Databases", padding="10")
        db_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        db_text = "PostgreSQL, MySQL, SQLite, MongoDB, Redis, Cassandra, Elasticsearch, InfluxDB, MariaDB, Oracle, SQL Server, CockroachDB, TimescaleDB, DynamoDB, Firestore, CouchDB, Neo4j, ArangoDB, ClickHouse, Snowflake"

        db_label = ttk.Label(db_frame, text=db_text, wraplength=600, justify=tk.LEFT)
        db_label.grid(row=0, column=0, sticky=(tk.W, tk.E))

        self.current_step_frame = welcome_frame

    def show_database_selection_step(self):
        """Show database selection step."""
        self.clear_content()
        self.update_progress(2, 16)
        self.steps_listbox.selection_set(1)

        # Database selection content
        selection_frame = ttk.Frame(self.content_frame)
        selection_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=20, pady=20)
        selection_frame.columnconfigure(0, weight=1)

        # Title
        title = ttk.Label(
            selection_frame,
            text="Select Database Type",
            style='Title.TLabel'
        )
        title.grid(row=0, column=0, pady=(0, 20))

        # Database categories
        categories = {
            "Relational Databases": [
                ("PostgreSQL", "Advanced open-source relational database"),
                ("MySQL", "Popular open-source relational database"),
                ("SQLite", "Lightweight embedded database"),
                ("MariaDB", "MySQL-compatible database"),
                ("Oracle", "Enterprise relational database"),
                ("SQL Server", "Microsoft enterprise database"),
                ("CockroachDB", "Distributed SQL database"),
            ],
            "Document Databases": [
                ("MongoDB", "Flexible document database"),
                ("CouchDB", "Apache CouchDB document database"),
                ("Firestore", "Google Cloud Firestore"),
            ],
            "Key-Value Stores": [
                ("Redis", "In-memory data structure store"),
            ],
            "Search Engines": [
                ("Elasticsearch", "Distributed search and analytics"),
            ],
            "Time Series": [
                ("InfluxDB", "Time series database"),
                ("TimescaleDB", "PostgreSQL-based time series"),
            ],
            "Wide Column": [
                ("Cassandra", "Distributed wide-column store"),
            ],
            "Graph Databases": [
                ("Neo4j", "Graph database platform"),
                ("ArangoDB", "Multi-model database"),
            ],
            "Analytics": [
                ("ClickHouse", "Columnar database"),
                ("Snowflake", "Cloud data warehouse"),
            ],
            "Cloud Databases": [
                ("DynamoDB", "Amazon DynamoDB"),
            ]
        }

        # Create notebook for categories
        notebook = ttk.Notebook(selection_frame)
        notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))

        self.selected_database = tk.StringVar()

        for category, databases in categories.items():
            tab_frame = ttk.Frame(notebook)
            notebook.add(tab_frame, text=category)

            for i, (db_name, description) in enumerate(databases):
                radio = ttk.Radiobutton(
                    tab_frame,
                    text=f"{db_name} - {description}",
                    variable=self.selected_database,
                    value=db_name.lower().replace(" ", "_")
                )
                radio.grid(row=i, column=0, sticky=tk.W, pady=5, padx=10)

        # Info panel
        info_frame = ttk.LabelFrame(selection_frame, text="Database Information", padding="10")
        info_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))

        self.db_info_text = scrolledtext.ScrolledText(
            info_frame,
            height=6,
            width=70,
            state='disabled'
        )
        self.db_info_text.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Bind selection change
        self.selected_database.trace('w', self.on_database_selection_change)

        self.current_step_frame = selection_frame

    def on_database_selection_change(self, *args):
        """Handle database selection change."""
        selected = self.selected_database.get()
        if not selected:
            return

        # Update info panel with database information
        info_text = f"Selected: {selected.replace('_', ' ').title()}\n\n"

        # Add database-specific information
        db_info = {
            "postgresql": "Advanced features, ACID compliance, excellent for complex queries",
            "mysql": "Fast, reliable, great for web applications",
            "sqlite": "Zero-configuration, perfect for development and small applications",
            "mongodb": "Flexible schema, great for rapid development",
            "redis": "Ultra-fast, perfect for caching and real-time applications",
            # Add more database info...
        }

        info_text += db_info.get(selected, "Enterprise-grade database solution")

        self.db_info_text.config(state='normal')
        self.db_info_text.delete(1.0, tk.END)
        self.db_info_text.insert(1.0, info_text)
        self.db_info_text.config(state='disabled')

    def clear_content(self):
        """Clear current content frame."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def update_progress(self, current: int, total: int):
        """Update progress bar and label."""
        progress = (current / total) * 100
        self.progress_bar['value'] = progress
        self.progress_label.config(text=f"Step {current} of {total}")

    def go_next(self):
        """Go to next step."""
        current_step = self.wizard.progress.current_step

        if current_step == WizardStep.WELCOME:
            self.show_database_selection_step()
        elif current_step == WizardStep.DATABASE_SELECTION:
            self.process_database_selection()
        # Add more step transitions...

        self.back_button.config(state='normal')

    def go_back(self):
        """Go to previous step."""
        # Implement back navigation
        pass

    def cancel_wizard(self):
        """Cancel the wizard."""
        if messagebox.askyesno("Cancel Setup", "Are you sure you want to cancel the database setup?"):
            self.root.quit()

    def process_database_selection(self):
        """Process database selection and move to next step."""
        selected = self.selected_database.get()
        if not selected:
            messagebox.showerror("Error", "Please select a database type")
            return

        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.wizard.select_database(selected))
            self.root.after(0, lambda: self.handle_database_selection_result(result))

        thread = threading.Thread(target=run_async)
        thread.daemon = True
        if thread and hasattr(thread, "start"): thread.start()

    def handle_database_selection_result(self, result: Dict[str, Any]):
        """Handle database selection result."""
        if result.get("success"):
            self.show_connection_config_step(result)
        else:
            messagebox.showerror("Error", result.get("error", "Unknown error"))

    def show_connection_config_step(self, wizard_result: Dict[str, Any]):
        """Show connection configuration step."""
        self.clear_content()
        self.update_progress(3, 16)
        self.steps_listbox.selection_set(2)

        # Connection config content
        config_frame = ttk.Frame(self.content_frame)
        config_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=20, pady=20)
        config_frame.columnconfigure(1, weight=1)

        # Title
        title = ttk.Label(
            config_frame,
            text="Database Connection Configuration",
            style='Title.TLabel'
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Configuration fields
        db_info = wizard_result.get("database_info", {})
        config_template = wizard_result.get("configuration_template", {})
        required_fields = config_template.get("required_fields", [])
        default_config = config_template.get("default_config", {})

        self.config_vars = {}
        row = 1

        for field in required_fields:
            label = ttk.Label(config_frame, text=f"{field.replace('_', ' ').title()}:")
            label.grid(row=row, column=0, sticky=tk.W, pady=5, padx=(0, 10))

            if field == "password":
                entry = ttk.Entry(config_frame, show="*", width=40)
            else:
                entry = ttk.Entry(config_frame, width=40)

            # Set default value if available
            if field in default_config:
                entry.insert(0, str(default_config[field]))

            entry.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
            self.config_vars[field] = entry
            row += 1

        # Test connection button
        test_button = ttk.Button(
            config_frame,
            text="Test Connection",
            command=self.test_connection
        )
        test_button.grid(row=row, column=0, columnspan=2, pady=20)

        self.current_step_frame = config_frame

    def test_connection(self):
        """Test database connection."""
        # Collect configuration values
        config = {}
        for field, entry in self.config_vars.items():
            config[field] = entry.get()

        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # First configure connection
            config_result = loop.run_until_complete(self.wizard.configure_connection(config))
            if config_result.get("success"):
                # Then test connection
                test_result = loop.run_until_complete(self.wizard.test_connection())
                self.root.after(0, lambda: self.handle_connection_test_result(test_result))
            else:
                self.root.after(0, lambda: self.handle_connection_test_result(config_result))

        thread = threading.Thread(target=run_async)
        thread.daemon = True
        if thread and hasattr(thread, "start"): thread.start()

    def handle_connection_test_result(self, result: Dict[str, Any]):
        """Handle connection test result."""
        if result.get("success"):
            messagebox.showinfo("Success", "Database connection successful!")
        else:
            error_msg = result.get("error", "Connection failed")
            troubleshooting = result.get("troubleshooting", [])

            full_msg = f"Connection failed: {error_msg}\n\nTroubleshooting tips:\n"
            full_msg += "\n".join(f"* {tip}" for tip in troubleshooting)

            messagebox.showerror("Connection Failed", full_msg)


def main():
    """Run the GUI database setup wizard."""
    root = tk.Tk()
    app = DatabaseSetupGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
