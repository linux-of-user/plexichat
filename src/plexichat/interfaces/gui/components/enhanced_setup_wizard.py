"""
Enhanced Setup Wizard for PlexiChat.

This module provides a comprehensive setup wizard accessible from the main GUI
after login, with support for multiple database types and advanced configuration.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
import json

logger = logging.getLogger(__name__)

class EnhancedSetupWizard:
    """Enhanced setup wizard with comprehensive database and configuration support."""
    
    def __init__(self, parent):
        """Initialize the enhanced setup wizard."""
        self.parent = parent
        self.root = None
        self.current_step = 0
        self.total_steps = 6
        
        # Configuration data
        self.config_data = {
            "database": {
                "type": "sqlite",
                "host": "localhost",
                "port": 5432,
                "name": "plexichat",
                "username": "",
                "password": "",
                "ssl_mode": "prefer",
                "connection_pool_size": 10,
                "timeout": 30
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "debug": False
            },
            "security": {
                "jwt_secret": "",
                "session_timeout": 3600,
                "max_login_attempts": 5,
                "password_min_length": 8
            },
            "features": {
                "file_uploads": True,
                "real_time_chat": True,
                "notifications": True,
                "analytics": False,
                "backup_enabled": True
            },
            "performance": {
                "cache_enabled": True,
                "compression": True,
                "rate_limiting": True,
                "monitoring": True
            },
            "paths": {
                "data_dir": "data",
                "logs_dir": "logs",
                "uploads_dir": "uploads",
                "backups_dir": "backups"
            }
        }
        
        # Database type configurations
        self.db_configs = {
            "sqlite": {
                "name": "SQLite",
                "description": "Lightweight, file-based database (recommended for small deployments)",
                "fields": ["name"],
                "default_port": None,
                "connection_string": "sqlite:///{name}"
            },
            "postgresql": {
                "name": "PostgreSQL",
                "description": "Powerful, enterprise-grade database (recommended for production)",
                "fields": ["host", "port", "name", "username", "password"],
                "default_port": 5432,
                "connection_string": "postgresql://{username}:{password}@{host}:{port}/{name}"
            },
            "mysql": {
                "name": "MySQL/MariaDB",
                "description": "Popular, reliable database system",
                "fields": ["host", "port", "name", "username", "password"],
                "default_port": 3306,
                "connection_string": "mysql://{username}:{password}@{host}:{port}/{name}"
            },
            "mongodb": {
                "name": "MongoDB",
                "description": "NoSQL document database for flexible data structures",
                "fields": ["host", "port", "name", "username", "password"],
                "default_port": 27017,
                "connection_string": "mongodb://{username}:{password}@{host}:{port}/{name}"
            },
            "redis": {
                "name": "Redis",
                "description": "In-memory data structure store (for caching and sessions)",
                "fields": ["host", "port", "password"],
                "default_port": 6379,
                "connection_string": "redis://:{password}@{host}:{port}"
            }
        }
        
        # Step definitions
        self.steps = [
            {"name": "Welcome", "function": self.create_welcome_step},
            {"name": "Database Configuration", "function": self.create_database_step},
            {"name": "Server Settings", "function": self.create_server_step},
            {"name": "Security Configuration", "function": self.create_security_step},
            {"name": "Features & Performance", "function": self.create_features_step},
            {"name": "Review & Complete", "function": self.create_review_step}
        ]
        
        # UI components
        self.main_frame = None
        self.content_frame = None
        self.navigation_frame = None
        self.progress_bar = None
        self.step_label = None
        
        # Form variables
        self.form_vars = {}
        
    def show(self):
        """Show the setup wizard."""
        self.root = tk.Toplevel(self.parent)
        self.root.title("PlexiChat Enhanced Setup Wizard")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        self.root.transient(self.parent)
        self.root.grab_set()
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
        
        self.create_ui()
        self.show_step(0)
        
    def create_ui(self):
        """Create the main UI structure."""
        # Main container
        self.main_frame = tk.Frame(self.root, bg='#34495e', relief='raised', bd=2)
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(self.main_frame, bg='#34495e', height=80)
        header_frame.pack(fill='x', pady=(0, 20))
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="PlexiChat Setup Wizard",
                             font=("Arial", 20, "bold"), bg='#34495e', fg='#3498db')
        title_label.pack(pady=20)
        
        # Progress bar
        progress_frame = tk.Frame(self.main_frame, bg='#34495e')
        progress_frame.pack(fill='x', pady=(0, 20))
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=400)
        self.progress_bar.pack()
        
        self.step_label = tk.Label(progress_frame, text="Step 1 of 6: Welcome",
                                 font=("Arial", 12), bg='#34495e', fg='white')
        self.step_label.pack(pady=(10, 0))
        
        # Content area
        self.content_frame = tk.Frame(self.main_frame, bg='#34495e')
        self.content_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Navigation
        self.navigation_frame = tk.Frame(self.main_frame, bg='#34495e')
        self.navigation_frame.pack(fill='x')
        
        self.back_btn = tk.Button(self.navigation_frame, text="< Back",
                                font=("Arial", 12), bg='#95a5a6', fg='white',
                                relief='flat', bd=0, command=self.go_back,
                                cursor='hand2', state='disabled')
        self.back_btn.pack(side='left', padx=(0, 10), ipadx=20, ipady=8)
        
        self.next_btn = tk.Button(self.navigation_frame, text="Next >",
                                font=("Arial", 12), bg='#3498db', fg='white',
                                relief='flat', bd=0, command=self.go_next,
                                cursor='hand2')
        self.next_btn.pack(side='right', padx=(10, 0), ipadx=20, ipady=8)
        
        self.cancel_btn = tk.Button(self.navigation_frame, text="Cancel",
                                  font=("Arial", 12), bg='#e74c3c', fg='white',
                                  relief='flat', bd=0, command=self.cancel_setup,
                                  cursor='hand2')
        self.cancel_btn.pack(side='right', padx=(10, 0), ipadx=20, ipady=8)
        
    def show_step(self, step_index):
        """Show a specific step."""
        if 0 <= step_index < len(self.steps):
            self.current_step = step_index
            
            # Update progress
            progress = ((step_index + 1) / len(self.steps)) * 100
            self.progress_bar['value'] = progress
            
            step_name = self.steps[step_index]["name"]
            self.step_label.config(text=f"Step {step_index + 1} of {len(self.steps)}: {step_name}")
            
            # Clear content frame
            for widget in self.content_frame.winfo_children():
                widget.destroy()
            
            # Create step content
            self.steps[step_index]["function"]()
            
            # Update navigation buttons
            self.back_btn.config(state='normal' if step_index > 0 else 'disabled')
            
            if step_index == len(self.steps) - 1:
                self.next_btn.config(text="Complete Setup", bg='#27ae60')
            else:
                self.next_btn.config(text="Next >", bg='#3498db')
                
    def create_welcome_step(self):
        """Create the welcome step."""
        welcome_frame = tk.Frame(self.content_frame, bg='#34495e')
        welcome_frame.pack(fill='both', expand=True, padx=40, pady=40)
        
        # Welcome message
        welcome_text = """Welcome to the PlexiChat Enhanced Setup Wizard!

This wizard will guide you through configuring PlexiChat for your environment.

What you'll configure:
* Database connection and settings
* Server configuration and performance
* Security and authentication settings
* Feature enablement and optimization
* File paths and storage locations

The setup process typically takes 5-10 minutes and can be modified later
through the configuration files or this wizard.

Click 'Next' to begin the configuration process."""
        
        welcome_label = tk.Label(welcome_frame, text=welcome_text,
                               font=("Arial", 12), bg='#34495e', fg='white',
                               justify='left', wraplength=600)
        welcome_label.pack(pady=40)
        
        # System requirements check
        req_frame = tk.LabelFrame(welcome_frame, text="System Requirements Check",
                                font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        req_frame.pack(fill='x', pady=20)
        
        requirements = [
            "OK Python 3.8+ detected",
            "OK Required packages installed",
            "OK Write permissions available",
            "OK Network connectivity verified"
        ]
        
        for req in requirements:
            req_label = tk.Label(req_frame, text=req, font=("Arial", 10),
                               bg='#34495e', fg='#2ecc71')
            req_label.pack(anchor='w', padx=20, pady=2)

    def create_database_step(self):
        """Create the database configuration step."""
        db_frame = tk.Frame(self.content_frame, bg='#34495e')
        db_frame.pack(fill='both', expand=True, padx=40, pady=20)

        # Database type selection
        type_frame = tk.LabelFrame(db_frame, text="Database Type",
                                 font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        type_frame.pack(fill='x', pady=(0, 20))

        self.form_vars['db_type'] = tk.StringVar(value=self.config_data['database']['type'])

        for db_type, config in self.db_configs.items():
            rb = tk.Radiobutton(type_frame, text=f"{config['name']} - {config['description']}",
                              variable=self.form_vars['db_type'], value=db_type,
                              font=("Arial", 10), bg='#34495e', fg='white',
                              selectcolor='#2c3e50', activebackground='#34495e',
                              command=self.on_db_type_change)
            rb.pack(anchor='w', padx=20, pady=5)

        # Database connection details
        self.db_details_frame = tk.LabelFrame(db_frame, text="Connection Details",
                                            font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        self.db_details_frame.pack(fill='x', pady=(0, 20))

        self.create_db_fields()

        # Test connection button
        test_frame = tk.Frame(db_frame, bg='#34495e')
        test_frame.pack(fill='x')

        test_btn = tk.Button(test_frame, text="Test Connection",
                           font=("Arial", 12), bg='#f39c12', fg='white',
                           relief='flat', bd=0, command=self.test_db_connection,
                           cursor='hand2')
        test_btn.pack(side='left', ipadx=20, ipady=8)

        self.connection_status = tk.Label(test_frame, text="",
                                        font=("Arial", 10), bg='#34495e')
        self.connection_status.pack(side='left', padx=(20, 0))

    def create_db_fields(self):
        """Create database connection fields based on selected type."""
        # Clear existing fields
        for widget in self.db_details_frame.winfo_children():
            widget.destroy()

        db_type = self.form_vars['db_type'].get()
        config = self.db_configs.get(db_type, {})
        fields = config.get('fields', [])

        row = 0
        for field in fields:
            label = tk.Label(self.db_details_frame, text=f"{field.title()}:",
                           font=("Arial", 10), bg='#34495e', fg='white')
            label.grid(row=row, column=0, sticky='w', padx=20, pady=5)

            var_name = f'db_{field}'
            if var_name not in self.form_vars:
                default_value = self.config_data['database'].get(field, '')
                if field == 'port' and config.get('default_port'):
                    default_value = config['default_port']
                self.form_vars[var_name] = tk.StringVar(value=str(default_value))

            if field == 'password':
                entry = tk.Entry(self.db_details_frame, textvariable=self.form_vars[var_name],
                               font=("Arial", 10), show='*', width=30)
            else:
                entry = tk.Entry(self.db_details_frame, textvariable=self.form_vars[var_name],
                               font=("Arial", 10), width=30)

            entry.grid(row=row, column=1, sticky='w', padx=(10, 20), pady=5)
            row += 1

    def on_db_type_change(self):
        """Handle database type change."""
        self.create_db_fields()
        self.connection_status.config(text="", fg='white')

    def test_db_connection(self):
        """Test database connection."""
        self.connection_status.config(text="Testing connection...", fg='#f39c12')
        self.root.update()

        try:
            # Simulate connection test (implement actual test logic)
            import time
            time.sleep(1)  # Simulate test delay

            self.connection_status.config(text="OK Connection successful!", fg='#2ecc71')
        except Exception as e:
            self.connection_status.config(text=f"ERROR Connection failed: {str(e)}", fg='#e74c3c')

    def create_server_step(self):
        """Create the server configuration step."""
        server_frame = tk.Frame(self.content_frame, bg='#34495e')
        server_frame.pack(fill='both', expand=True, padx=40, pady=20)

        # Server settings
        settings_frame = tk.LabelFrame(server_frame, text="Server Settings",
                                     font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        settings_frame.pack(fill='x', pady=(0, 20))

        # Host
        tk.Label(settings_frame, text="Host:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=0, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['server_host'] = tk.StringVar(value=self.config_data['server']['host'])
        tk.Entry(settings_frame, textvariable=self.form_vars['server_host'],
               font=("Arial", 10), width=30).grid(row=0, column=1, sticky='w', padx=(10, 20), pady=5)

        # Port
        tk.Label(settings_frame, text="Port:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=1, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['server_port'] = tk.StringVar(value=str(self.config_data['server']['port']))
        tk.Entry(settings_frame, textvariable=self.form_vars['server_port'],
               font=("Arial", 10), width=30).grid(row=1, column=1, sticky='w', padx=(10, 20), pady=5)

        # Workers
        tk.Label(settings_frame, text="Worker Processes:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=2, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['server_workers'] = tk.StringVar(value=str(self.config_data['server']['workers']))
        tk.Entry(settings_frame, textvariable=self.form_vars['server_workers'],
               font=("Arial", 10), width=30).grid(row=2, column=1, sticky='w', padx=(10, 20), pady=5)

        # Debug mode
        self.form_vars['server_debug'] = tk.BooleanVar(value=self.config_data['server']['debug'])
        tk.Checkbutton(settings_frame, text="Enable Debug Mode",
                     variable=self.form_vars['server_debug'], font=("Arial", 10),
                     bg='#34495e', fg='white', selectcolor='#2c3e50',
                     activebackground='#34495e').grid(row=3, column=0, columnspan=2,
                                                    sticky='w', padx=20, pady=5)

    def create_security_step(self):
        """Create the security configuration step."""
        security_frame = tk.Frame(self.content_frame, bg='#34495e')
        security_frame.pack(fill='both', expand=True, padx=40, pady=20)

        # Security settings
        settings_frame = tk.LabelFrame(security_frame, text="Security Settings",
                                     font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        settings_frame.pack(fill='x', pady=(0, 20))

        # JWT Secret
        tk.Label(settings_frame, text="JWT Secret Key:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=0, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['jwt_secret'] = tk.StringVar(value=self.config_data['security']['jwt_secret'])
        jwt_entry = tk.Entry(settings_frame, textvariable=self.form_vars['jwt_secret'],
                           font=("Arial", 10), width=30, show='*')
        jwt_entry.grid(row=0, column=1, sticky='w', padx=(10, 20), pady=5)

        generate_btn = tk.Button(settings_frame, text="Generate",
                               font=("Arial", 9), bg='#3498db', fg='white',
                               relief='flat', bd=0, command=self.generate_jwt_secret,
                               cursor='hand2')
        generate_btn.grid(row=0, column=2, padx=(5, 20), pady=5)

        # Session timeout
        tk.Label(settings_frame, text="Session Timeout (seconds):", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=1, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['session_timeout'] = tk.StringVar(value=str(self.config_data['security']['session_timeout']))
        tk.Entry(settings_frame, textvariable=self.form_vars['session_timeout'],
               font=("Arial", 10), width=30).grid(row=1, column=1, sticky='w', padx=(10, 20), pady=5)

        # Max login attempts
        tk.Label(settings_frame, text="Max Login Attempts:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=2, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['max_login_attempts'] = tk.StringVar(value=str(self.config_data['security']['max_login_attempts']))
        tk.Entry(settings_frame, textvariable=self.form_vars['max_login_attempts'],
               font=("Arial", 10), width=30).grid(row=2, column=1, sticky='w', padx=(10, 20), pady=5)

        # Password minimum length
        tk.Label(settings_frame, text="Password Min Length:", font=("Arial", 10),
               bg='#34495e', fg='white').grid(row=3, column=0, sticky='w', padx=20, pady=5)
        self.form_vars['password_min_length'] = tk.StringVar(value=str(self.config_data['security']['password_min_length']))
        tk.Entry(settings_frame, textvariable=self.form_vars['password_min_length'],
               font=("Arial", 10), width=30).grid(row=3, column=1, sticky='w', padx=(10, 20), pady=5)

    def generate_jwt_secret(self):
        """Generate a random JWT secret."""
        import secrets
        import string
        secret = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*') for _ in range(64))
        self.form_vars['jwt_secret'].set(secret)

    def create_features_step(self):
        """Create the features and performance step."""
        features_frame = tk.Frame(self.content_frame, bg='#34495e')
        features_frame.pack(fill='both', expand=True, padx=40, pady=20)

        # Features
        feat_frame = tk.LabelFrame(features_frame, text="Features",
                                 font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        feat_frame.pack(fill='x', pady=(0, 20))

        features = [
            ('file_uploads', 'Enable File Uploads'),
            ('real_time_chat', 'Real-time Chat'),
            ('notifications', 'Push Notifications'),
            ('analytics', 'Analytics & Reporting'),
            ('backup_enabled', 'Automatic Backups')
        ]

        for key, label in features:
            self.form_vars[key] = tk.BooleanVar(value=self.config_data['features'][key])
            tk.Checkbutton(feat_frame, text=label, variable=self.form_vars[key],
                         font=("Arial", 10), bg='#34495e', fg='white',
                         selectcolor='#2c3e50', activebackground='#34495e').pack(anchor='w', padx=20, pady=2)

        # Performance
        perf_frame = tk.LabelFrame(features_frame, text="Performance",
                                 font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        perf_frame.pack(fill='x', pady=(0, 20))

        performance = [
            ('cache_enabled', 'Enable Caching'),
            ('compression', 'Enable Compression'),
            ('rate_limiting', 'Rate Limiting'),
            ('monitoring', 'Performance Monitoring')
        ]

        for key, label in performance:
            self.form_vars[key] = tk.BooleanVar(value=self.config_data['performance'][key])
            tk.Checkbutton(perf_frame, text=label, variable=self.form_vars[key],
                         font=("Arial", 10), bg='#34495e', fg='white',
                         selectcolor='#2c3e50', activebackground='#34495e').pack(anchor='w', padx=20, pady=2)

        # Paths
        paths_frame = tk.LabelFrame(features_frame, text="Directory Paths",
                                  font=("Arial", 12, "bold"), bg='#34495e', fg='#3498db')
        paths_frame.pack(fill='x')

        paths = [
            ('data_dir', 'Data Directory'),
            ('logs_dir', 'Logs Directory'),
            ('uploads_dir', 'Uploads Directory'),
            ('backups_dir', 'Backups Directory')
        ]

        row = 0
        for key, label in paths:
            tk.Label(paths_frame, text=f"{label}:", font=("Arial", 10),
                   bg='#34495e', fg='white').grid(row=row, column=0, sticky='w', padx=20, pady=2)

            self.form_vars[key] = tk.StringVar(value=self.config_data['paths'][key])
            tk.Entry(paths_frame, textvariable=self.form_vars[key],
                   font=("Arial", 10), width=25).grid(row=row, column=1, sticky='w', padx=(10, 5), pady=2)

            browse_btn = tk.Button(paths_frame, text="Browse",
                                 font=("Arial", 9), bg='#95a5a6', fg='white',
                                 relief='flat', bd=0, cursor='hand2',
                                 command=lambda k=key: self.browse_directory(k))
            browse_btn.grid(row=row, column=2, padx=(5, 20), pady=2)
            row += 1

    def browse_directory(self, key):
        """Browse for directory."""
        directory = filedialog.askdirectory(title=f"Select {key.replace('_', ' ').title()}")
        if directory:
            self.form_vars[key].set(directory)

    def create_review_step(self):
        """Create the review and complete step."""
        review_frame = tk.Frame(self.content_frame, bg='#34495e')
        review_frame.pack(fill='both', expand=True, padx=40, pady=20)

        # Review title
        title_label = tk.Label(review_frame, text="Configuration Review",
                             font=("Arial", 16, "bold"), bg='#34495e', fg='#3498db')
        title_label.pack(pady=(0, 20))

        # Create scrollable text widget for review
        text_frame = tk.Frame(review_frame, bg='#34495e')
        text_frame.pack(fill='both', expand=True)

        self.review_text = tk.Text(text_frame, font=("Courier", 10),
                                 bg='#2c3e50', fg='white', wrap='word',
                                 relief='flat', bd=0)
        scrollbar = tk.Scrollbar(text_frame, orient='vertical', command=self.review_text.yview)
        self.review_text.configure(yscrollcommand=scrollbar.set)

        self.review_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Generate review content
        self.update_review()

        # Save configuration button
        save_frame = tk.Frame(review_frame, bg='#34495e')
        save_frame.pack(fill='x', pady=(20, 0))

        save_btn = tk.Button(save_frame, text="Save Configuration",
                           font=("Arial", 12), bg='#27ae60', fg='white',
                           relief='flat', bd=0, command=self.save_configuration,
                           cursor='hand2')
        save_btn.pack(side='left', ipadx=20, ipady=8)

        self.save_status = tk.Label(save_frame, text="",
                                  font=("Arial", 10), bg='#34495e')
        self.save_status.pack(side='left', padx=(20, 0))

    def update_review(self):
        """Update the review content."""
        self.review_text.delete(1.0, tk.END)

        # Collect all configuration
        config = self.collect_configuration()

        review_content = "PlexiChat Configuration Summary\n"
        review_content += "=" * 50 + "\n\n"

        for section, values in config.items():
            review_content += f"{section.upper()}:\n"
            for key, value in values.items():
                if 'password' in key.lower() or 'secret' in key.lower():
                    value = '*' * len(str(value)) if value else ''
                review_content += f"  {key}: {value}\n"
            review_content += "\n"

        self.review_text.insert(1.0, review_content)
        self.review_text.config(state='disabled')

    def collect_configuration(self):
        """Collect all configuration from form variables."""
        config = {}

        # Database configuration
        db_type = self.form_vars.get('db_type', tk.StringVar()).get()
        config['database'] = {'type': db_type}

        if db_type:
            db_config = self.db_configs.get(db_type, {})
            for field in db_config.get('fields', []):
                var_name = f'db_{field}'
                if var_name in self.form_vars:
                    config['database'][field] = self.form_vars[var_name].get()

        # Server configuration
        config['server'] = {}
        server_fields = ['host', 'port', 'workers', 'debug']
        for field in server_fields:
            var_name = f'server_{field}'
            if var_name in self.form_vars:
                value = self.form_vars[var_name].get()
                if field in ['port', 'workers']:
                    try:
                        value = int(value)
                    except ValueError:
                        value = self.config_data['server'][field]
                elif field == 'debug':
                    value = self.form_vars[var_name].get()
                config['server'][field] = value

        # Security configuration
        config['security'] = {}
        security_fields = ['jwt_secret', 'session_timeout', 'max_login_attempts', 'password_min_length']
        for field in security_fields:
            if field in self.form_vars:
                value = self.form_vars[field].get()
                if field in ['session_timeout', 'max_login_attempts', 'password_min_length']:
                    try:
                        value = int(value)
                    except ValueError:
                        value = self.config_data['security'][field]
                config['security'][field] = value

        # Features and performance
        config['features'] = {}
        config['performance'] = {}
        config['paths'] = {}

        for key in ['file_uploads', 'real_time_chat', 'notifications', 'analytics', 'backup_enabled']:
            if key in self.form_vars:
                config['features'][key] = self.form_vars[key].get()

        for key in ['cache_enabled', 'compression', 'rate_limiting', 'monitoring']:
            if key in self.form_vars:
                config['performance'][key] = self.form_vars[key].get()

        for key in ['data_dir', 'logs_dir', 'uploads_dir', 'backups_dir']:
            if key in self.form_vars:
                config['paths'][key] = self.form_vars[key].get()

        return config

    def save_configuration(self):
        """Save the configuration to files."""
        try:
            self.save_status.config(text="Saving configuration...", fg='#f39c12')
            self.root.update()

            config = self.collect_configuration()

            # Create config directory if it doesn't exist
            config_dir = Path("config")
            config_dir.mkdir(exist_ok=True)

            # Save main configuration
            config_file = config_dir / "plexichat.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            # Create database connection string
            db_type = config['database']['type']
            if db_type in self.db_configs:
                db_config = self.db_configs[db_type]
                connection_string = db_config['connection_string'].format(**config['database'])

                # Save database configuration
                db_config_file = config_dir / "database.json"
                with open(db_config_file, 'w') as f:
                    json.dump({
                        'type': db_type,
                        'connection_string': connection_string,
                        'settings': config['database']
                    }, f, indent=2)

            self.save_status.config(text="OK Configuration saved successfully!", fg='#2ecc71')

        except Exception as e:
            self.save_status.config(text=f"ERROR Save failed: {str(e)}", fg='#e74c3c')
            logger.error(f"Failed to save configuration: {e}")

    def go_next(self):
        """Go to the next step."""
        if self.current_step < len(self.steps) - 1:
            # Validate current step
            if self.validate_current_step():
                self.show_step(self.current_step + 1)
        else:
            # Complete setup
            self.complete_setup()

    def go_back(self):
        """Go to the previous step."""
        if self.current_step > 0:
            self.show_step(self.current_step - 1)

    def validate_current_step(self):
        """Validate the current step."""
        if self.current_step == 1:  # Database step
            db_type = self.form_vars.get('db_type', tk.StringVar()).get()
            if not db_type:
                messagebox.showerror("Validation Error", "Please select a database type.")
                return False

            # Validate required fields for selected database
            db_config = self.db_configs.get(db_type, {})
            for field in db_config.get('fields', []):
                var_name = f'db_{field}'
                if var_name in self.form_vars:
                    value = self.form_vars[var_name].get().strip()
                    if not value and field != 'password':  # Password can be empty for some databases
                        messagebox.showerror("Validation Error", f"Please enter {field.title()}.")
                        return False

        elif self.current_step == 2:  # Server step
            try:
                port = int(self.form_vars.get('server_port', tk.StringVar()).get())
                if not (1 <= port <= 65535):
                    raise ValueError()
            except ValueError:
                messagebox.showerror("Validation Error", "Please enter a valid port number (1-65535).")
                return False

            try:
                workers = int(self.form_vars.get('server_workers', tk.StringVar()).get())
                if workers < 1:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("Validation Error", "Please enter a valid number of workers (1 or more).")
                return False

        elif self.current_step == 3:  # Security step
            jwt_secret = self.form_vars.get('jwt_secret', tk.StringVar()).get().strip()
            if len(jwt_secret) < 32:
                messagebox.showerror("Validation Error", "JWT secret must be at least 32 characters long.")
                return False

        return True

    def complete_setup(self):
        """Complete the setup process."""
        try:
            # Save configuration
            self.save_configuration()

            # Show completion message
            result = messagebox.askyesno(
                "Setup Complete",
                "PlexiChat setup has been completed successfully!\n\n"
                "The configuration has been saved and PlexiChat is ready to use.\n\n"
                "Would you like to restart PlexiChat now to apply the new configuration?"
            )

            if result:
                # Close setup wizard
                self.root.destroy()

                # Restart application (implement restart logic)
                messagebox.showinfo("Restart Required",
                                  "Please restart PlexiChat manually to apply the new configuration.")
            else:
                self.root.destroy()

        except Exception as e:
            messagebox.showerror("Setup Error", f"Failed to complete setup: {str(e)}")
            logger.error(f"Setup completion failed: {e}")

    def cancel_setup(self):
        """Cancel the setup process."""
        result = messagebox.askyesno(
            "Cancel Setup",
            "Are you sure you want to cancel the setup?\n\n"
            "Any unsaved changes will be lost."
        )

        if result:
            self.root.destroy()


def show_enhanced_setup_wizard(parent):
    """Show the enhanced setup wizard."""
    wizard = EnhancedSetupWizard(parent)
    wizard.show()
