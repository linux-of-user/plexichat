import argparse
import asyncio
import sys
from pathlib import Path

from src.plexichat.core.database_setup_wizard import database_wizard

#!/usr/bin/env python3
"""
PlexiChat Database Setup CLI Tool
Command-line interface for database configuration and setup.
"""

# Add the project root to the Python path
project_root = from pathlib import Path
Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
except ImportError as e:
    print(f" Failed to import PlexiChat modules: {e}")
    print("Make sure you're running this from the PlexiChat project directory")
    sys.exit(1)

def print_banner():
    """Print the PlexiChat database setup banner."""
    print("=" * 60)
    print("  PlexiChat Database Setup Tool")
    print("=" * 60)
    print()

def print_status(message: str, status: str = "info"):
    """Print a status message with appropriate formatting."""
    icons = {
        "info": "",
        "success": "",
        "warning": "",
        "error": "",
        "question": ""
    }
    print(f"{icons.get(status, '')} {message}")

async def interactive_setup():
    """Run interactive database setup."""
    print_banner()
    print("Welcome to the PlexiChat Database Setup Wizard!")
    print("This tool will help you configure your database connection.")
    print()
    
    # Step 1: Choose database type
    print("Step 1: Choose Database Type")
    print("-" * 30)
    
    db_types = database_wizard.get_database_types()
    for i, db_info in enumerate(db_types["database_types"], 1):
        db_info["type"]
        config = db_info["config"]
        recommended = " (Recommended)" if db_info.get("recommended") else ""
        print(f"{i}. {config['name']}{recommended}")
        print(f"   {config['description']}")
        print()
    
    while True:
        try:
            choice = input("Select database type (1-4): ").strip()
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(db_types["database_types"]):
                selected_type = db_types["database_types"][choice_idx]["type"]
                break
            else:
                print_status("Invalid choice. Please select 1-4.", "error")
        except ValueError:
            print_status("Please enter a number.", "error")
    
    # Set database type
    result = database_wizard.set_database_type(selected_type)
    if not result["success"]:
        print_status(f"Failed to set database type: {result['error']}", "error")
        return False
    
    print_status(f"Database type set to {selected_type}", "success")
    print()
    
    # Step 2: Connection details
    print("Step 2: Connection Details")
    print("-" * 30)
    
    if selected_type == "sqlite":
        file_path = input("Database file path (default: data/plexichat.db): ").strip()
        if not file_path:
            file_path = "data/plexichat.db"
        
        details = {"file_path": file_path}
    else:
        host = input("Database host (default: localhost): ").strip() or "localhost"
        
        if selected_type == "postgresql":
            default_port = 5432
        else:  # mysql/mariadb
            default_port = 3306
        
        port_input = input(f"Database port (default: {default_port}): ").strip()
        port = int(port_input) if port_input else default_port
        
        database = input("Database name (default: plexichat): ").strip() or "plexichat"
        
        details = {
            "host": host,
            "port": port,
            "database": database
        }
    
    result = database_wizard.set_connection_details(details)
    if not result["success"]:
        print_status(f"Failed to set connection details: {result['error']}", "error")
        return False
    
    print_status("Connection details configured", "success")
    print()
    
    # Step 3: Authentication (if needed)
    if selected_type != "sqlite":
        print("Step 3: Authentication")
        print("-" * 30)
        
        username = input("Database username: ").strip()
        password = input("Database password: ").strip()
        
        if not username or not password:
            print_status("Username and password are required", "error")
            return False
        
        auth_details = {
            "username": username,
            "password": password
        }
        
        result = database_wizard.set_authentication(auth_details)
        if not result["success"]:
            print_status(f"Failed to set authentication: {result['error']}", "error")
            return False
        
        print_status("Authentication configured", "success")
        print()
    
    # Step 4: Advanced settings (optional)
    print("Step 4: Advanced Settings (Optional)")
    print("-" * 30)
    
    use_defaults = input("Use default advanced settings? (Y/n): ").strip().lower()
    if use_defaults != 'n':
        result = database_wizard.set_advanced_settings({})
    else:
        pool_size = input("Connection pool size (default: 10): ").strip()
        pool_size = int(pool_size) if pool_size else 10
        
        ssl_mode = None
        if selected_type != "sqlite":
            ssl_input = input("Enable SSL? (Y/n): ").strip().lower()
            if ssl_input != 'n':
                ssl_mode = "require"
        
        advanced_settings = {
            "pool_size": pool_size,
            "ssl_mode": ssl_mode
        }
        
        result = database_wizard.set_advanced_settings(advanced_settings)
    
    if not result["success"]:
        print_status(f"Failed to set advanced settings: {result['error']}", "error")
        return False
    
    print_status("Advanced settings configured", "success")
    print()
    
    # Step 5: Test connection
    print("Step 5: Testing Connection")
    print("-" * 30)
    
    print_status("Testing database connection...", "info")
    result = await database_wizard.test_connection()
    
    if result["success"]:
        print_status("Database connection successful!", "success")
        test_results = result["test_results"]
        print(f"   Database version: {test_results.get('version_info', 'Unknown')}")
        print(f"   Response time: {test_results.get('response_time_ms', 0):.2f}ms")
        print()
    else:
        print_status("Database connection failed!", "error")
        print(f"   Error: {result['error']}")
        
        if "troubleshooting" in result:
            print("\nTroubleshooting tips:")
            for tip in result["troubleshooting"]:
                print(f"    {tip}")
        
        retry = input("\nWould you like to retry with different settings? (y/N): ").strip().lower()
        if retry == 'y':
            return await interactive_setup()
        else:
            return False
    
    # Step 6: Initialize schema
    print("Step 6: Initialize Database Schema")
    print("-" * 30)
    
    create_sample = input("Create sample data for testing? (y/N): ").strip().lower() == 'y'
    
    print_status("Initializing database schema...", "info")
    result = await database_wizard.initialize_schema({
        "create_sample_data": create_sample
    })
    
    if result["success"]:
        print_status("Database schema initialized successfully!", "success")
        schema_results = result["schema_results"]
        print(f"   Tables created: {schema_results.get('tables_created', 0)}")
        if create_sample:
            print(f"   Sample data: {'Created' if schema_results.get('sample_data_created') else 'Failed'}")
        print()
    else:
        print_status(f"Schema initialization failed: {result['error']}", "error")
        return False
    
    # Step 7: Save configuration
    print("Step 7: Save Configuration")
    print("-" * 30)
    
    result = database_wizard.save_configuration()
    if result["success"]:
        print_status("Configuration saved successfully!", "success")
        print("Files created:")
        for file_path in result["files_created"]:
            print(f"    {file_path}")
        print()
    else:
        print_status(f"Failed to save configuration: {result['error']}", "error")
        return False
    
    # Setup complete
    print(" Database Setup Complete!")
    print("-" * 30)
    print("Your PlexiChat database is now configured and ready to use.")
    print("You can start the PlexiChat server with: python -m src.plexichat.app.main")
    print()
    
    return True

async def quick_setup(db_type: str, **kwargs):
    """Quick setup with minimal prompts."""
    print_banner()
    print(f"Quick setup for {db_type} database...")
    print()
    
    # Set database type
    result = database_wizard.set_database_type(db_type)
    if not result["success"]:
        print_status(f"Failed to set database type: {result['error']}", "error")
        return False
    
    # Set connection details
    if db_type == "sqlite":
        details = {"file_path": kwargs.get("file_path", "data/plexichat.db")}
    else:
        details = {
            "host": kwargs.get("host", "localhost"),
            "port": kwargs.get("port", 5432 if db_type == "postgresql" else 3306),
            "database": kwargs.get("database", "plexichat")
        }
    
    result = database_wizard.set_connection_details(details)
    if not result["success"]:
        print_status(f"Failed to set connection details: {result['error']}", "error")
        return False
    
    # Set authentication if needed
    if db_type != "sqlite":
        if not kwargs.get("username") or not kwargs.get("password"):
            print_status("Username and password required for non-SQLite databases", "error")
            return False
        
        auth_details = {
            "username": kwargs["username"],
            "password": kwargs["password"]
        }
        
        result = database_wizard.set_authentication(auth_details)
        if not result["success"]:
            print_status(f"Failed to set authentication: {result['error']}", "error")
            return False
    
    # Use default advanced settings
    result = database_wizard.set_advanced_settings({})
    if not result["success"]:
        print_status(f"Failed to set advanced settings: {result['error']}", "error")
        return False
    
    # Test connection
    print_status("Testing connection...", "info")
    result = await database_wizard.test_connection()
    if not result["success"]:
        print_status(f"Connection test failed: {result['error']}", "error")
        return False
    
    # Initialize schema
    print_status("Initializing schema...", "info")
    result = await database_wizard.initialize_schema({
        "create_sample_data": kwargs.get("sample_data", False)
    })
    if not result["success"]:
        print_status(f"Schema initialization failed: {result['error']}", "error")
        return False
    
    # Save configuration
    result = database_wizard.save_configuration()
    if not result["success"]:
        print_status(f"Failed to save configuration: {result['error']}", "error")
        return False
    
    print_status("Database setup completed successfully!", "success")
    return True

def show_status():
    """Show current database setup status."""
    print_banner()
    
    status = database_wizard.get_wizard_status()
    
    print("Database Setup Status")
    print("-" * 30)
    print(f"Current step: {status['current_step']}")
    print(f"Progress: {status['progress_percentage']:.1f}%")
    print(f"Completed steps: {len(status['completed_steps'])}/{status['total_steps']}")
    
    if status['has_errors']:
        print_status("Setup has errors", "error")
    elif status['connection_configured']:
        print_status("Database configured", "success")
    else:
        print_status("Database not configured", "warning")
    
    print()

async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="PlexiChat Database Setup Tool")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run interactive setup")
    parser.add_argument("--quick", "-q", help="Quick setup with database type (sqlite, postgresql, mysql)")
    parser.add_argument("--status", "-s", action="store_true", help="Show setup status")
    parser.add_argument("--reset", "-r", action="store_true", help="Reset setup wizard")
    
    # Quick setup options
    parser.add_argument("--host", help="Database host")
    parser.add_argument("--port", type=int, help="Database port")
    parser.add_argument("--database", help="Database name")
    parser.add_argument("--username", help="Database username")
    parser.add_argument("--password", help="Database password")
    parser.add_argument("--file-path", help="SQLite database file path")
    parser.add_argument("--sample-data", action="store_true", help="Create sample data")
    
    args = parser.parse_args()
    
    if args.reset:
        database_wizard.reset_wizard()
        print_status("Setup wizard reset", "success")
        return
    
    if args.status:
        show_status()
        return
    
    if args.interactive:
        success = await interactive_setup()
        sys.exit(0 if success else 1)
    
    if args.quick:
        kwargs = {
            "host": args.host,
            "port": args.port,
            "database": args.database,
            "username": args.username,
            "password": args.password,
            "file_path": args.file_path,
            "sample_data": args.sample_data
        }
        # Remove None values
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        
        success = await quick_setup(args.quick, **kwargs)
        sys.exit(0 if success else 1)
    
    # Default: show help
    parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
