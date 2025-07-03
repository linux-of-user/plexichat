"""
NetLink CLI Admin User Management
Secure command-line tools for managing admin users.
"""

import os
import sys
import json
import hashlib
import secrets
import getpass
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import bcrypt

class AdminUserManager:
    """Secure admin user management from command line."""
    
    def __init__(self):
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        self.admin_file = self.config_dir / "admin_users.json"
        self.audit_file = self.config_dir / "admin_audit.log"
        self.load_admin_users()
    
    def load_admin_users(self):
        """Load admin users from secure storage."""
        try:
            if self.admin_file.exists():
                with open(self.admin_file, 'r', encoding='utf-8') as f:
                    self.admin_users = json.load(f)
            else:
                self.admin_users = {}
                self.save_admin_users()
        except Exception as e:
            print(f"Error loading admin users: {e}")
            self.admin_users = {}
    
    def save_admin_users(self):
        """Save admin users to secure storage."""
        try:
            # Set restrictive permissions
            with open(self.admin_file, 'w', encoding='utf-8') as f:
                json.dump(self.admin_users, f, indent=2)
            
            # Set file permissions (read/write for owner only)
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.admin_file, 0o600)
                
        except Exception as e:
            print(f"Error saving admin users: {e}")
    
    def log_audit(self, action: str, username: str, details: str = ""):
        """Log admin actions for audit trail."""
        try:
            timestamp = datetime.now().isoformat()
            audit_entry = f"{timestamp} | {action} | {username} | {details}\n"
            
            with open(self.audit_file, 'a', encoding='utf-8') as f:
                f.write(audit_entry)
                
        except Exception as e:
            print(f"Error logging audit: {e}")
    
    def hash_password(self, password: str) -> str:
        """Securely hash password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password."""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def create_admin_user(self, username: str, password: str = None, role: str = "admin", 
                         email: str = None, full_name: str = None) -> bool:
        """Create a new admin user."""
        try:
            # Validate username
            if not username or len(username) < 3:
                print("Error: Username must be at least 3 characters long")
                return False
            
            if username in self.admin_users:
                print(f"Error: User '{username}' already exists")
                return False
            
            # Get password
            if not password:
                password = getpass.getpass("Enter password for new admin user: ")
                confirm_password = getpass.getpass("Confirm password: ")
                
                if password != confirm_password:
                    print("Error: Passwords do not match")
                    return False
            
            if len(password) < 8:
                print("Error: Password must be at least 8 characters long")
                return False
            
            # Create user record
            user_data = {
                "username": username,
                "password_hash": self.hash_password(password),
                "role": role,
                "email": email or "",
                "full_name": full_name or "",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "is_active": True,
                "failed_login_attempts": 0,
                "locked_until": None,
                "api_key": secrets.token_urlsafe(32),
                "permissions": self.get_default_permissions(role)
            }
            
            self.admin_users[username] = user_data
            self.save_admin_users()
            
            # Log the action
            self.log_audit("CREATE_USER", username, f"Role: {role}, Email: {email}")
            
            print(f"✅ Admin user '{username}' created successfully")
            print(f"   Role: {role}")
            print(f"   API Key: {user_data['api_key']}")
            
            return True
            
        except Exception as e:
            print(f"Error creating admin user: {e}")
            return False
    
    def get_default_permissions(self, role: str) -> List[str]:
        """Get default permissions for a role."""
        permissions = {
            "super_admin": [
                "user_management", "system_config", "security_audit", 
                "backup_management", "cluster_management", "api_access",
                "log_access", "performance_monitoring", "emergency_access"
            ],
            "admin": [
                "user_management", "system_config", "backup_management",
                "api_access", "log_access", "performance_monitoring"
            ],
            "operator": [
                "system_config", "backup_management", "api_access", "log_access"
            ],
            "viewer": [
                "api_access", "log_access"
            ]
        }
        return permissions.get(role, permissions["viewer"])
    
    def list_admin_users(self):
        """List all admin users."""
        if not self.admin_users:
            print("No admin users found")
            return
        
        print("\n📋 Admin Users:")
        print("=" * 80)
        print(f"{'Username':<20} {'Role':<15} {'Status':<10} {'Last Login':<20} {'Created':<20}")
        print("-" * 80)
        
        for username, user_data in self.admin_users.items():
            status = "Active" if user_data.get("is_active", True) else "Inactive"
            last_login = user_data.get("last_login", "Never")
            if last_login and last_login != "Never":
                last_login = last_login[:19]  # Truncate timestamp
            created = user_data.get("created_at", "Unknown")[:19]
            
            print(f"{username:<20} {user_data.get('role', 'admin'):<15} {status:<10} {last_login:<20} {created:<20}")
        
        print("=" * 80)
    
    def delete_admin_user(self, username: str) -> bool:
        """Delete an admin user."""
        try:
            if username not in self.admin_users:
                print(f"Error: User '{username}' not found")
                return False
            
            # Confirm deletion
            confirm = input(f"Are you sure you want to delete user '{username}'? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return False
            
            # Remove user
            user_data = self.admin_users.pop(username)
            self.save_admin_users()
            
            # Log the action
            self.log_audit("DELETE_USER", username, f"Role: {user_data.get('role', 'unknown')}")
            
            print(f"✅ Admin user '{username}' deleted successfully")
            return True
            
        except Exception as e:
            print(f"Error deleting admin user: {e}")
            return False
    
    def reset_password(self, username: str) -> bool:
        """Reset password for an admin user."""
        try:
            if username not in self.admin_users:
                print(f"Error: User '{username}' not found")
                return False
            
            # Get new password
            new_password = getpass.getpass(f"Enter new password for '{username}': ")
            confirm_password = getpass.getpass("Confirm new password: ")
            
            if new_password != confirm_password:
                print("Error: Passwords do not match")
                return False
            
            if len(new_password) < 8:
                print("Error: Password must be at least 8 characters long")
                return False
            
            # Update password
            self.admin_users[username]["password_hash"] = self.hash_password(new_password)
            self.admin_users[username]["failed_login_attempts"] = 0
            self.admin_users[username]["locked_until"] = None
            self.save_admin_users()
            
            # Log the action
            self.log_audit("RESET_PASSWORD", username, "Password reset by admin")
            
            print(f"✅ Password reset successfully for user '{username}'")
            return True
            
        except Exception as e:
            print(f"Error resetting password: {e}")
            return False
    
    def toggle_user_status(self, username: str) -> bool:
        """Toggle user active/inactive status."""
        try:
            if username not in self.admin_users:
                print(f"Error: User '{username}' not found")
                return False
            
            current_status = self.admin_users[username].get("is_active", True)
            new_status = not current_status
            
            self.admin_users[username]["is_active"] = new_status
            self.save_admin_users()
            
            status_text = "activated" if new_status else "deactivated"
            self.log_audit("TOGGLE_STATUS", username, f"User {status_text}")
            
            print(f"✅ User '{username}' {status_text} successfully")
            return True
            
        except Exception as e:
            print(f"Error toggling user status: {e}")
            return False
    
    def show_user_details(self, username: str):
        """Show detailed information about a user."""
        if username not in self.admin_users:
            print(f"Error: User '{username}' not found")
            return
        
        user_data = self.admin_users[username]
        
        print(f"\n👤 User Details: {username}")
        print("=" * 50)
        print(f"Role: {user_data.get('role', 'admin')}")
        print(f"Email: {user_data.get('email', 'Not set')}")
        print(f"Full Name: {user_data.get('full_name', 'Not set')}")
        print(f"Status: {'Active' if user_data.get('is_active', True) else 'Inactive'}")
        print(f"Created: {user_data.get('created_at', 'Unknown')}")
        print(f"Last Login: {user_data.get('last_login', 'Never')}")
        print(f"Failed Login Attempts: {user_data.get('failed_login_attempts', 0)}")
        print(f"API Key: {user_data.get('api_key', 'Not set')}")
        print(f"Permissions: {', '.join(user_data.get('permissions', []))}")
        print("=" * 50)
    
    def generate_api_key(self, username: str) -> bool:
        """Generate new API key for user."""
        try:
            if username not in self.admin_users:
                print(f"Error: User '{username}' not found")
                return False
            
            new_api_key = secrets.token_urlsafe(32)
            self.admin_users[username]["api_key"] = new_api_key
            self.save_admin_users()
            
            self.log_audit("GENERATE_API_KEY", username, "New API key generated")
            
            print(f"✅ New API key generated for '{username}': {new_api_key}")
            return True
            
        except Exception as e:
            print(f"Error generating API key: {e}")
            return False

def main():
    """Main CLI interface for admin user management."""
    parser = argparse.ArgumentParser(
        description="NetLink Admin User Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m netlink.cli.admin_manager create --username admin --role super_admin
  python -m netlink.cli.admin_manager list
  python -m netlink.cli.admin_manager reset-password --username admin
  python -m netlink.cli.admin_manager delete --username olduser
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create user command
    create_parser = subparsers.add_parser('create', help='Create new admin user')
    create_parser.add_argument('--username', required=True, help='Username for new admin')
    create_parser.add_argument('--role', choices=['super_admin', 'admin', 'operator', 'viewer'], 
                              default='admin', help='User role')
    create_parser.add_argument('--email', help='User email address')
    create_parser.add_argument('--full-name', help='User full name')
    create_parser.add_argument('--password', help='User password (will prompt if not provided)')
    
    # List users command
    subparsers.add_parser('list', help='List all admin users')
    
    # Delete user command
    delete_parser = subparsers.add_parser('delete', help='Delete admin user')
    delete_parser.add_argument('--username', required=True, help='Username to delete')
    
    # Reset password command
    reset_parser = subparsers.add_parser('reset-password', help='Reset user password')
    reset_parser.add_argument('--username', required=True, help='Username to reset password')
    
    # Toggle status command
    toggle_parser = subparsers.add_parser('toggle-status', help='Toggle user active/inactive')
    toggle_parser.add_argument('--username', required=True, help='Username to toggle')
    
    # Show user details command
    details_parser = subparsers.add_parser('details', help='Show user details')
    details_parser.add_argument('--username', required=True, help='Username to show details')
    
    # Generate API key command
    api_parser = subparsers.add_parser('generate-api-key', help='Generate new API key')
    api_parser.add_argument('--username', required=True, help='Username to generate API key')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize admin manager
    admin_manager = AdminUserManager()
    
    # Execute command
    if args.command == 'create':
        admin_manager.create_admin_user(
            username=args.username,
            password=args.password,
            role=args.role,
            email=args.email,
            full_name=args.full_name
        )
    elif args.command == 'list':
        admin_manager.list_admin_users()
    elif args.command == 'delete':
        admin_manager.delete_admin_user(args.username)
    elif args.command == 'reset-password':
        admin_manager.reset_password(args.username)
    elif args.command == 'toggle-status':
        admin_manager.toggle_user_status(args.username)
    elif args.command == 'details':
        admin_manager.show_user_details(args.username)
    elif args.command == 'generate-api-key':
        admin_manager.generate_api_key(args.username)

if __name__ == "__main__":
    main()
