"""
PlexiChat CLI Admin Commands

Command-line interface for administrative operations.
"""

import asyncio
import click
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from plexichat.core.auth.admin_manager import admin_manager
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    admin_manager = None
    get_logger = lambda x: print
    settings = {}

logger = get_logger(__name__)

@click.group()
def admin():
    """Administrative commands for PlexiChat."""
    pass

@admin.command()
@click.option('--username', '-u', prompt=True, help='Admin username')
@click.option('--email', '-e', prompt=True, help='Admin email')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Admin password')
@click.option('--role', '-r', default='admin', help='Admin role (admin, super_admin)')
def create_admin(username: str, email: str, password: str, role: str):
    """Create a new admin user."""
    if not admin_manager:
        click.echo("Error: Admin manager not available", err=True)
        sys.exit(1)
    
    try:
        permissions = []
        if role == "super_admin":
            permissions = [
                "user_management", "system_config", "security_audit",
                "backup_management", "cluster_management", "api_access",
                "log_access", "performance_monitoring", "emergency_access"
            ]
        else:
            permissions = ["user_management", "system_config"]
        
        success = admin_manager.create_admin(username, email, password, role, permissions)
        
        if success:
            click.echo(f"✅ Admin user '{username}' created successfully")
        else:
            click.echo(f"❌ Failed to create admin user '{username}' (may already exist)", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error creating admin: {e}", err=True)
        sys.exit(1)

@admin.command()
def list_admins():
    """List all admin users."""
    if not admin_manager:
        click.echo("Error: Admin manager not available", err=True)
        sys.exit(1)
    
    try:
        admins = admin_manager.list_admins()
        
        if not admins:
            click.echo("No admin users found")
            return
        
        click.echo("\n📋 Admin Users:")
        click.echo("-" * 80)
        
        for admin in admins:
            status = "🟢 Active" if admin.is_active else "🔴 Inactive"
            last_login = admin.last_login.strftime("%Y-%m-%d %H:%M:%S") if admin.last_login else "Never"
            
            click.echo(f"Username: {admin.username}")
            click.echo(f"Email: {admin.email}")
            click.echo(f"Role: {admin.role}")
            click.echo(f"Status: {status}")
            click.echo(f"Last Login: {last_login}")
            click.echo(f"Permissions: {', '.join(admin.permissions)}")
            click.echo("-" * 80)
            
    except Exception as e:
        click.echo(f"❌ Error listing admins: {e}", err=True)
        sys.exit(1)

@admin.command()
@click.option('--username', '-u', prompt=True, help='Admin username')
def delete_admin(username: str):
    """Delete an admin user."""
    if not admin_manager:
        click.echo("Error: Admin manager not available", err=True)
        sys.exit(1)
    
    try:
        if username not in admin_manager.admins:
            click.echo(f"❌ Admin user '{username}' not found", err=True)
            sys.exit(1)
        
        if click.confirm(f"Are you sure you want to delete admin '{username}'?"):
            del admin_manager.admins[username]
            admin_manager._save_data()
            click.echo(f"✅ Admin user '{username}' deleted successfully")
        else:
            click.echo("Operation cancelled")
            
    except Exception as e:
        click.echo(f"❌ Error deleting admin: {e}", err=True)
        sys.exit(1)

@admin.command()
def list_sessions():
    """List active admin sessions."""
    if not admin_manager:
        click.echo("Error: Admin manager not available", err=True)
        sys.exit(1)
    
    try:
        admin_manager._clean_expired_sessions()
        sessions = admin_manager.sessions
        
        if not sessions:
            click.echo("No active admin sessions")
            return
        
        click.echo("\n🔐 Active Admin Sessions:")
        click.echo("-" * 80)
        
        for token, session in sessions.items():
            created = session.created_at.strftime("%Y-%m-%d %H:%M:%S")
            expires = session.expires_at.strftime("%Y-%m-%d %H:%M:%S")
            
            click.echo(f"Username: {session.username}")
            click.echo(f"Token: {token[:16]}...")
            click.echo(f"Created: {created}")
            click.echo(f"Expires: {expires}")
            click.echo(f"IP Address: {session.ip_address or 'Unknown'}")
            click.echo("-" * 80)
            
    except Exception as e:
        click.echo(f"❌ Error listing sessions: {e}", err=True)
        sys.exit(1)

@admin.command()
@click.option('--token', '-t', help='Session token to revoke (partial match)')
@click.option('--username', '-u', help='Revoke all sessions for username')
@click.option('--all', 'revoke_all', is_flag=True, help='Revoke all sessions')
def revoke_session(token: Optional[str], username: Optional[str], revoke_all: bool):
    """Revoke admin sessions."""
    if not admin_manager:
        click.echo("Error: Admin manager not available", err=True)
        sys.exit(1)
    
    try:
        if revoke_all:
            if click.confirm("Are you sure you want to revoke ALL admin sessions?"):
                count = len(admin_manager.sessions)
                admin_manager.sessions.clear()
                admin_manager._save_data()
                click.echo(f"✅ Revoked {count} admin sessions")
            else:
                click.echo("Operation cancelled")
                
        elif username:
            revoked = []
            for session_token, session in list(admin_manager.sessions.items()):
                if session.username == username:
                    revoked.append(session_token)
                    del admin_manager.sessions[session_token]
            
            if revoked:
                admin_manager._save_data()
                click.echo(f"✅ Revoked {len(revoked)} sessions for user '{username}'")
            else:
                click.echo(f"No sessions found for user '{username}'")
                
        elif token:
            found_token = None
            for session_token in admin_manager.sessions:
                if session_token.startswith(token):
                    found_token = session_token
                    break
            
            if found_token:
                del admin_manager.sessions[found_token]
                admin_manager._save_data()
                click.echo(f"✅ Revoked session {found_token[:16]}...")
            else:
                click.echo(f"❌ Session token not found", err=True)
                
        else:
            click.echo("❌ Must specify --token, --username, or --all", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error revoking session: {e}", err=True)
        sys.exit(1)

@admin.command()
def system_status():
    """Show system status information."""
    try:
        click.echo("\n🖥️  PlexiChat System Status")
        click.echo("=" * 50)
        
        # Basic system info
        click.echo(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if admin_manager:
            admin_count = len(admin_manager.admins)
            active_sessions = len(admin_manager.sessions)
            click.echo(f"Admin Users: {admin_count}")
            click.echo(f"Active Sessions: {active_sessions}")
        
        # Configuration info
        if settings:
            click.echo(f"Debug Mode: {settings.get('debug', False)}")
            click.echo(f"Log Level: {settings.get('log_level', 'INFO')}")
        
        click.echo("=" * 50)
        
    except Exception as e:
        click.echo(f"❌ Error getting system status: {e}", err=True)
        sys.exit(1)

@admin.command()
@click.option('--format', 'output_format', default='json', 
              type=click.Choice(['json', 'yaml']), help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def export_config(output_format: str, output: Optional[str]):
    """Export system configuration."""
    try:
        config_data = {
            "admins": [],
            "settings": settings,
            "exported_at": datetime.now().isoformat()
        }
        
        if admin_manager:
            for admin in admin_manager.list_admins():
                config_data["admins"].append({
                    "username": admin.username,
                    "email": admin.email,
                    "role": admin.role,
                    "permissions": admin.permissions,
                    "is_active": admin.is_active,
                    "created_at": admin.created_at.isoformat()
                })
        
        if output_format == 'json':
            content = json.dumps(config_data, indent=2)
        else:  # yaml
            try:
                import yaml
                content = yaml.dump(config_data, default_flow_style=False)
            except ImportError:
                click.echo("❌ PyYAML not installed. Use 'pip install pyyaml'", err=True)
                sys.exit(1)
        
        if output:
            with open(output, 'w') as f:
                f.write(content)
            click.echo(f"✅ Configuration exported to {output}")
        else:
            click.echo(content)
            
    except Exception as e:
        click.echo(f"❌ Error exporting configuration: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    admin()
