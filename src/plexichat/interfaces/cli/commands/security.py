# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
from typing import List, Optional


import logging
from typing import List, Optional

import time
from plexichat.app.security.permissions import (
    Permission,
    PermissionManager,
    PermissionScope,
    Role,
    UserPermissions,
)
from plexichat.app.security.rate_limiter import (
    ComprehensiveRateLimiter,
    RateLimitAction,
    RateLimitRule,
    RateLimitType,
)


logger = logging.getLogger(__name__)
class SecurityCLI:
    """CLI for security management."""
        def __init__(self):
        self.rate_limiter = ComprehensiveRateLimiter()
        self.permission_manager = PermissionManager()

    def print_colored(self, text: str, color: str = "white") -> None:
        """Print colored text."""
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "reset": "\033[0m"
        }
        logger.info(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")

    # Rate Limiting Commands
    async def list_rate_limit_rules(self) -> None:
        """List all rate limiting rules."""
        self.print_colored(" Rate Limiting Rules", "cyan")
        self.print_colored("=" * 50, "cyan")

        if not self.rate_limiter.rules:
            self.print_colored("No rate limiting rules configured.", "yellow")
            return

        for rule in self.rate_limiter.rules.values():
            status = " Enabled" if rule.enabled else " Disabled"
            self.print_colored(f"\n {rule.name}", "blue")
            logger.info(f"   Type: {rule.limit_type.value}")
            logger.info(f"   Limit: {rule.max_requests} requests per {rule.time_window} seconds")
            logger.info(f"   Action: {rule.action.value}")
            logger.info(f"   Status: {status}")

            if rule.whitelist_ips:
                logger.info(f"   Whitelisted IPs: {', '.join(rule.whitelist_ips)}")
            if rule.blacklist_ips:
                logger.info(f"   Blacklisted IPs: {', '.join(rule.blacklist_ips)}")
            if rule.user_roles:
                logger.info(f"   User Roles: {', '.join(rule.user_roles)}")
            if rule.endpoints:
                logger.info(f"   Endpoints: {', '.join(rule.endpoints)}")

    async def create_rate_limit_rule(self, args: List[str]) -> None:
        """Create a new rate limiting rule."""
        if len(args) < 5:
            self.print_colored("Usage: create-rule <name> <type> <max_requests> <time_window> <action>", "red")
            self.print_colored("Types: " + ", ".join([t.value for t in RateLimitType]), "yellow")
            self.print_colored("Actions: " + ", ".join([a.value for a in RateLimitAction]), "yellow")
            return

        name, limit_type, max_requests, time_window, action = args[:5]

        try:
            limit_type_enum = RateLimitType(limit_type)
            action_enum = RateLimitAction(action)
            max_requests_int = int(max_requests)
            time_window_int = int(time_window)
        except ValueError as e:
            self.print_colored(f" Invalid parameter: {e}", "red")
            return

        rule = RateLimitRule(
            name=name,
            limit_type=limit_type_enum,
            max_requests=max_requests_int,
            time_window=time_window_int,
            action=action_enum
        )

        if name in self.rate_limiter.rules:
            self.print_colored(f" Rule '{name}' already exists", "red")
            return

        self.rate_limiter.rules[name] = rule
        self.rate_limiter.save_config()
        self.print_colored(f" Created rate limiting rule: {name}", "green")

    async def delete_rate_limit_rule(self, rule_name: str) -> None:
        """Delete a rate limiting rule."""
        if rule_name not in self.rate_limiter.rules:
            self.print_colored(f" Rule '{rule_name}' not found", "red")
            return

        del self.rate_limiter.rules[rule_name]
        self.rate_limiter.save_config()
        self.print_colored(f" Deleted rate limiting rule: {rule_name}", "green")

    async def show_rate_limit_status(self, client_ip: str, user_id: Optional[str] = None) -> None:
        """Show rate limit status for a client."""
        self.print_colored(f" Rate Limit Status for {client_ip}", "cyan")
        if user_id:
            self.print_colored(f"   User ID: {user_id}", "cyan")
        self.print_colored("=" * 50, "cyan")

        for rule in self.rate_limiter.rules.values():
            if not rule.enabled:
                continue

            client_key = self.rate_limiter._get_client_key(client_ip, user_id, rule)
            current_count = self.rate_limiter.tracker.get_request_count(client_key, rule.time_window)

            status = " EXCEEDED" if current_count >= rule.max_requests else " OK"
            self.print_colored(f"\n {rule.name}: {status}", "yellow" if current_count >= rule.max_requests else "green")
            logger.info(f"   Current: {current_count}/{rule.max_requests}")
            logger.info(f"   Window: {rule.time_window} seconds")

    async def show_banned_entities(self) -> None:
        """Show all banned IPs and users."""
        self.print_colored(" Banned Entities", "red")
        self.print_colored("=" * 50, "red")

        if self.rate_limiter.tracker.banned_ips:
            self.print_colored("\n Banned IPs:", "yellow")
            for ip, until in self.rate_limiter.tracker.banned_ips.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(f"   {ip} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        if self.rate_limiter.tracker.banned_users:
            self.print_colored("\n Banned Users:", "yellow")
            for user_id, until in self.rate_limiter.tracker.banned_users.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(f"   {user_id} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        if self.rate_limiter.tracker.quarantined_ips:
            self.print_colored("\n Quarantined IPs:", "yellow")
            for ip, until in self.rate_limiter.tracker.quarantined_ips.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(f"   {ip} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        if not any([self.rate_limiter.tracker.banned_ips,
                self.rate_limiter.tracker.banned_users,
                self.rate_limiter.tracker.quarantined_ips]):
            self.print_colored("No banned or quarantined entities.", "green")

    async def unban_ip(self, ip: str) -> None:
        """Unban an IP address."""
        if ip in self.rate_limiter.tracker.banned_ips:
            del self.rate_limiter.tracker.banned_ips[ip]
            self.print_colored(f" Unbanned IP: {ip}", "green")
        else:
            self.print_colored(f" IP not found in ban list: {ip}", "red")

    async def unban_user(self, user_id: str) -> None:
        """Unban a user."""
        if user_id in self.rate_limiter.tracker.banned_users:
            del self.rate_limiter.tracker.banned_users[user_id]
            self.print_colored(f" Unbanned user: {user_id}", "green")
        else:
            self.print_colored(f" User not found in ban list: {user_id}", "red")

    # Permission Management Commands
    async def list_roles(self) -> None:
        """List all roles."""
        self.print_colored(" User Roles", "cyan")
        self.print_colored("=" * 50, "cyan")

        if not self.permission_manager.roles:
            self.print_colored("No roles configured.", "yellow")
            return

        # Sort by priority
        sorted_roles = sorted(self.permission_manager.roles.values(), key=lambda r: r.priority, reverse=True)

        for role in sorted_roles:
            system_badge = " [SYSTEM]" if role.is_system else ""
            default_badge = " [DEFAULT]" if role.is_default else ""
            self.print_colored(f"\n {role.display_name} ({role.name}){system_badge}{default_badge}", "blue")
            logger.info(f"   Description: {role.description}")
            logger.info(f"   Priority: {role.priority}")
            logger.info(f"   Color: {role.color}")
            logger.info(f"   Permissions: {len(role.permissions)}")

            if len(role.permissions) <= 10:
                perms = ", ".join([p.value for p in role.permissions])
                logger.info(f"    {perms}")
            else:
                logger.info(f"    {len(role.permissions)} permissions (use 'show-role {role.name}' for details)")

    async def show_role(self, role_name: str) -> None:
        """Show detailed information about a role."""
        if role_name not in self.permission_manager.roles:
            self.print_colored(f" Role '{role_name}' not found", "red")
            return

        role = self.permission_manager.roles[role_name]

        self.print_colored(f" Role: {role.display_name} ({role.name})", "cyan")
        self.print_colored("=" * 50, "cyan")

        logger.info(f"Description: {role.description}")
        logger.info(f"Priority: {role.priority}")
        logger.info(f"Color: {role.color}")
        logger.info(f"System Role: {'Yes' if role.is_system else 'No'}")
        logger.info(f"Default Role: {'Yes' if role.is_default else 'No'}")
        logger.info(f"Created: {role.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Updated: {role.updated_at.strftime('%Y-%m-%d %H:%M:%S')}")

        self.print_colored(f"\n Permissions ({len(role.permissions)}):", "yellow")
        for perm in sorted(role.permissions, key=lambda p: p.value):
            logger.info(f"    {perm.value}")

    async def create_role(self, args: List[str]) -> None:
        """Create a new role."""
        if len(args) < 3:
            self.print_colored("Usage: create-role <name> <display_name> <description> [permissions...]", "red")
            return

        name = args[0]
        display_name = args[1]
        description = args[2]
        permissions = args[3:] if len(args) > 3 else []

        # Validate permissions
        try:
            perm_set = set(Permission(p) for p in permissions)
        except ValueError as e:
            self.print_colored(f" Invalid permission: {e}", "red")
            return

        role = Role(
            name=name,
            display_name=display_name,
            description=description,
            permissions=perm_set
        )

        success = self.permission_manager.create_role(role)
        if success:
            self.print_colored(f" Created role: {name}", "green")
        else:
            self.print_colored(f" Failed to create role (may already exist): {name}", "red")

    async def delete_role(self, role_name: str) -> None:
        """Delete a role."""
        success = self.permission_manager.delete_role(role_name)
        if success:
            self.print_colored(f" Deleted role: {role_name}", "green")
        else:
            self.print_colored(f" Failed to delete role: {role_name}", "red")

    async def assign_role(self, user_id: str, role_name: str, scope: str = "global", scope_id: Optional[str] = None) -> None:
        """Assign a role to a user."""
        try:
            scope_enum = PermissionScope(scope)
        except ValueError:
            self.print_colored(f" Invalid scope: {scope}", "red")
            return

        success = self.permission_manager.assign_role(user_id, role_name, scope_enum, scope_id)
        if success:
            self.print_colored(f" Assigned role '{role_name}' to user '{user_id}' in scope '{scope}'", "green")
        else:
            self.print_colored(" Failed to assign role", "red")

    async def revoke_role(self, user_id: str, role_name: str, scope: str = "global", scope_id: Optional[str] = None) -> None:
        """Revoke a role from a user."""
        try:
            scope_enum = PermissionScope(scope)
        except ValueError:
            self.print_colored(f" Invalid scope: {scope}", "red")
            return

        success = self.permission_manager.revoke_role(user_id, role_name, scope_enum, scope_id)
        if success:
            self.print_colored(f" Revoked role '{role_name}' from user '{user_id}' in scope '{scope}'", "green")
        else:
            self.print_colored(" Failed to revoke role", "red")

    async def check_permission(self, user_id: str, permission: str, scope: str = "global", scope_id: Optional[str] = None) -> None:
        """Check if a user has a specific permission."""
        try:
            perm_enum = Permission(permission)
            scope_enum = PermissionScope(scope)
        except ValueError as e:
            self.print_colored(f" Invalid parameter: {e}", "red")
            return

        check_result = self.permission_manager.check_permission(user_id, perm_enum, scope_enum, scope_id)

        status = " GRANTED" if check_result.granted else " DENIED"
        self.print_colored(f" Permission Check: {status}", "green" if check_result.granted else "red")
        logger.info(f"   User: {user_id}")
        logger.info(f"   Permission: {permission}")
        logger.info(f"   Scope: {scope}")
        if scope_id:
            logger.info(f"   Scope ID: {scope_id}")
        logger.info(f"   Reason: {check_result.reason}")
        if check_result.roles_checked:
            logger.info(f"   Roles Checked: {', '.join(check_result.roles_checked)}")

    async def show_user_permissions(self, user_id: str) -> None:
        """Show all permissions for a user."""
        if user_id not in self.permission_manager.user_permissions:
            self.print_colored(f" User permissions not found: {user_id}", "red")
            return

        user_perms = self.permission_manager.user_permissions[user_id]

        self.print_colored(f" User Permissions: {user_id}", "cyan")
        self.print_colored("=" * 50, "cyan")

        logger.info(f"Active: {'Yes' if user_perms.is_active else 'No'}")
        logger.info(f"Created: {user_perms.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Updated: {user_perms.updated_at.strftime('%Y-%m-%d %H:%M:%S')}")

        if user_perms.global_roles:
            self.print_colored("\n Global Roles:", "yellow")
            for role in user_perms.global_roles:
                logger.info(f"    {role}")

        if user_perms.server_roles:
            self.print_colored("\n Server Roles:", "yellow")
            for server_id, roles in user_perms.server_roles.items():
                logger.info(f"   Server {server_id}: {', '.join(roles)}")

        if user_perms.channel_roles:
            self.print_colored("\n Channel Roles:", "yellow")
            for channel_id, roles in user_perms.channel_roles.items():
                logger.info(f"   Channel {channel_id}: {', '.join(roles)}")

        if user_perms.explicit_permissions:
            self.print_colored("\n Explicit Permissions:", "green")
            for scope_id, perms in user_perms.explicit_permissions.items():
                perm_list = [p.value for p in perms]
                logger.info(f"   {scope_id}: {', '.join(perm_list)}")

        if user_perms.denied_permissions:
            self.print_colored("\n Denied Permissions:", "red")
            for scope_id, perms in user_perms.denied_permissions.items():
                perm_list = [p.value for p in perms]
                logger.info(f"   {scope_id}: {', '.join(perm_list)}")

async def handle_security_command(args: List[str]) -> None:
    """Handle security management commands."""
    if not args:
        logger.info(" Security Management Commands:")
        logger.info("Rate Limiting:")
        logger.info("  list-rules                    - List rate limiting rules")
        logger.info("  create-rule <args>            - Create rate limiting rule")
        logger.info("  delete-rule <name>            - Delete rate limiting rule")
        logger.info("  status <ip> [user_id]         - Show rate limit status")
        logger.info("  banned                        - Show banned entities")
        logger.info("  unban-ip <ip>                 - Unban IP address")
        logger.info("  unban-user <user_id>          - Unban user")
        logger.info("")
        logger.info("Permissions:")
        logger.info("  list-roles                    - List all roles")
        logger.info("  show-role <name>              - Show role details")
        logger.info("  create-role <args>            - Create new role")
        logger.info("  delete-role <name>            - Delete role")
        logger.info("  assign-role <user> <role>     - Assign role to user")
        logger.info("  revoke-role <user> <role>     - Revoke role from user")
        logger.info("  check-perm <user> <perm>      - Check user permission")
        logger.info("  show-user <user_id>           - Show user permissions")
        return

    cli = SecurityCLI()
    command = args[0]
    command_args = args[1:]

    try:
        if command == "list-rules":
            await cli.list_rate_limit_rules()
        elif command == "create-rule":
            await cli.create_rate_limit_rule(command_args)
        elif command == "delete-rule" and command_args:
            await cli.delete_rate_limit_rule(command_args[0])
        elif command == "status" and command_args:
            user_id = command_args[1] if len(command_args) > 1 else None
            await cli.show_rate_limit_status(command_args[0], user_id)
        elif command == "banned":
            await cli.show_banned_entities()
        elif command == "unban-ip" and command_args:
            await cli.unban_ip(command_args[0])
        elif command == "unban-user" and command_args:
            await cli.unban_user(command_args[0])
        elif command == "list-roles":
            await cli.list_roles()
        elif command == "show-role" and command_args:
            await cli.show_role(command_args[0])
        elif command == "create-role":
            await cli.create_role(command_args)
        elif command == "delete-role" and command_args:
            await cli.delete_role(command_args[0])
        elif command == "assign-role" and len(command_args) >= 2:
            scope = command_args[2] if len(command_args) > 2 else "global"
            scope_id = command_args[3] if len(command_args) > 3 else None
            await cli.assign_role(command_args[0], command_args[1], scope, scope_id)
        elif command == "revoke-role" and len(command_args) >= 2:
            scope = command_args[2] if len(command_args) > 2 else "global"
            scope_id = command_args[3] if len(command_args) > 3 else None
            await cli.revoke_role(command_args[0], command_args[1], scope, scope_id)
        elif command == "check-perm" and len(command_args) >= 2:
            scope = command_args[2] if len(command_args) > 2 else "global"
            scope_id = command_args[3] if len(command_args) > 3 else None
            await cli.check_permission(command_args[0], command_args[1], scope, scope_id)
        elif command == "show-user" and command_args:
            await cli.show_user_permissions(command_args[0])
        else:
            logger.info(f" Unknown command or missing arguments: {command}")

    except Exception as e:
        logger.info(f" Command failed: {e}")
        logger.error(f"Security CLI command failed: {e}")
