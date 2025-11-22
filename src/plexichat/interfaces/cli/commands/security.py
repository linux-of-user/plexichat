# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import UTC, datetime
import json
import logging
from typing import Any

# Use the authentication manager and Role enum
from plexichat.core.authentication import Role, get_auth_manager
from plexichat.core.middleware.rate_limiting import (
    ComprehensiveRateLimiter,
    RateLimitAction,
    RateLimitRule,
    RateLimitType,
)

# Optional integrations - gracefully degrade if modules are missing
try:
    from plexichat.core.security.ddos_protection import get_ddos_protection
except Exception:
    get_ddos_protection = None

try:
    from plexichat.core.plugins.security_manager import (
        PermissionStatus,
        PermissionType,
        SecurityPolicy,
        SecurityPolicy,
        get_security_module,
        plugin_security_manager,
    )
except Exception:
    plugin_security_manager = None
    PermissionType = None
    SecurityPolicy = None
    PermissionStatus = None
    get_security_module = None

try:
    from plexichat.core.security.key_vault import key_vault
except Exception:
    key_vault = None

logger = logging.getLogger(__name__)


class SecurityCLI:
    """CLI for security management."""

    def __init__(self):
        self.rate_limiter = ComprehensiveRateLimiter()
        # Use auth manager for permission and role operations
        self.auth_manager = get_auth_manager()
        self.ddos = get_ddos_protection() if get_ddos_protection else None
        self.plugin_sec = plugin_security_manager if plugin_security_manager else None
        self.kv = key_vault if key_vault else None

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
            "reset": "\033[0m",
        }
        try:
            print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")
        except Exception:
            # Fallback to logger if printing fails
            logger.info(text)

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
            logger.info(
                f"   Limit: {rule.max_requests} requests per {rule.time_window} seconds"
            )
            logger.info(f"   Action: {rule.action.value}")
            logger.info(f"   Status: {status}")

            if getattr(rule, "whitelist_ips", None):
                logger.info(f"   Whitelisted IPs: {', '.join(rule.whitelist_ips)}")
            if getattr(rule, "blacklist_ips", None):
                logger.info(f"   Blacklisted IPs: {', '.join(rule.blacklist_ips)}")
            if getattr(rule, "user_roles", None):
                logger.info(f"   User Roles: {', '.join(rule.user_roles)}")
            if getattr(rule, "endpoints", None):
                logger.info(f"   Endpoints: {', '.join(rule.endpoints)}")

    async def create_rate_limit_rule(self, args: list[str]) -> None:
        """Create a new rate limiting rule."""
        if len(args) < 5:
            self.print_colored(
                "Usage: create-rule <name> <type> <max_requests> <time_window> <action>",
                "red",
            )
            self.print_colored(
                "Types: " + ", ".join([t.value for t in RateLimitType]), "yellow"
            )
            self.print_colored(
                "Actions: " + ", ".join([a.value for a in RateLimitAction]), "yellow"
            )
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
            action=action_enum,
        )

        if name in self.rate_limiter.rules:
            self.print_colored(f" Rule '{name}' already exists", "red")
            return

        self.rate_limiter.rules[name] = rule
        try:
            self.rate_limiter.save_config()
        except Exception as e:
            logger.warning(f"Could not persist rate limiter config: {e}")
        self.print_colored(f" Created rate limiting rule: {name}", "green")

    async def delete_rate_limit_rule(self, rule_name: str) -> None:
        """Delete a rate limiting rule."""
        if rule_name not in self.rate_limiter.rules:
            self.print_colored(f" Rule '{rule_name}' not found", "red")
            return

        del self.rate_limiter.rules[rule_name]
        try:
            self.rate_limiter.save_config()
        except Exception as e:
            logger.warning(f"Could not persist rate limiter config: {e}")
        self.print_colored(f" Deleted rate limiting rule: {rule_name}", "green")

    async def show_rate_limit_status(
        self, client_ip: str, user_id: str | None = None
    ) -> None:
        """Show rate limit status for a client."""
        self.print_colored(f" Rate Limit Status for {client_ip}", "cyan")
        if user_id:
            self.print_colored(f"   User ID: {user_id}", "cyan")
        self.print_colored("=" * 50, "cyan")

        for rule in self.rate_limiter.rules.values():
            if not rule.enabled:
                continue

            client_key = self.rate_limiter._get_client_key(client_ip, user_id, rule)
            current_count = self.rate_limiter.tracker.get_request_count(
                client_key, rule.time_window
            )

            status = " EXCEEDED" if current_count >= rule.max_requests else " OK"
            self.print_colored(
                f"\n {rule.name}: {status}",
                "yellow" if current_count >= rule.max_requests else "green",
            )
            logger.info(f"   Current: {current_count}/{rule.max_requests}")
            logger.info(f"   Window: {rule.time_window} seconds")

    async def show_banned_entities(self) -> None:
        """Show all banned IPs and users."""
        self.print_colored(" Banned Entities", "red")
        self.print_colored("=" * 50, "red")

        if getattr(self.rate_limiter.tracker, "banned_ips", None):
            self.print_colored("\n Banned IPs:", "yellow")
            for ip, until in self.rate_limiter.tracker.banned_ips.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(f"   {ip} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        if getattr(self.rate_limiter.tracker, "banned_users", None):
            self.print_colored("\n Banned Users:", "yellow")
            for user_id, until in self.rate_limiter.tracker.banned_users.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(
                    f"   {user_id} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                )

        if getattr(self.rate_limiter.tracker, "quarantined_ips", None):
            self.print_colored("\n Quarantined IPs:", "yellow")
            for ip, until in self.rate_limiter.tracker.quarantined_ips.items():
                until_dt = datetime.fromtimestamp(until)
                logger.info(f"   {ip} - until {until_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        if not any(
            [
                getattr(self.rate_limiter.tracker, "banned_ips", None),
                getattr(self.rate_limiter.tracker, "banned_users", None),
                getattr(self.rate_limiter.tracker, "quarantined_ips", None),
            ]
        ):
            self.print_colored("No banned or quarantined entities.", "green")

    async def unban_ip(self, ip: str) -> None:
        """Unban an IP address from rate limiter bans."""
        if (
            getattr(self.rate_limiter.tracker, "banned_ips", None)
            and ip in self.rate_limiter.tracker.banned_ips
        ):
            del self.rate_limiter.tracker.banned_ips[ip]
            self.print_colored(f" Unbanned IP: {ip}", "green")
        else:
            self.print_colored(f" IP not found in ban list: {ip}", "red")

    async def unban_user(self, user_id: str) -> None:
        """Unban a user."""
        if (
            getattr(self.rate_limiter.tracker, "banned_users", None)
            and user_id in self.rate_limiter.tracker.banned_users
        ):
            del self.rate_limiter.tracker.banned_users[user_id]
            self.print_colored(f" Unbanned user: {user_id}", "green")
        else:
            self.print_colored(f" User not found in ban list: {user_id}", "red")

    # DDoS Protection Commands
    async def show_ddos_status(self) -> None:
        """Show DDoS protection status."""
        if not self.ddos:
            self.print_colored("DDoS protection subsystem not available.", "red")
            return

        status = self.ddos.get_protection_status()
        self.print_colored(" DDoS Protection Status", "cyan")
        self.print_colored("=" * 50, "cyan")
        logger.info(f"Enabled: {status.get('enabled', False)}")
        stats = status.get("stats", {})
        for k, v in stats.items():
            logger.info(f"{k}: {v}")
        blocked = status.get("blocked_ips", {})
        logger.info(f"Blocked IPs: {len(blocked)}")
        self.print_colored(
            " Use 'ddos-list-blocked' and 'ddos-unblock <ip>' to manage blocks",
            "yellow",
        )

    async def ddos_block_ip(self, ip: str, duration_seconds: int = 3600) -> None:
        """Manually block an IP via DDoS protection manager."""
        if not self.ddos:
            self.print_colored("DDoS protection subsystem not available.", "red")
            return
        try:
            self.ddos.ip_block_manager.block_ip(
                ip, duration_seconds, reason="manual-block-via-cli"
            )
            self.print_colored(
                f"Blocked IP {ip} for {duration_seconds} seconds", "green"
            )
        except Exception as e:
            self.print_colored(f"Failed to block IP: {e}", "red")

    async def ddos_unblock_ip(self, ip: str) -> None:
        """Unblock an IP from DDoS protection manager."""
        if not self.ddos:
            self.print_colored("DDoS protection subsystem not available.", "red")
            return
        try:
            self.ddos.ip_block_manager.unblock_ip(ip)
            self.print_colored(f"Unblocked IP {ip}", "green")
        except Exception as e:
            self.print_colored(f"Failed to unblock IP: {e}", "red")

    async def ddos_list_blocked(self) -> None:
        """List blocked IPs from DDoS protection manager."""
        if not self.ddos:
            self.print_colored("DDoS protection subsystem not available.", "red")
            return
        blocked = self.ddos.ip_block_manager.get_blocked_ips()
        if not blocked:
            self.print_colored("No blocked IPs", "green")
            return
        self.print_colored("Blocked IPs:", "yellow")
        for ip, info in blocked.items():
            expires = info.get("expires_at")
            remaining = info.get("remaining_seconds")
            logger.info(
                f" {ip} - type={info.get('type')} expires_at={expires} remaining={remaining}"
            )

    async def ddos_recent_alerts(self, hours: int = 1) -> None:
        """Show recent DDoS alerts."""
        if not self.ddos:
            self.print_colored("DDoS protection subsystem not available.", "red")
            return
        alerts = self.ddos.alert_manager.get_recent_alerts(hours)
        if not alerts:
            self.print_colored("No recent alerts", "green")
            return
        self.print_colored(f"Recent DDoS Alerts (last {hours} hours):", "yellow")
        for a in alerts:
            logger.info(
                f"{datetime.fromtimestamp(a.timestamp).isoformat()} - {a.attack_type.value} - {a.source_ip} - {a.description}"
            )

    # Security Scanning & Audit
    async def run_security_scan(self) -> None:
        """Perform a quick security scan and present findings."""
        self.print_colored(" Running quick security scan...", "cyan")
        findings = []

        # Plugin security summary
        if self.plugin_sec:
            try:
                summary = self.plugin_sec.get_security_summary()
                if summary.get("quarantined_plugins", 0) > 0:
                    findings.append(
                        f"Quarantined plugins: {summary.get('quarantined_plugins')}"
                    )
                if summary.get("pending_permission_requests", 0) > 0:
                    findings.append(
                        f"Pending permission requests: {summary.get('pending_permission_requests')}"
                    )
                critical_events = summary.get("last_24h_critical_events", 0)
                if critical_events > 0:
                    findings.append(
                        f"Critical plugin security events in last 24h: {critical_events}"
                    )
            except Exception as e:
                logger.error(f"Error fetching plugin security summary: {e}")
                findings.append("Failed to gather plugin security summary")

        # DDoS status
        if self.ddos:
            try:
                stats = self.ddos.get_protection_status().get("stats", {})
                if stats.get("active_attacks", 0) > 0:
                    findings.append(
                        f"Active DDoS attacks detected: {stats.get('active_attacks')}"
                    )
                if stats.get("blocked_ips", 0) > 0:
                    findings.append(f"Blocked IPs: {stats.get('blocked_ips')}")
            except Exception as e:
                logger.error(f"Error fetching DDoS stats: {e}")
                findings.append("Failed to gather DDoS stats")

        # Rate limiter sanity checks
        try:
            if not self.rate_limiter.rules:
                findings.append("No rate limiting rules configured - this is risky")
        except Exception:
            findings.append("Failed to read rate limiter configuration")

        # Present findings
        if not findings:
            self.print_colored("No immediate issues detected by quick scan.", "green")
        else:
            self.print_colored(" Security Scan Findings:", "red")
            for f in findings:
                logger.info(f" - {f}")

    async def list_audit_events(
        self, hours: int = 24, threat_level: str | None = None
    ) -> None:
        """List audit events from plugin security manager."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        events = []
        try:
            # plugin_sec stores events in memory - use interface if available
            summary = self.plugin_sec.get_security_summary()
            # Access the internal list if present
            internal = getattr(self.plugin_sec, "_audit_events", [])
            cutoff = datetime.now(UTC).timestamp() - (hours * 3600)
            for e in internal:
                ts = e.timestamp.timestamp() if hasattr(e.timestamp, "timestamp") else 0
                if ts >= cutoff:
                    if (
                        threat_level
                        and getattr(e.threat_level, "value", None) != threat_level
                    ):
                        continue
                    events.append(e)
        except Exception as e:
            logger.error(f"Error fetching audit events: {e}")
            self.print_colored("Failed to fetch audit events", "red")
            return

        if not events:
            self.print_colored(
                "No audit events found for the requested timeframe.", "green"
            )
            return

        self.print_colored(f" Audit Events (last {hours} hours):", "yellow")
        for e in events:
            logger.info(
                f"{e.timestamp.isoformat()} - {e.event_type.value} - {e.plugin_name} - {e.threat_level.value} - {e.description}"
            )

    async def export_audit_logs(
        self, path: str = "audit_logs.json", hours: int = 168
    ) -> None:
        """Export audit logs to a JSON file."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return

        try:
            internal = getattr(self.plugin_sec, "_audit_events", [])
            cutoff = datetime.now(UTC).timestamp() - (hours * 3600)
            export = []
            for e in internal:
                ts = e.timestamp.timestamp() if hasattr(e.timestamp, "timestamp") else 0
                if ts >= cutoff:
                    export.append(
                        {
                            "event_id": e.event_id,
                            "plugin_name": e.plugin_name,
                            "event_type": getattr(
                                e.event_type, "value", str(e.event_type)
                            ),
                            "threat_level": getattr(
                                e.threat_level, "value", str(e.threat_level)
                            ),
                            "description": e.description,
                            "timestamp": e.timestamp.isoformat(),
                            "details": e.details,
                        }
                    )
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(export, fh, indent=2)
            self.print_colored(
                f"Exported {len(export)} audit events to {path}", "green"
            )
        except Exception as e:
            logger.error(f"Failed to export audit logs: {e}")
            self.print_colored(f"Failed to export audit logs: {e}", "red")

    # Plugin Permission Management
    async def list_pending_plugin_permissions(self) -> None:
        """List pending plugin permission requests."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return

        try:
            pending = self.plugin_sec.get_pending_permission_requests()
            if not pending:
                self.print_colored("No pending plugin permission requests.", "green")
                return
            self.print_colored(" Pending Plugin Permission Requests:", "yellow")
            for r in pending:
                logger.info(
                    f"{r.plugin_name} - {r.permission_type.value} - requested_at={r.requested_at.isoformat()} - justification={r.justification}"
                )
        except Exception as e:
            logger.error(f"Error listing pending permissions: {e}")
            self.print_colored(f"Failed to fetch pending permissions: {e}", "red")

    async def approve_plugin_permission(
        self,
        plugin_name: str,
        permission: str,
        approved_by: str,
        expires_in_days: int | None = None,
    ) -> None:
        """Approve a plugin permission."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            if PermissionType:
                perm = PermissionType(permission)
            else:
                # Fallback: try string-based handling in manager
                perm = permission
            result = self.plugin_sec.approve_permission(
                plugin_name, perm, approved_by, expires_in_days
            )
            if result:
                self.print_colored(
                    f"Approved permission {permission} for {plugin_name}", "green"
                )
            else:
                self.print_colored(
                    f"Failed to approve permission (maybe not pending): {permission}",
                    "red",
                )
        except Exception as e:
            logger.error(f"Error approving permission: {e}")
            self.print_colored(f"Failed to approve permission: {e}", "red")

    async def deny_plugin_permission(
        self, plugin_name: str, permission: str, denied_by: str
    ) -> None:
        """Deny a plugin permission."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            if PermissionType:
                perm = PermissionType(permission)
            else:
                perm = permission
            result = self.plugin_sec.deny_permission(plugin_name, perm, denied_by)
            if result:
                self.print_colored(
                    f"Denied permission {permission} for {plugin_name}", "green"
                )
            else:
                self.print_colored(
                    f"Failed to deny permission (maybe not pending): {permission}",
                    "red",
                )
        except Exception as e:
            logger.error(f"Error denying permission: {e}")
            self.print_colored(f"Failed to deny permission: {e}", "red")

    async def revoke_plugin_permission(
        self, plugin_name: str, permission: str, revoked_by: str
    ) -> None:
        """Revoke an approved plugin permission."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            if PermissionType:
                perm = PermissionType(permission)
            else:
                perm = permission
            result = self.plugin_sec.revoke_permission(plugin_name, perm, revoked_by)
            if result:
                self.print_colored(
                    f"Revoked permission {permission} for {plugin_name}", "green"
                )
            else:
                self.print_colored(f"Failed to revoke permission: {permission}", "red")
        except Exception as e:
            logger.error(f"Error revoking permission: {e}")
            self.print_colored(f"Failed to revoke permission: {e}", "red")

    async def show_plugin_permissions(self, plugin_name: str) -> None:
        """Show plugin permissions and pending requests."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            perms = self.plugin_sec.get_plugin_permissions(plugin_name)
            self.print_colored(f" Permissions for plugin: {plugin_name}", "cyan")
            self.print_colored("=" * 50, "cyan")
            logger.info(
                f"Approved: {', '.join(perms.get('approved_permissions', [])) or 'None'}"
            )
            pending = perms.get("pending_requests", [])
            if pending:
                self.print_colored("\n Pending Requests:", "yellow")
                for p in pending:
                    logger.info(
                        f" {p.get('permission_type')} - {p.get('justification')} - requested_at={p.get('requested_at')}"
                    )
            else:
                logger.info("No pending requests")
            if perms.get("is_quarantined"):
                logger.info("Plugin is currently quarantined")
        except Exception as e:
            logger.error(f"Error showing plugin permissions: {e}")
            self.print_colored(f"Failed to show plugin permissions: {e}", "red")

    # Security Policy Management
    async def show_security_policy(self, plugin_name: str) -> None:
        """Show security policy for a plugin."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            policy = self.plugin_sec.get_security_policy(plugin_name)
            self.print_colored(f" Security Policy: {plugin_name}", "cyan")
            self.print_colored("=" * 50, "cyan")
            for k, v in getattr(policy, "__dict__", {}).items():
                logger.info(f"{k}: {v}")
        except Exception as e:
            logger.error(f"Error fetching security policy: {e}")
            self.print_colored(f"Failed to fetch security policy: {e}", "red")

    async def set_security_policy(self, plugin_name: str, key: str, value: str) -> None:
        """Set a single value on a plugin's security policy."""
        if not self.plugin_sec:
            self.print_colored("Plugin security manager not available.", "red")
            return
        try:
            policy = self.plugin_sec.get_security_policy(plugin_name)
            if not hasattr(policy, key):
                self.print_colored(f"Unknown policy key: {key}", "red")
                return

            current = getattr(policy, key)
            # Try to coerce value type based on current type
            new_value: Any = value
            if isinstance(current, bool):
                new_value = value.lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                new_value = int(value)
            elif isinstance(current, float):
                new_value = float(value)
            elif isinstance(current, (list, tuple, set)):
                # Accept comma-separated values
                new_value = [v.strip() for v in value.split(",") if v.strip()]

            setattr(policy, key, new_value)
            self.plugin_sec.set_security_policy(plugin_name, policy)
            self.print_colored(
                f"Updated security policy {key} for {plugin_name}", "green"
            )
        except Exception as e:
            logger.error(f"Error setting security policy: {e}")
            self.print_colored(f"Failed to set security policy: {e}", "red")

    # Key Management (Key Vault integration)
    async def list_keys(self) -> None:
        """List keys in key vault."""
        if not self.kv:
            self.print_colored("Key vault not available.", "red")
            return
        try:
            keys = self.kv.list_keys()
            if not keys:
                self.print_colored("No keys in vault.", "yellow")
                return
            self.print_colored(" Keys in Vault", "cyan")
            for k in keys:
                logger.info(
                    f" {k.get('id')} - created_at: {k.get('created_at')} - type: {k.get('type')}"
                )
        except Exception as e:
            logger.error(f"Error listing keys: {e}")
            self.print_colored(f"Failed to list keys: {e}", "red")

    async def rotate_key(self, key_id: str) -> None:
        """Rotate a key in key vault."""
        if not self.kv:
            self.print_colored("Key vault not available.", "red")
            return
        try:
            self.kv.rotate_key(key_id)
            self.print_colored(f"Rotated key: {key_id}", "green")
        except Exception as e:
            logger.error(f"Error rotating key: {e}")
            self.print_colored(f"Failed to rotate key: {e}", "red")

    async def show_key(self, key_id: str) -> None:
        """Show key details (non-sensitive metadata)."""
        if not self.kv:
            self.print_colored("Key vault not available.", "red")
            return
        try:
            meta = self.kv.get_key_metadata(key_id)
            if not meta:
                self.print_colored("Key not found.", "red")
                return
            self.print_colored(f" Key: {key_id}", "cyan")
            for k, v in meta.items():
                logger.info(f"{k}: {v}")
        except Exception as e:
            logger.error(f"Error showing key metadata: {e}")
            self.print_colored(f"Failed to show key metadata: {e}", "red")

    # Permission Management Commands (updated to use unified auth manager)
    async def list_roles(self) -> None:
        """List all roles using the auth manager."""
        self.print_colored(" User Roles", "cyan")
        self.print_colored("=" * 50, "cyan")

        roles_mapping = getattr(self.auth_manager, "role_permissions", None)
        if not roles_mapping:
            self.print_colored("No roles configured.", "yellow")
            return

        # Convert Role enum -> permission sets
        # Present a simple summary since manager doesn't carry rich metadata
        sorted_roles = sorted(roles_mapping.items(), key=lambda r: r[0].value)
        for role_enum, perms in sorted_roles:
            system_badge = (
                " [SYSTEM]"
                if getattr(role_enum, "name", "").upper() == "SYSTEM"
                else ""
            )
            default_badge = ""
            self.print_colored(
                f"\n {role_enum.value}{system_badge}{default_badge}", "blue"
            )
            logger.info(f"   Permissions: {len(perms)}")
            if len(perms) <= 10:
                perms_list = ", ".join(sorted(perms))
                logger.info(f"    {perms_list}")
            else:
                logger.info(
                    f"    {len(perms)} permissions (use 'show-role {role_enum.value}' for details)"
                )

    async def show_role(self, role_name: str) -> None:
        """Show detailed information about a role from the auth manager."""
        # Try to resolve role_name to Role enum by value or member name
        role_enum = None
        try:
            role_enum = Role(role_name)
        except Exception:
            # Try by member name (e.g., ADMIN)
            name_upper = role_name.upper()
            if name_upper in Role.__members__:
                role_enum = Role[name_upper]
        if not role_enum:
            self.print_colored(f" Role '{role_name}' not found", "red")
            return

        perms = getattr(self.auth_manager, "role_permissions", {}).get(role_enum, set())

        self.print_colored(f" Role: {role_enum.value}", "cyan")
        self.print_colored("=" * 50, "cyan")
        logger.info(f"Permissions: {len(perms)}")
        if perms:
            for perm in sorted(perms):
                logger.info(f"    {perm}")

    async def create_role(self, args: list[str]) -> None:
        """Create a new role.

        Note: Creating new Role enum members at runtime is not supported by the unified auth manager.
        This operation is not available; instruct the operator accordingly.
        """
        self.print_colored(
            "Creating custom roles is not supported via the auth manager CLI.",
            "red",
        )
        self.print_colored(
            "Define roles in code/config and restart the service to add new roles.",
            "yellow",
        )

    async def delete_role(self, role_name: str) -> None:
        """Delete a role.

        Note: Removing Role enum members at runtime is not supported.
        Instead, you can remove permissions from a role via update_user_permissions or update the code/config.
        """
        self.print_colored(
            "Deleting roles is not supported via the auth manager CLI.", "red"
        )
        self.print_colored(
            "Remove or change role definitions in code/config and restart the service.",
            "yellow",
        )

    async def assign_role(
        self,
        user_id: str,
        role_name: str,
        scope: str = "global",
        scope_id: str | None = None,
    ) -> None:
        """Assign a role to a user using auth manager."""
        # Resolve role_name to Role enum
        role_enum = None
        try:
            role_enum = Role(role_name)
        except Exception:
            name_upper = role_name.upper()
            if name_upper in Role.__members__:
                role_enum = Role[name_upper]
        if not role_enum:
            self.print_colored(f" Invalid role: {role_name}", "red")
            return

        success = self.auth_manager.assign_role(user_id, role_enum)
        if success:
            self.print_colored(
                f" Assigned role '{role_enum.value}' to user '{user_id}'", "green"
            )
        else:
            self.print_colored(" Failed to assign role", "red")

    async def revoke_role(
        self,
        user_id: str,
        role_name: str,
        scope: str = "global",
        scope_id: str | None = None,
    ) -> None:
        """Revoke a role from a user using unified auth manager."""
        role_enum = None
        try:
            role_enum = Role(role_name)
        except Exception:
            name_upper = role_name.upper()
            if name_upper in Role.__members__:
                role_enum = Role[name_upper]
        if not role_enum:
            self.print_colored(f" Invalid role: {role_name}", "red")
            return

        success = self.auth_manager.revoke_role(user_id, role_enum)
        if success:
            self.print_colored(
                f" Revoked role '{role_enum.value}' from user '{user_id}'", "green"
            )
        else:
            self.print_colored(" Failed to revoke role", "red")

    async def check_permission(
        self,
        user_id: str,
        permission: str,
        scope: str = "global",
        scope_id: str | None = None,
    ) -> None:
        """Check if a user has a specific permission using unified auth manager."""
        try:
            # UnifiedAuthManager expects a permission string
            granted = self.auth_manager.check_permission(user_id, permission)
        except Exception as e:
            self.print_colored(f" Invalid parameter or error: {e}", "red")
            return

        status = " GRANTED" if granted else " DENIED"
        self.print_colored(
            f" Permission Check: {status}", "green" if granted else "red"
        )
        logger.info(f"   User: {user_id}")
        logger.info(f"   Permission: {permission}")
        logger.info(f"   Scope: {scope}")
        if scope_id:
            logger.info(f"   Scope ID: {scope_id}")

    async def show_user_permissions(self, user_id: str) -> None:
        """Show all permissions for a user using unified auth manager."""
        try:
            perms = self.auth_manager.get_user_permissions(user_id)
            if perms is None:
                self.print_colored(f" User permissions not found: {user_id}", "red")
                return

            self.print_colored(f" User Permissions: {user_id}", "cyan")
            self.print_colored("=" * 50, "cyan")

            # Try to fetch roles if available
            roles = set()
            try:
                roles = self.auth_manager._get_user_roles(user_id)
            except Exception:
                # If private helper not available, skip roles listing
                roles = set()

            logger.info(f"Permissions count: {len(perms)}")
            if roles:
                self.print_colored("\n Roles:", "yellow")
                for role in roles:
                    logger.info(
                        f"    {role.value if hasattr(role, 'value') else str(role)}"
                    )

            if perms:
                self.print_colored("\n Explicit Permissions:", "green")
                for p in sorted(perms):
                    logger.info(f"   {p}")
            else:
                logger.info("   No explicit permissions assigned")
        except Exception as e:
            logger.error(f"Error showing user permissions: {e}")
            self.print_colored(f"Failed to show user permissions: {e}", "red")


async def handle_security_command(args: list[str]) -> None:
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
        logger.info("DDoS Protection:")
        logger.info("  ddos-status                   - Show DDoS protection status")
        logger.info(
            "  ddos-list-blocked             - List blocked IPs in DDoS protection"
        )
        logger.info(
            "  ddos-block <ip> [seconds]     - Manually block IP via DDoS protection"
        )
        logger.info("  ddos-unblock <ip>             - Unblock IP in DDoS protection")
        logger.info("  ddos-alerts [hours]           - Show recent DDoS alerts")
        logger.info("")
        logger.info("Security Scanning & Audit:")
        logger.info("  scan                          - Run quick security scan")
        logger.info("  list-audit [hours] [level]    - List audit events")
        logger.info("  export-audit <path> [hours]   - Export audit logs to JSON")
        logger.info("")
        logger.info("Key Management:")
        logger.info("  list-keys                     - List keys in key vault")
        logger.info("  rotate-key <key_id>           - Rotate key")
        logger.info("  show-key <key_id>             - Show key metadata")
        logger.info("")
        logger.info("Plugin Permissions:")
        logger.info(
            "  list-pending                  - List pending plugin permission requests"
        )
        logger.info(
            "  approve-perm <plugin> <perm> <approver> [days] - Approve permission"
        )
        logger.info("  deny-perm <plugin> <perm> <denier>          - Deny permission")
        logger.info("  revoke-perm <plugin> <perm> <revoker>      - Revoke permission")
        logger.info("  show-plugin <plugin>          - Show plugin permissions")
        logger.info("")
        logger.info("Security Policies:")
        logger.info("  show-policy <plugin>          - Show plugin security policy")
        logger.info("  set-policy <plugin> <key> <value> - Set policy key value")
        logger.info("")
        logger.info("Permissions:")
        logger.info("  list-roles                    - List all roles")
        logger.info("  show-role <name>              - Show role details")
        logger.info("  create-role <args>            - Create new role (not supported)")
        logger.info("  delete-role <name>            - Delete role (not supported)")
        logger.info("  assign-role <user> <role>     - Assign role to user")
        logger.info("  revoke-role <user> <role>     - Revoke role from user")
        logger.info("  check-perm <user> <perm>      - Check user permission")
        logger.info("  show-user <user_id>           - Show user permissions")
        return

    cli = SecurityCLI()
    command = args[0]
    command_args = args[1:]

    try:
        # Rate limiting
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

        # DDoS commands
        elif command == "ddos-status":
            await cli.show_ddos_status()
        elif command == "ddos-list-blocked":
            await cli.ddos_list_blocked()
        elif command == "ddos-block" and command_args:
            dur = int(command_args[1]) if len(command_args) > 1 else 3600
            await cli.ddos_block_ip(command_args[0], dur)
        elif command == "ddos-unblock" and command_args:
            await cli.ddos_unblock_ip(command_args[0])
        elif command == "ddos-alerts":
            hours = int(command_args[0]) if command_args else 1
            await cli.ddos_recent_alerts(hours)

        # Security scanning & audit
        elif command == "scan":
            await cli.run_security_scan()
        elif command == "list-audit":
            hours = int(command_args[0]) if command_args else 24
            level = command_args[1] if len(command_args) > 1 else None
            await cli.list_audit_events(hours, level)
        elif command == "export-audit" and command_args:
            path = command_args[0]
            hours = int(command_args[1]) if len(command_args) > 1 else 168
            await cli.export_audit_logs(path, hours)

        # Key management
        elif command == "list-keys":
            await cli.list_keys()
        elif command == "rotate-key" and command_args:
            await cli.rotate_key(command_args[0])
        elif command == "show-key" and command_args:
            await cli.show_key(command_args[0])

        # Plugin permission management
        elif command == "list-pending":
            await cli.list_pending_plugin_permissions()
        elif command == "approve-perm" and len(command_args) >= 3:
            expires = int(command_args[3]) if len(command_args) > 3 else None
            await cli.approve_plugin_permission(
                command_args[0], command_args[1], command_args[2], expires
            )
        elif command == "deny-perm" and len(command_args) >= 3:
            await cli.deny_plugin_permission(
                command_args[0], command_args[1], command_args[2]
            )
        elif command == "revoke-perm" and len(command_args) >= 3:
            await cli.revoke_plugin_permission(
                command_args[0], command_args[1], command_args[2]
            )
        elif command == "show-plugin" and command_args:
            await cli.show_plugin_permissions(command_args[0])

        # Security policies
        elif command == "show-policy" and command_args:
            await cli.show_security_policy(command_args[0])
        elif command == "set-policy" and len(command_args) >= 3:
            await cli.set_security_policy(
                command_args[0], command_args[1], command_args[2]
            )

        # Permission management (updated)
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
            await cli.check_permission(
                command_args[0], command_args[1], scope, scope_id
            )
        elif command == "show-user" and command_args:
            await cli.show_user_permissions(command_args[0])
        else:
            logger.info(f" Unknown command or missing arguments: {command}")

    except Exception as e:
        logger.info(f" Command failed: {e}")
        logger.error(f"Security CLI command failed: {e}")
