import asyncio
import datetime
import logging
from pathlib import Path
from typing import Any

# Try to import real managers; fall back to mocks for standalone/CI environments
try:
    from plexichat.core.plugins.manager import (
        unified_plugin_manager as real_plugin_manager,
    )
except Exception:
    real_plugin_manager = None

try:
    from plexichat.core.plugins.security_manager import (
        PermissionType as RealPermissionType,
    )
    from plexichat.core.plugins.security_manager import (
        get_security_manager as real_get_security_manager,
    )
except Exception:
    real_get_security_manager = None
    RealPermissionType = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mock implementations used when running this module standalone or during
# tests where core services are not available. These provide the minimal
# behaviour expected by the CLI to allow it to operate gracefully.
# ---------------------------------------------------------------------------

class MockPluginManager:
    def __init__(self):
        # example plugin entries
        self._plugins = {
            "example": {
                "name": "example",
                "version": "0.1.0",
                "enabled": True,
                "description": "An example plugin",
            }
        }

    def get_plugin_dashboard_data(self) -> dict[str, Any]:
        return {"plugins": list(self._plugins.values())}

    async def install_plugin_from_zip(self, zip_path: Path, source: str) -> dict[str, Any]:
        # naive install simulation
        p_name = zip_path.stem
        self._plugins[p_name] = {"name": p_name, "version": "0.0.1", "enabled": False, "description": f"Installed from {source}"}
        return {"success": True, "message": f"Installed plugin '{p_name}' from {zip_path}"}

    async def uninstall_plugin(self, plugin_name: str, remove_data: bool) -> dict[str, Any]:
        if plugin_name in self._plugins:
            del self._plugins[plugin_name]
            return {"success": True, "message": f"Uninstalled plugin '{plugin_name}'"}
        return {"success": False, "message": f"Plugin '{plugin_name}' not found"}

    def enable_plugin(self, plugin_name: str) -> bool:
        p = self._plugins.get(plugin_name)
        if not p:
            return False
        p["enabled"] = True
        return True

    def disable_plugin(self, plugin_name: str) -> bool:
        p = self._plugins.get(plugin_name)
        if not p:
            return False
        p["enabled"] = False
        return True

    async def update_plugin(self, plugin_name: str) -> dict[str, Any]:
        if plugin_name in self._plugins:
            self._plugins[plugin_name]["version"] = "updated"
            return {"success": True, "message": f"Updated plugin '{plugin_name}'"}
        return {"success": False, "message": f"Plugin '{plugin_name}' not found"}

    async def check_for_updates(self, plugin_name: str | None = None) -> dict[str, Any]:
        # Always say no updates in mock
        return {"success": True, "updates": {}}

    def get_plugin_info(self, plugin_name: str) -> dict[str, Any] | None:
        return self._plugins.get(plugin_name)


class MockSecurityManager:
    def __init__(self):
        self._approved_permissions: dict[str, set] = {}
        self._pending_requests: dict[str, list[dict[str, Any]]] = {}
        self._audit_events: list[dict[str, Any]] = []
        self._quarantined: set = set()
        self._policies: dict[str, dict[str, Any]] = {}

    def get_plugin_permissions(self, plugin_name: str) -> dict[str, Any]:
        return {
            "approved_permissions": list(self._approved_permissions.get(plugin_name, set())),
            "pending_requests": list(self._pending_requests.get(plugin_name, [])),
            "is_quarantined": plugin_name in self._quarantined,
        }

    def approve_permission(self, plugin_name: str, permission_type: Any, approved_by: str, expires_in_days: int | None = None) -> bool:
        p_val = permission_type.value if hasattr(permission_type, "value") else str(permission_type)
        self._approved_permissions.setdefault(plugin_name, set()).add(p_val)
        # Remove any pending
        pending = self._pending_requests.get(plugin_name, [])
        self._pending_requests[plugin_name] = [r for r in pending if r.get("permission_type") != p_val]
        self.log_audit_event({
            "event": "permission_granted",
            "plugin": plugin_name,
            "permission": p_val,
            "by": approved_by,
            "expires_in_days": expires_in_days,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        return True

    def deny_permission(self, plugin_name: str, permission_type: Any, denied_by: str) -> bool:
        p_val = permission_type.value if hasattr(permission_type, "value") else str(permission_type)
        pending = self._pending_requests.get(plugin_name, [])
        self._pending_requests[plugin_name] = [r for r in pending if r.get("permission_type") != p_val]
        self.log_audit_event({
            "event": "permission_denied",
            "plugin": plugin_name,
            "permission": p_val,
            "by": denied_by,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        return True

    def request_permission(self, plugin_name: str, permission_type: Any, justification: str) -> str:
        p_val = permission_type.value if hasattr(permission_type, "value") else str(permission_type)
        req = {"permission_type": p_val, "justification": justification, "requested_at": datetime.datetime.utcnow().isoformat(), "status": "pending"}
        self._pending_requests.setdefault(plugin_name, []).append(req)
        self.log_audit_event({
            "event": "permission_requested",
            "plugin": plugin_name,
            "permission": p_val,
            "justification": justification,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        return f"{plugin_name}:{p_val}:{len(self._pending_requests[plugin_name])}"

    def get_pending_permission_requests(self) -> list[dict[str, Any]]:
        out = []
        for reqs in self._pending_requests.values():
            out.extend(reqs)
        return out

    def get_security_summary(self) -> dict[str, Any]:
        return {
            "total_plugins_monitored": 0,
            "quarantined_plugins": len(self._quarantined),
            "pending_permission_requests": sum(len(v) for v in self._pending_requests.values()),
            "recent_audit_events": len(self._audit_events),
            "threat_level_distribution": {},
            "event_type_distribution": {},
            "last_24h_critical_events": 0,
        }

    def log_audit_event(self, event: dict[str, Any]):
        self._audit_events.append(event)
        # trim
        if len(self._audit_events) > 1000:
            self._audit_events = self._audit_events[-500:]
        logger.info(f"AUDIT: {event.get('event', 'unknown')} - {event.get('plugin')} - {event}")

    def get_recent_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(self._audit_events[-limit:])[::-1]

    def quarantine_plugin(self, plugin_name: str, reason: str, quarantined_by: str):
        self._quarantined.add(plugin_name)
        self.log_audit_event({"event": "plugin_quarantined", "plugin": plugin_name, "reason": reason, "by": quarantined_by, "timestamp": datetime.datetime.utcnow().isoformat()})

    def release_from_quarantine(self, plugin_name: str, released_by: str):
        self._quarantined.discard(plugin_name)
        self.log_audit_event({"event": "plugin_released", "plugin": plugin_name, "by": released_by, "timestamp": datetime.datetime.utcnow().isoformat()})

    def get_security_policy(self, plugin_name: str) -> dict[str, Any]:
        return self._policies.get(plugin_name, {})

    def set_security_policy(self, plugin_name: str, policy: dict[str, Any]):
        self._policies[plugin_name] = policy
        self.log_audit_event({"event": "policy_set", "plugin": plugin_name, "policy": policy, "timestamp": datetime.datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# Helpers to obtain manager instances (real or mock)
# ---------------------------------------------------------------------------

def get_enhanced_plugin_manager():
    if real_plugin_manager is not None:
        return real_plugin_manager
    return MockPluginManager()


def get_security_manager():
    if real_get_security_manager is not None:
        try:
            return real_get_security_manager()
        except Exception:
            # If the real factory raises, fallback to mock
            return MockSecurityManager()
    return MockSecurityManager()


# Helper to map permission string to PermissionType if available
def resolve_permission_type(permission_str: str):
    if RealPermissionType is None:
        # Return the raw string in mock scenarios
        return permission_str
    try:
        # allow both exact value and name
        # PermissionType has values like "file_read"
        for p in RealPermissionType:
            if p.value == permission_str or p.name.lower() == permission_str.lower():
                return p
        # last attempt: construct from value
        return RealPermissionType(permission_str)
    except Exception:
        # fallback to string
        return permission_str


# ---------------------------------------------------------------------------
# CLI Implementation
# ---------------------------------------------------------------------------

class PluginCLI:
    """Command-line interface for plugin management."""
    def __init__(self):
        self.plugin_manager = get_enhanced_plugin_manager()
        self.security_manager = get_security_manager()

    async def cmd_list(self, args: list[str]):
        """List all installed plugins."""
        data = self.plugin_manager.get_plugin_dashboard_data()
        plugins = data.get("plugins", [])
        if not plugins:
            logger.info("No plugins installed.")
            return
        for plugin in plugins:
            name = plugin.get('name') or plugin.get('plugin_id') or "<unknown>"
            version = plugin.get('version', "unknown")
            enabled = plugin.get('enabled', False)
            logger.info(f"- {name} v{version} [{'enabled' if enabled else 'disabled'}] - {plugin.get('description', '')}")

    async def cmd_install(self, args: list[str]):
        """Install a plugin from a ZIP file."""
        if not args:
            logger.error("Usage: plugin install <zip_file>")
            return
        zip_path = Path(args[0])
        if not zip_path.exists():
            logger.error(f"File not found: {zip_path}")
            return
        result = await self.plugin_manager.install_plugin_from_zip(zip_path, 'local')
        logger.info(result.get("message"))

    async def cmd_uninstall(self, args: list[str]):
        """Uninstall a plugin."""
        if not args:
            logger.error("Usage: plugin uninstall <plugin_name> [--remove-data]")
            return
        plugin_name = args[0]
        remove_data = '--remove-data' in args or '--purge' in args
        result = await self.plugin_manager.uninstall_plugin(plugin_name, remove_data)
        logger.info(result.get("message"))

    async def cmd_enable(self, args: list[str]):
        """Enable a plugin."""
        if not args:
            logger.error("Usage: plugin enable <plugin_name>")
            return
        plugin_name = args[0]
        ok = self.plugin_manager.enable_plugin(plugin_name)
        if asyncio.iscoroutine(ok):
            ok = await ok
        if ok:
            logger.info(f"Plugin '{plugin_name}' enabled.")
        else:
            logger.error(f"Failed to enable plugin '{plugin_name}'.")

    async def cmd_disable(self, args: list[str]):
        """Disable a plugin."""
        if not args:
            logger.error("Usage: plugin disable <plugin_name>")
            return
        plugin_name = args[0]
        ok = self.plugin_manager.disable_plugin(plugin_name)
        if asyncio.iscoroutine(ok):
            ok = await ok
        if ok:
            logger.info(f"Plugin '{plugin_name}' disabled.")
        else:
            logger.error(f"Failed to disable plugin '{plugin_name}'.")

    async def cmd_update(self, args: list[str]):
        """Update a plugin."""
        if not args:
            logger.error("Usage: plugin update <plugin_name>")
            return
        plugin_name = args[0]
        result = await self.plugin_manager.update_plugin(plugin_name)
        logger.info(result.get("message"))

    async def cmd_check_updates(self, args: list[str]):
        """Check for plugin updates."""
        target = args[0] if args else None
        result = await self.plugin_manager.check_for_updates(target)
        updates = result.get("updates", {})
        if not updates:
            logger.info("All plugins are up-to-date.")
        else:
            logger.info(f"Updates available for: {', '.join(updates.keys())}")

    # ----------------------
    # Security / Permissions
    # ----------------------

    async def cmd_permissions(self, args: list[str]):
        """List permissions for a plugin or all pending requests.
        Usage: plugin permissions <plugin_name>
               plugin permissions pending
        """
        if not args:
            logger.error("Usage: plugin permissions <plugin_name> | pending")
            return
        key = args[0]
        if key.lower() == "pending":
            pending = self.security_manager.get_pending_permission_requests() if hasattr(self.security_manager, "get_pending_permission_requests") else []
            if not pending:
                logger.info("No pending permission requests.")
                return
            for req in pending:
                logger.info(f"- Plugin: {req.get('plugin_name') or req.get('plugin', '<unknown>')} Permission: {req.get('permission_type')} Justification: {req.get('justification')}")
            return

        plugin_name = key
        perms = {}
        try:
            perms = self.security_manager.get_plugin_permissions(plugin_name)
        except Exception as e:
            logger.error(f"Failed to retrieve permissions: {e}")
            return
        logger.info(f"Permissions for plugin '{plugin_name}':")
        logger.info(f"  Approved: {perms.get('approved_permissions', [])}")
        logger.info(f"  Pending: {[p.get('permission_type') for p in perms.get('pending_requests', [])]}")
        logger.info(f"  Quarantined: {perms.get('is_quarantined', False)}")

    async def cmd_request_permission(self, args: list[str]):
        """Request a permission for a plugin.
        Usage: plugin request-permission <plugin_name> <permission> [justification...]
        """
        if len(args) < 2:
            logger.error("Usage: plugin request-permission <plugin_name> <permission> [justification]")
            return
        plugin_name = args[0]
        permission = args[1]
        justification = " ".join(args[2:]) if len(args) > 2 else "Requested via CLI"
        p_type = resolve_permission_type(permission)
        if hasattr(self.security_manager, "request_permission"):
            req_id = self.security_manager.request_permission(plugin_name, p_type, justification)
            logger.info(f"Permission requested: {req_id}")
        else:
            logger.error("Security manager does not support permission requests in this environment.")

    async def cmd_approve_permission(self, args: list[str]):
        """Approve a permission request.
        Usage: plugin approve-permission <plugin_name> <permission> [expires_days]
        """
        if len(args) < 2:
            logger.error("Usage: plugin approve-permission <plugin_name> <permission> [expires_days]")
            return
        plugin_name = args[0]
        permission = args[1]
        expires = int(args[2]) if len(args) > 2 else None
        p_type = resolve_permission_type(permission)
        approved_by = "cli"
        if hasattr(self.security_manager, "approve_permission"):
            ok = self.security_manager.approve_permission(plugin_name, p_type, approved_by, expires)
            if asyncio.iscoroutine(ok):
                ok = await ok
            if ok:
                logger.info(f"Permission '{permission}' approved for plugin '{plugin_name}'.")
            else:
                logger.error(f"Failed to approve permission '{permission}' for plugin '{plugin_name}'.")
        else:
            # fallback to mock method name approve_permission may not exist
            try:
                ok = self.security_manager.approve_permission(plugin_name, p_type, approved_by, expires)
                logger.info(f"Permission '{permission}' approved for plugin '{plugin_name}': {ok}")
            except Exception as e:
                logger.error(f"Security manager cannot approve permissions: {e}")

    async def cmd_deny_permission(self, args: list[str]):
        """Deny a permission request.
        Usage: plugin deny-permission <plugin_name> <permission>
        """
        if len(args) < 2:
            logger.error("Usage: plugin deny-permission <plugin_name> <permission>")
            return
        plugin_name = args[0]
        permission = args[1]
        p_type = resolve_permission_type(permission)
        denied_by = "cli"
        if hasattr(self.security_manager, "deny_permission"):
            ok = self.security_manager.deny_permission(plugin_name, p_type, denied_by)
            if asyncio.iscoroutine(ok):
                ok = await ok
            if ok:
                logger.info(f"Permission '{permission}' denied for plugin '{plugin_name}'.")
            else:
                logger.error(f"Failed to deny permission '{permission}' for plugin '{plugin_name}'.")
        else:
            logger.error("Security manager does not support denying permissions in this environment.")

    async def cmd_view_security(self, args: list[str]):
        """View security summary or plugin-specific security status.
        Usage: plugin view-security [plugin_name]
        """
        if not args:
            try:
                summary = self.security_manager.get_security_summary() if hasattr(self.security_manager, "get_security_summary") else {}
                logger.info("Security Summary:")
                for k, v in (summary or {}).items():
                    logger.info(f"  {k}: {v}")
            except Exception as e:
                logger.error(f"Failed to get security summary: {e}")
            return

        plugin_name = args[0]
        try:
            perms = self.security_manager.get_plugin_permissions(plugin_name)
            logger.info(f"Security status for '{plugin_name}':")
            logger.info(f"  Approved: {perms.get('approved_permissions', [])}")
            logger.info(f"  Pending: {[p.get('permission_type') for p in perms.get('pending_requests', [])]}")
            logger.info(f"  Quarantined: {perms.get('is_quarantined', False)}")
            policy = self.security_manager.get_security_policy(plugin_name) if hasattr(self.security_manager, "get_security_policy") else None
            if policy:
                logger.info(f"  Policy: {policy}")
        except Exception as e:
            logger.error(f"Failed to get plugin security info: {e}")

    async def cmd_quarantine(self, args: list[str]):
        """Quarantine a plugin due to security concerns.
        Usage: plugin quarantine <plugin_name> <reason...>
        """
        if len(args) < 2:
            logger.error("Usage: plugin quarantine <plugin_name> <reason>")
            return
        plugin_name = args[0]
        reason = " ".join(args[1:])
        if hasattr(self.security_manager, "quarantine_plugin"):
            self.security_manager.quarantine_plugin(plugin_name, reason, "cli")
            logger.critical(f"Plugin '{plugin_name}' quarantined: {reason}")
        else:
            logger.error("Security manager does not support quarantining in this environment.")

    async def cmd_release(self, args: list[str]):
        """Release a plugin from quarantine.
        Usage: plugin release <plugin_name>
        """
        if not args:
            logger.error("Usage: plugin release <plugin_name>")
            return
        plugin_name = args[0]
        if hasattr(self.security_manager, "release_from_quarantine"):
            ok = self.security_manager.release_from_quarantine(plugin_name, "cli")
            if asyncio.iscoroutine(ok):
                ok = await ok
            if ok:
                logger.info(f"Plugin '{plugin_name}' released from quarantine.")
            else:
                logger.error(f"Failed to release plugin '{plugin_name}' from quarantine.")
        else:
            logger.error("Security manager does not support release operation in this environment.")

    async def cmd_sandbox_status(self, args: list[str]):
        """Show sandbox status for a plugin. This will create/inspect the sandbox.
        Usage: plugin sandbox-status <plugin_name>
        """
        if not args:
            logger.error("Usage: plugin sandbox-status <plugin_name>")
            return
        plugin_name = args[0]
        if hasattr(self.security_manager, "create_sandbox") and hasattr(self.security_manager, "get_security_policy"):
            try:
                sandbox = self.security_manager.create_sandbox(plugin_name)
                policy = self.security_manager.get_security_policy(plugin_name)
                logger.info(f"Sandbox for '{plugin_name}' created/inspected. Policy: {policy}")
                # Try to extract resource summary safely
                try:
                    usage = sandbox.resource_monitor.get_usage_summary() if hasattr(sandbox, "resource_monitor") else {}
                    files = sandbox.file_access_monitor.get_access_summary() if hasattr(sandbox, "file_access_monitor") else {}
                    net = sandbox.network_monitor.get_connection_summary() if hasattr(sandbox, "network_monitor") else {}
                    logger.info(f"  Resource usage summary: {usage}")
                    logger.info(f"  File access summary: {files}")
                    logger.info(f"  Network summary: {net}")
                except Exception as e:
                    logger.warning(f"Could not retrieve detailed sandbox metrics: {e}")
            except Exception as e:
                logger.error(f"Failed to create/inspect sandbox: {e}")
        else:
            logger.error("Sandboxing APIs are not available in this environment.")

    async def cmd_set_policy(self, args: list[str]):
        """Set a simple security policy for a plugin.
        Usage: plugin set-policy <plugin_name> key=value [key2=value2 ...]
        Example: plugin set-policy example max_memory_bytes=104857600 max_cpu_percent=5.0
        """
        if len(args) < 2:
            logger.error("Usage: plugin set-policy <plugin_name> key=value [key2=value2 ...]")
            return
        plugin_name = args[0]
        kv_pairs = args[1:]
        policy_changes = {}
        for kv in kv_pairs:
            if '=' not in kv:
                logger.warning(f"Ignoring invalid policy entry: {kv}")
                continue
            k, v = kv.split('=', 1)
            # Try to coerce values to int/float/bool
            if v.lower() in ("true", "false"):
                val = v.lower() == "true"
            else:
                try:
                    if '.' in v:
                        val = float(v)
                    else:
                        val = int(v)
                except Exception:
                    val = v
            policy_changes[k] = val
        if hasattr(self.security_manager, "set_security_policy"):
            self.security_manager.set_security_policy(plugin_name, policy_changes)
            logger.info(f"Policy updated for plugin '{plugin_name}': {policy_changes}")
        else:
            logger.error("Security manager does not support policy updates in this environment.")

    async def cmd_audit(self, args: list[str]):
        """Show recent audit events.
        Usage: plugin audit [limit]
        """
        limit = int(args[0]) if args and args[0].isdigit() else 50
        events = []
        if hasattr(self.security_manager, "get_recent_audit_events"):
            events = self.security_manager.get_recent_audit_events(limit=limit)
        else:
            # try to access internal audit list (fallback)
            events = getattr(self.security_manager, "_audit_events", [])[-limit:]
        if not events:
            logger.info("No audit events found.")
            return
        for ev in events:
            logger.info(f"- {ev.get('timestamp', ev.get('time', ''))} {ev.get('event', ev.get('event_type', ''))} Plugin: {ev.get('plugin')} Details: {ev}")

    # Main dispatcher
    async def execute_command(self, command: str, args: list[str]):
        """Execute a plugin CLI command."""
        commands = {
            "list": self.cmd_list,
            "install": self.cmd_install,
            "uninstall": self.cmd_uninstall,
            "enable": self.cmd_enable,
            "disable": self.cmd_disable,
            "update": self.cmd_update,
            "check-updates": self.cmd_check_updates,
            "permissions": self.cmd_permissions,
            "request-permission": self.cmd_request_permission,
            "approve-permission": self.cmd_approve_permission,
            "deny-permission": self.cmd_deny_permission,
            "view-security": self.cmd_view_security,
            "quarantine": self.cmd_quarantine,
            "release": self.cmd_release,
            "sandbox-status": self.cmd_sandbox_status,
            "set-policy": self.cmd_set_policy,
            "audit": self.cmd_audit,
        }
        handler = commands.get(command)
        if handler:
            await handler(args)
        else:
            logger.error(f"Unknown command: {command}")
            logger.info("Available commands: " + ", ".join(sorted(commands.keys())))


# ---------------------------------------------------------------------------
# Entry point helper
# ---------------------------------------------------------------------------

async def handle_plugin_command(args: list[str]):
    """Handle plugin CLI commands."""
    if not args:
        logger.info("Usage: plugin <command> [args...]")
        logger.info("Try: plugin list | install | uninstall | enable | disable | permissions | approve-permission")
        return

    plugin_cli = PluginCLI()
    command, *command_args = args
    await plugin_cli.execute_command(command, command_args)


if __name__ == '__main__':
    # Example usage: python -m plexichat.interfaces.cli.commands.plugins list
    import sys
    if len(sys.argv) > 1:
        asyncio.run(handle_plugin_command(sys.argv[1:]))
    else:
        print("Please provide a command: list, install, uninstall, enable, disable, permissions, approve-permission, etc.")
