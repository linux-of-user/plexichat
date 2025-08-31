"""
Plugin SDK Integration for PlexiChat Security Module
Provides hooks for security plugins to extend functionality.

Features:
- Security event notifications
- Custom validation hooks
- Plugin security rule integration
- Extensible security architecture
"""

import asyncio
import inspect
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


class SecurityHookType(Enum):
    """Types of security hooks available."""
    PRE_REQUEST_VALIDATION = "pre_request_validation"
    POST_REQUEST_VALIDATION = "post_request_validation"
    CONTENT_VALIDATION = "content_validation"
    FILE_UPLOAD_VALIDATION = "file_upload_validation"
    AUTH_ATTEMPT = "auth_attempt"
    SESSION_VALIDATION = "session_validation"
    SECURITY_EVENT = "security_event"
    RATE_LIMIT_CHECK = "rate_limit_check"


@dataclass
class SecurityPlugin:
    """Represents a registered security plugin."""
    name: str
    version: str
    hooks: Dict[SecurityHookType, Callable]
    metadata: Dict[str, Any]
    enabled: bool = True


@dataclass
class HookContext:
    """Context passed to security hooks."""
    hook_type: SecurityHookType
    data: Dict[str, Any]
    security_context: Optional[Any] = None
    plugin_context: Dict[str, Any] = None


class SecurityPluginManager:
    """
    Manages security plugins and their hooks.

    Features:
    - Plugin registration and management
    - Hook execution orchestration
    - Plugin security validation
    - Event-driven security extensions
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)

        if not self.enabled:
            logger.info("Security plugin manager is disabled")
            return

        # Plugin storage
        self.plugins: Dict[str, SecurityPlugin] = {}
        self.hook_subscriptions: Dict[SecurityHookType, List[str]] = {}

        # Plugin security settings
        self.security_extensions_enabled = config.get('security_extensions', True)
        self.custom_validators_enabled = config.get('custom_validators', True)

        # Metrics
        self.metrics = {
            'hooks_executed': 0,
            'plugins_loaded': 0,
            'hook_errors': 0,
            'validation_extensions': 0
        }

        logger.info("Security plugin manager initialized")

    def register_plugin(self, plugin_info: Dict[str, Any]) -> bool:
        """
        Register a security plugin.

        Args:
            plugin_info: Plugin information including name, hooks, etc.

        Returns:
            True if registration successful, False otherwise
        """
        if not self.enabled:
            return False

        try:
            name = plugin_info.get('name')
            if not name:
                logger.error("Plugin registration failed: missing name")
                return False

            if name in self.plugins:
                logger.warning(f"Plugin {name} already registered, updating")
                self.unregister_plugin(name)

            # Validate plugin structure
            if not self._validate_plugin_structure(plugin_info):
                return False

            # Create plugin instance
            plugin = SecurityPlugin(
                name=name,
                version=plugin_info.get('version', '1.0.0'),
                hooks=plugin_info.get('hooks', {}),
                metadata=plugin_info.get('metadata', {}),
                enabled=plugin_info.get('enabled', True)
            )

            # Register hooks
            for hook_type, hook_func in plugin.hooks.items():
                if isinstance(hook_type, str):
                    try:
                        hook_type = SecurityHookType(hook_type)
                    except ValueError:
                        logger.error(f"Invalid hook type {hook_type} for plugin {name}")
                        continue

                if hook_type not in self.hook_subscriptions:
                    self.hook_subscriptions[hook_type] = []

                self.hook_subscriptions[hook_type].append(name)

            self.plugins[name] = plugin
            self.metrics['plugins_loaded'] += 1

            logger.info(f"Security plugin {name} v{plugin.version} registered successfully")
            return True

        except Exception as e:
            logger.error(f"Error registering plugin {plugin_info.get('name', 'unknown')}: {e}")
            return False

    def unregister_plugin(self, plugin_name: str) -> bool:
        """Unregister a security plugin."""
        if plugin_name not in self.plugins:
            return False

        # Remove from hook subscriptions
        for hook_type, subscribers in self.hook_subscriptions.items():
            if plugin_name in subscribers:
                subscribers.remove(plugin_name)

        # Remove plugin
        del self.plugins[plugin_name]
        logger.info(f"Security plugin {plugin_name} unregistered")
        return True

    def _validate_plugin_structure(self, plugin_info: Dict[str, Any]) -> bool:
        """Validate plugin structure and requirements."""
        required_fields = ['name', 'hooks']
        for field in required_fields:
            if field not in plugin_info:
                logger.error(f"Plugin missing required field: {field}")
                return False

        # Validate hooks
        hooks = plugin_info.get('hooks', {})
        if not isinstance(hooks, dict):
            logger.error("Plugin hooks must be a dictionary")
            return False

        # Validate hook functions
        for hook_type, hook_func in hooks.items():
            if not callable(hook_func):
                logger.error(f"Hook {hook_type} is not callable")
                return False

            # Check if it's a coroutine function
            if not inspect.iscoroutinefunction(hook_func):
                logger.warning(f"Hook {hook_type} is not async - wrapping as sync")

        return True

    async def execute_hook(self, hook_type: SecurityHookType, context: HookContext) -> List[Dict[str, Any]]:
        """
        Execute all plugins subscribed to a hook type.

        Args:
            hook_type: Type of hook to execute
            context: Context data for the hook

        Returns:
            List of results from all executed hooks
        """
        if not self.enabled or hook_type not in self.hook_subscriptions:
            return []

        subscribers = self.hook_subscriptions[hook_type]
        if not subscribers:
            return []

        results = []

        for plugin_name in subscribers:
            if plugin_name not in self.plugins:
                continue

            plugin = self.plugins[plugin_name]
            if not plugin.enabled:
                continue

            hook_func = plugin.hooks.get(hook_type)
            if not hook_func:
                continue

            try:
                self.metrics['hooks_executed'] += 1

                # Execute hook
                if inspect.iscoroutinefunction(hook_func):
                    result = await hook_func(context)
                else:
                    # Run sync function in thread pool
                    result = await asyncio.get_event_loop().run_in_executor(None, hook_func, context)

                results.append({
                    'plugin': plugin_name,
                    'result': result,
                    'success': True
                })

            except Exception as e:
                self.metrics['hook_errors'] += 1
                logger.error(f"Error executing hook {hook_type.value} for plugin {plugin_name}: {e}")

                results.append({
                    'plugin': plugin_name,
                    'error': str(e),
                    'success': False
                })

        return results

    async def run_security_checks(self, request_data: Any, security_context: Any) -> Dict[str, Any]:
        """
        Run security checks through registered plugins.

        Args:
            request_data: Request data to check
            security_context: Security context

        Returns:
            Dict with check results
        """
        if not self.enabled or not self.security_extensions_enabled:
            return {'allowed': True, 'message': 'Plugin security disabled'}

        try:
            context = HookContext(
                hook_type=SecurityHookType.PRE_REQUEST_VALIDATION,
                data={'request_data': request_data},
                security_context=security_context
            )

            results = await self.execute_hook(SecurityHookType.PRE_REQUEST_VALIDATION, context)

            # Aggregate results
            blocked = False
            messages = []

            for result in results:
                if not result['success']:
                    continue

                plugin_result = result['result']
                if isinstance(plugin_result, dict):
                    if not plugin_result.get('allowed', True):
                        blocked = True
                        messages.append(f"{result['plugin']}: {plugin_result.get('message', 'Blocked')}")

            return {
                'allowed': not blocked,
                'message': '; '.join(messages) if messages else 'All plugin checks passed',
                'plugin_results': results
            }

        except Exception as e:
            logger.error(f"Error running plugin security checks: {e}")
            return {'allowed': True, 'message': f'Plugin check error: {str(e)}'}

    async def validate_file_upload(self, filename: str, content_type: str, file_size: int,
                                 context: Any) -> Dict[str, Any]:
        """
        Validate file upload through plugins.

        Args:
            filename: Name of uploaded file
            content_type: MIME content type
            file_size: Size of file in bytes
            context: Security context

        Returns:
            Dict with validation results
        """
        if not self.enabled or not self.custom_validators_enabled:
            return {'allowed': True, 'message': 'Plugin validation disabled'}

        try:
            hook_context = HookContext(
                hook_type=SecurityHookType.FILE_UPLOAD_VALIDATION,
                data={
                    'filename': filename,
                    'content_type': content_type,
                    'file_size': file_size
                },
                security_context=context
            )

            results = await self.execute_hook(SecurityHookType.FILE_UPLOAD_VALIDATION, hook_context)

            # Check for blocks
            blocked = False
            messages = []

            for result in results:
                if not result['success']:
                    continue

                plugin_result = result['result']
                if isinstance(plugin_result, dict) and not plugin_result.get('allowed', True):
                    blocked = True
                    messages.append(f"{result['plugin']}: {plugin_result.get('message', 'Blocked')}")

            return {
                'allowed': not blocked,
                'message': '; '.join(messages) if messages else 'File validation passed',
                'plugin_results': results
            }

        except Exception as e:
            logger.error(f"Error in plugin file validation: {e}")
            return {'allowed': True, 'message': f'Plugin validation error: {str(e)}'}

    async def validate_message_content(self, content: str, context: Any) -> Dict[str, Any]:
        """
        Validate message content through plugins.

        Args:
            content: Message content to validate
            context: Security context

        Returns:
            Dict with validation results
        """
        if not self.enabled or not self.custom_validators_enabled:
            return {'allowed': True, 'message': 'Plugin validation disabled'}

        try:
            hook_context = HookContext(
                hook_type=SecurityHookType.CONTENT_VALIDATION,
                data={'content': content},
                security_context=context
            )

            results = await self.execute_hook(SecurityHookType.CONTENT_VALIDATION, hook_context)

            # Check for blocks
            blocked = False
            messages = []

            for result in results:
                if not result['success']:
                    continue

                plugin_result = result['result']
                if isinstance(plugin_result, dict) and not plugin_result.get('allowed', True):
                    blocked = True
                    messages.append(f"{result['plugin']}: {plugin_result.get('message', 'Blocked')}")

            return {
                'allowed': not blocked,
                'message': '; '.join(messages) if messages else 'Content validation passed',
                'plugin_results': results
            }

        except Exception as e:
            logger.error(f"Error in plugin content validation: {e}")
            return {'allowed': True, 'message': f'Plugin validation error: {str(e)}'}

    async def notify_security_event(self, event: Any):
        """
        Notify plugins of security events.

        Args:
            event: Security event to notify about
        """
        if not self.enabled:
            return

        try:
            hook_context = HookContext(
                hook_type=SecurityHookType.SECURITY_EVENT,
                data={'event': event}
            )

            await self.execute_hook(SecurityHookType.SECURITY_EVENT, hook_context)

        except Exception as e:
            logger.error(f"Error notifying plugins of security event: {e}")

    def get_plugin_status(self) -> Dict[str, Any]:
        """Get status of all registered plugins."""
        if not self.enabled:
            return {'enabled': False}

        plugin_status = {}
        for name, plugin in self.plugins.items():
            plugin_status[name] = {
                'version': plugin.version,
                'enabled': plugin.enabled,
                'hooks': list(plugin.hooks.keys()),
                'metadata': plugin.metadata
            }

        return {
            'enabled': True,
            'total_plugins': len(self.plugins),
            'enabled_plugins': len([p for p in self.plugins.values() if p.enabled]),
            'hook_subscriptions': {k.value: v for k, v in self.hook_subscriptions.items()},
            'plugins': plugin_status,
            'metrics': self.metrics
        }

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a specific plugin."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            logger.info(f"Plugin {plugin_name} enabled")
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a specific plugin."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            logger.info(f"Plugin {plugin_name} disabled")
            return True
        return False

    def update_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Update configuration for a specific plugin."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].metadata.update(config)
            logger.info(f"Plugin {plugin_name} configuration updated")
            return True
        return False

    def get_available_hooks(self) -> List[str]:
        """Get list of available hook types."""
        return [hook.value for hook in SecurityHookType]

    def update_config(self, new_config: Dict[str, Any]):
        """Update plugin manager configuration."""
        if not self.enabled:
            return

        self.config.update(new_config)
        self.security_extensions_enabled = new_config.get('security_extensions', self.security_extensions_enabled)
        self.custom_validators_enabled = new_config.get('custom_validators', self.custom_validators_enabled)

        logger.info("Plugin manager configuration updated")

    async def shutdown(self):
        """Shutdown the plugin manager."""
        # Notify plugins of shutdown
        try:
            shutdown_context = HookContext(
                hook_type=SecurityHookType.SECURITY_EVENT,
                data={'event_type': 'shutdown'}
            )

            await self.execute_hook(SecurityHookType.SECURITY_EVENT, shutdown_context)

        except Exception as e:
            logger.error(f"Error during plugin shutdown notification: {e}")

        logger.info("Security plugin manager shut down")


__all__ = ["SecurityPluginManager", "SecurityPlugin", "SecurityHookType", "HookContext"]