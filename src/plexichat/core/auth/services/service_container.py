"""
Authentication Service Container
Manages dependency injection and service lifecycle for authentication components.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Type, TypeVar
from weakref import WeakValueDictionary

from plexichat.core.logging import get_logger

from .interfaces import (
    IAuditService,
    IAuthenticationService,
    IMFAProvider,
    ISessionService,
    ITokenService,
    IUserService,
)

logger = get_logger(__name__)

T = TypeVar("T")


class AuthServiceContainer:
    """
    Service container for authentication services with dependency injection.
    Manages service registration, resolution, and lifecycle.
    """

    def __init__(self):
        self._services: Dict[Type, Any] = {}
        self._singletons: Dict[Type, Any] = {}
        self._factories: Dict[Type, callable] = {}
        self._scoped_instances: WeakValueDictionary = WeakValueDictionary()
        self._lock = asyncio.Lock()

    def register_singleton(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a singleton service."""
        self._services[interface] = implementation
        logger.debug(
            f"Registered singleton service: {interface.__name__} -> {implementation.__name__}"
        )

    def register_transient(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a transient service (new instance each time)."""
        self._services[interface] = implementation
        logger.debug(
            f"Registered transient service: {interface.__name__} -> {implementation.__name__}"
        )

    def register_factory(self, interface: Type[T], factory: callable) -> None:
        """Register a factory function for service creation."""
        self._factories[interface] = factory
        logger.debug(f"Registered factory for service: {interface.__name__}")

    def register_instance(self, interface: Type[T], instance: T) -> None:
        """Register a pre-created instance as a singleton."""
        self._singletons[interface] = instance
        logger.debug(f"Registered instance for service: {interface.__name__}")

    async def resolve(self, interface: Type[T]) -> T:
        """Resolve a service instance."""
        async with self._lock:
            # Check for existing singleton
            if interface in self._singletons:
                return self._singletons[interface]

            # Check for factory
            if interface in self._factories:
                instance = await self._create_instance_with_factory(interface)
                if self._is_singleton(interface):
                    self._singletons[interface] = instance
                return instance

            # Check for registered service
            if interface in self._services:
                instance = await self._create_instance(interface)
                if self._is_singleton(interface):
                    self._singletons[interface] = instance
                return instance

            from plexichat.core.exceptions import SystemError, ErrorCode`n            raise SystemError(`n                f"No registration found for service: {interface.__name__}",`n                ErrorCode.SYSTEM_INTERNAL_ERROR,`n                component="service_container",`n                resource_type="service_registration",`n                resource_id=interface.__name__`n            )

    async def _create_instance_with_factory(self, interface: Type[T]) -> T:
        """Create instance using factory function."""
        factory = self._factories[interface]
        try:
            if asyncio.iscoroutinefunction(factory):
                instance = await factory()
            else:
                instance = factory()
            return instance
        except Exception as e:
            logger.error(
                f"Error creating service instance with factory for {interface.__name__}: {e}"
            )
            raise

    async def _create_instance(self, interface: Type[T]) -> T:
        """Create service instance with dependency injection."""
        implementation = self._services[interface]

        try:
            # Get constructor parameters
            import inspect

            sig = inspect.signature(implementation.__init__)
            params = {}

            for param_name, param in sig.parameters.items():
                if param_name == "self":
                    continue

                # Try to resolve dependencies
                if param.annotation != inspect.Parameter.empty:
                    try:
                        resolved = await self.resolve(param.annotation)
                        params[param_name] = resolved
                    except ValueError:
                        # If dependency cannot be resolved, use default or skip
                        if param.default == inspect.Parameter.empty:
                            logger.warning(
                                f"Cannot resolve dependency {param.annotation} for {implementation.__name__}.{param_name}"
                            )
                        pass
                elif param.default == inspect.Parameter.empty:
                    logger.warning(
                        f"No type annotation for parameter {param_name} in {implementation.__name__}"
                    )

            instance = implementation(**params)
            return instance

        except Exception as e:
            logger.error(
                f"Error creating service instance for {interface.__name__}: {e}"
            )
            raise

    def _is_singleton(self, interface: Type) -> bool:
        """Check if service should be singleton (based on naming convention)."""
        # Services ending with 'Service' are typically singletons
        # This is a simple heuristic - could be made more sophisticated
        return interface.__name__.endswith("Service")

    async def dispose(self) -> None:
        """Dispose of all services and clean up resources."""
        async with self._lock:
            # Dispose of singleton instances
            for interface, instance in self._singletons.items():
                if hasattr(instance, "dispose"):
                    try:
                        if asyncio.iscoroutinefunction(instance.dispose):
                            await instance.dispose()
                        else:
                            instance.dispose()
                    except Exception as e:
                        logger.error(
                            f"Error disposing service {interface.__name__}: {e}"
                        )

            # Clear all registrations
            self._services.clear()
            self._singletons.clear()
            self._factories.clear()
            self._scoped_instances.clear()

            logger.info("Authentication service container disposed")

    def get_registered_services(self) -> Dict[str, str]:
        """Get list of registered services for debugging."""
        services = {}
        for interface in self._services:
            services[interface.__name__] = self._services[interface].__name__
        for interface in self._factories:
            services[interface.__name__] = "Factory"
        for interface in self._singletons:
            services[interface.__name__] = type(self._singletons[interface]).__name__
        return services

    @asynccontextmanager
    async def scoped_container(self):
        """Create a scoped container for request-specific services."""
        scoped = AuthServiceContainer()

        # Copy singleton registrations
        scoped._services = self._services.copy()
        scoped._factories = self._factories.copy()
        scoped._singletons = self._singletons.copy()

        try:
            yield scoped
        finally:
            await scoped.dispose()


# Global service container instance
_container_instance: Optional[AuthServiceContainer] = None


def get_service_container() -> AuthServiceContainer:
    """Get the global service container instance."""
    global _container_instance
    if _container_instance is None:
        _container_instance = AuthServiceContainer()
    return _container_instance


def reset_service_container() -> AuthServiceContainer:
    """Reset the global service container (for testing)."""
    global _container_instance
    if _container_instance:
        asyncio.create_task(_container_instance.dispose())
    _container_instance = AuthServiceContainer()
    return _container_instance


__all__ = ["AuthServiceContainer", "get_service_container", "reset_service_container"]
