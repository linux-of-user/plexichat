"""
Base Module for PlexiChat Infrastructure

This module provides base classes and interfaces for all PlexiChat modules.
It re-exports the main interfaces and base classes from interfaces.py
to maintain backward compatibility with existing imports.
"""

# Re-export everything from interfaces to maintain compatibility
from .interfaces import ()
    # Enums and types
    ModuleCapability,
    ModulePriority,
    ModuleState,

    # Data classes
    ModulePermissions,
    ModuleMetrics,
    ModuleConfiguration,

    # Interfaces
    IModuleLifecycle,
    IModuleConfiguration,
    IModuleAPI,
    IModuleSecurity,

    # Base class
    BaseModule,
)

# Export all the main classes and interfaces
__all__ = [
    # From interfaces
    "ModuleCapability",
    "ModulePriority",
    "ModuleState",
    "ModulePermissions",
    "ModuleMetrics",
    "ModuleConfiguration",
    "IModuleLifecycle",
    "IModuleConfiguration",
    "IModuleAPI",
    "IModuleSecurity",
    "BaseModule",
]
