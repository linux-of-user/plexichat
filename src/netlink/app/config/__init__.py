# app/config/__init__.py
"""
Configuration management package for Chat API.
Provides centralized configuration handling with validation and documentation.
"""

from .config_manager import config_manager, ConfigurationManager, ConfigValidationError

__all__ = ["config_manager", "ConfigurationManager", "ConfigValidationError"]
