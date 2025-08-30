import logging
import importlib

# Attempt to import the SDK-generated plugins_internal in a robust way so the plugin
# will work whether the SDK file is provided as plexichat.plugins_internal or as a
# top-level plugins_internal module. If neither import is available, provide a
# lightweight fallback to avoid hard crashes during discovery / testing.
try:
    # Preferred import when the SDK is installed as part of the plexichat package.
    from plexichat.plugins_internal import EnhancedBasePlugin, EnhancedPluginConfig  # type: ignore
except Exception:
    try:
        # Fallback to a top-level import which some runtime layouts may use.
        from plugins_internal import EnhancedBasePlugin, EnhancedPluginConfig  # type: ignore
    except Exception:
        # Final attempt: try to import dynamically using importlib with common names.
        _candidates = [
            "plexichat.plugins_internal",
            "plugins_internal",
            "plexichat.plugins_internal",
        ]
        EnhancedBasePlugin = None
        EnhancedPluginConfig = None
        for _mod in _candidates:
            try:
                module = importlib.import_module(_mod)
                EnhancedBasePlugin = getattr(module, "EnhancedBasePlugin", None)
                EnhancedPluginConfig = getattr(module, "EnhancedPluginConfig", None)
                if EnhancedBasePlugin and EnhancedPluginConfig:
                    break
            except Exception:
                continue

        if not (EnhancedBasePlugin and EnhancedPluginConfig):
            # If all import attempts failed, provide safe fallback implementations.
            logger = logging.getLogger(__name__)
            logger.warning(
                "Could not import plugins_internal SDK (tried %s). "
                "Using local fallback implementations. "
                "This should be replaced by the real SDK in production.",
                ", ".join(_candidates),
            )

            class EnhancedPluginConfig:
                """
                Minimal fallback config object for plugin discovery and testing.
                Matches the fields used by AdvancedAntivirusPlugin in this module.
                """

                def __init__(
                    self,
                    name: str,
                    version: str = "0.0.0",
                    description: str = "",
                    author: str = "",
                    plugin_type: str = "",
                    tags: list | None = None,
                ):
                    self.name = name
                    self.version = version
                    self.description = description
                    self.author = author
                    self.plugin_type = plugin_type
                    self.tags = tags or []

                def to_dict(self):
                    return {
                        "name": self.name,
                        "version": self.version,
                        "description": self.description,
                        "author": self.author,
                        "plugin_type": self.plugin_type,
                        "tags": list(self.tags),
                    }

            class EnhancedBasePlugin:
                """
                Minimal fallback base plugin class.
                Provides the attributes and basic lifecycle methods expected by the plugin
                system and by AdvancedAntivirusPlugin in this module.
                """

                def __init__(self, config: EnhancedPluginConfig):
                    self.config = config
                    # Plugin-specific logger
                    self.logger = logging.getLogger(f"plugin.{getattr(config, 'name', 'unknown')}")
                    # Basic API surface that plugin code may expect (logger only)
                    self.api = type("API", (), {"logger": self.logger})()
                    self.enabled = False
                    self._initialized = False

                async def _initialize(self):
                    """
                    Fallback initialize - real SDK will provide richer behavior.
                    """
                    self.logger.debug("Fallback EnhancedBasePlugin._initialize called")
                    self._initialized = True
                    return True

                async def cleanup(self):
                    """
                    Fallback cleanup - real SDK will do proper resource cleanup.
                    """
                    self.logger.debug("Fallback EnhancedBasePlugin.cleanup called")
                    self.enabled = False
                    self._initialized = False

                def is_initialized(self) -> bool:
                    return bool(self._initialized)

                def enable(self) -> None:
                    if self._initialized:
                        self.enabled = True
                        self.logger.info("Plugin enabled (fallback)")
                    else:
                        self.logger.warning("Cannot enable uninitialized plugin (fallback)")

                def disable(self) -> None:
                    self.enabled = False
                    self.logger.info("Plugin disabled (fallback)")

# Import the EnhancedAntivirusManager from the plugin package.
# This import assumes the module layout where this file lives at:
# plugins/advanced_antivirus/main.py and the manager is in:
# plugins/advanced_antivirus/comprehensive_antivirus_manager.py
try:
    from plugins.advanced_antivirus.comprehensive_antivirus_manager import EnhancedAntivirusManager  # type: ignore
except Exception:
    # If that import fails, provide a lightweight fallback manager so the plugin
    # can still be discovered and won't crash immediately. The real manager will
    # be used when SDK and package layout are correct.
    logging.getLogger(__name__).warning(
        "Could not import EnhancedAntivirusManager from plugins.advanced_antivirus. "
        "Using fallback stub. Ensure comprehensive_antivirus_manager is available."
    )

    class EnhancedAntivirusManager:
        """
        Fallback stub manager. Real manager should implement initialize and shutdown
        and accept an 'api' keyword argument.
        """

        def __init__(self, api=None, **kwargs):
            self.api = api
            self.logger = getattr(api, "logger", logging.getLogger("EnhancedAntivirusManager"))

        async def initialize(self):
            self.logger.info("Fallback EnhancedAntivirusManager.initialize called")

        async def shutdown(self):
            self.logger.info("Fallback EnhancedAntivirusManager.shutdown called")


class AdvancedAntivirusPlugin(EnhancedBasePlugin):
    """
    Advanced Antivirus Plugin for PlexiChat.
    Integrates a comprehensive scanning engine into the PlexiChat ecosystem.
    """

    def __init__(self):
        config = EnhancedPluginConfig(
            name="AdvancedAntivirus",
            version="1.1.0",
            description="Comprehensive antivirus and security scanning system.",
            author="PlexiChat Security Team",
            plugin_type="security_node",
            tags=["antivirus", "security", "malware", "scanner"],
        )
        super().__init__(config)
        self.manager = None

    async def _initialize(self):
        """
        Initialize the plugin and the antivirus manager.
        The `self.api` object from the SDK is passed down to the manager,
        which will then pass it to the engine and its sub-components.
        This ensures all parts of the plugin use the unified SDK for
        database access, caching, and logging.
        """
        # Ensure logger exists on base class or fallback
        if not hasattr(self, "logger") or self.logger is None:
            self.logger = logging.getLogger(f"plugin.{getattr(self.config, 'name', 'AdvancedAntivirus')}")

        self.logger.info("Initializing Advanced Antivirus Plugin...")

        # Pass the SDK's api object to the manager
        try:
            self.manager = EnhancedAntivirusManager(api=getattr(self, "api", None))
            await self.manager.initialize()
            self.logger.info("Advanced Antivirus Plugin initialized successfully.")
        except Exception as e:
            self.logger.error("Failed to initialize EnhancedAntivirusManager: %s", e)
            raise

    async def cleanup(self):
        """Shutdown the antivirus manager on plugin cleanup."""
        if self.manager:
            try:
                await self.manager.shutdown()
                self.logger.info("Advanced Antivirus Manager has been shut down.")
            except Exception as e:
                self.logger.error("Error shutting down EnhancedAntivirusManager: %s", e)

# Instantiate the plugin for the plugin manager to discover
plugin = AdvancedAntivirusPlugin()
