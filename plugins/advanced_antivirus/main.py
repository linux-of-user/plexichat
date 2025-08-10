from plugins_internal import EnhancedBasePlugin, EnhancedPluginConfig
from .comprehensive_antivirus_manager import EnhancedAntivirusManager

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
        self.logger.info("Initializing Advanced Antivirus Plugin...")

        # Pass the SDK's api object to the manager
        self.manager = EnhancedAntivirusManager(api=self.api)
        await self.manager.initialize()

        self.logger.info("Advanced Antivirus Plugin initialized successfully.")

    async def cleanup(self):
        """Shutdown the antivirus manager on plugin cleanup."""
        if self.manager:
            await self.manager.shutdown()
            self.logger.info("Advanced Antivirus Manager has been shut down.")

# Instantiate the plugin for the plugin manager to discover
plugin = AdvancedAntivirusPlugin()
