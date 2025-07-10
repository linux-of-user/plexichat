"""
NetLink AI-Powered Features Service Integration

Handles initialization, lifecycle management, and integration of AI-powered features
with NetLink's main application and service management framework.
"""

import asyncio
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from ..ai.features.ai_powered_features_service import AIPoweredFeaturesService
from ..core.logging import get_logger
from ..core.config import get_config
from ..core.service_manager import ServiceManager, BaseService

logger = get_logger(__name__)


class AIPoweredFeaturesIntegration(BaseService):
    """Integration service for AI-powered features."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("ai_powered_features", config or {})
        self.ai_features_service: Optional[AIPoweredFeaturesService] = None
        self._initialized = False
        self._startup_tasks = []
        
    async def initialize(self) -> bool:
        """Initialize the AI-powered features service."""
        try:
            logger.info("🤖 Initializing AI-Powered Features service...")
            
            # Load configuration
            config = await self._load_configuration()
            
            # Create service instance
            self.ai_features_service = AIPoweredFeaturesService(config)
            
            # Perform health check
            health = await self.ai_features_service.health_check()
            if health.get("service_state") != "running":
                logger.warning("⚠️ AI-Powered Features service health check failed")
                return False
            
            # Initialize semantic search index if needed
            await self._initialize_semantic_index()
            
            # Register with service manager
            service_manager = ServiceManager.get_instance()
            if service_manager:
                service_manager.register_service("ai_powered_features", self)
            
            self._initialized = True
            logger.info("✅ AI-Powered Features service initialized successfully")
            
            # Log available features
            await self._log_available_features()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize AI-Powered Features service: {e}")
            return False
    
    async def start(self) -> bool:
        """Start the AI-powered features service."""
        if not self._initialized:
            if not await self.initialize():
                return False
        
        try:
            logger.info("🚀 Starting AI-Powered Features service...")
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Warm up caches if configured
            await self._warm_up_caches()
            
            self.status = "running"
            logger.info("✅ AI-Powered Features service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to start AI-Powered Features service: {e}")
            self.status = "error"
            return False
    
    async def stop(self) -> bool:
        """Stop the AI-powered features service."""
        try:
            logger.info("🛑 Stopping AI-Powered Features service...")
            
            # Stop background tasks
            await self._stop_background_tasks()
            
            # Save any pending data
            if self.ai_features_service:
                await self.ai_features_service.save_configuration()
            
            self.status = "stopped"
            logger.info("✅ AI-Powered Features service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to stop AI-Powered Features service: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the AI-powered features service."""
        if not self.ai_features_service:
            return {
                "status": "error",
                "message": "Service not initialized",
                "timestamp": self._get_timestamp()
            }
        
        try:
            health = await self.ai_features_service.health_check()
            return {
                "status": "healthy" if health.get("service_state") == "running" else "unhealthy",
                "details": health,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": self._get_timestamp()
            }
    
    def get_service(self) -> Optional[AIPoweredFeaturesService]:
        """Get the AI-powered features service instance."""
        return self.ai_features_service
    
    async def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration for AI-powered features."""
        try:
            # Get base configuration
            base_config = get_config()
            ai_features_config = base_config.get("ai_powered_features", {})
            
            # Set default configuration paths
            config_dir = Path("config")
            config_dir.mkdir(exist_ok=True)
            
            default_config = {
                "config_path": str(config_dir / "ai_powered_features.yaml"),
                "cache_dir": str(Path("data") / "ai_features_cache"),
                "summarization": {
                    "enabled": True,
                    "model_preference": ["gpt-4", "claude-3-sonnet", "gpt-3.5-turbo"],
                    "max_length": 500,
                    "cache_ttl": 3600
                },
                "content_suggestions": {
                    "enabled": True,
                    "max_suggestions": 5,
                    "cache_ttl": 1800
                },
                "sentiment_analysis": {
                    "enabled": True,
                    "include_emotions": True,
                    "cache_ttl": 3600
                },
                "semantic_search": {
                    "enabled": True,
                    "index_size_limit": 100000,
                    "similarity_threshold": 0.3
                },
                "automated_moderation": {
                    "enabled": True,
                    "auto_action": False,
                    "severity_threshold": 0.7
                }
            }
            
            # Merge with user configuration
            merged_config = {**default_config, **ai_features_config}
            
            logger.info("📋 AI-Powered Features configuration loaded")
            return merged_config
            
        except Exception as e:
            logger.error(f"❌ Failed to load AI-Powered Features configuration: {e}")
            raise
    
    async def _initialize_semantic_index(self):
        """Initialize semantic search index with default content if needed."""
        try:
            if not self.ai_features_service:
                return
            
            # Check if index needs initialization
            stats = await self.ai_features_service.get_feature_statistics()
            index_size = stats.get("cache_sizes", {}).get("semantic_search", 0)
            
            if index_size == 0:
                logger.info("📚 Initializing semantic search index with default content...")
                
                # Add some default content for testing
                default_content = [
                    {
                        "content_id": "welcome_doc",
                        "content": "Welcome to NetLink's AI-powered features. This system provides intelligent summarization, content suggestions, sentiment analysis, semantic search, and automated content moderation.",
                        "metadata": {"category": "documentation", "type": "welcome"}
                    },
                    {
                        "content_id": "features_overview",
                        "content": "NetLink AI features include: text summarization for creating brief summaries, content suggestions for writing assistance, sentiment analysis for understanding emotions, semantic search for finding relevant content, and automated moderation for content safety.",
                        "metadata": {"category": "documentation", "type": "features"}
                    }
                ]
                
                for item in default_content:
                    await self.ai_features_service.add_to_semantic_index(
                        content_id=item["content_id"],
                        content=item["content"],
                        metadata=item["metadata"]
                    )
                
                logger.info("✅ Semantic search index initialized with default content")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to initialize semantic search index: {e}")
    
    async def _start_background_tasks(self):
        """Start background tasks for AI-powered features."""
        try:
            # Cache cleanup task
            cleanup_task = asyncio.create_task(self._cache_cleanup_task())
            self._startup_tasks.append(cleanup_task)
            
            # Statistics collection task
            stats_task = asyncio.create_task(self._statistics_collection_task())
            self._startup_tasks.append(stats_task)
            
            logger.info("🔄 AI-Powered Features background tasks started")
            
        except Exception as e:
            logger.error(f"❌ Failed to start background tasks: {e}")
    
    async def _stop_background_tasks(self):
        """Stop background tasks."""
        try:
            for task in self._startup_tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            
            self._startup_tasks.clear()
            logger.info("🛑 AI-Powered Features background tasks stopped")
            
        except Exception as e:
            logger.error(f"❌ Failed to stop background tasks: {e}")
    
    async def _cache_cleanup_task(self):
        """Background task for cache cleanup."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                if self.ai_features_service:
                    await self.ai_features_service._cleanup_expired_cache()
                    logger.debug("🧹 Cache cleanup completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Cache cleanup task error: {e}")
    
    async def _statistics_collection_task(self):
        """Background task for statistics collection."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                if self.ai_features_service:
                    stats = await self.ai_features_service.get_feature_statistics()
                    logger.debug(f"📊 AI Features statistics: {stats.get('feature_stats', {})}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Statistics collection task error: {e}")
    
    async def _warm_up_caches(self):
        """Warm up caches with common operations."""
        try:
            if not self.ai_features_service:
                return
            
            logger.info("🔥 Warming up AI-Powered Features caches...")
            
            # Warm up with a simple test operation
            await self.ai_features_service.semantic_search(
                query="test",
                max_results=1,
                similarity_threshold=0.9
            )
            
            logger.info("✅ Cache warm-up completed")
            
        except Exception as e:
            logger.warning(f"⚠️ Cache warm-up failed: {e}")
    
    async def _log_available_features(self):
        """Log available AI-powered features."""
        try:
            if not self.ai_features_service:
                return
            
            config = self.ai_features_service.config
            enabled_features = []
            
            if config.get("summarization", {}).get("enabled", False):
                enabled_features.append("📝 Text Summarization")
            
            if config.get("content_suggestions", {}).get("enabled", False):
                enabled_features.append("💡 Content Suggestions")
            
            if config.get("sentiment_analysis", {}).get("enabled", False):
                enabled_features.append("😊 Sentiment Analysis")
            
            if config.get("semantic_search", {}).get("enabled", False):
                enabled_features.append("🔍 Semantic Search")
            
            if config.get("automated_moderation", {}).get("enabled", False):
                enabled_features.append("🛡️ Content Moderation")
            
            if enabled_features:
                logger.info("🤖 Available AI-Powered Features:")
                for feature in enabled_features:
                    logger.info(f"   {feature}")
            else:
                logger.warning("⚠️ No AI-Powered Features are enabled")
                
        except Exception as e:
            logger.error(f"❌ Failed to log available features: {e}")


# Global integration instance
_ai_features_integration: Optional[AIPoweredFeaturesIntegration] = None


def get_ai_features_integration() -> Optional[AIPoweredFeaturesIntegration]:
    """Get the global AI-powered features integration instance."""
    return _ai_features_integration


def initialize_ai_features_integration(config: Dict[str, Any] = None) -> AIPoweredFeaturesIntegration:
    """Initialize the global AI-powered features integration."""
    global _ai_features_integration
    _ai_features_integration = AIPoweredFeaturesIntegration(config)
    return _ai_features_integration


async def startup_ai_features():
    """Startup function for AI-powered features integration."""
    try:
        integration = get_ai_features_integration()
        if not integration:
            integration = initialize_ai_features_integration()
        
        success = await integration.start()
        if success:
            logger.info("🚀 AI-Powered Features integration started successfully")
        else:
            logger.error("❌ Failed to start AI-Powered Features integration")
        
        return success
        
    except Exception as e:
        logger.error(f"❌ AI-Powered Features startup failed: {e}")
        return False


async def shutdown_ai_features():
    """Shutdown function for AI-powered features integration."""
    try:
        integration = get_ai_features_integration()
        if integration:
            success = await integration.stop()
            if success:
                logger.info("🛑 AI-Powered Features integration stopped successfully")
            else:
                logger.error("❌ Failed to stop AI-Powered Features integration")
            return success
        return True
        
    except Exception as e:
        logger.error(f"❌ AI-Powered Features shutdown failed: {e}")
        return False
