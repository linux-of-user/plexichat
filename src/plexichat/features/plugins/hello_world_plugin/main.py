import logging
from src.plexichat.infrastructure.modules.plugin_manager import PluginInterface
from fastapi import APIRouter
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/hello", tags=["HelloWorld"])

@router.get("/")
async def hello_world():
    return {"message": "Hello from the HelloWorld plugin!"}

class HelloWorldPlugin(PluginInterface):
    """
    Example Hello World plugin for PlexiChat.
    """
    def __init__(self):
        super().__init__(name="HelloWorldPlugin", version="1.0.0")
        self.router = router

    async def _plugin_initialize(self) -> bool:
        logger.info("Initializing HelloWorld Plugin...")
        return True

    def get_metadata(self):
        return {
            "name": "Hello World Plugin",
            "version": "1.0.0",
            "description": "A simple Hello World plugin for demonstration.",
            "plugin_type": "utility"
        } 