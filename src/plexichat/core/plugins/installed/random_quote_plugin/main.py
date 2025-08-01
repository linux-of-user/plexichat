# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
import random
from ..plugins_internal import PluginInterface
from fastapi import APIRouter
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/quote", tags=["RandomQuote"])

QUOTES = [
    "The only way to do great work is to love what you do. - Steve Jobs",
    "Success is not the key to happiness. Happiness is the key to success.",
    "The best time to plant a tree was 20 years ago. The second best time is now.",
    "Your time is limited, don't waste it living someone else's life. - Steve Jobs",
    "The journey of a thousand miles begins with one step. - Lao Tzu"
]

@router.get("/")
async def random_quote():
    return {"quote": random.choice(QUOTES)}

class RandomQuotePlugin(PluginInterface):
    """
    Example Random Quote plugin for PlexiChat.
    """
    def __init__(self):
        super().__init__(name="RandomQuotePlugin", version="1.0.0")
        self.router = router

    async def _plugin_initialize(self) -> bool:
        logger.info("Initializing Random Quote Plugin...")
        return True

    def get_metadata(self):
        return {
            "name": "Random Quote Plugin",
            "version": "1.0.0",
            "description": "A plugin that returns a random inspirational quote.",
            "plugin_type": "utility"
        }
