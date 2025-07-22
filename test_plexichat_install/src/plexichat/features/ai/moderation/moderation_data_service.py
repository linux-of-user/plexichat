from typing import Any, Dict, List, Optional

class ModerationDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def save_moderation_result(self, result: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.save_moderation_result(result)

    async def get_moderation_results(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_moderation_results(filters)
        return []

    async def update_moderation_result(self, result_id: int, updates: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_moderation_result(result_id, updates)

    async def delete_moderation_result(self, result_id: int):
        if self.db_manager:
            await self.db_manager.delete_moderation_result(result_id) 