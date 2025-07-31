from typing import Any, Dict, List, Optional

class FeedbackDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def add_feedback_data(self, feedback: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.add_feedback_data(feedback)

    async def get_feedback_data(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_feedback_data(filters)
        return []

    async def update_feedback_data(self, feedback_id: int, updates: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_feedback_data(feedback_id, updates)

    async def delete_feedback_data(self, feedback_id: int):
        if self.db_manager:
            await self.db_manager.delete_feedback_data(feedback_id) 