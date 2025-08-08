from typing import Any, Dict, List, Optional

class FeedbackDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager  # type: ignore
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

    async def add_feedback(self, feedback: Any):
        """Add feedback data."""
        if self.db_manager:
            await self.db_manager.add_feedback(feedback)  # type: ignore

    async def mark_feedback_processed(self, content_id: str, user_id: str):
        """Mark feedback as processed."""
        if self.db_manager:
            await self.db_manager.mark_feedback_processed(content_id, user_id)  # type: ignore

    async def get_feedback_stats(self, days: int) -> Dict[str, Any]:
        """Get feedback statistics."""
        if self.db_manager:
            return await self.db_manager.get_feedback_stats(days)  # type: ignore
        return {"total": 0, "processed": 0, "pending": 0}

    async def get_user_feedback_history(self, user_id: str, limit: int) -> List[Dict[str, Any]]:
        """Get user feedback history."""
        if self.db_manager:
            return await self.db_manager.get_user_feedback_history(user_id, limit)  # type: ignore
        return []