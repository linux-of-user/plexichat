from typing import Any


class ModerationDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager  # type: ignore

            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def save_moderation_result(self, result: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.save_moderation_result(result)

    async def get_moderation_results(
        self, filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_moderation_results(filters)
        return []

    async def update_moderation_result(self, result_id: int, updates: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_moderation_result(result_id, updates)

    async def delete_moderation_result(self, result_id: int):
        if self.db_manager:
            await self.db_manager.delete_moderation_result(result_id)

    async def get_latest_moderation_result_by_hash(
        self, content_hash: str
    ) -> Any | None:
        """Get latest moderation result by content hash."""
        if self.db_manager:
            return await self.db_manager.get_latest_moderation_result_by_hash(content_hash)  # type: ignore
        return None

    async def add_moderation_result(self, content_hash: str, result: Any):
        """Add moderation result."""
        if self.db_manager:
            await self.db_manager.add_moderation_result(content_hash, result)  # type: ignore
