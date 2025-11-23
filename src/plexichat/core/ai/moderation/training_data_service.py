from typing import Any


class TrainingDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager  # type: ignore

            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def add_training_data(self, training_data: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.add_training_data(training_data)

    async def get_training_data(
        self, filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_training_data(filters)
        return []

    async def update_training_data(self, training_id: int, updates: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_training_data(training_id, updates)

    async def delete_training_data(self, training_id: int):
        if self.db_manager:
            await self.db_manager.delete_training_data(training_id)

    async def get_training_stats(self) -> dict[str, Any]:
        """Get training statistics."""
        if self.db_manager:
            return await self.db_manager.get_training_stats()  # type: ignore
        return {"total": 0, "sources": {}, "labels": {}}
