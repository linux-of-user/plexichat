from typing import Any, Dict, List, Optional

class AnalyticsDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager
            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def save_metric(self, metric: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.save_analytics_metric(metric)

    async def get_metrics(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_analytics_metrics(filters)
        return []

    async def update_metric(self, metric_id: int, updates: Dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_analytics_metric(metric_id, updates)

    async def delete_metric(self, metric_id: int):
        if self.db_manager:
            await self.db_manager.delete_analytics_metric(metric_id) 