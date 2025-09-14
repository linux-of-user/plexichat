from typing import Any


class AnalyticsDataService:
    def __init__(self):
        try:
            from plexichat.core.database.manager import database_manager  # type: ignore

            self.db_manager = database_manager
        except ImportError:
            self.db_manager = None

    async def save_metric(self, metric: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.save_analytics_metric(metric)

    async def get_metrics(
        self, filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        if self.db_manager:
            return await self.db_manager.get_analytics_metrics(filters)
        return []

    async def update_metric(self, metric_id: int, updates: dict[str, Any]):
        if self.db_manager:
            await self.db_manager.update_analytics_metric(metric_id, updates)

    async def delete_metric(self, metric_id: int):
        if self.db_manager:
            await self.db_manager.delete_analytics_metric(metric_id)

    async def save_usage_metrics(self, metrics: list[Any]):
        """Save usage metrics."""
        if self.db_manager:
            await self.db_manager.save_usage_metrics(metrics)  # type: ignore

    async def save_performance_metrics(self, metrics: list[Any]):
        """Save performance metrics."""
        if self.db_manager:
            await self.db_manager.save_performance_metrics(metrics)  # type: ignore

    async def save_alert(self, alert_data: dict[str, Any]):
        """Save alert data."""
        if self.db_manager:
            await self.db_manager.save_alert(alert_data)  # type: ignore

    async def get_usage_stats(
        self, start_time: Any, end_time: Any, provider: Any, model: Any
    ) -> dict[str, Any]:
        """Get usage statistics."""
        if self.db_manager:
            return await self.db_manager.get_usage_stats(start_time, end_time, provider, model)  # type: ignore
        return {"total": 0, "cost": 0, "latency": 0}
