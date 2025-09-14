"""
PlexiChat Performance Optimization Engine

Provides a centralized performance optimization engine.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class OptimizationResult:
    """Result of an optimization operation."""

    success: bool
    improvement_percent: float = 0.0
    time_taken_ms: float = 0.0
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class OptimizationStrategy:
    """Configuration for an optimization strategy."""

    name: str
    priority: int
    enabled: bool = True
    target_metric: str = ""
    threshold: float = 0.0
    strategy_func: Callable[..., Any] | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


class PerformanceOptimizationEngine:
    """A comprehensive performance optimization engine."""

    def __init__(self) -> None:
        self.strategies: dict[str, OptimizationStrategy] = {}
        self.optimization_history: list[OptimizationResult] = []
        self.enabled = True
        self.logger = logger

    def register_strategy(
        self,
        name: str,
        priority: int,
        strategy_func: Callable[..., Any],
        target_metric: str = "",
        threshold: float = 0.0,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        """Register a new optimization strategy."""
        strategy = OptimizationStrategy(
            name=name,
            priority=priority,
            target_metric=target_metric,
            threshold=threshold,
            strategy_func=strategy_func,
            parameters=parameters or {},
        )

        self.strategies[name] = strategy
        self.logger.info(
            f"Registered optimization strategy: {name} (priority: {priority})"
        )

    def unregister_strategy(self, name: str) -> bool:
        """Unregister an optimization strategy."""
        if name in self.strategies:
            del self.strategies[name]
            self.logger.info(f"Unregistered optimization strategy: {name}")
            return True
        return False

    def enable_strategy(self, name: str) -> bool:
        """Enable a specific optimization strategy."""
        if name in self.strategies:
            self.strategies[name].enabled = True
            return True
        return False

    def disable_strategy(self, name: str) -> bool:
        """Disable a specific optimization strategy."""
        if name in self.strategies:
            self.strategies[name].enabled = False
            return True
        return False

    async def optimize(
        self, target: str | None = None, context: dict[str, Any] | None = None
    ) -> list[OptimizationResult]:
        """
        Execute optimization strategies.

        Args:
            target: Specific optimization target (optional)
            context: Additional context for optimization

        Returns:
            List of optimization results
        """
        if not self.enabled:
            return []

        context = context or {}
        results = []

        # Get enabled strategies, sorted by priority (higher priority first)
        enabled_strategies = [
            strategy
            for strategy in self.strategies.values()
            if strategy.enabled and (not target or strategy.name == target)
        ]
        enabled_strategies.sort(key=lambda s: s.priority, reverse=True)

        self.logger.info(
            f"Starting optimization with {len(enabled_strategies)} strategies"
        )

        for strategy in enabled_strategies:
            try:
                start_time = time.perf_counter()

                result = await self._execute_strategy(strategy, context)

                time_taken = (time.perf_counter() - start_time) * 1000
                result.time_taken_ms = time_taken

                results.append(result)
                self.optimization_history.append(result)

                # Limit history size
                if len(self.optimization_history) > 1000:
                    self.optimization_history = self.optimization_history[-500:]

                self.logger.info(
                    f"Strategy '{strategy.name}' executed: success={result.success}, "
                    f"improvement={result.improvement_percent:.1f}%, time={time_taken:.2f}ms"
                )

            except Exception as e:
                self.logger.error(f"Error executing strategy '{strategy.name}': {e}")
                results.append(
                    OptimizationResult(
                        success=False,
                        metadata={"error": str(e), "strategy": strategy.name},
                    )
                )

        return results

    async def _execute_strategy(
        self, strategy: OptimizationStrategy, context: dict[str, Any]
    ) -> OptimizationResult:
        """Execute a single optimization strategy."""
        if not strategy.strategy_func:
            return OptimizationResult(
                success=False, metadata={"error": "No strategy function defined"}
            )

        try:
            # Prepare parameters
            params = {**strategy.parameters, **context}

            # Execute strategy function
            if asyncio.iscoroutinefunction(strategy.strategy_func):
                result = await strategy.strategy_func(**params)
            else:
                result = strategy.strategy_func(**params)

            # Process result
            if isinstance(result, OptimizationResult):
                return result
            elif isinstance(result, dict):
                return OptimizationResult(
                    success=result.get("success", True),
                    improvement_percent=result.get("improvement_percent", 0.0),
                    recommendations=result.get("recommendations", []),
                    metadata=result.get("metadata", {}),
                )
            else:
                return OptimizationResult(success=True, metadata={"raw_result": result})

        except Exception as e:
            return OptimizationResult(success=False, metadata={"error": str(e)})

    def get_strategy_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all optimization strategies."""
        return {
            name: {
                "enabled": strategy.enabled,
                "priority": strategy.priority,
                "target_metric": strategy.target_metric,
                "threshold": strategy.threshold,
                "has_function": strategy.strategy_func is not None,
            }
            for name, strategy in self.strategies.items()
        }

    def get_optimization_history(
        self, limit: int = 100, strategy_name: str | None = None
    ) -> list[dict[str, Any]]:
        """Get optimization history."""
        history = self.optimization_history[-limit:]

        if strategy_name:
            history = [
                result
                for result in history
                if result.metadata.get("strategy") == strategy_name
            ]

        return [
            {
                "success": result.success,
                "improvement_percent": result.improvement_percent,
                "time_taken_ms": result.time_taken_ms,
                "recommendations": result.recommendations,
                "timestamp": result.timestamp.isoformat(),
                "metadata": result.metadata,
            }
            for result in history
        ]

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics for the optimization engine."""
        recent_results = (
            self.optimization_history[-100:] if self.optimization_history else []
        )

        successful_optimizations = [r for r in recent_results if r.success]
        total_improvements = sum(
            r.improvement_percent for r in successful_optimizations
        )
        avg_time = (
            sum(r.time_taken_ms for r in recent_results) / len(recent_results)
            if recent_results
            else 0
        )

        return {
            "total_strategies": len(self.strategies),
            "enabled_strategies": len(
                [s for s in self.strategies.values() if s.enabled]
            ),
            "total_optimizations": len(self.optimization_history),
            "recent_optimizations": len(recent_results),
            "success_rate": (
                len(successful_optimizations) / len(recent_results)
                if recent_results
                else 0
            ),
            "average_improvement": (
                total_improvements / len(successful_optimizations)
                if successful_optimizations
                else 0
            ),
            "average_execution_time_ms": avg_time,
            "enabled": self.enabled,
        }

    def enable(self) -> None:
        """Enable the optimization engine."""
        self.enabled = True
        self.logger.info("Performance optimization engine enabled")

    def disable(self) -> None:
        """Disable the optimization engine."""
        self.enabled = False
        self.logger.info("Performance optimization engine disabled")

    def clear_history(self) -> None:
        """Clear optimization history."""
        self.optimization_history.clear()
        self.logger.info("Optimization history cleared")


# Example optimization strategies
async def cache_optimization_strategy(**kwargs: Any) -> OptimizationResult:
    """Example cache optimization strategy."""
    # Placeholder implementation
    return OptimizationResult(
        success=True,
        improvement_percent=5.0,
        recommendations=["Enable query result caching", "Increase cache size"],
    )


async def database_query_optimization(**kwargs: Any) -> OptimizationResult:
    """Example database query optimization strategy."""
    # Placeholder implementation
    return OptimizationResult(
        success=True,
        improvement_percent=8.0,
        recommendations=["Add database indexes", "Optimize slow queries"],
    )


def memory_optimization_strategy(**kwargs: Any) -> OptimizationResult:
    """Example memory optimization strategy."""
    # Placeholder implementation
    return OptimizationResult(
        success=True,
        improvement_percent=3.0,
        recommendations=["Run garbage collection", "Release unused objects"],
    )


# Global instance
optimization_engine = PerformanceOptimizationEngine()

# Register default strategies
optimization_engine.register_strategy(
    "cache_optimization",
    priority=10,
    strategy_func=cache_optimization_strategy,
    target_metric="cache_hit_rate",
    threshold=0.8,
)

optimization_engine.register_strategy(
    "database_optimization",
    priority=8,
    strategy_func=database_query_optimization,
    target_metric="query_time",
    threshold=100.0,
)

optimization_engine.register_strategy(
    "memory_optimization",
    priority=5,
    strategy_func=memory_optimization_strategy,
    target_metric="memory_usage",
    threshold=80.0,
)


# Convenience functions
async def optimize_performance(
    target: str | None = None, context: dict[str, Any] | None = None
) -> list[OptimizationResult]:
    """Run performance optimization."""
    return await optimization_engine.optimize(target, context)


def get_optimization_status() -> dict[str, Any]:
    """Get optimization engine status."""
    return {
        "strategies": optimization_engine.get_strategy_status(),
        "metrics": optimization_engine.get_performance_metrics(),
    }


def register_custom_strategy(
    name: str, priority: int, strategy_func: Callable[..., Any], **kwargs: Any
) -> None:
    """Register a custom optimization strategy."""
    optimization_engine.register_strategy(name, priority, strategy_func, **kwargs)


__all__ = [
    "OptimizationResult",
    "OptimizationStrategy",
    "PerformanceOptimizationEngine",
    "get_optimization_status",
    "optimization_engine",
    "optimize_performance",
    "register_custom_strategy",
]
