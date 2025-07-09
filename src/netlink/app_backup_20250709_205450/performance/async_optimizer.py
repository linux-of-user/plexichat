"""
Async Performance Optimizer
Advanced async operations optimization with connection pooling and resource management.
"""

import asyncio
import aiohttp
import aiofiles
from typing import Any, Dict, List, Optional, Callable, Awaitable
from datetime import datetime
import logging
import time
from concurrent.futures import ThreadPoolExecutor
import weakref

logger = logging.getLogger("netlink.performance.async")

class AsyncOptimizer:
    """Advanced async operations optimizer."""
    
    def __init__(self):
        self.connection_pools: Dict[str, aiohttp.ClientSession] = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.task_registry = weakref.WeakSet()
        
        # Performance metrics
        self.metrics = {
            "async_tasks_created": 0,
            "async_tasks_completed": 0,
            "async_tasks_failed": 0,
            "connection_pool_hits": 0,
            "thread_pool_tasks": 0,
            "average_task_duration": 0.0
        }
        
        # Configuration
        self.config = {
            "max_concurrent_tasks": 100,
            "connection_timeout": 30,
            "read_timeout": 60,
            "max_connections": 100,
            "enable_connection_pooling": True,
            "enable_task_monitoring": True
        }
    
    async def create_optimized_session(self, base_url: str = None) -> aiohttp.ClientSession:
        """Create or get optimized HTTP session with connection pooling."""
        try:
            session_key = base_url or "default"
            
            if session_key in self.connection_pools:
                self.metrics["connection_pool_hits"] += 1
                return self.connection_pools[session_key]
            
            # Create new session with optimized settings
            timeout = aiohttp.ClientTimeout(
                total=self.config["connection_timeout"],
                connect=self.config["connection_timeout"],
                sock_read=self.config["read_timeout"]
            )
            
            connector = aiohttp.TCPConnector(
                limit=self.config["max_connections"],
                limit_per_host=20,
                enable_cleanup_closed=True,
                keepalive_timeout=30
            )
            
            session = aiohttp.ClientSession(
                base_url=base_url,
                timeout=timeout,
                connector=connector,
                headers={
                    "User-Agent": "NetLink/1.0 AsyncOptimizer",
                    "Connection": "keep-alive"
                }
            )
            
            self.connection_pools[session_key] = session
            logger.info(f"Created optimized HTTP session for {session_key}")
            
            return session
            
        except Exception as e:
            logger.error(f"Error creating optimized session: {e}")
            raise
    
    async def batch_execute(self, tasks: List[Awaitable], 
                          max_concurrent: Optional[int] = None,
                          return_exceptions: bool = True) -> List[Any]:
        """Execute multiple async tasks with concurrency control."""
        try:
            if max_concurrent is None:
                max_concurrent = self.config["max_concurrent_tasks"]
            
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def controlled_task(task):
                async with semaphore:
                    start_time = time.time()
                    try:
                        result = await task
                        self.metrics["async_tasks_completed"] += 1
                        
                        # Update average duration
                        duration = time.time() - start_time
                        self._update_average_duration(duration)
                        
                        return result
                    except Exception as e:
                        self.metrics["async_tasks_failed"] += 1
                        if return_exceptions:
                            return e
                        raise
            
            # Wrap tasks with concurrency control
            controlled_tasks = [controlled_task(task) for task in tasks]
            self.metrics["async_tasks_created"] += len(controlled_tasks)
            
            # Execute all tasks
            results = await asyncio.gather(*controlled_tasks, return_exceptions=return_exceptions)
            
            logger.info(f"Batch executed {len(tasks)} tasks with max concurrency {max_concurrent}")
            return results
            
        except Exception as e:
            logger.error(f"Batch execution error: {e}")
            raise
    
    async def run_in_thread(self, func: Callable, *args, **kwargs) -> Any:
        """Run CPU-intensive function in thread pool."""
        try:
            loop = asyncio.get_event_loop()
            self.metrics["thread_pool_tasks"] += 1
            
            result = await loop.run_in_executor(
                self.thread_pool, 
                lambda: func(*args, **kwargs)
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Thread pool execution error: {e}")
            raise
    
    async def optimized_file_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Perform optimized file operations asynchronously."""
        try:
            results = []
            
            for op in operations:
                op_type = op.get("type")
                file_path = op.get("path")
                
                if op_type == "read":
                    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                        content = await f.read()
                        results.append(content)
                
                elif op_type == "write":
                    content = op.get("content", "")
                    async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                        await f.write(content)
                        results.append(True)
                
                elif op_type == "append":
                    content = op.get("content", "")
                    async with aiofiles.open(file_path, 'a', encoding='utf-8') as f:
                        await f.write(content)
                        results.append(True)
                
                elif op_type == "exists":
                    import aiofiles.os
                    exists = await aiofiles.os.path.exists(file_path)
                    results.append(exists)
                
                else:
                    results.append(None)
            
            return results
            
        except Exception as e:
            logger.error(f"File operations error: {e}")
            raise
    
    async def create_background_task(self, coro: Awaitable, 
                                   name: str = None,
                                   monitor: bool = True) -> asyncio.Task:
        """Create and monitor background task."""
        try:
            task = asyncio.create_task(coro, name=name)
            
            if monitor and self.config["enable_task_monitoring"]:
                self.task_registry.add(task)
                
                # Add completion callback
                task.add_done_callback(self._task_completion_callback)
            
            self.metrics["async_tasks_created"] += 1
            return task
            
        except Exception as e:
            logger.error(f"Background task creation error: {e}")
            raise
    
    async def wait_for_tasks(self, tasks: List[asyncio.Task], 
                           timeout: Optional[float] = None) -> List[Any]:
        """Wait for multiple tasks with timeout."""
        try:
            if timeout:
                done, pending = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout
                )
                
                # Cancel pending tasks
                for task in pending:
                    task.cancel()
                
                return done
            else:
                return await asyncio.gather(*tasks, return_exceptions=True)
                
        except asyncio.TimeoutError:
            logger.warning(f"Task timeout after {timeout} seconds")
            raise
        except Exception as e:
            logger.error(f"Task waiting error: {e}")
            raise
    
    async def optimize_database_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Optimize database operations with batching and connection pooling."""
        try:
            # Group operations by type for batching
            grouped_ops = {}
            for i, op in enumerate(operations):
                op_type = op.get("type", "unknown")
                if op_type not in grouped_ops:
                    grouped_ops[op_type] = []
                grouped_ops[op_type].append((i, op))
            
            results = [None] * len(operations)
            
            # Execute grouped operations
            for op_type, ops in grouped_ops.items():
                if op_type == "select":
                    # Batch SELECT operations
                    batch_results = await self._batch_select_operations([op[1] for op in ops])
                    for (index, _), result in zip(ops, batch_results):
                        results[index] = result
                
                elif op_type == "insert":
                    # Batch INSERT operations
                    batch_results = await self._batch_insert_operations([op[1] for op in ops])
                    for (index, _), result in zip(ops, batch_results):
                        results[index] = result
                
                elif op_type == "update":
                    # Batch UPDATE operations
                    batch_results = await self._batch_update_operations([op[1] for op in ops])
                    for (index, _), result in zip(ops, batch_results):
                        results[index] = result
                
                else:
                    # Handle individual operations
                    for index, op in ops:
                        results[index] = await self._execute_single_operation(op)
            
            return results
            
        except Exception as e:
            logger.error(f"Database optimization error: {e}")
            raise
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        active_tasks = len([task for task in self.task_registry if not task.done()])
        
        return {
            **self.metrics,
            "active_tasks": active_tasks,
            "connection_pools": len(self.connection_pools),
            "thread_pool_size": self.thread_pool._max_workers,
            "timestamp": datetime.now().isoformat()
        }
    
    async def cleanup(self):
        """Clean up resources."""
        try:
            # Close all HTTP sessions
            for session in self.connection_pools.values():
                await session.close()
            self.connection_pools.clear()
            
            # Shutdown thread pool
            self.thread_pool.shutdown(wait=True)
            
            # Cancel active tasks
            for task in list(self.task_registry):
                if not task.done():
                    task.cancel()
            
            logger.info("AsyncOptimizer cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def _task_completion_callback(self, task: asyncio.Task):
        """Callback for task completion monitoring."""
        try:
            if task.exception():
                self.metrics["async_tasks_failed"] += 1
                logger.error(f"Task {task.get_name()} failed: {task.exception()}")
            else:
                self.metrics["async_tasks_completed"] += 1
                
        except Exception as e:
            logger.error(f"Task callback error: {e}")
    
    def _update_average_duration(self, duration: float):
        """Update average task duration."""
        current_avg = self.metrics["average_task_duration"]
        completed_tasks = self.metrics["async_tasks_completed"]
        
        if completed_tasks == 1:
            self.metrics["average_task_duration"] = duration
        else:
            # Calculate running average
            self.metrics["average_task_duration"] = (
                (current_avg * (completed_tasks - 1) + duration) / completed_tasks
            )
    
    async def _batch_select_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Batch SELECT operations for better performance."""
        # Placeholder for actual database batching implementation
        results = []
        for op in operations:
            # Simulate database operation
            await asyncio.sleep(0.001)  # Simulate DB latency
            results.append({"status": "success", "data": []})
        return results
    
    async def _batch_insert_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Batch INSERT operations for better performance."""
        # Placeholder for actual database batching implementation
        results = []
        for op in operations:
            # Simulate database operation
            await asyncio.sleep(0.001)  # Simulate DB latency
            results.append({"status": "success", "id": 1})
        return results
    
    async def _batch_update_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Batch UPDATE operations for better performance."""
        # Placeholder for actual database batching implementation
        results = []
        for op in operations:
            # Simulate database operation
            await asyncio.sleep(0.001)  # Simulate DB latency
            results.append({"status": "success", "affected_rows": 1})
        return results
    
    async def _execute_single_operation(self, operation: Dict[str, Any]) -> Any:
        """Execute single database operation."""
        # Placeholder for actual database operation implementation
        await asyncio.sleep(0.001)  # Simulate DB latency
        return {"status": "success"}

# Global async optimizer instance
async_optimizer = AsyncOptimizer()

# Decorator for async optimization
def async_optimized(max_concurrent: int = None):
    """Decorator to optimize async functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return await async_optimizer.run_in_thread(func, *args, **kwargs)
        return wrapper
    return decorator
