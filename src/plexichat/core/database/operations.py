"""
Database Operations

Common database operations and utilities.
"""

from typing import Any, Dict, List, Optional
from .manager import database_manager, execute_query as _execute_query, execute_transaction as _execute_transaction

# Re-export for convenience
execute_query = _execute_query
execute_transaction = _execute_transaction

__all__ = ["execute_query", "execute_transaction"]
