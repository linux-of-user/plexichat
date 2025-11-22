from typing import Any, Dict, Optional, List
from .config import config
from .logging import get_logger
import sqlite3
import os

logger = get_logger(__name__)

class Database:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._connect()
        return cls._instance

    def _connect(self):
        db_type = config.get("database.type", "sqlite")
        if db_type == "sqlite":
            db_path = config.get("database.path", "data/plexichat.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite database at {db_path}")
        else:
            logger.error(f"Unsupported database type: {db_type}")
            raise ValueError(f"Unsupported database type: {db_type}")

    def execute(self, query: str, params: tuple = ()) -> Any:
        """
        Execute a query safely.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            self.conn.commit()
            return cursor
        except Exception as e:
            logger.error(f"Database error: {e}")
            self.conn.rollback()
            raise

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        cursor = self.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        cursor = self.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        if self.conn:
            self.conn.close()

db = Database()
