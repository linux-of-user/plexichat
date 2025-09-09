"""
Advanced Search Service for PlexiChat

Provides comprehensive search functionality with full-text search, filters,
search suggestions, and search history tracking.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SearchFilter:
    """Search filter configuration."""

    query: str
    user_id: Optional[str] = None
    channel_id: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    message_type: Optional[str] = None
    has_attachments: Optional[bool] = None
    limit: int = 50
    offset: int = 0


@dataclass
class SearchResult:
    """Search result data structure."""

    message_id: str
    content: str
    user_id: str
    channel_id: str
    created_at: datetime
    score: float
    highlights: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchSuggestion:
    """Search suggestion data structure."""

    text: str
    type: str  # "query", "user", "channel"
    frequency: int = 0
    last_used: Optional[datetime] = None


@dataclass
class SearchHistory:
    """Search history entry."""

    id: str
    user_id: str
    query: str
    filters: Dict[str, Any]
    result_count: int
    timestamp: datetime
    duration_ms: int


class FullTextSearch:
    """Full-text search implementation using SQLite FTS5."""

    def __init__(self):
        self.fts_table = "messages_fts"
        self.content_table = "messages"

    async def initialize_fts(self) -> bool:
        """Initialize full-text search table."""
        try:
            async with database_manager.get_session() as session:
                # Create FTS5 virtual table
                fts_query = f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS {self.fts_table} USING fts5(
                    content, user_id, channel_id, created_at, message_type,
                    content={self.content_table},
                    tokenize="porter unicode61"
                )
                """
                await session.execute(fts_query)

                # Create triggers to keep FTS table in sync
                triggers = [
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {self.fts_table}_insert
                    AFTER INSERT ON {self.content_table}
                    BEGIN
                        INSERT INTO {self.fts_table}(rowid, content, user_id, channel_id, created_at, message_type)
                        VALUES (new.rowid, new.content, new.user_id, new.channel_id, new.created_at, new.message_type);
                    END
                    """,
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {self.fts_table}_delete
                    AFTER DELETE ON {self.content_table}
                    BEGIN
                        DELETE FROM {self.fts_table} WHERE rowid = old.rowid;
                    END
                    """,
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {self.fts_table}_update
                    AFTER UPDATE ON {self.content_table}
                    BEGIN
                        UPDATE {self.fts_table} SET
                            content = new.content,
                            user_id = new.user_id,
                            channel_id = new.channel_id,
                            created_at = new.created_at,
                            message_type = new.message_type
                        WHERE rowid = new.rowid;
                    END
                    """,
                ]

                for trigger in triggers:
                    await session.execute(trigger)

                await session.commit()
                logger.info("Full-text search initialized successfully")
                return True

        except Exception as e:
            logger.error(f"Failed to initialize FTS: {e}")
            return False

    async def search(self, query: str, filters: SearchFilter) -> List[SearchResult]:
        """Perform full-text search with filters."""
        try:
            async with database_manager.get_session() as session:
                # Build FTS query
                fts_conditions = []

                # Add text search
                if query:
                    # Use BM25 ranking with query expansion
                    search_terms = self._expand_query(query)
                    fts_query = " OR ".join(f'"{term}"' for term in search_terms)
                    fts_conditions.append(f"{self.fts_table} MATCH '{fts_query}'")

                # Add metadata filters
                if filters.user_id:
                    fts_conditions.append(f"user_id = '{filters.user_id}'")
                if filters.channel_id:
                    fts_conditions.append(f"channel_id = '{filters.channel_id}'")
                if filters.message_type:
                    fts_conditions.append(f"message_type = '{filters.message_type}'")

                where_clause = " AND ".join(fts_conditions) if fts_conditions else "1=1"

                # Build main query with ranking
                sql = f"""
                SELECT
                    m.id,
                    m.content,
                    m.user_id,
                    m.channel_id,
                    m.created_at,
                    m.message_type,
                    m.attachments,
                    bm25({self.fts_table}) as score,
                    highlight({self.fts_table}, 0, '<mark>', '</mark>') as highlight
                FROM {self.content_table} m
                JOIN {self.fts_table} fts ON m.rowid = fts.rowid
                WHERE {where_clause}
                """

                # Add date filters
                params = {}
                if filters.date_from:
                    sql += " AND m.created_at >= :date_from"
                    params["date_from"] = filters.date_from.isoformat()
                if filters.date_to:
                    sql += " AND m.created_at <= :date_to"
                    params["date_to"] = filters.date_to.isoformat()

                # Add attachment filter
                if filters.has_attachments is not None:
                    if filters.has_attachments:
                        sql += " AND json_array_length(m.attachments) > 0"
                    else:
                        sql += " AND (m.attachments IS NULL OR json_array_length(m.attachments) = 0)"

                # Add ordering and pagination
                sql += f" ORDER BY score LIMIT {filters.limit} OFFSET {filters.offset}"

                results = await session.fetchall(sql, params)

                # Convert to SearchResult objects
                search_results = []
                for row in results:
                    # Parse highlights from FTS
                    highlights = []
                    if row["highlight"]:
                        # Extract highlighted terms
                        highlight_matches = re.findall(
                            r"<mark>(.*?)</mark>", row["highlight"]
                        )
                        highlights.extend(highlight_matches)

                    result = SearchResult(
                        message_id=row["id"],
                        content=row["content"],
                        user_id=row["user_id"],
                        channel_id=row["channel_id"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        score=float(row["score"]) if row["score"] else 0.0,
                        highlights=highlights,
                        metadata={
                            "message_type": row["message_type"],
                            "attachments": json.loads(row["attachments"] or "[]"),
                        },
                    )
                    search_results.append(result)

                return search_results

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def _expand_query(self, query: str) -> List[str]:
        """Expand search query with synonyms and variations."""
        terms = []

        # Split query into words
        words = re.findall(r"\w+", query.lower())

        for word in words:
            terms.append(word)

            # Add common variations
            if len(word) > 3:
                # Add stem variations
                if word.endswith("ing"):
                    terms.append(word[:-3])
                    terms.append(word[:-3] + "e")
                elif word.endswith("ed"):
                    terms.append(word[:-2])
                    terms.append(word[:-2] + "e")
                elif word.endswith("er"):
                    terms.append(word[:-2])
                elif word.endswith("est"):
                    terms.append(word[:-3])

                # Add plural variations
                if word.endswith("s"):
                    terms.append(word[:-1])
                else:
                    terms.append(word + "s")

        return list(set(terms))  # Remove duplicates


class SearchSuggestions:
    """Search suggestions service."""

    def __init__(self):
        self.suggestions_table = "search_suggestions"

    async def initialize(self) -> bool:
        """Initialize suggestions table."""
        try:
            schema = {
                "id": "TEXT PRIMARY KEY",
                "text": "TEXT NOT NULL",
                "type": "TEXT NOT NULL",
                "frequency": "INTEGER DEFAULT 1",
                "last_used": "TEXT",
                "created_at": "TEXT NOT NULL",
                "updated_at": "TEXT NOT NULL",
            }
            return await database_manager.ensure_table_exists(
                self.suggestions_table, schema
            )
        except Exception as e:
            logger.error(f"Failed to initialize suggestions: {e}")
            return False

    async def get_suggestions(
        self, prefix: str, limit: int = 10
    ) -> List[SearchSuggestion]:
        """Get search suggestions for a prefix."""
        try:
            async with database_manager.get_session() as session:
                query = f"""
                SELECT text, type, frequency, last_used
                FROM {self.suggestions_table}
                WHERE text LIKE :prefix
                ORDER BY frequency DESC, last_used DESC
                LIMIT :limit
                """
                results = await session.fetchall(
                    query, {"prefix": f"{prefix}%", "limit": limit}
                )

                suggestions = []
                for row in results:
                    suggestion = SearchSuggestion(
                        text=row["text"],
                        type=row["type"],
                        frequency=row["frequency"],
                        last_used=(
                            datetime.fromisoformat(row["last_used"])
                            if row["last_used"]
                            else None
                        ),
                    )
                    suggestions.append(suggestion)

                return suggestions

        except Exception as e:
            logger.error(f"Failed to get suggestions: {e}")
            return []

    async def add_suggestion(self, text: str, suggestion_type: str) -> bool:
        """Add or update a search suggestion."""
        try:
            async with database_manager.get_session() as session:
                now = datetime.now(timezone.utc).isoformat()

                # Check if suggestion exists
                check_query = f"SELECT id, frequency FROM {self.suggestions_table} WHERE text = :text AND type = :type"
                existing = await session.fetchone(
                    check_query, {"text": text, "type": suggestion_type}
                )

                if existing:
                    # Update existing
                    update_query = f"""
                    UPDATE {self.suggestions_table}
                    SET frequency = frequency + 1, last_used = :last_used, updated_at = :updated_at
                    WHERE id = :id
                    """
                    await session.execute(
                        update_query,
                        {"last_used": now, "updated_at": now, "id": existing["id"]},
                    )
                else:
                    # Insert new
                    suggestion_id = str(uuid4())
                    insert_query = f"""
                    INSERT INTO {self.suggestions_table}
                    (id, text, type, frequency, last_used, created_at, updated_at)
                    VALUES (:id, :text, :type, 1, :last_used, :created_at, :updated_at)
                    """
                    await session.execute(
                        insert_query,
                        {
                            "id": suggestion_id,
                            "text": text,
                            "type": suggestion_type,
                            "last_used": now,
                            "created_at": now,
                            "updated_at": now,
                        },
                    )

                await session.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to add suggestion: {e}")
            return False


class SearchHistoryService:
    """Search history tracking service."""

    def __init__(self):
        self.history_table = "search_history"

    async def initialize(self) -> bool:
        """Initialize search history table."""
        try:
            schema = {
                "id": "TEXT PRIMARY KEY",
                "user_id": "TEXT NOT NULL",
                "query": "TEXT NOT NULL",
                "filters": "TEXT NOT NULL",
                "result_count": "INTEGER NOT NULL",
                "timestamp": "TEXT NOT NULL",
                "duration_ms": "INTEGER NOT NULL",
                "created_at": "TEXT NOT NULL",
            }
            return await database_manager.ensure_table_exists(
                self.history_table, schema
            )
        except Exception as e:
            logger.error(f"Failed to initialize search history: {e}")
            return False

    async def record_search(self, history: SearchHistory) -> bool:
        """Record a search in history."""
        try:
            async with database_manager.get_session() as session:
                insert_query = f"""
                INSERT INTO {self.history_table}
                (id, user_id, query, filters, result_count, timestamp, duration_ms, created_at)
                VALUES (:id, :user_id, :query, :filters, :result_count, :timestamp, :duration_ms, :created_at)
                """
                await session.execute(
                    insert_query,
                    {
                        "id": history.id,
                        "user_id": history.user_id,
                        "query": history.query,
                        "filters": json.dumps(history.filters),
                        "result_count": history.result_count,
                        "timestamp": history.timestamp.isoformat(),
                        "duration_ms": history.duration_ms,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                await session.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to record search history: {e}")
            return False

    async def get_user_history(
        self, user_id: str, limit: int = 20
    ) -> List[SearchHistory]:
        """Get search history for a user."""
        try:
            async with database_manager.get_session() as session:
                query = f"""
                SELECT id, user_id, query, filters, result_count, timestamp, duration_ms
                FROM {self.history_table}
                WHERE user_id = :user_id
                ORDER BY timestamp DESC
                LIMIT :limit
                """
                results = await session.fetchall(
                    query, {"user_id": user_id, "limit": limit}
                )

                history = []
                for row in results:
                    entry = SearchHistory(
                        id=row["id"],
                        user_id=row["user_id"],
                        query=row["query"],
                        filters=json.loads(row["filters"]),
                        result_count=row["result_count"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        duration_ms=row["duration_ms"],
                    )
                    history.append(entry)

                return history

        except Exception as e:
            logger.error(f"Failed to get search history: {e}")
            return []


class AdvancedSearchService:
    """Main advanced search service."""

    def __init__(self):
        self.fts = FullTextSearch()
        self.suggestions = SearchSuggestions()
        self.history = SearchHistoryService()
        self._initialized = False

    async def initialize(self) -> bool:
        """Initialize all search components."""
        if self._initialized:
            return True

        try:
            logger.info("Initializing Advanced Search Service")

            # Initialize components
            fts_ok = await self.fts.initialize_fts()
            suggestions_ok = await self.suggestions.initialize()
            history_ok = await self.history.initialize()

            if fts_ok and suggestions_ok and history_ok:
                self._initialized = True
                logger.info("Advanced Search Service initialized successfully")
                return True
            else:
                logger.error("Failed to initialize some search components")
                return False

        except Exception as e:
            logger.error(f"Failed to initialize search service: {e}")
            return False

    async def search_messages(
        self, filters: SearchFilter, user_id: str
    ) -> Tuple[List[SearchResult], int]:
        """Perform advanced message search."""
        if not self._initialized:
            await self.initialize()

        try:
            start_time = datetime.now(timezone.utc)

            # Perform search
            results = await self.fts.search(filters.query, filters)

            # Record search in history
            duration = int(
                (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            )
            history_entry = SearchHistory(
                id=str(uuid4()),
                user_id=user_id,
                query=filters.query,
                filters={
                    "user_id": filters.user_id,
                    "channel_id": filters.channel_id,
                    "date_from": (
                        filters.date_from.isoformat() if filters.date_from else None
                    ),
                    "date_to": filters.date_to.isoformat() if filters.date_to else None,
                    "message_type": filters.message_type,
                    "has_attachments": filters.has_attachments,
                },
                result_count=len(results),
                timestamp=start_time,
                duration_ms=duration,
            )
            await self.history.record_search(history_entry)

            # Add search suggestion
            if filters.query:
                await self.suggestions.add_suggestion(filters.query, "query")

            return results, len(results)

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return [], 0

    async def get_suggestions(
        self, prefix: str, limit: int = 10
    ) -> List[SearchSuggestion]:
        """Get search suggestions."""
        if not self._initialized:
            await self.initialize()

        return await self.suggestions.get_suggestions(prefix, limit)

    async def get_search_history(
        self, user_id: str, limit: int = 20
    ) -> List[SearchHistory]:
        """Get user's search history."""
        if not self._initialized:
            await self.initialize()

        return await self.history.get_user_history(user_id, limit)

    async def get_search_stats(self) -> Dict[str, Any]:
        """Get search service statistics."""
        try:
            async with database_manager.get_session() as session:
                # Get total searches
                total_query = (
                    f"SELECT COUNT(*) as total FROM {self.history.history_table}"
                )
                total_result = await session.fetchone(total_query)
                total_searches = total_result["total"] if total_result else 0

                # Get recent searches (last 24 hours)
                yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                recent_query = f"""
                SELECT COUNT(*) as recent FROM {self.history.history_table}
                WHERE timestamp >= :yesterday
                """
                recent_result = await session.fetchone(
                    recent_query, {"yesterday": yesterday}
                )
                recent_searches = recent_result["recent"] if recent_result else 0

                # Get popular queries
                popular_query = f"""
                SELECT query, COUNT(*) as count
                FROM {self.history.history_table}
                GROUP BY query
                ORDER BY count DESC
                LIMIT 10
                """
                popular_results = await session.fetchall(popular_query)
                popular_queries = [
                    {"query": row["query"], "count": row["count"]}
                    for row in popular_results
                ]

                return {
                    "total_searches": total_searches,
                    "recent_searches": recent_searches,
                    "popular_queries": popular_queries,
                    "service_status": (
                        "operational" if self._initialized else "initializing"
                    ),
                }

        except Exception as e:
            logger.error(f"Failed to get search stats: {e}")
            return {"error": str(e)}


# Global search service instance
advanced_search_service = AdvancedSearchService()


async def get_search_service() -> AdvancedSearchService:
    """Get the global search service instance."""
    if not advanced_search_service._initialized:
        await advanced_search_service.initialize()
    return advanced_search_service


__all__ = [
    "SearchFilter",
    "SearchResult",
    "SearchSuggestion",
    "SearchHistory",
    "FullTextSearch",
    "SearchSuggestions",
    "SearchHistoryService",
    "AdvancedSearchService",
    "get_search_service",
]
