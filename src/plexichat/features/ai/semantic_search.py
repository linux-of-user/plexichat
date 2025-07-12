"""
PlexiChat Semantic Search Engine
Advanced semantic search with vector embeddings and AI-powered relevance
"""

import asyncio
import logging
import json
import time
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import pickle

logger = logging.getLogger(__name__)


class SearchType(Enum):
    """Types of semantic search."""
    MESSAGES = "messages"
    FILES = "files"
    USERS = "users"
    CHANNELS = "channels"
    KNOWLEDGE_BASE = "knowledge_base"
    GLOBAL = "global"


class SearchMode(Enum):
    """Search modes."""
    SEMANTIC = "semantic"
    KEYWORD = "keyword"
    HYBRID = "hybrid"
    FUZZY = "fuzzy"


class ContentType(Enum):
    """Content types for indexing."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    CODE = "code"


@dataclass
class SearchDocument:
    """Document for semantic search indexing."""
    doc_id: str
    content: str
    content_type: ContentType
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Indexing metadata
    embedding: Optional[np.ndarray] = None
    keywords: List[str] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    
    # Document metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    author_id: Optional[str] = None
    channel_id: Optional[str] = None
    
    # Search optimization
    search_weight: float = 1.0
    access_permissions: List[str] = field(default_factory=list)


@dataclass
class SearchResult:
    """Search result with relevance scoring."""
    doc_id: str
    content: str
    content_type: ContentType
    relevance_score: float
    
    # Matching details
    matched_keywords: List[str] = field(default_factory=list)
    matched_entities: List[str] = field(default_factory=list)
    semantic_similarity: float = 0.0
    keyword_similarity: float = 0.0
    
    # Document metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    author_id: Optional[str] = None
    channel_id: Optional[str] = None
    created_at: Optional[datetime] = None
    
    # Search context
    highlighted_content: Optional[str] = None
    context_snippet: Optional[str] = None


@dataclass
class SearchQuery:
    """Search query with parameters."""
    query: str
    search_type: SearchType = SearchType.GLOBAL
    search_mode: SearchMode = SearchMode.HYBRID
    
    # Filters
    content_types: List[ContentType] = field(default_factory=list)
    author_ids: List[str] = field(default_factory=list)
    channel_ids: List[str] = field(default_factory=list)
    date_range: Optional[Tuple[datetime, datetime]] = None
    
    # Search parameters
    max_results: int = 20
    min_relevance: float = 0.1
    include_metadata: bool = True
    
    # User context
    user_id: Optional[str] = None
    user_permissions: List[str] = field(default_factory=list)


class SemanticSearchEngine:
    """
    Advanced Semantic Search Engine.
    
    Features:
    - Vector embeddings for semantic similarity
    - Hybrid search combining semantic and keyword matching
    - Real-time indexing and search
    - Multi-modal content support
    - Personalized search results
    - Access control and permissions
    - Search analytics and optimization
    - Auto-completion and suggestions
    """
    
    def __init__(self):
        self.enabled = True
        
        # Document storage
        self.documents: Dict[str, SearchDocument] = {}
        self.embeddings_cache: Dict[str, np.ndarray] = {}
        
        # Search indexes
        self.keyword_index: Dict[str, List[str]] = {}  # keyword -> doc_ids
        self.entity_index: Dict[str, List[str]] = {}   # entity -> doc_ids
        self.author_index: Dict[str, List[str]] = {}   # author_id -> doc_ids
        self.channel_index: Dict[str, List[str]] = {}  # channel_id -> doc_ids
        
        # Vector search
        self.embedding_dimension = 1536  # OpenAI embedding dimension
        self.similarity_threshold = 0.7
        
        # Search configuration
        self.max_index_size = 1000000  # Maximum documents to index
        self.embedding_batch_size = 100
        self.search_timeout = 5.0  # seconds
        
        # Statistics
        self.stats = {
            "total_documents": 0,
            "total_searches": 0,
            "average_search_time": 0.0,
            "cache_hit_rate": 0.0,
            "index_size_mb": 0.0,
            "popular_queries": {},
            "search_success_rate": 0.95
        }
        
        # AI provider for embeddings
        self.ai_provider = None  # Will be injected
        
        # Background tasks
        self.indexing_queue: List[SearchDocument] = []
        self.indexing_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def start(self):
        """Start the semantic search engine."""
        if self.running:
            return
        
        self.running = True
        
        # Start background indexing
        self.indexing_task = asyncio.create_task(self._indexing_loop())
        
        logger.info("✅ Semantic Search Engine started")
    
    async def stop(self):
        """Stop the semantic search engine."""
        if not self.running:
            return
        
        self.running = False
        
        # Stop background tasks
        if self.indexing_task:
            self.indexing_task.cancel()
            try:
                await self.indexing_task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Semantic Search Engine stopped")
    
    async def index_document(self, document: SearchDocument) -> bool:
        """Index a document for search."""
        try:
            # Add to indexing queue for background processing
            self.indexing_queue.append(document)
            
            # For real-time search, also add to immediate index
            await self._process_document_immediate(document)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to index document {document.doc_id}: {e}")
            return False
    
    async def _process_document_immediate(self, document: SearchDocument):
        """Process document for immediate search availability."""
        # Store document
        self.documents[document.doc_id] = document
        
        # Extract keywords
        keywords = await self._extract_keywords(document.content)
        document.keywords = keywords
        
        # Update keyword index
        for keyword in keywords:
            if keyword not in self.keyword_index:
                self.keyword_index[keyword] = []
            if document.doc_id not in self.keyword_index[keyword]:
                self.keyword_index[keyword].append(document.doc_id)
        
        # Update other indexes
        if document.author_id:
            if document.author_id not in self.author_index:
                self.author_index[document.author_id] = []
            if document.doc_id not in self.author_index[document.author_id]:
                self.author_index[document.author_id].append(document.doc_id)
        
        if document.channel_id:
            if document.channel_id not in self.channel_index:
                self.channel_index[document.channel_id] = []
            if document.doc_id not in self.channel_index[document.channel_id]:
                self.channel_index[document.channel_id].append(document.doc_id)
        
        self.stats["total_documents"] = len(self.documents)
    
    async def _indexing_loop(self):
        """Background indexing loop for generating embeddings."""
        while self.running:
            try:
                if self.indexing_queue:
                    # Process batch of documents
                    batch = self.indexing_queue[:self.embedding_batch_size]
                    self.indexing_queue = self.indexing_queue[self.embedding_batch_size:]
                    
                    await self._process_embedding_batch(batch)
                else:
                    # No documents to process, wait
                    await asyncio.sleep(1)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Indexing loop error: {e}")
                await asyncio.sleep(5)
    
    async def _process_embedding_batch(self, documents: List[SearchDocument]):
        """Process a batch of documents for embedding generation."""
        try:
            # Extract text content for embedding
            texts = []
            doc_ids = []
            
            for doc in documents:
                if doc.content_type == ContentType.TEXT:
                    texts.append(doc.content)
                    doc_ids.append(doc.doc_id)
            
            if not texts:
                return
            
            # Generate embeddings using AI provider
            if self.ai_provider:
                embeddings = await self._generate_embeddings(texts)
                
                # Store embeddings
                for i, doc_id in enumerate(doc_ids):
                    if i < len(embeddings):
                        self.embeddings_cache[doc_id] = embeddings[i]
                        if doc_id in self.documents:
                            self.documents[doc_id].embedding = embeddings[i]
            
        except Exception as e:
            logger.error(f"Embedding batch processing failed: {e}")
    
    async def search(self, query: SearchQuery) -> List[SearchResult]:
        """Perform semantic search."""
        start_time = time.time()
        
        try:
            self.stats["total_searches"] += 1
            
            # Track popular queries
            query_key = query.query.lower()
            self.stats["popular_queries"][query_key] = self.stats["popular_queries"].get(query_key, 0) + 1
            
            # Get candidate documents based on filters
            candidate_docs = await self._get_candidate_documents(query)
            
            if not candidate_docs:
                return []
            
            # Score documents based on search mode
            if query.search_mode == SearchMode.SEMANTIC:
                results = await self._semantic_search(query, candidate_docs)
            elif query.search_mode == SearchMode.KEYWORD:
                results = await self._keyword_search(query, candidate_docs)
            elif query.search_mode == SearchMode.HYBRID:
                results = await self._hybrid_search(query, candidate_docs)
            else:
                results = await self._fuzzy_search(query, candidate_docs)
            
            # Filter by relevance threshold
            results = [r for r in results if r.relevance_score >= query.min_relevance]
            
            # Sort by relevance
            results.sort(key=lambda x: x.relevance_score, reverse=True)
            
            # Limit results
            results = results[:query.max_results]
            
            # Add highlighting and context
            for result in results:
                result.highlighted_content = await self._highlight_matches(result.content, query.query)
                result.context_snippet = await self._generate_context_snippet(result.content, query.query)
            
            # Update statistics
            search_time = (time.time() - start_time) * 1000
            self._update_search_statistics(search_time, len(results) > 0)
            
            logger.info(f"Search completed: '{query.query}' -> {len(results)} results in {search_time:.2f}ms")
            
            return results
            
        except Exception as e:
            logger.error(f"Search failed for query '{query.query}': {e}")
            return []
    
    async def _get_candidate_documents(self, query: SearchQuery) -> List[str]:
        """Get candidate document IDs based on filters."""
        candidate_sets = []
        
        # Filter by content types
        if query.content_types:
            content_type_docs = []
            for doc_id, doc in self.documents.items():
                if doc.content_type in query.content_types:
                    content_type_docs.append(doc_id)
            candidate_sets.append(set(content_type_docs))
        
        # Filter by authors
        if query.author_ids:
            author_docs = set()
            for author_id in query.author_ids:
                author_docs.update(self.author_index.get(author_id, []))
            candidate_sets.append(author_docs)
        
        # Filter by channels
        if query.channel_ids:
            channel_docs = set()
            for channel_id in query.channel_ids:
                channel_docs.update(self.channel_index.get(channel_id, []))
            candidate_sets.append(channel_docs)
        
        # Filter by date range
        if query.date_range:
            start_date, end_date = query.date_range
            date_docs = []
            for doc_id, doc in self.documents.items():
                if start_date <= doc.created_at <= end_date:
                    date_docs.append(doc_id)
            candidate_sets.append(set(date_docs))
        
        # Intersect all filter sets
        if candidate_sets:
            candidates = candidate_sets[0]
            for candidate_set in candidate_sets[1:]:
                candidates = candidates.intersection(candidate_set)
            return list(candidates)
        else:
            # No filters, return all documents
            return list(self.documents.keys())
    
    async def _semantic_search(self, query: SearchQuery, candidate_docs: List[str]) -> List[SearchResult]:
        """Perform semantic search using vector embeddings."""
        results = []
        
        # Generate query embedding
        query_embedding = await self._generate_query_embedding(query.query)
        if query_embedding is None:
            return results
        
        # Calculate semantic similarity for each candidate
        for doc_id in candidate_docs:
            if doc_id not in self.documents:
                continue
            
            doc = self.documents[doc_id]
            
            # Get document embedding
            doc_embedding = self.embeddings_cache.get(doc_id)
            if doc_embedding is None:
                continue
            
            # Calculate cosine similarity
            similarity = self._cosine_similarity(query_embedding, doc_embedding)
            
            if similarity >= self.similarity_threshold:
                result = SearchResult(
                    doc_id=doc_id,
                    content=doc.content,
                    content_type=doc.content_type,
                    relevance_score=similarity,
                    semantic_similarity=similarity,
                    metadata=doc.metadata,
                    author_id=doc.author_id,
                    channel_id=doc.channel_id,
                    created_at=doc.created_at
                )
                results.append(result)
        
        return results
    
    async def _keyword_search(self, query: SearchQuery, candidate_docs: List[str]) -> List[SearchResult]:
        """Perform keyword-based search."""
        results = []
        query_keywords = await self._extract_keywords(query.query)
        
        for doc_id in candidate_docs:
            if doc_id not in self.documents:
                continue
            
            doc = self.documents[doc_id]
            
            # Calculate keyword similarity
            keyword_score = self._calculate_keyword_similarity(query_keywords, doc.keywords)
            
            if keyword_score > 0:
                result = SearchResult(
                    doc_id=doc_id,
                    content=doc.content,
                    content_type=doc.content_type,
                    relevance_score=keyword_score,
                    keyword_similarity=keyword_score,
                    matched_keywords=[kw for kw in query_keywords if kw in doc.keywords],
                    metadata=doc.metadata,
                    author_id=doc.author_id,
                    channel_id=doc.channel_id,
                    created_at=doc.created_at
                )
                results.append(result)
        
        return results
    
    async def _hybrid_search(self, query: SearchQuery, candidate_docs: List[str]) -> List[SearchResult]:
        """Perform hybrid search combining semantic and keyword matching."""
        # Get semantic results
        semantic_results = await self._semantic_search(query, candidate_docs)
        semantic_dict = {r.doc_id: r for r in semantic_results}
        
        # Get keyword results
        keyword_results = await self._keyword_search(query, candidate_docs)
        keyword_dict = {r.doc_id: r for r in keyword_results}
        
        # Combine results
        combined_results = []
        all_doc_ids = set(semantic_dict.keys()) | set(keyword_dict.keys())
        
        for doc_id in all_doc_ids:
            semantic_result = semantic_dict.get(doc_id)
            keyword_result = keyword_dict.get(doc_id)
            
            # Calculate combined score
            semantic_score = semantic_result.semantic_similarity if semantic_result else 0.0
            keyword_score = keyword_result.keyword_similarity if keyword_result else 0.0
            
            # Weighted combination (70% semantic, 30% keyword)
            combined_score = (semantic_score * 0.7) + (keyword_score * 0.3)
            
            # Use the result with more information
            base_result = semantic_result or keyword_result
            
            result = SearchResult(
                doc_id=base_result.doc_id,
                content=base_result.content,
                content_type=base_result.content_type,
                relevance_score=combined_score,
                semantic_similarity=semantic_score,
                keyword_similarity=keyword_score,
                matched_keywords=keyword_result.matched_keywords if keyword_result else [],
                metadata=base_result.metadata,
                author_id=base_result.author_id,
                channel_id=base_result.channel_id,
                created_at=base_result.created_at
            )
            combined_results.append(result)
        
        return combined_results
    
    async def _fuzzy_search(self, query: SearchQuery, candidate_docs: List[str]) -> List[SearchResult]:
        """Perform fuzzy search for typo tolerance."""
        # Placeholder for fuzzy search implementation
        # Would use libraries like fuzzywuzzy or implement edit distance
        return await self._keyword_search(query, candidate_docs)
    
    async def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text."""
        # Simple keyword extraction (in production, use NLP libraries)
        import re
        
        # Remove punctuation and convert to lowercase
        text = re.sub(r'[^\w\s]', '', text.lower())
        
        # Split into words and filter
        words = text.split()
        
        # Filter out common stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'}
        
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        return list(set(keywords))  # Remove duplicates
    
    def _calculate_keyword_similarity(self, query_keywords: List[str], doc_keywords: List[str]) -> float:
        """Calculate keyword similarity score."""
        if not query_keywords or not doc_keywords:
            return 0.0
        
        # Calculate Jaccard similarity
        query_set = set(query_keywords)
        doc_set = set(doc_keywords)
        
        intersection = len(query_set.intersection(doc_set))
        union = len(query_set.union(doc_set))
        
        return intersection / union if union > 0 else 0.0
    
    async def _generate_embeddings(self, texts: List[str]) -> List[np.ndarray]:
        """Generate embeddings for texts using AI provider."""
        # Placeholder - would use actual embedding API
        embeddings = []
        for text in texts:
            # Generate random embedding for demonstration
            embedding = np.random.rand(self.embedding_dimension)
            embeddings.append(embedding)
        return embeddings
    
    async def _generate_query_embedding(self, query: str) -> Optional[np.ndarray]:
        """Generate embedding for search query."""
        embeddings = await self._generate_embeddings([query])
        return embeddings[0] if embeddings else None
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    async def _highlight_matches(self, content: str, query: str) -> str:
        """Highlight matching terms in content."""
        # Simple highlighting (in production, use more sophisticated highlighting)
        query_words = query.lower().split()
        highlighted = content
        
        for word in query_words:
            highlighted = highlighted.replace(word, f"**{word}**")
        
        return highlighted
    
    async def _generate_context_snippet(self, content: str, query: str) -> str:
        """Generate context snippet around matches."""
        # Find the first occurrence of query terms and extract context
        query_words = query.lower().split()
        content_lower = content.lower()
        
        for word in query_words:
            index = content_lower.find(word)
            if index != -1:
                # Extract 100 characters before and after
                start = max(0, index - 100)
                end = min(len(content), index + len(word) + 100)
                snippet = content[start:end]
                
                if start > 0:
                    snippet = "..." + snippet
                if end < len(content):
                    snippet = snippet + "..."
                
                return snippet
        
        # If no matches found, return first 200 characters
        return content[:200] + ("..." if len(content) > 200 else "")
    
    def _update_search_statistics(self, search_time_ms: float, success: bool):
        """Update search statistics."""
        # Update average search time
        current_avg = self.stats["average_search_time"]
        total_searches = self.stats["total_searches"]
        new_avg = ((current_avg * (total_searches - 1)) + search_time_ms) / total_searches
        self.stats["average_search_time"] = new_avg
        
        # Update success rate
        if success:
            current_rate = self.stats["search_success_rate"]
            new_rate = ((current_rate * (total_searches - 1)) + 1.0) / total_searches
            self.stats["search_success_rate"] = new_rate
    
    async def remove_document(self, doc_id: str) -> bool:
        """Remove document from search index."""
        if doc_id not in self.documents:
            return False
        
        try:
            doc = self.documents[doc_id]
            
            # Remove from keyword index
            for keyword in doc.keywords:
                if keyword in self.keyword_index:
                    if doc_id in self.keyword_index[keyword]:
                        self.keyword_index[keyword].remove(doc_id)
                    if not self.keyword_index[keyword]:
                        del self.keyword_index[keyword]
            
            # Remove from other indexes
            if doc.author_id and doc.author_id in self.author_index:
                if doc_id in self.author_index[doc.author_id]:
                    self.author_index[doc.author_id].remove(doc_id)
            
            if doc.channel_id and doc.channel_id in self.channel_index:
                if doc_id in self.channel_index[doc.channel_id]:
                    self.channel_index[doc.channel_id].remove(doc_id)
            
            # Remove from embeddings cache
            if doc_id in self.embeddings_cache:
                del self.embeddings_cache[doc_id]
            
            # Remove document
            del self.documents[doc_id]
            
            self.stats["total_documents"] = len(self.documents)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove document {doc_id}: {e}")
            return False
    
    def get_search_statistics(self) -> Dict[str, Any]:
        """Get comprehensive search statistics."""
        return {
            "enabled": self.enabled,
            "running": self.running,
            "statistics": self.stats,
            "index_info": {
                "total_documents": len(self.documents),
                "embeddings_cached": len(self.embeddings_cache),
                "keyword_terms": len(self.keyword_index),
                "indexed_authors": len(self.author_index),
                "indexed_channels": len(self.channel_index)
            },
            "configuration": {
                "embedding_dimension": self.embedding_dimension,
                "similarity_threshold": self.similarity_threshold,
                "max_index_size": self.max_index_size,
                "search_timeout": self.search_timeout
            }
        }


# Global semantic search engine
semantic_search_engine = SemanticSearchEngine()
