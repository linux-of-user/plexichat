"""
PlexiChat Base Data Access Object (DAO) Pattern
Provides a standardized interface for database operations with advanced features
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Type, TypeVar, Generic, Union
from datetime import datetime, timezone
# ABC removed - BaseDAO is now concrete
from dataclasses import dataclass, field
from enum import Enum
import uuid

from sqlalchemy import select, insert, update, delete, and_, or_, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload
from sqlmodel import SQLModel

logger = logging.getLogger(__name__)

# Type variables for generic DAO
T = TypeVar('T', bound=SQLModel)
CreateT = TypeVar('CreateT')
UpdateT = TypeVar('UpdateT')


class SortOrder(Enum):
    """Sort order enumeration."""
    ASC = "asc"
    DESC = "desc"


class FilterOperator(Enum):
    """Filter operators for queries."""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_EQUAL = "lte"
    LIKE = "like"
    ILIKE = "ilike"
    IN = "in"
    NOT_IN = "not_in"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"
    BETWEEN = "between"
    CONTAINS = "contains"


@dataclass
class FilterCriteria:
    """Filter criteria for database queries."""
    field: str
    operator: FilterOperator
    value: Any
    case_sensitive: bool = True


@dataclass
class SortCriteria:
    """Sort criteria for database queries."""
    field: str
    order: SortOrder = SortOrder.ASC


@dataclass
class PaginationParams:
    """Pagination parameters."""
    page: int = 1
    page_size: int = 20
    
    @property
    def offset(self) -> int:
        """Calculate offset from page and page_size."""
        return (self.page - 1) * self.page_size


@dataclass
class QueryOptions:
    """Advanced query options."""
    filters: List[FilterCriteria] = field(default_factory=list)
    sorts: List[SortCriteria] = field(default_factory=list)
    pagination: Optional[PaginationParams] = None
    include_deleted: bool = False
    include_relations: List[str] = field(default_factory=list)
    select_fields: List[str] = field(default_factory=list)
    group_by: List[str] = field(default_factory=list)
    having: List[FilterCriteria] = field(default_factory=list)



@dataclass
class QueryResult(Generic[T]):
    """Query result with metadata."""
    data: List[T]
    total_count: int
    page: int = 1
    page_size: int = 20
    has_next: bool = False
    has_previous: bool = False
    
    @property
    def total_pages(self) -> int:
        """Calculate total pages."""
        return (self.total_count + self.page_size - 1) // self.page_size


class BaseDAO(Generic[T, CreateT, UpdateT]):
    """
    Base Data Access Object providing standardized database operations.
    
    Features:
    - Generic CRUD operations
    - Advanced filtering and sorting
    - Pagination support
    - Soft delete functionality
    - Audit trail integration
    - Caching support
    - Bulk operations
    - Transaction management
    """
    
    def __init__(self, model_class: Type[T], session_factory):
        self.model_class = model_class
        self.session_factory = session_factory
        self.table_name = getattr(model_class, '__tablename__', model_class.__name__.lower())
        
        # Caching
        self.cache_enabled = True
        self.cache_ttl = 300  # 5 minutes
        self._cache: Dict[str, Any] = {}
        
        # Audit trail
        self.audit_enabled = True
        
        # Soft delete
        self.soft_delete_enabled = hasattr(model_class, 'deleted_at')

        # Statistics
        self.stats: Dict[str, Any] = {}
    
    async def get_session(self) -> AsyncSession:  # type: ignore
        """Get database session."""
        if callable(self.session_factory):
            result = self.session_factory()
            if hasattr(result, '__await__'):
                return await result  # type: ignore
            return result  # type: ignore
        return self.session_factory  # type: ignore
    
    # CRUD Operations
    
    async def create(self, data: CreateT, **kwargs) -> T:
        """Create a new record."""
        async with await self.get_session() as session:
            try:
                # Convert data to model instance
                if isinstance(data, dict):
                    instance = self.model_class(**data)
                elif hasattr(data, 'dict'):
                    instance = self.model_class(**data.dict())  # type: ignore
                else:
                    instance = self.model_class(**data.__dict__)
                
                # Add audit fields if available
                if hasattr(instance, 'created_at'):
                    instance.created_at = datetime.now(timezone.utc)
                if hasattr(instance, 'updated_at'):
                    instance.updated_at = datetime.now(timezone.utc)
                if hasattr(instance, 'id') and not getattr(instance, 'id', None):
                    setattr(instance, 'id', str(uuid.uuid4()))
                
                session.add(instance)
                await session.commit()
                await session.refresh(instance)
                
                # Clear cache
                self._clear_cache()
                
                # Log audit trail
                if self.audit_enabled:
                    record_id = getattr(instance, 'id', None) or str(uuid.uuid4())
                    await self._log_audit('CREATE', record_id, None, instance)
                
                logger.debug(f"Created {self.model_class.__name__}: {getattr(instance, 'id', 'unknown')}")
                return instance
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to create {self.model_class.__name__}: {e}")
                raise
    
    async def get_by_id(self, id: str, include_relations: Optional[List[str]] = None) -> Optional[T]:
        """Get record by ID."""
        cache_key = f"{self.table_name}:id:{id}"
        
        # Check cache first
        if self.cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]
        
        async with await self.get_session() as session:
            try:
                query = select(self.model_class).where(getattr(self.model_class, 'id') == id)
                
                # Add soft delete filter
                if self.soft_delete_enabled:
                    deleted_at_attr = getattr(self.model_class, 'deleted_at', None)
                    if deleted_at_attr is not None:
                        query = query.where(deleted_at_attr.is_(None))
                
                # Include relations
                if include_relations:
                    for relation in include_relations:
                        if hasattr(self.model_class, relation):
                            query = query.options(selectinload(getattr(self.model_class, relation)))
                
                result = await session.execute(query)
                instance = result.scalar_one_or_none()
                
                # Cache result
                if self.cache_enabled and instance:
                    self._cache[cache_key] = instance
                
                return instance
                
            except Exception as e:
                logger.error(f"Failed to get {self.model_class.__name__} by ID {id}: {e}")
                raise
    
    async def get_all(self, options: Optional[QueryOptions] = None) -> QueryResult[T]:
        """Get all records with advanced filtering and pagination."""
        if options is None:
            options = QueryOptions()
        
        async with await self.get_session() as session:
            try:
                # Build base query
                query = select(self.model_class)
                
                # Apply soft delete filter
                if self.soft_delete_enabled and not options.include_deleted:
                    deleted_at_attr = getattr(self.model_class, 'deleted_at', None)
                    if deleted_at_attr is not None:
                        query = query.where(deleted_at_attr.is_(None))
                
                # Apply filters
                query = self._apply_filters(query, options.filters)
                
                # Apply having clauses (for aggregated queries)
                if options.having:
                    query = self._apply_having(query, options.having)
                
                # Apply group by
                if options.group_by:
                    for field in options.group_by:
                        if hasattr(self.model_class, field):
                            query = query.group_by(getattr(self.model_class, field))
                
                # Get total count before pagination
                count_query = select(func.count()).select_from(query.subquery())
                total_count_result = await session.execute(count_query)
                total_count = total_count_result.scalar()
                
                # Apply sorting
                query = self._apply_sorting(query, options.sorts)
                
                # Apply pagination
                if options.pagination:
                    query = query.offset(options.pagination.offset).limit(options.pagination.page_size)
                
                # Include relations
                if options.include_relations:
                    for relation in options.include_relations:
                        if hasattr(self.model_class, relation):
                            query = query.options(selectinload(getattr(self.model_class, relation)))
                
                # Execute query
                result = await session.execute(query)
                instances = result.scalars().all()
                
                # Build result
                page = options.pagination.page if options.pagination else 1
                page_size = options.pagination.page_size if options.pagination else len(instances)
                
                # Ensure total_count is not None
                total_count = total_count or 0

                return QueryResult(
                    data=list(instances),
                    total_count=total_count,
                    page=page,
                    page_size=page_size,
                    has_next=page * page_size < total_count,
                    has_previous=page > 1
                )
                
            except Exception as e:
                logger.error(f"Failed to get all {self.model_class.__name__}: {e}")
                raise
    
    async def update(self, id: str, data: UpdateT, **kwargs) -> Optional[T]:
        """Update record by ID."""
        async with await self.get_session() as session:
            try:
                # Get existing instance
                instance = await self.get_by_id(id)
                if not instance:
                    return None
                
                # Store old values for audit
                if hasattr(instance, 'model_dump'):
                    old_values = instance.model_dump()
                elif hasattr(instance, 'dict'):
                    old_values = instance.dict()  # type: ignore
                else:
                    old_values = instance.__dict__.copy()
                
                # Update fields
                if isinstance(data, dict):
                    update_data = data
                elif hasattr(data, 'model_dump'):
                    update_data = data.model_dump(exclude_unset=True)  # type: ignore
                elif hasattr(data, 'dict'):
                    update_data = data.dict(exclude_unset=True)  # type: ignore
                else:
                    update_data = {k: v for k, v in data.__dict__.items() if not k.startswith('_')}
                
                for field, value in update_data.items():
                    if hasattr(instance, field):
                        setattr(instance, field, value)
                
                # Update audit fields
                if hasattr(instance, 'updated_at'):
                    instance.updated_at = datetime.now(timezone.utc)
                
                await session.commit()
                await session.refresh(instance)
                
                # Clear cache
                self._clear_cache()
                
                # Log audit trail
                if self.audit_enabled:
                    await self._log_audit('UPDATE', id, old_values, instance)
                
                logger.debug(f"Updated {self.model_class.__name__}: {id}")
                return instance
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to update {self.model_class.__name__} {id}: {e}")
                raise
    
    async def delete(self, id: str, soft_delete: Optional[bool] = None) -> bool:
        """Delete record by ID (soft or hard delete)."""
        if soft_delete is None:
            soft_delete = self.soft_delete_enabled
        
        async with await self.get_session() as session:
            try:
                instance = await self.get_by_id(id)
                if not instance:
                    return False
                
                if soft_delete and hasattr(instance, 'deleted_at'):
                    # Soft delete
                    instance.deleted_at = datetime.now(timezone.utc)
                    if hasattr(instance, 'updated_at'):
                        instance.updated_at = datetime.now(timezone.utc)
                    await session.commit()
                else:
                    # Hard delete
                    await session.delete(instance)
                    await session.commit()
                
                # Clear cache
                self._clear_cache()
                
                # Log audit trail
                if self.audit_enabled:
                    action = 'SOFT_DELETE' if soft_delete else 'DELETE'
                    await self._log_audit(action, id, instance, None)
                
                logger.debug(f"Deleted {self.model_class.__name__}: {id} (soft={soft_delete})")
                return True
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to delete {self.model_class.__name__} {id}: {e}")
                raise
    
    # Bulk Operations
    
    async def bulk_create(self, data_list: List[CreateT]) -> List[T]:
        """Create multiple records in bulk."""
        async with await self.get_session() as session:
            try:
                instances = []
                for data in data_list:
                    if isinstance(data, dict):
                        instance = self.model_class(**data)
                    elif hasattr(data, 'model_dump'):
                        instance = self.model_class(**data.model_dump())  # type: ignore
                    elif hasattr(data, 'dict'):
                        instance = self.model_class(**data.dict())  # type: ignore
                    else:
                        instance = self.model_class(**data.__dict__)
                    
                    # Add audit fields
                    if hasattr(instance, 'created_at'):
                        instance.created_at = datetime.now(timezone.utc)
                    if hasattr(instance, 'updated_at'):
                        instance.updated_at = datetime.now(timezone.utc)
                    if hasattr(instance, 'id') and not getattr(instance, 'id', None):
                        setattr(instance, 'id', str(uuid.uuid4()))
                    
                    instances.append(instance)
                
                session.add_all(instances)
                await session.commit()
                
                # Refresh all instances
                for instance in instances:
                    await session.refresh(instance)
                
                # Clear cache
                self._clear_cache()
                
                logger.debug(f"Bulk created {len(instances)} {self.model_class.__name__} records")
                return instances
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to bulk create {self.model_class.__name__}: {e}")
                raise
    
    async def bulk_update(self, updates: List[Dict[str, Any]]) -> int:
        """Update multiple records in bulk."""
        async with await self.get_session() as session:
            try:
                updated_count = 0
                
                for update_data in updates:
                    if 'id' not in update_data:
                        continue
                    
                    record_id = update_data.pop('id')
                    update_data['updated_at'] = datetime.now(timezone.utc)
                    
                    query = update(self.model_class).where(getattr(self.model_class, 'id') == record_id).values(**update_data)
                    result = await session.execute(query)
                    updated_count += result.rowcount
                
                await session.commit()
                
                # Clear cache
                self._clear_cache()
                
                logger.debug(f"Bulk updated {updated_count} {self.model_class.__name__} records")
                return updated_count
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to bulk update {self.model_class.__name__}: {e}")
                raise
    
    # Helper Methods
    
    def _apply_filters(self, query, filters: List[FilterCriteria]):
        """Apply filter criteria to query."""
        if not filters:
            return query
        
        for filter_criteria in filters:
            field = getattr(self.model_class, filter_criteria.field, None)
            if field is None:
                continue
            
            if filter_criteria.operator == FilterOperator.EQUALS:
                query = query.where(field == filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.NOT_EQUALS:
                query = query.where(field != filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.GREATER_THAN:
                query = query.where(field > filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.GREATER_EQUAL:
                query = query.where(field >= filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.LESS_THAN:
                query = query.where(field < filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.LESS_EQUAL:
                query = query.where(field <= filter_criteria.value)
            elif filter_criteria.operator == FilterOperator.LIKE:
                if filter_criteria.case_sensitive:
                    query = query.where(field.like(filter_criteria.value))
                else:
                    query = query.where(field.ilike(filter_criteria.value))
            elif filter_criteria.operator == FilterOperator.IN:
                query = query.where(field.in_(filter_criteria.value))
            elif filter_criteria.operator == FilterOperator.NOT_IN:
                query = query.where(~field.in_(filter_criteria.value))
            elif filter_criteria.operator == FilterOperator.IS_NULL:
                query = query.where(field.is_(None))
            elif filter_criteria.operator == FilterOperator.IS_NOT_NULL:
                query = query.where(field.is_not(None))
            elif filter_criteria.operator == FilterOperator.BETWEEN:
                if isinstance(filter_criteria.value, (list, tuple)) and len(filter_criteria.value) == 2:
                    query = query.where(field.between(filter_criteria.value[0], filter_criteria.value[1]))
        
        return query
    
    def _apply_sorting(self, query, sorts: List[SortCriteria]):
        """Apply sort criteria to query."""
        if not sorts:
            return query
        
        for sort_criteria in sorts:
            field = getattr(self.model_class, sort_criteria.field, None)
            if field is None:
                continue
            
            if sort_criteria.order == SortOrder.DESC:
                query = query.order_by(field.desc())
            else:
                query = query.order_by(field.asc())
        
        return query
    
    def _apply_having(self, query, having_clauses: List[FilterCriteria]):
        """Apply having clauses to query."""
        # Acknowledge parameter to avoid unused warning
        _ = having_clauses
        # Implementation would depend on specific aggregation needs
        return query
    
    def _clear_cache(self):
        """Clear DAO cache."""
        if self.cache_enabled:
            self._cache.clear()
    
    async def _log_audit(self, action: str, record_id: str, old_values: Any, new_values: Any):
        """Log audit trail entry."""
        # Acknowledge parameters to avoid unused warnings
        _ = old_values, new_values
        # Implementation would integrate with audit system
        logger.debug(f"Audit: {action} {self.model_class.__name__} {record_id}")
    
    # Default implementations for custom methods

    async def find_by_criteria(self, criteria: Dict[str, Any]) -> List[T]:
        """Find records by custom criteria."""
        # Default implementation using standard filtering
        filters = []
        for key, value in criteria.items():
            if hasattr(self.model_class, key):
                filters.append(FilterCriteria(field=key, operator=FilterOperator.EQUALS, value=value))

        options = QueryOptions(filters=filters)
        result = await self.get_all(options=options)
        return result.data

    async def get_statistics(self) -> Dict[str, Any]:
        """Get DAO statistics."""
        # Default implementation providing basic statistics
        async with await self.get_session() as session:
            try:
                # Count total records
                count_query = select(func.count()).select_from(self.model_class)
                if self.soft_delete_enabled:
                    count_query = count_query.where(getattr(self.model_class, 'deleted_at').is_(None))

                result = await session.execute(count_query)
                total_count = result.scalar() or 0

                return {
                    "total_records": total_count,
                    "table_name": self.table_name,
                    "cache_enabled": self.cache_enabled,
                    "soft_delete_enabled": self.soft_delete_enabled,
                    "audit_enabled": self.audit_enabled
                }
            except Exception as e:
                logger.error(f"Error getting statistics for {self.model_class.__name__}: {e}")
                return {
                    "total_records": 0,
                    "table_name": self.table_name,
                    "error": str(e)
                }
