from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from plexichat.app.logger_config import logger
from plexichat.app.services.documentation_service import documentation_service

"""
Documentation API endpoints for PlexiChat.
Provides comprehensive documentation management and viewing capabilities.
"""

# Pydantic models for API
class DocumentSearchRequest(BaseModel):
    query: str
    category: Optional[str] = None
    limit: int = 10


class DocumentResponse(BaseModel):
    filename: str
    title: str
    category: str
    content: str
    html_content: str
    headings: List[Dict[str, Any]]
    word_count: int
    last_modified: str


router = APIRouter(prefix="/api/v1/docs", tags=["Documentation"])


@router.get("/")
async def list_documents():
    """Get list of all documentation."""
    try:
        documents = documentation_service.get_all_documents()
        
        return {
            "success": True,
            "documents": documents,
            "total_count": len(documents)
        }
        
    except Exception as e:
        logger.error(f"Failed to list documents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories")
async def get_categories():
    """Get all documentation categories."""
    try:
        categories = documentation_service.get_categories()
        
        return {
            "success": True,
            "categories": categories
        }
        
    except Exception as e:
        logger.error(f"Failed to get categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/navigation")
async def get_navigation_tree():
    """Get hierarchical navigation tree."""
    try:
        tree = documentation_service.get_navigation_tree()
        
        return {
            "success": True,
            "navigation": tree
        }
        
    except Exception as e:
        logger.error(f"Failed to get navigation tree: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_documents(
    q: str = Query(..., description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(10, description="Maximum number of results")
):
    """Search documentation."""
    try:
        results = documentation_service.search_documents(q, category)
        
        # Limit results
        limited_results = results[:limit]
        
        return {
            "success": True,
            "query": q,
            "category": category,
            "results": limited_results,
            "total_found": len(results),
            "returned_count": len(limited_results)
        }
        
    except Exception as e:
        logger.error(f"Failed to search documents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/document/{filename}")
async def get_document(filename: str):
    """Get specific document content."""
    try:
        document = documentation_service.get_document(filename)
        
        if not document:
            raise HTTPException(status_code=404, detail=f"Document not found: {filename}")
        
        return {
            "success": True,
            "document": document
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get document {filename}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_documentation_statistics():
    """Get documentation statistics."""
    try:
        stats = documentation_service.get_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Failed to get documentation statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/refresh")
async def refresh_documentation_index():
    """Refresh the documentation search index."""
    try:
        documentation_service.refresh_index()
        
        return {
            "success": True,
            "message": "Documentation index refreshed successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to refresh documentation index: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/category/{category}")
async def get_documents_by_category(category: str):
    """Get all documents in a specific category."""
    try:
        categories = documentation_service.get_categories()
        
        if category not in categories:
            raise HTTPException(status_code=404, detail=f"Category not found: {category}")
        
        category_info = categories[category]
        documents = []
        
        for doc_info in category_info['documents']:
            doc_data = documentation_service.get_document(doc_info['filename'])
            if doc_data:
                # Remove full content for list view
                doc_summary = {
                    'filename': doc_data['filename'],
                    'title': doc_data['title'],
                    'category': doc_data['category'],
                    'word_count': doc_data['word_count'],
                    'last_modified': doc_data['last_modified'],
                    'headings_count': len(doc_data['headings'])
                }
                documents.append(doc_summary)
        
        return {
            "success": True,
            "category": category,
            "category_name": category_info['name'],
            "documents": documents,
            "total_count": len(documents)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get documents for category {category}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
