# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
from collections.abc import Callable
from functools import wraps
from typing import Any

from fastapi.security import HTTPAuthorizationCredentials
from flask import Blueprint, flash, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

from plexichat.core.auth.fastapi_adapter import get_auth_adapter
from plexichat.core.logging import get_logger
from plexichat.features.ai.features.ai_powered_features_service import (
    AIPoweredFeaturesService,
)

"""
PlexiChat AI-Powered Features Admin Routes

Flask routes for managing AI-powered features including summarization,
content suggestions, sentiment analysis, semantic search, and moderation.

This module uses the unified authentication adapter (FastAPI adapter) to
validate tokens and enforce admin-only access on these routes.
"""

logger = get_logger(__name__)

ai_features_bp = Blueprint('ai_features_admin', __name__, url_prefix='/admin/ai-features')

# Global service instance
_ai_features_service: AIPoweredFeaturesService | None = None

def get_ai_features_service() -> AIPoweredFeaturesService:
    """Get or create AI features service instance."""
    global _ai_features_service
    if _ai_features_service is None:
        _ai_features_service = AIPoweredFeaturesService()
    return _ai_features_service


def route_wrapper(bp, *args, **kwargs):
    return bp.route(*args, **kwargs)


def _is_api_request() -> bool:
    """Utility to determine if the incoming request is an API call."""
    path = request.path or ""
    # If path contains '/api/' we consider it an API endpoint
    if "/api/" in path:
        return True
    # If Accept header prefers JSON, treat as API
    accept = request.headers.get("Accept", "")
    if "application/json" in accept:
        return True
    return False


def _unauthorized_response(message: str = "Admin privileges required"):
    """
    Consistent unauthorized response for API and UI routes.
    API endpoints return JSON with a 403 status code.
    UI endpoints flash a message and render the admin dashboard template with empty data.
    """
    logger.warning(f"Unauthorized access: {message} - Path: {request.path}")
    if _is_api_request():
        return jsonify({"success": False, "error": "forbidden", "message": message}), 403
    # For UI requests, flash a message and render the dashboard with empty/default context
    flash(message, "error")
    try:
        return render_template('admin/ai_features_management.html', stats={}, health={}, config={}), 403
    except Exception:
        # Fallback simple response if template rendering fails
        return jsonify({"success": False, "error": "forbidden", "message": message}), 403


def require_admin(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Flask-compatible decorator that enforces admin privileges using the unified
    FastAPI authentication adapter. This decorator will extract the Authorization
    header from the incoming Flask request, validate the token via the unified
    auth manager, and ensure the current user has admin privileges.

    On failure it returns either a JSON 403 response for API calls or flashes a
    message and renders the admin dashboard for UI calls.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        adapter = get_auth_adapter()
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
        if not auth_header:
            return _unauthorized_response("Missing Authorization header")

        # Parse possible schemes: "Bearer <token>", "Token <token>", or raw token
        parts = auth_header.split()
        if len(parts) == 1:
            scheme = "Bearer"
            token = parts[0]
        else:
            scheme = parts[0]
            token = parts[1]

        # Build HTTPAuthorizationCredentials expected by the FastAPI adapter
        credentials = HTTPAuthorizationCredentials(scheme=scheme, credentials=token)

        # The adapter.get_current_user is async; run it in the event loop for Flask endpoints
        try:
            user = asyncio.run(adapter.get_current_user(credentials))
        except Exception as e:
            logger.debug(f"Authentication failure while validating token: {e}")
            return _unauthorized_response("Invalid or expired authentication token")

        if not user or not isinstance(user, dict):
            return _unauthorized_response("Invalid authentication context")

        if not user.get("is_admin", False):
            return _unauthorized_response("Admin privileges required")

        # Attach the user to kwargs for convenience if the wrapped function wants it
        # but avoid overwriting any existing 'current_user' kwarg
        if 'current_user' not in kwargs:
            kwargs['current_user'] = user

        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log unexpected exceptions here to make debugging easier
            logger.exception(f"Unhandled exception in admin route '{func.__name__}': {e}")
            # Re-raise so Flask's error handlers or the route's own handlers can manage it,
            # but provide a JSON internal error for API endpoints.
            if _is_api_request():
                return jsonify({'success': False, 'error': 'Internal server error', 'message': str(e)}), 500
            raise

    return wrapper


@route_wrapper(ai_features_bp, '/')
@require_admin
def dashboard(current_user: dict[str, Any] | None = None):
    """AI features management dashboard."""
    try:
        service = get_ai_features_service()
        stats = asyncio.run(service.get_feature_statistics())
        health = asyncio.run(service.health_check())
        return render_template(
            'admin/ai_features_management.html',
            stats=stats,
            health=health,
            config=service.config
        )
    except Exception as e:
        logger.error(f"Failed to load AI features dashboard: {e}")
        flash(f"Error loading dashboard: {e!s}", 'error')
        return render_template('admin/ai_features_management.html', stats={}, health={}, config={})


@route_wrapper(ai_features_bp, '/api/summarize', methods=['POST'])
@require_admin
def api_summarize(current_user: dict[str, Any] | None = None):
    """API endpoint for text summarization."""
    try:
        data = request.get_json() or {}
        if 'text' not in data:
            raise BadRequest("Missing 'text' field in request")
        text = data['text']
        summary_type = data.get('summary_type', 'brief')
        max_length = data.get('max_length')
        user_id = data.get('user_id', current_user.get('id') if current_user else 'admin')
        service = get_ai_features_service()
        result = asyncio.run(service.create_summary(
            text=text,
            summary_type=summary_type,
            user_id=user_id,
            max_length=max_length
        ))
        return jsonify({
            'success': True,
            'result': {
                'summary_id': result.summary_id,
                'summary': result.summary,
                'summary_type': result.summary_type,
                'confidence_score': result.confidence_score,
                'processing_time_ms': result.processing_time_ms,
                'word_count_original': result.word_count_original,
                'word_count_summary': result.word_count_summary,
                'compression_ratio': result.compression_ratio,
                'key_topics': result.key_topics,
                'created_at': result.created_at.isoformat()
            }
        })
    except BadRequest as br:
        logger.debug(f"Summarization API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Summarization API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/suggest-content', methods=['POST'])
@require_admin
def api_suggest_content(current_user: dict[str, Any] | None = None):
    """API endpoint for content suggestions."""
    try:
        data = request.get_json() or {}
        if 'context' not in data:
            raise BadRequest("Missing 'context' field in request")
        context = data['context']
        suggestion_type = data.get('suggestion_type', 'completion')
        max_suggestions = data.get('max_suggestions', 3)
        user_id = data.get('user_id', current_user.get('id') if current_user else 'admin')
        service = get_ai_features_service()
        suggestions = asyncio.run(service.generate_content_suggestions(
            context=context,
            suggestion_type=suggestion_type,
            user_id=user_id,
            max_suggestions=max_suggestions
        ))
        return jsonify({
            'success': True,
            'suggestions': [
                {
                    'suggestion_id': s.suggestion_id,
                    'suggestion': s.suggestion,
                    'suggestion_type': s.suggestion_type,
                    'confidence_score': s.confidence_score,
                    'relevance_score': s.relevance_score,
                    'created_at': s.created_at.isoformat()
                }
                for s in suggestions
            ]
        })
    except BadRequest as br:
        logger.debug(f"Content suggestions API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Content suggestions API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/analyze-sentiment', methods=['POST'])
@require_admin
def api_analyze_sentiment(current_user: dict[str, Any] | None = None):
    """API endpoint for sentiment analysis."""
    try:
        data = request.get_json() or {}
        if 'text' not in data:
            raise BadRequest("Missing 'text' field in request")
        text = data['text']
        include_emotions = data.get('include_emotions', True)
        user_id = data.get('user_id', current_user.get('id') if current_user else 'admin')
        service = get_ai_features_service()
        result = asyncio.run(service.analyze_sentiment(
            text=text,
            user_id=user_id,
            include_emotions=include_emotions
        ))
        return jsonify({
            'success': True,
            'result': {
                'analysis_id': result.analysis_id,
                'sentiment': result.sentiment.value,
                'confidence_score': result.confidence_score,
                'emotion_scores': result.emotion_scores,
                'key_phrases': result.key_phrases,
                'processing_time_ms': result.processing_time_ms,
                'created_at': result.created_at.isoformat()
            }
        })
    except BadRequest as br:
        logger.debug(f"Sentiment analysis API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Sentiment analysis API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/semantic-search', methods=['POST'])
@require_admin
def api_semantic_search(current_user: dict[str, Any] | None = None):
    """API endpoint for semantic search."""
    try:
        data = request.get_json() or {}
        if 'query' not in data:
            raise BadRequest("Missing 'query' field in request")
        query = data['query']
        max_results = data.get('max_results', 10)
        similarity_threshold = data.get('similarity_threshold', 0.3)
        filters = data.get('filters')
        service = get_ai_features_service()
        results = asyncio.run(service.semantic_search(
            query=query,
            max_results=max_results,
            similarity_threshold=similarity_threshold,
            filters=filters
        ))
        return jsonify({
            'success': True,
            'results': [
                {
                    'result_id': r.result_id,
                    'content': r.content[:500] + '...' if len(r.content) > 500 else r.content,
                    'similarity_score': r.similarity_score,
                    'metadata': r.metadata,
                    'highlighted_text': r.highlighted_text[:500] + '...' if r.highlighted_text and len(r.highlighted_text) > 500 else r.highlighted_text
                }
                for r in results
            ],
            'total_results': len(results)
        })
    except BadRequest as br:
        logger.debug(f"Semantic search API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Semantic search API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/moderate-content', methods=['POST'])
@require_admin
def api_moderate_content(current_user: dict[str, Any] | None = None):
    """API endpoint for content moderation."""
    try:
        data = request.get_json() or {}
        if 'content' not in data:
            raise BadRequest("Missing 'content' field in request")
        content = data['content']
        content_id = data.get('content_id')
        user_id = data.get('user_id', current_user.get('id') if current_user else 'admin')
        metadata = data.get('metadata')
        service = get_ai_features_service()
        result = asyncio.run(service.moderate_content(
            content=content,
            content_id=content_id,
            user_id=user_id,
            metadata=metadata
        ))
        return jsonify({
            'success': True,
            'result': {
                'moderation_id': result.moderation_id,
                'action': result.action.value,
                'confidence_score': result.confidence_score,
                'violation_categories': result.violation_categories,
                'severity_score': result.severity_score,
                'explanation': result.explanation,
                'processing_time_ms': result.processing_time_ms,
                'created_at': result.created_at.isoformat()
            }
        })
    except BadRequest as br:
        logger.debug(f"Content moderation API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Content moderation API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/add-to-index', methods=['POST'])
@require_admin
def api_add_to_index(current_user: dict[str, Any] | None = None):
    """API endpoint to add content to semantic search index."""
    try:
        data = request.get_json() or {}
        if 'content_id' not in data or 'content' not in data:
            raise BadRequest("Missing 'content_id' or 'content' field in request")
        content_id = data['content_id']
        content = data['content']
        metadata = data.get('metadata', {})
        service = get_ai_features_service()
        success = asyncio.run(service.add_to_semantic_index(
            content_id=content_id,
            content=content,
            metadata=metadata
        ))
        return jsonify({
            'success': success,
            'message': 'Content added to semantic index' if success else 'Failed to add content to index'
        })
    except BadRequest as br:
        logger.debug(f"Add to index API bad request: {br}")
        return jsonify({'success': False, 'error': str(br)}), 400
    except Exception as e:
        logger.error(f"Add to index API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/statistics')
@require_admin
def api_statistics(current_user: dict[str, Any] | None = None):
    """API endpoint to get feature statistics."""
    try:
        service = get_ai_features_service()
        stats = asyncio.run(service.get_feature_statistics())
        return jsonify({'success': True, 'statistics': stats})
    except Exception as e:
        logger.error(f"Statistics API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/health')
@require_admin
def api_health(current_user: dict[str, Any] | None = None):
    """API endpoint for health check."""
    try:
        service = get_ai_features_service()
        health = asyncio.run(service.health_check())
        return jsonify({'success': True, 'health': health})
    except Exception as e:
        logger.error(f"Health check API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/api/clear-cache', methods=['POST'])
@require_admin
def api_clear_cache(current_user: dict[str, Any] | None = None):
    """API endpoint to clear feature caches."""
    try:
        data = request.get_json() or {}
        feature_type = data.get('feature_type')
        service = get_ai_features_service()
        asyncio.run(service.clear_cache(feature_type))
        return jsonify({'success': True, 'message': f'Cache cleared for: {feature_type or "all features"}'})
    except Exception as e:
        logger.error(f"Clear cache API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@route_wrapper(ai_features_bp, '/config', methods=['GET', 'POST'])
@require_admin
def config_management(current_user: dict[str, Any] | None = None):
    """AI features configuration management."""
    service = get_ai_features_service()
    if request.method == 'POST':
        try:
            new_config = request.get_json() or {}
            if new_config:
                service.config.update(new_config)
                service.save_configuration()
                flash('AI features configuration updated successfully', 'success')
            else:
                flash('Invalid configuration data', 'error')
        except Exception as e:
            logger.error(f"Failed to update AI features configuration: {e}")
            flash(f'Error updating configuration: {e!s}', 'error')
    return jsonify({'success': True, 'config': service.config})


# Error handlers
@ai_features_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'success': False, 'error': 'Bad request', 'message': str(error.description)}), 400

@ai_features_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500
