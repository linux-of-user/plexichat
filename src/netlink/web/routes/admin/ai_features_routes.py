"""
NetLink AI-Powered Features Admin Routes

Flask routes for managing AI-powered features including summarization,
content suggestions, sentiment analysis, semantic search, and moderation.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.exceptions import BadRequest
import logging

from ....ai.features.ai_powered_features_service import AIPoweredFeaturesService
from ....core.logging import get_logger
from ....core.auth.decorators import require_admin
from ....core.config import get_config

logger = get_logger(__name__)

# Create blueprint
ai_features_bp = Blueprint('ai_features_admin', __name__, url_prefix='/admin/ai-features')

# Global service instance
ai_features_service: Optional[AIPoweredFeaturesService] = None


def get_ai_features_service() -> AIPoweredFeaturesService:
    """Get or create AI features service instance."""
    global ai_features_service
    if ai_features_service is None:
        ai_features_service = AIPoweredFeaturesService()
    return ai_features_service


@ai_features_bp.route('/')
@require_admin
def dashboard():
    """AI features management dashboard."""
    try:
        service = get_ai_features_service()
        
        # Get service statistics
        stats = asyncio.run(service.get_feature_statistics())
        
        # Get health status
        health = asyncio.run(service.health_check())
        
        return render_template(
            'admin/ai_features_management.html',
            stats=stats,
            health=health,
            config=service.config
        )
        
    except Exception as e:
        logger.error(f"Failed to load AI features dashboard: {e}")
        flash(f"Error loading dashboard: {str(e)}", 'error')
        return render_template('admin/ai_features_management.html', stats={}, health={}, config={})


@ai_features_bp.route('/api/summarize', methods=['POST'])
@require_admin
def api_summarize():
    """API endpoint for text summarization."""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            raise BadRequest("Missing 'text' field in request")
        
        text = data['text']
        summary_type = data.get('summary_type', 'brief')
        max_length = data.get('max_length')
        user_id = data.get('user_id', 'admin')
        
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
        
    except Exception as e:
        logger.error(f"Summarization API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/suggest-content', methods=['POST'])
@require_admin
def api_suggest_content():
    """API endpoint for content suggestions."""
    try:
        data = request.get_json()
        if not data or 'context' not in data:
            raise BadRequest("Missing 'context' field in request")
        
        context = data['context']
        suggestion_type = data.get('suggestion_type', 'completion')
        max_suggestions = data.get('max_suggestions', 3)
        user_id = data.get('user_id', 'admin')
        
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
        
    except Exception as e:
        logger.error(f"Content suggestions API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/analyze-sentiment', methods=['POST'])
@require_admin
def api_analyze_sentiment():
    """API endpoint for sentiment analysis."""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            raise BadRequest("Missing 'text' field in request")
        
        text = data['text']
        include_emotions = data.get('include_emotions', True)
        user_id = data.get('user_id', 'admin')
        
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
        
    except Exception as e:
        logger.error(f"Sentiment analysis API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/semantic-search', methods=['POST'])
@require_admin
def api_semantic_search():
    """API endpoint for semantic search."""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
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
        
    except Exception as e:
        logger.error(f"Semantic search API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/moderate-content', methods=['POST'])
@require_admin
def api_moderate_content():
    """API endpoint for content moderation."""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            raise BadRequest("Missing 'content' field in request")
        
        content = data['content']
        content_id = data.get('content_id')
        user_id = data.get('user_id', 'admin')
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
        
    except Exception as e:
        logger.error(f"Content moderation API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/add-to-index', methods=['POST'])
@require_admin
def api_add_to_index():
    """API endpoint to add content to semantic search index."""
    try:
        data = request.get_json()
        if not data or 'content_id' not in data or 'content' not in data:
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
        
    except Exception as e:
        logger.error(f"Add to index API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/statistics')
@require_admin
def api_statistics():
    """API endpoint to get feature statistics."""
    try:
        service = get_ai_features_service()
        stats = asyncio.run(service.get_feature_statistics())
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Statistics API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/health')
@require_admin
def api_health():
    """API endpoint for health check."""
    try:
        service = get_ai_features_service()
        health = asyncio.run(service.health_check())
        
        return jsonify({
            'success': True,
            'health': health
        })
        
    except Exception as e:
        logger.error(f"Health check API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/api/clear-cache', methods=['POST'])
@require_admin
def api_clear_cache():
    """API endpoint to clear feature caches."""
    try:
        data = request.get_json() or {}
        feature_type = data.get('feature_type')
        
        service = get_ai_features_service()
        asyncio.run(service.clear_cache(feature_type))
        
        return jsonify({
            'success': True,
            'message': f'Cache cleared for: {feature_type or "all features"}'
        })
        
    except Exception as e:
        logger.error(f"Clear cache API error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@ai_features_bp.route('/config', methods=['GET', 'POST'])
@require_admin
def config_management():
    """AI features configuration management."""
    service = get_ai_features_service()
    
    if request.method == 'POST':
        try:
            # Update configuration
            new_config = request.get_json()
            if new_config:
                service.config.update(new_config)
                service.save_configuration()
                flash('AI features configuration updated successfully', 'success')
            else:
                flash('Invalid configuration data', 'error')
                
        except Exception as e:
            logger.error(f"Failed to update AI features configuration: {e}")
            flash(f'Error updating configuration: {str(e)}', 'error')
    
    return jsonify({
        'success': True,
        'config': service.config
    })


# Error handlers
@ai_features_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': 'Bad request',
        'message': str(error.description)
    }), 400


@ai_features_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500
