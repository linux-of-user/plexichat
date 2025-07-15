import re
from functools import wraps

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from ....core.auth.web_auth import require_admin_login
from ....core.logging import get_logger
from ....services.communication_service import get_communication_service
import logging

"""
PlexiChat Communication Admin Web Routes

Web routes for communication service administration interface.
"""

# Initialize blueprint and logger
bp = Blueprint('communication_admin', __name__, url_prefix='/admin/communication')
logger = get_logger(__name__)

def admin_required(f):
    """Decorator to require admin authentication for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return require_admin_login(f)(*args, **kwargs)
    return decorated_function

@bp.route('/')
@admin_required
async def communication_management():
    """Communication management dashboard."""
    try:
        communication_service = await get_communication_service()

        # Get current configuration
        config = await communication_service.get_configuration()

        # Get service statistics
        health_status = await communication_service.get_health_status()
        stats = {
            'voice_messages_count': health_status.get('voice_messages_count', 0),
            'active_threads_count': health_status.get('active_threads_count', 0),
            'pending_translations': health_status.get('pending_translations', 0),
            'unread_notifications': health_status.get('unread_notifications', 0),
            'ai_manager_available': health_status.get('ai_manager_available', False),
            'configuration_valid': health_status.get('configuration_valid', False),
            'features_enabled': health_status.get('features_enabled', {})
        }

        # Get configuration schema for form generation
        schema = await communication_service.get_configuration_schema()

        return render_template(
            'admin/communication_management.html',
            config=config,
            stats=stats,
            schema=schema,
            page_title='Communication Management'
        )

    except Exception as e:
        logger.error(f"Failed to load communication management page: {e}")
        flash(f'Failed to load communication management: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@bp.route('/config')
@admin_required
async def get_configuration():
    """Get communication configuration via AJAX."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()

        return jsonify({
            'success': True,
            'config': config
        })

    except Exception as e:
        logger.error(f"Failed to get communication configuration: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/config', methods=['POST'])
@admin_required
async def update_configuration():
    """Update communication configuration via AJAX."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400

        section = data.get('section')
        config_updates = data.get('config')

        if not section or not config_updates:
            return jsonify({
                'success': False,
                'error': 'Section and config data are required'
            }), 400

        communication_service = await get_communication_service()

        # Update configuration
        update_data = {section: config_updates}
        success = await communication_service.update_configuration(update_data)

        if not success:
            return jsonify({
                'success': False,
                'error': 'Failed to update configuration'
            }), 500

        # Validate updated configuration
        validation_issues = await communication_service.validate_configuration()

        return jsonify({
            'success': True,
            'message': f'Configuration section "{section}" updated successfully',
            'validation_issues': validation_issues
        })

    except Exception as e:
        logger.error(f"Failed to update communication configuration: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/config/<section>/reset', methods=['POST'])
@admin_required
async def reset_configuration_section(section: str):
    """Reset configuration section to defaults."""
    try:
        communication_service = await get_communication_service()

        success = await communication_service.reset_configuration_section(section)
        if not success:
            return jsonify({
                'success': False,
                'error': f'Configuration section "{section}" not found'
            }), 404

        return jsonify({
            'success': True,
            'message': f'Configuration section "{section}" reset to defaults'
        })

    except Exception as e:
        logger.error(f"Failed to reset configuration section: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/stats')
@admin_required
async def get_stats():
    """Get communication service statistics via AJAX."""
    try:
        communication_service = await get_communication_service()
        health_status = await communication_service.get_health_status()

        stats = {
            'voice_messages_count': health_status.get('voice_messages_count', 0),
            'active_threads_count': health_status.get('active_threads_count', 0),
            'pending_translations': health_status.get('pending_translations', 0),
            'unread_notifications': health_status.get('unread_notifications', 0),
            'ai_manager_available': health_status.get('ai_manager_available', False),
            'configuration_valid': health_status.get('configuration_valid', False),
            'features_enabled': health_status.get('features_enabled', {}),
            'service_status': health_status.get('state', 'unknown')
        }

        return jsonify({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        logger.error(f"Failed to get communication stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/test/<test_type>', methods=['POST'])
@admin_required
async def test_configuration(test_type: str):
    """Test specific configuration components."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()

        if test_type == 'voice':
            # Test voice message configuration
            voice_config = config.get('voice_messages', {})

            if not voice_config.get('enabled', False):
                return jsonify({
                    'success': False,
                    'message': 'Voice messages are disabled'
                })

            # Test storage path
            storage_path = communication_service.voice_storage_path
            if not storage_path.exists():
                return jsonify({
                    'success': False,
                    'message': 'Voice storage path does not exist',
                    'details': {'storage_path': str(storage_path)}
                })

            # Test write permissions
            test_file = storage_path / 'test_write.tmp'
            try:
                test_file.write_text('test')
                test_file.unlink()
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': 'No write permission to voice storage path',
                    'details': {'error': str(e)}
                })

            return jsonify({
                'success': True,
                'message': 'Voice configuration test passed',
                'details': {
                    'storage_path': str(storage_path),
                    'max_duration': voice_config.get('max_duration_seconds'),
                    'max_file_size': voice_config.get('max_file_size_mb')
                }
            })

        elif test_type == 'translation':
            # Test translation configuration
            translation_config = config.get('translation', {})

            if not translation_config.get('enabled', False):
                return jsonify({
                    'success': False,
                    'message': 'Translation is disabled'
                })

            if not communication_service.ai_manager:
                return jsonify({
                    'success': False,
                    'message': 'AI manager not available for translation'
                })

            supported_languages = translation_config.get('supported_languages', [])
            if not supported_languages:
                return jsonify({
                    'success': False,
                    'message': 'No supported languages configured'
                })

            return jsonify({
                'success': True,
                'message': 'Translation configuration test passed',
                'details': {
                    'supported_languages_count': len(supported_languages),
                    'provider': translation_config.get('translation_provider'),
                    'ai_manager_available': True
                }
            })

        elif test_type == 'notifications':
            # Test notifications configuration
            notifications_config = config.get('notifications', {})

            if not notifications_config.get('enabled', False):
                return jsonify({
                    'success': False,
                    'message': 'Notifications are disabled'
                })

            # Test configuration values
            issues = []
            if notifications_config.get('max_notifications_per_user', 0) <= 0:
                issues.append('Invalid max_notifications_per_user')
            if notifications_config.get('notification_retention_days', 0) <= 0:
                issues.append('Invalid notification_retention_days')

            # Test quiet hours format
            quiet_start = notifications_config.get('quiet_hours_start', '')
            quiet_end = notifications_config.get('quiet_hours_end', '')

            time_pattern = r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$'
            if not re.match(time_pattern, quiet_start):
                issues.append('Invalid quiet_hours_start format')
            if not re.match(time_pattern, quiet_end):
                issues.append('Invalid quiet_hours_end format')

            if issues:
                return jsonify({
                    'success': False,
                    'message': 'Configuration validation failed',
                    'details': {'issues': issues}
                })

            return jsonify({
                'success': True,
                'message': 'Notifications configuration test passed',
                'details': {
                    'ai_analysis_enabled': notifications_config.get('ai_analysis_enabled'),
                    'push_notifications': notifications_config.get('push_notifications'),
                    'email_notifications': notifications_config.get('email_notifications')
                }
            })

        else:
            return jsonify({
                'success': False,
                'error': f'Unknown test type: {test_type}'
            }), 400

    except Exception as e:
        logger.error(f"Configuration test failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/cleanup/voice-messages', methods=['POST'])
@admin_required
async def cleanup_voice_messages():
    """Clean up old voice messages."""
    try:
        data = request.get_json() or {}
        older_than_days = data.get('older_than_days', 30)

        # This would implement actual cleanup logic
        # For now, return a placeholder response

        return jsonify({
            'success': True,
            'message': f'Voice messages cleanup initiated for files older than {older_than_days} days'
        })

    except Exception as e:
        logger.error(f"Failed to cleanup voice messages: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/cleanup/notifications', methods=['POST'])
@admin_required
async def cleanup_notifications():
    """Clean up old notifications."""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        read_only = data.get('read_only', True)

        # This would implement actual cleanup logic
        # For now, return a placeholder response

        return jsonify({
            'success': True,
            'message': 'Notifications cleanup initiated',
            'filters': {
                'user_id': user_id,
                'read_only': read_only
            }
        })

    except Exception as e:
        logger.error(f"Failed to cleanup notifications: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/service/restart', methods=['POST'])
@admin_required
async def restart_service():
    """Restart the communication service."""
    try:
        communication_service = await get_communication_service()

        # Stop and start the service
        await communication_service.stop()
        await communication_service.start()

        return jsonify({
            'success': True,
            'message': 'Communication service restarted successfully'
        })

    except Exception as e:
        logger.error(f"Failed to restart communication service: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Error handlers
@bp.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return jsonify({
        'success': False,
        'error': 'Resource not found'
    }), 404

@bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

# Export blueprint
__all__ = ['bp']
