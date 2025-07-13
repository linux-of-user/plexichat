import asyncio
import json
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, render_template, request, send_file

from ....core.auth.decorators import admin_required
from ....core.utils.response_utils import error_response, success_response
from ....services.zero_knowledge_security_service import (
from datetime import datetime

from datetime import datetime

    Admin,
    AuditEventType,
    BytesIO,
    Flask,
    MessageType,
    PlexiChat,
    PrivacyLevel,
    Provides,
    Routes,
    Security,
    WebUI.,
    Zero-Knowledge,
    """,
    admin,
    and,
    comprehensive,
    configuration,
    features,
    for,
    from,
    import,
    interfaces.,
    io,
    managing,
    monitoring,
    routes,
    security,
    testing,
    the,
    through,
    zero-knowledge,
    zero_knowledge_security,
)

logger = logging.getLogger(__name__)

# Create blueprint
zero_knowledge_security_bp = Bluelogger.info(
    'zero_knowledge_security_admin',
    __name__,
    url_prefix='/admin/zero-knowledge-security'
)


logger = logging.getLogger(__name__)
def async_route(f):
    """Decorator to handle async route functions."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper


@zero_knowledge_security_bp.route('/')
@admin_required
@async_route
async def zero_knowledge_security_management():
    """Main zero-knowledge security management page."""
    try:
        # Get current configuration and statistics
        config = await zero_knowledge_security.get_configuration()
        stats = await zero_knowledge_security.get_service_statistics()

        return render_template(
            'admin/zero_knowledge_security_management.html',
            config=config,
            stats=stats,
            page_title="Zero-Knowledge Security Management"
        )

    except Exception as e:
        logger.error(f"Error loading zero-knowledge security management page: {e}")
        return error_response(f"Failed to load management page: {str(e)}")


@zero_knowledge_security_bp.route('/stats')
@admin_required
@async_route
async def get_statistics():
    """Get current zero-knowledge security statistics."""
    try:
        stats = await zero_knowledge_security.get_service_statistics()
        return success_response(stats=stats)

    except Exception as e:
        logger.error(f"Error getting zero-knowledge security statistics: {e}")
        return error_response(f"Failed to get statistics: {str(e)}")


@zero_knowledge_security_bp.route('/config', methods=['GET', 'POST'])
@admin_required
@async_route
async def manage_configuration():
    """Get or update zero-knowledge security configuration."""
    try:
        if request.method == 'GET':
            config = await zero_knowledge_security.get_configuration()
            return success_response(config=config)

        elif request.method == 'POST':
            config_updates = request.get_json()
            if not config_updates:
                return error_response("No configuration data provided")

            success = await zero_knowledge_security.update_configuration(config_updates)
            if success:
                return success_response(message="Configuration updated successfully")
            else:
                return error_response("Failed to update configuration")

    except Exception as e:
        logger.error(f"Error managing zero-knowledge security configuration: {e}")
        return error_response(f"Configuration error: {str(e)}")


@zero_knowledge_security_bp.route('/test-all', methods=['POST'])
@admin_required
@async_route
async def test_all_systems():
    """Run comprehensive tests on all zero-knowledge security systems."""
    try:
        test_results = {}

        # Test client-side encryption
        try:
            test_data = "Test message for encryption"
            encrypted_data, proof_hash = await zero_knowledge_security.encrypt_client_side(
                test_data, "test_user", PrivacyLevel.ENHANCED
            )
            decrypted_data = await zero_knowledge_security.decrypt_client_side(
                encrypted_data, "test_user", proof_hash, PrivacyLevel.ENHANCED
            )

            if decrypted_data.decode('utf-8') == test_data:
                test_results['client_side_encryption'] = {
                    'status': 'PASSED',
                    'details': 'Encryption and decryption successful'
                }
            else:
                test_results['client_side_encryption'] = {
                    'status': 'FAILED',
                    'details': 'Decrypted data does not match original'
                }
        except Exception as e:
            test_results['client_side_encryption'] = {
                'status': 'FAILED',
                'details': f'Encryption test failed: {str(e)}'
            }

        # Test disappearing messages
        try:
            message_id = await zero_knowledge_security.create_disappearing_message(
                "Test disappearing message", "test_sender", "test_recipient", ttl_hours=1
            )
            retrieved_message = await zero_knowledge_security.get_disappearing_message(
                message_id, "test_sender"
            )

            if retrieved_message == "Test disappearing message":
                test_results['disappearing_messages'] = {
                    'status': 'PASSED',
                    'details': 'Disappearing message creation and retrieval successful'
                }
            else:
                test_results['disappearing_messages'] = {
                    'status': 'FAILED',
                    'details': 'Failed to retrieve disappearing message'
                }
        except Exception as e:
            test_results['disappearing_messages'] = {
                'status': 'FAILED',
                'details': f'Disappearing messages test failed: {str(e)}'
            }

        # Test anonymous messaging
        try:
            anonymous_id = await zero_knowledge_security.create_anonymous_session(duration_hours=1)
            message_id = await zero_knowledge_security.send_anonymous_message(
                anonymous_id, "Test anonymous message"
            )

            if message_id:
                test_results['anonymous_messaging'] = {
                    'status': 'PASSED',
                    'details': 'Anonymous session and message creation successful'
                }
            else:
                test_results['anonymous_messaging'] = {
                    'status': 'FAILED',
                    'details': 'Failed to create anonymous message'
                }
        except Exception as e:
            test_results['anonymous_messaging'] = {
                'status': 'FAILED',
                'details': f'Anonymous messaging test failed: {str(e)}'
            }

        # Test audit trail integrity
        try:
            integrity_result = await zero_knowledge_security.verify_audit_integrity()
            if integrity_result.get('audit_status') == 'PASSED':
                test_results['audit_integrity'] = {
                    'status': 'PASSED',
                    'details': f'Integrity score: {integrity_result.get("integrity_score", 0) * 100:.1f}%'
                }
            else:
                test_results['audit_integrity'] = {
                    'status': 'FAILED',
                    'details': f'Audit integrity check failed: {integrity_result.get("audit_status", "UNKNOWN")}'
                }
        except Exception as e:
            test_results['audit_integrity'] = {
                'status': 'FAILED',
                'details': f'Audit integrity test failed: {str(e)}'
            }

        # Determine overall test status
        all_passed = all(result['status'] == 'PASSED' for result in test_results.values())

        return success_response(
            results=test_results,
            overall_status='PASSED' if all_passed else 'FAILED',
            message=f"Comprehensive test completed. {len([r for r in test_results.values() if r['status'] == 'PASSED'])}/{len(test_results)} tests passed."
        )

    except Exception as e:
        logger.error(f"Error running comprehensive tests: {e}")
        return error_response(f"Test execution failed: {str(e)}")


@zero_knowledge_security_bp.route('/test-encryption', methods=['POST'])
@admin_required
@async_route
async def test_encryption():
    """Test client-side encryption functionality."""
    try:
        test_data = "Test encryption message with special characters: "
        user_id = "encryption_test_user"

        # Test different privacy levels
        test_results = {}

        for privacy_level in [PrivacyLevel.STANDARD, PrivacyLevel.ENHANCED, PrivacyLevel.QUANTUM_PROOF]:
            try:
                # Encrypt data
                encrypted_data, proof_hash = await zero_knowledge_security.encrypt_client_side(
                    test_data, user_id, privacy_level
                )

                # Decrypt data
                decrypted_data = await zero_knowledge_security.decrypt_client_side(
                    encrypted_data, user_id, proof_hash, privacy_level
                )

                # Verify data integrity
                if decrypted_data.decode('utf-8') == test_data:
                    test_results[privacy_level.value] = {
                        'status': 'PASSED',
                        'details': f'Encryption/decryption successful, data size: {len(encrypted_data)} bytes'
                    }
                else:
                    test_results[privacy_level.value] = {
                        'status': 'FAILED',
                        'details': 'Data integrity check failed'
                    }

            except Exception as e:
                test_results[privacy_level.value] = {
                    'status': 'FAILED',
                    'details': f'Test failed: {str(e)}'
                }

        all_passed = all(result['status'] == 'PASSED' for result in test_results.values())

        return success_response(
            results=test_results,
            overall_status='PASSED' if all_passed else 'FAILED'
        )

    except Exception as e:
        logger.error(f"Error testing encryption: {e}")
        return error_response(f"Encryption test failed: {str(e)}")


@zero_knowledge_security_bp.route('/test-disappearing', methods=['POST'])
@admin_required
@async_route
async def test_disappearing_messages():
    """Test disappearing messages functionality."""
    try:
        test_results = {}

        # Test message creation and retrieval
        try:
            message_content = "Test disappearing message"
            sender_id = "test_sender"
            recipient_id = "test_recipient"

            # Create disappearing message with short TTL for testing
            message_id = await zero_knowledge_security.create_disappearing_message(
                message_content, sender_id, recipient_id, ttl_hours=1
            )

            # Test sender can retrieve message
            retrieved_by_sender = await zero_knowledge_security.get_disappearing_message(
                message_id, sender_id
            )

            # Test recipient can retrieve message
            retrieved_by_recipient = await zero_knowledge_security.get_disappearing_message(
                message_id, recipient_id
            )

            if retrieved_by_sender == message_content and retrieved_by_recipient == message_content:
                test_results['message_creation_retrieval'] = {
                    'status': 'PASSED',
                    'details': 'Message creation and retrieval by authorized users successful'
                }
            else:
                test_results['message_creation_retrieval'] = {
                    'status': 'FAILED',
                    'details': 'Message retrieval failed'
                }

        except Exception as e:
            test_results['message_creation_retrieval'] = {
                'status': 'FAILED',
                'details': f'Test failed: {str(e)}'
            }

        # Test unauthorized access prevention
        try:
            unauthorized_result = await zero_knowledge_security.get_disappearing_message(
                message_id, "unauthorized_user"
            )

            if unauthorized_result is None:
                test_results['access_control'] = {
                    'status': 'PASSED',
                    'details': 'Unauthorized access properly prevented'
                }
            else:
                test_results['access_control'] = {
                    'status': 'FAILED',
                    'details': 'Unauthorized access was not prevented'
                }

        except Exception as e:
            test_results['access_control'] = {
                'status': 'FAILED',
                'details': f'Access control test failed: {str(e)}'
            }

        all_passed = all(result['status'] == 'PASSED' for result in test_results.values())

        return success_response(
            results=test_results,
            overall_status='PASSED' if all_passed else 'FAILED'
        )

    except Exception as e:
        logger.error(f"Error testing disappearing messages: {e}")
        return error_response(f"Disappearing messages test failed: {str(e)}")


@zero_knowledge_security_bp.route('/test-anonymous', methods=['POST'])
@admin_required
@async_route
async def test_anonymous_messaging():
    """Test anonymous messaging functionality."""
    try:
        test_results = {}

        # Test anonymous session creation
        try:
            anonymous_id = await zero_knowledge_security.create_anonymous_session(duration_hours=1)

            if anonymous_id and anonymous_id.startswith('anon_'):
                test_results['session_creation'] = {
                    'status': 'PASSED',
                    'details': f'Anonymous session created: {anonymous_id[:16]}...'
                }
            else:
                test_results['session_creation'] = {
                    'status': 'FAILED',
                    'details': 'Failed to create anonymous session'
                }

        except Exception as e:
            test_results['session_creation'] = {
                'status': 'FAILED',
                'details': f'Session creation failed: {str(e)}'
            }

        # Test anonymous message sending
        try:
            message_content = "Test anonymous message"
            message_id = await zero_knowledge_security.send_anonymous_message(
                anonymous_id, message_content
            )

            if message_id:
                test_results['message_sending'] = {
                    'status': 'PASSED',
                    'details': f'Anonymous message sent: {message_id}'
                }
            else:
                test_results['message_sending'] = {
                    'status': 'FAILED',
                    'details': 'Failed to send anonymous message'
                }

        except Exception as e:
            test_results['message_sending'] = {
                'status': 'FAILED',
                'details': f'Message sending failed: {str(e)}'
            }

        all_passed = all(result['status'] == 'PASSED' for result in test_results.values())

        return success_response(
            results=test_results,
            overall_status='PASSED' if all_passed else 'FAILED'
        )

    except Exception as e:
        logger.error(f"Error testing anonymous messaging: {e}")
        return error_response(f"Anonymous messaging test failed: {str(e)}")


@zero_knowledge_security_bp.route('/rotate-keys', methods=['POST'])
@admin_required
@async_route
async def rotate_encryption_keys():
    """Rotate all encryption keys."""
    try:
        # Clear existing client keys to force regeneration
        zero_knowledge_security.client_keys.clear()

        # Log key rotation event
        await zero_knowledge_security._log_audit_event(
            AuditEventType.KEY_ROTATION,
            None,  # Admin action
            {
                "action": "manual_key_rotation",
                "rotated_at": datetime.now(timezone.utc).isoformat(),
                "admin_initiated": True
            }
        )

        return success_response(message="All encryption keys rotated successfully")

    except Exception as e:
        logger.error(f"Error rotating encryption keys: {e}")
        return error_response(f"Key rotation failed: {str(e)}")


@zero_knowledge_security_bp.route('/cleanup-expired', methods=['POST'])
@admin_required
@async_route
async def cleanup_expired_messages():
    """Manually trigger cleanup of expired messages."""
    try:
        len(zero_knowledge_security.encrypted_messages)

        # Find and clean up expired messages
        now = datetime.now(timezone.utc)
        expired_messages = []

        for message_id, message in zero_knowledge_security.encrypted_messages.items():
            if (message.message_type == MessageType.DISAPPEARING and
                message.expires_at and now > message.expires_at):
                expired_messages.append(message_id)

        # Securely delete expired messages
        for message_id in expired_messages:
            await zero_knowledge_security._secure_delete_message(message_id)

        cleaned_count = len(expired_messages)

        return success_response(
            message="Cleanup completed successfully",
            cleaned_count=cleaned_count,
            remaining_messages=len(zero_knowledge_security.encrypted_messages)
        )

    except Exception as e:
        logger.error(f"Error cleaning up expired messages: {e}")
        return error_response(f"Cleanup failed: {str(e)}")


@zero_knowledge_security_bp.route('/verify-audit', methods=['POST'])
@admin_required
@async_route
async def verify_audit_integrity():
    """Verify audit trail integrity."""
    try:
        integrity_result = await zero_knowledge_security.verify_audit_integrity()

        return success_response(
            integrity_result=integrity_result,
            message=f"Audit integrity verification completed: {integrity_result.get('audit_status', 'UNKNOWN')}"
        )

    except Exception as e:
        logger.error(f"Error verifying audit integrity: {e}")
        return error_response(f"Audit verification failed: {str(e)}")


@zero_knowledge_security_bp.route('/export-audit')
@admin_required
@async_route
async def export_audit_trail():
    """Export audit trail data."""
    try:
        audit_events = await zero_knowledge_security.get_audit_trail()

        # Convert audit events to exportable format
        export_data = []
        for event in audit_events:
            export_data.append({
                'entry_id': event.entry_id,
                'event_type': event.event_type.value,
                'user_id': event.user_id,
                'timestamp': event.timestamp.isoformat(),
                'event_hash': event.event_hash,
                'privacy_proof': event.privacy_proof,
                'metadata': event.metadata
            })

        # Create JSON export
        export_json = json.dumps(export_data, indent=2, default=str)

        # Return as downloadable file
        output = BytesIO()
        output.write(export_json.encode('utf-8'))
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name=f'plexichat_audit_trail_{from datetime import datetime
datetime = datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            mimetype='application/json'
        )

    except Exception as e:
        logger.error(f"Error exporting audit trail: {e}")
        return error_response(f"Export failed: {str(e)}")


@zero_knowledge_security_bp.route('/anonymous-sessions')
@admin_required
@async_route
async def get_anonymous_sessions():
    """Get information about active anonymous sessions."""
    try:
        now = datetime.now(timezone.utc)
        active_sessions = []

        for anonymous_id, session_data in zero_knowledge_security.anonymous_sessions.items():
            if session_data["expires_at"] > now:
                # Return session info without revealing sensitive data
                active_sessions.append({
                    'anonymous_id': anonymous_id,
                    'created_at': session_data["created_at"].isoformat(),
                    'expires_at': session_data["expires_at"].isoformat(),
                    'message_count': session_data["message_count"],
                    'max_messages': session_data["max_messages"]
                })

        return success_response(sessions=active_sessions)

    except Exception as e:
        logger.error(f"Error getting anonymous sessions: {e}")
        return error_response(f"Failed to get anonymous sessions: {str(e)}")


@zero_knowledge_security_bp.route('/audit-events')
@admin_required
@async_route
async def get_audit_events():
    """Get recent audit events."""
    try:
        limit = request.args.get('limit', 10, type=int)
        event_type = request.args.get('event_type')

        # Get audit events
        audit_events = await zero_knowledge_security.get_audit_trail()

        # Filter by event type if specified
        if event_type:
            try:
                filter_type = AuditEventType(event_type)
                audit_events = [event for event in audit_events   # Invalid event type, ignore filter

        # Sort by timestamp (most recent first) and limit
        audit_events.sort(key=lambda x: x.timestamp, reverse=True)
        audit_events = audit_events[:limit]

        # Convert to serializable format
        events_data = []
        for event in audit_events:
            events_data.append({
                'entry_id': event.entry_id,
                'event_type': event.event_type.value,
                'user_id': event.user_id,
                'timestamp': event.timestamp.isoformat(),
                'metadata': event.metadata
            })

        return success_response(events=events_data)

    except Exception as e:
        logger.error(f"Error getting audit events: {e}")
        return error_response(f"Failed to get audit events: {str(e)}")


@zero_knowledge_security_bp.route('/reset-section/<section>', methods=['POST'])
@admin_required
@async_route
async def reset_configuration_section(section: str):
    """Reset a configuration section to defaults."""
    try:
        # Get default configuration
        default_config = zero_knowledge_security._get_default_configuration()

        if section not in default_config:
            return error_response(f"Invalid configuration section: {section}")

        # Update with default values for the section
        section_update = {section: default_config[section]}
        success = await zero_knowledge_security.update_configuration(section_update)

        if success:
            return success_response(message=f"Section '{section}' reset to defaults")
        else:
            return error_response(f"Failed to reset section '{section}'")

    except Exception as e:
        logger.error(f"Error resetting configuration section {section}: {e}")
        return error_response(f"Reset failed: {str(e)}")
