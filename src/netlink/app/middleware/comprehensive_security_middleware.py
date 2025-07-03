"""
Comprehensive Security Middleware

Integrates all security systems through the unified security service:
- SQL injection detection with progressive blocking
- Message antivirus scanning
- Rate limiting and DDoS protection
- Input validation and sanitization
- Threat correlation and intelligent response
- Security metrics and monitoring
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time

logger = logging.getLogger(__name__)

class ComprehensiveSecurityMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security middleware that coordinates all security systems.
    
    This middleware:
    1. Extracts request information
    2. Performs comprehensive security assessment
    3. Takes appropriate action based on threat level
    4. Logs security events
    5. Provides witty responses for violations
    """
    
    def __init__(self, app, enabled: bool = True, config: Optional[Dict] = None):
        super().__init__(app)
        self.enabled = enabled
        self.config = config or {}
        
        # Initialize unified security service
        try:
            from app.services.unified_security_service import unified_security_service
            self.security_service = unified_security_service
            self.security_available = True
        except ImportError:
            logger.error("Unified security service not available")
            self.security_service = None
            self.security_available = False
        
        # Endpoints that require security scanning
        self.secured_endpoints = {
            '/api/v1/messages',
            '/api/v1/messages/send',
            '/api/v1/auth/login',
            '/api/v1/auth/register',
            '/api/v1/files/upload',
            '/admin/',
            '/api/v1/system/'
        }
        
        # Endpoints that should be excluded from security scanning
        self.excluded_endpoints = {
            '/docs',
            '/openapi.json',
            '/favicon.ico',
            '/static/',
            '/health',
            '/metrics'
        }
        
        # Content types that should be scanned
        self.scannable_content_types = {
            'application/json',
            'text/plain',
            'text/html',
            'application/x-www-form-urlencoded'
        }
        
        logger.info(f"🛡️ Comprehensive Security Middleware initialized (enabled: {enabled})")
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method."""
        if not self.enabled or not self.security_available:
            return await call_next(request)
        
        start_time = time.time()
        
        # Extract request information
        request_data = await self._extract_request_data(request)
        
        # Check if endpoint should be secured
        if not self._should_secure_endpoint(request_data['endpoint']):
            return await call_next(request)
        
        # Extract content for scanning if applicable
        content = await self._extract_content(request)
        
        try:
            # Perform comprehensive security assessment
            assessment = await self.security_service.assess_request_security(
                request_data, content
            )
            
            # Handle security response
            if assessment.threat_detected:
                security_response = await self.security_service.handle_security_response(assessment)
                
                # Log security event
                self._log_security_event(assessment, request_data)
                
                # Return appropriate response
                return self._create_security_response(assessment, security_response)
            
            # Request is clean, proceed
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response, assessment)
            
            # Log successful request
            processing_time = (time.time() - start_time) * 1000
            logger.debug(f"Security check passed for {request_data['client_ip']} "
                        f"on {request_data['endpoint']} ({processing_time:.1f}ms)")
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            # On error, allow request but log the issue
            return await call_next(request)
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant request data for security assessment."""
        # Get client IP (handle proxies)
        client_ip = request.headers.get('x-forwarded-for', '').split(',')[0].strip()
        if not client_ip:
            client_ip = request.headers.get('x-real-ip', '')
        if not client_ip:
            client_ip = getattr(request.client, 'host', 'unknown')
        
        # Get user information if available
        user_id = getattr(request.state, 'user_id', None)
        user_info = getattr(request.state, 'user_info', {})
        
        return {
            'client_ip': client_ip,
            'user_id': user_id,
            'user_info': user_info,
            'endpoint': request.url.path,
            'method': request.method,
            'user_agent': request.headers.get('user-agent', ''),
            'content_type': request.headers.get('content-type', ''),
            'content_length': request.headers.get('content-length', '0'),
            'referer': request.headers.get('referer', ''),
            'origin': request.headers.get('origin', ''),
            'query_params': dict(request.query_params),
            'timestamp': datetime.now(timezone.utc)
        }
    
    def _should_secure_endpoint(self, endpoint: str) -> bool:
        """Determine if endpoint should be secured."""
        # Check excluded endpoints first
        for excluded in self.excluded_endpoints:
            if endpoint.startswith(excluded):
                return False
        
        # Check if endpoint is in secured list
        for secured in self.secured_endpoints:
            if endpoint.startswith(secured):
                return True
        
        # Default: secure all API endpoints
        return endpoint.startswith('/api/')
    
    async def _extract_content(self, request: Request) -> Optional[str]:
        """Extract content from request for scanning."""
        try:
            content_type = request.headers.get('content-type', '').lower()
            
            # Only scan certain content types
            if not any(ct in content_type for ct in self.scannable_content_types):
                return None
            
            # Get content length
            content_length = int(request.headers.get('content-length', '0'))
            if content_length == 0:
                return None
            
            # Limit content size for scanning (1MB max)
            if content_length > 1024 * 1024:
                logger.warning(f"Content too large for scanning: {content_length} bytes")
                return None
            
            # Read body
            body = await request.body()
            if not body:
                return None
            
            # Decode content
            if 'application/json' in content_type:
                try:
                    json_data = json.loads(body.decode('utf-8'))
                    return json.dumps(json_data)  # Normalize JSON
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return body.decode('utf-8', errors='ignore')
            else:
                return body.decode('utf-8', errors='ignore')
                
        except Exception as e:
            logger.error(f"Error extracting content: {e}")
            return None
    
    def _log_security_event(self, assessment, request_data: Dict[str, Any]):
        """Log security event with comprehensive details."""
        log_data = {
            'event_type': 'security_violation',
            'request_id': assessment.request_id,
            'timestamp': assessment.timestamp.isoformat(),
            'client_ip': assessment.client_ip,
            'user_id': assessment.user_id,
            'endpoint': assessment.endpoint,
            'method': assessment.method,
            'threat_type': assessment.threat_type.value,
            'threat_level': assessment.threat_level,
            'confidence_score': assessment.confidence_score,
            'recommended_action': assessment.recommended_action.value,
            'systems_checked': assessment.systems_checked,
            'scan_duration_ms': assessment.scan_duration_ms,
            'user_agent': request_data.get('user_agent', ''),
            'referer': request_data.get('referer', ''),
            'origin': request_data.get('origin', '')
        }
        
        # Add system-specific results
        if assessment.sql_injection_result:
            log_data['sql_injection'] = assessment.sql_injection_result
        if assessment.antivirus_result:
            log_data['antivirus'] = assessment.antivirus_result
        if assessment.rate_limit_result:
            log_data['rate_limit'] = assessment.rate_limit_result
        if assessment.ddos_result:
            log_data['ddos'] = assessment.ddos_result
        
        logger.warning(f"SECURITY_VIOLATION: {json.dumps(log_data, default=str)}")
    
    def _create_security_response(self, assessment, security_response: Dict[str, Any]) -> JSONResponse:
        """Create appropriate security response."""
        # Determine HTTP status code
        status_code = 403  # Forbidden by default
        
        if assessment.threat_type.value in ['rate_limit_violation', 'ddos_attack']:
            status_code = 429  # Too Many Requests
        elif assessment.recommended_action.value == 'warn':
            status_code = 200  # OK with warning
        
        # Create response content
        response_content = {
            'error': security_response.get('error', 'Security Violation'),
            'message': security_response.get('message', 'Request blocked by security systems'),
            'witty_response': security_response.get('witty_response', '🛡️ Security systems activated!'),
            'threat_type': assessment.threat_type.value,
            'request_id': assessment.request_id,
            'timestamp': assessment.timestamp.isoformat()
        }
        
        # Add additional fields if present
        for field in ['retry_after', 'block_duration', 'threat_level', 'confidence']:
            if field in security_response:
                response_content[field] = security_response[field]
        
        # Create response headers
        headers = {
            'X-Security-Status': 'blocked',
            'X-Threat-Type': assessment.threat_type.value,
            'X-Request-ID': assessment.request_id
        }
        
        if 'retry_after' in security_response:
            headers['Retry-After'] = str(security_response['retry_after'])
        
        return JSONResponse(
            status_code=status_code,
            content=response_content,
            headers=headers
        )
    
    def _add_security_headers(self, response: Response, assessment):
        """Add security headers to successful responses."""
        response.headers['X-Security-Status'] = 'passed'
        response.headers['X-Security-Scan-Duration'] = str(assessment.scan_duration_ms)
        response.headers['X-Security-Systems'] = ','.join(assessment.systems_checked)
        
        # Standard security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # CSP header for additional protection
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp_policy
