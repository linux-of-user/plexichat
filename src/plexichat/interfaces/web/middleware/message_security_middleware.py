"""
PlexiChat Message Security Middleware

Comprehensive security middleware for message processing that integrates:
- SQL injection detection with progressive blocking
- Antivirus scanning for message content
- Input sanitization and validation
- Rate limiting and DDoS protection
- Content filtering and threat detection
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from plexichat.services.security_service import SecurityService, ThreatType, ThreatLevel
import logging import logger

# Import antivirus components
try:
    from plexichat.antivirus.core.message_scanner import MessageAntivirusScanner, MessageThreatLevel
    ANTIVIRUS_AVAILABLE = True
except ImportError:
    logger.warning("Message antivirus scanner not available")
    ANTIVIRUS_AVAILABLE = False

class MessageSecurityMiddleware(BaseHTTPMiddleware):
    """
    Advanced message security middleware with comprehensive threat detection.
    
    Features:
    - Real-time SQL injection detection with progressive blocking
    - Message content antivirus scanning
    - Input sanitization and validation
    - Rate limiting with escalation
    - Threat intelligence integration
    - Witty security responses
    """
    
    def __init__(self, app, security_service: Optional[SecurityService] = None, data_dir: str = "data"):
        super().__init__(app)
        self.security_service = security_service or SecurityService()

        # Initialize message antivirus scanner
        if ANTIVIRUS_AVAILABLE:
            from pathlib import Path
            self.message_scanner = MessageAntivirusScanner(Path(data_dir))
        else:
            self.message_scanner = None

        # Message-specific security configuration
        self.message_endpoints = [
            "/api/v1/messages",
            "/api/v1/channels/",
            "/api/v1/guilds/",
            "/ws/messaging",
            "/ws/channels/",
            "/ws/guilds/"
        ]
        
        # Content limits
        self.max_message_length = 4000  # Discord-like limit
        self.max_attachment_size = 25 * 1024 * 1024  # 25MB
        
        # Rate limiting for messages
        self.message_rate_limits = {
            "messages_per_minute": 30,
            "messages_per_hour": 1000,
            "attachments_per_hour": 50
        }
        
        # Message tracking
        self.message_attempts: Dict[str, List[datetime]] = {}
        self.blocked_message_ips: Dict[str, datetime] = {}
        
        logger.info("🛡️ Message Security Middleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch with comprehensive security checks."""
        try:
            # Check if this is a message-related endpoint
            if not self._is_message_endpoint(request.url.path):
                return await call_next(request)
            
            # Get client information
            client_ip = self._get_client_ip(request)
            user_agent = request.headers.get("user-agent", "")
            
            # Pre-request security checks
            security_result = await self._perform_pre_request_checks(request, client_ip)
            if security_result:
                return security_result
            
            # For POST/PUT requests, check message content
            if request.method in ["POST", "PUT", "PATCH"]:
                content_result = await self._check_message_content(request, client_ip)
                if content_result:
                    return content_result
            
            # Process the request
            response = await call_next(request)
            
            # Post-request processing
            await self._perform_post_request_processing(request, response, client_ip)
            
            return response
            
        except Exception as e:
            logger.error(f"Message security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Security processing error",
                    "message": "An error occurred while processing your request",
                    "witty_response": "Our security system had a hiccup! 🤖 Please try again."
                }
            )
    
    def _is_message_endpoint(self, path: str) -> bool:
        """Check if the path is a message-related endpoint."""
        return any(endpoint in path for endpoint in self.message_endpoints)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _perform_pre_request_checks(self, request: Request, client_ip: str) -> Optional[JSONResponse]:
        """Perform pre-request security checks."""
        try:
            # Check if IP is blocked for SQL injection
            is_blocked, block_expiry, escalation_level = self.security_service.is_sql_injection_blocked(client_ip)
            if is_blocked:
                remaining_time = (block_expiry - datetime.now()).total_seconds()
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "IP Blocked",
                        "message": f"Your IP is blocked for {int(remaining_time)} seconds due to security violations",
                        "witty_response": "You're in timeout! ⏰ Maybe reflect on your life choices?",
                        "blocked_until": block_expiry.isoformat(),
                        "escalation_level": escalation_level
                    }
                )
            
            # Check message rate limits
            rate_limit_result = await self._check_message_rate_limits(client_ip)
            if rate_limit_result:
                return rate_limit_result
            
            # Check for suspicious headers
            suspicious_headers = self._check_suspicious_headers(request)
            if suspicious_headers:
                logger.warning(f"Suspicious headers detected from {client_ip}: {suspicious_headers}")
                # Log but don't block for headers alone
            
            return None
            
        except Exception as e:
            logger.error(f"Pre-request check error: {e}")
            return None
    
    async def _check_message_rate_limits(self, client_ip: str) -> Optional[JSONResponse]:
        """Check message-specific rate limits."""
        current_time = datetime.now()
        
        # Initialize tracking if needed
        if client_ip not in self.message_attempts:
            self.message_attempts[client_ip] = []
        
        # Clean old attempts
        minute_ago = current_time - timedelta(minutes=1)
        hour_ago = current_time - timedelta(hours=1)
        
        self.message_attempts[client_ip] = [
            attempt for attempt in self.message_attempts[client_ip]
            if attempt > hour_ago
        ]
        
        recent_attempts = [
            attempt for attempt in self.message_attempts[client_ip]
            if attempt > minute_ago
        ]
        
        # Check per-minute limit
        if len(recent_attempts) >= self.message_rate_limits["messages_per_minute"]:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many messages per minute",
                    "witty_response": "Slow down there, chatterbox! 💬 Give others a chance to speak!",
                    "retry_after": 60
                }
            )
        
        # Check per-hour limit
        if len(self.message_attempts[client_ip]) >= self.message_rate_limits["messages_per_hour"]:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "message": "Too many messages per hour",
                    "witty_response": "You've hit your daily chat quota! 📊 Time for a digital detox?",
                    "retry_after": 3600
                }
            )
        
        # Record this attempt
        self.message_attempts[client_ip].append(current_time)
        return None
    
    def _check_suspicious_headers(self, request: Request) -> List[str]:
        """Check for suspicious request headers."""
        suspicious = []
        
        # Check for common attack headers
        dangerous_headers = [
            "x-forwarded-host", "x-forwarded-server", "x-forwarded-proto",
            "x-rewrite-url", "x-original-url", "x-real-ip"
        ]
        
        for header in dangerous_headers:
            value = request.headers.get(header, "")
            if value and any(pattern in value.lower() for pattern in ["script", "javascript", "vbscript", "onload", "onerror"]):
                suspicious.append(f"{header}: {value}")
        
        return suspicious
    
    async def _check_message_content(self, request: Request, client_ip: str) -> Optional[JSONResponse]:
        """Comprehensive message content security checking."""
        try:
            # Read request body
            body = await request.body()
            if not body:
                return None
            
            # Parse JSON content
            try:
                content_data = json.loads(body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Invalid Content",
                        "message": "Request content is not valid JSON",
                        "witty_response": "Your message looks like it went through a blender! 🥤 Try valid JSON!"
                    }
                )
            
            # Extract message content
            message_content = self._extract_message_content(content_data)
            if not message_content:
                return None
            
            # Check message length
            if len(message_content) > self.max_message_length:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Message Too Long",
                        "message": f"Message exceeds maximum length of {self.max_message_length} characters",
                        "witty_response": f"Wow, that's a novel! 📚 Keep it under {self.max_message_length} characters please!"
                    }
                )
            
            # SQL injection detection
            sql_detected, sql_threat = self.security_service.detect_sql_injection(message_content, client_ip)
            if sql_detected and sql_threat:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Security Violation",
                        "message": "Message contains potentially malicious content",
                        "witty_response": sql_threat.witty_response,
                        "threat_id": sql_threat.threat_id,
                        "security_tip": "To send SQL safely, wrap it in quotes and brackets: \"[SELECT * FROM table]\""
                    }
                )

            # Antivirus scanning
            if self.message_scanner:
                try:
                    scan_result = await self.message_scanner.scan_message(
                        message_content,
                        sender_info={"ip": client_ip, "user_agent": request.headers.get("user-agent", "")}
                    )

                    # Check if threat detected
                    if scan_result.threat_level.value >= MessageThreatLevel.MEDIUM.value:
                        witty_responses = {
                            "sql_injection": "SQL injection detected by our advanced scanner! 🔍 Use proper quoting: \"[SQL]\"",
                            "xss_attempt": "XSS attempt blocked! 🚫 Keep your scripts to yourself!",
                            "malicious_link": "Suspicious link detected! 🔗 We don't click on sketchy URLs!",
                            "phishing_attempt": "Phishing attempt detected! 🎣 We're not biting your bait!",
                            "spam_content": "Spam content detected! 📧 Quality over quantity, please!"
                        }

                        witty_response = witty_responses.get(
                            scan_result.threat_type.value,
                            f"Threat detected: {scan_result.description} 🛡️"
                        )

                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Content Security Violation",
                                "message": scan_result.description,
                                "witty_response": witty_response,
                                "threat_type": scan_result.threat_type.value,
                                "threat_level": scan_result.threat_level.value,
                                "confidence": scan_result.confidence_score,
                                "scan_id": scan_result.message_hash,
                                "recommended_action": scan_result.recommended_action
                            }
                        )

                except Exception as e:
                    logger.error(f"Antivirus scanning error: {e}")
                    # Don't block on scanner errors, just log

            return None
            
        except Exception as e:
            logger.error(f"Message content check error: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Content Check Error",
                    "message": "Error processing message content",
                    "witty_response": "Our content scanner had a brain freeze! 🧠❄️ Try again!"
                }
            )
    
    def _extract_message_content(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract message content from request data."""
        # Try different possible content fields
        content_fields = ["content", "message", "text", "body"]
        
        for field in content_fields:
            if field in data and isinstance(data[field], str):
                return data[field]
        
        return None
    
    async def _perform_post_request_processing(self, request: Request, response: Response, client_ip: str):
        """Perform post-request security processing."""
        try:
            # Log successful message processing
            if response.status_code < 400:
                logger.info(f"✅ Message processed successfully from {client_ip}")
            else:
                logger.warning(f"⚠️ Message processing failed from {client_ip}: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Post-request processing error: {e}")
