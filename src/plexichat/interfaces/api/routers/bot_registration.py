#!/usr/bin/env python3
"""
Bot Account Special Registration System
Provides enhanced registration process for bot accounts with verification and higher rate limits
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import secrets
import logging
import re
import json

# Import security and validation
try:
    from ....core.security.security_decorators import rate_limit, audit_access
    from ....core.config.rate_limiting_config import AccountType, get_rate_limiting_config
    from ....shared.validators import validate_username, validate_email
    from ....core.validation import ValidationManager
except ImportError as e:
    print(f"Import error in bot registration: {e}")
    # Fallback decorators
    def rate_limit(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def audit_access(*args, **kwargs):
        def decorator(func): return func
        return decorator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bots", tags=["bot-registration"])

# Bot registration models
class BotType(str):
    """Bot type enumeration."""
    CHATBOT = "chatbot"
    AUTOMATION = "automation"
    INTEGRATION = "integration"
    MODERATION = "moderation"
    ANALYTICS = "analytics"
    CUSTOM = "custom"

class BotCapability(str):
    """Bot capability enumeration."""
    SEND_MESSAGES = "send_messages"
    READ_MESSAGES = "read_messages"
    MANAGE_USERS = "manage_users"
    MODERATE_CONTENT = "moderate_content"
    ACCESS_ANALYTICS = "access_analytics"
    FILE_UPLOAD = "file_upload"
    WEBHOOK_ACCESS = "webhook_access"
    API_ACCESS = "api_access"

class BotRegistrationRequest(BaseModel):
    """Bot registration request model."""
    bot_name: str = Field(..., min_length=3, max_length=50, description="Bot display name")
    bot_username: str = Field(..., min_length=3, max_length=30, description="Bot username (must be unique)")
    bot_description: str = Field(..., min_length=10, max_length=500, description="Bot description and purpose")
    bot_type: str = Field(..., description="Type of bot")
    bot_capabilities: List[str] = Field(..., description="Requested bot capabilities")
    
    # Owner information
    owner_username: str = Field(..., description="Username of the bot owner")
    owner_email: EmailStr = Field(..., description="Email of the bot owner")
    owner_organization: Optional[str] = Field(None, max_length=100, description="Organization name (if applicable)")
    
    # Technical details
    webhook_url: Optional[str] = Field(None, description="Webhook URL for bot notifications")
    api_endpoints: Optional[List[str]] = Field(None, description="List of API endpoints the bot will use")
    expected_request_volume: int = Field(..., ge=1, le=100000, description="Expected requests per hour")
    
    # Verification information
    verification_method: str = Field(..., description="Verification method (email, phone, manual)")
    business_verification: bool = Field(False, description="Request business verification")
    terms_accepted: bool = Field(..., description="Terms of service acceptance")
    privacy_policy_accepted: bool = Field(..., description="Privacy policy acceptance")
    
    # Additional metadata
    contact_info: Optional[Dict[str, str]] = Field(None, description="Additional contact information")
    use_case_details: Optional[str] = Field(None, max_length=1000, description="Detailed use case description")

    @validator('bot_username')
    def validate_bot_username(cls, v):
        """Validate bot username format."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Bot username can only contain letters, numbers, underscores, and hyphens')
        if v.startswith(('_', '-')) or v.endswith(('_', '-')):
            raise ValueError('Bot username cannot start or end with underscore or hyphen')
        if not v.endswith('_bot') and not v.endswith('-bot'):
            v = f"{v}_bot"  # Automatically append _bot suffix
        return v.lower()

    @validator('bot_capabilities')
    def validate_capabilities(cls, v):
        """Validate bot capabilities."""
        valid_capabilities = [
            BotCapability.SEND_MESSAGES, BotCapability.READ_MESSAGES,
            BotCapability.MANAGE_USERS, BotCapability.MODERATE_CONTENT,
            BotCapability.ACCESS_ANALYTICS, BotCapability.FILE_UPLOAD,
            BotCapability.WEBHOOK_ACCESS, BotCapability.API_ACCESS
        ]
        for capability in v:
            if capability not in valid_capabilities:
                raise ValueError(f'Invalid capability: {capability}')
        return v

    @validator('webhook_url')
    def validate_webhook_url(cls, v):
        """Validate webhook URL."""
        if v:
            if not v.startswith(('http://', 'https://')):
                raise ValueError('Webhook URL must start with http:// or https://')
            if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', v):
                raise ValueError('Invalid webhook URL format')
        return v

class BotRegistrationResponse(BaseModel):
    """Bot registration response model."""
    success: bool
    message: str
    bot_id: Optional[str] = None
    bot_token: Optional[str] = None
    bot_secret: Optional[str] = None
    verification_required: bool = False
    verification_method: Optional[str] = None
    verification_code: Optional[str] = None
    rate_limits: Optional[Dict[str, Any]] = None
    next_steps: List[str] = []

class BotVerificationRequest(BaseModel):
    """Bot verification request model."""
        bot_id: str = Field(..., description="Bot ID from registration")
    verification_code: str = Field(..., description="Verification code")
    verification_method: str = Field(..., description="Verification method used")

class BotStatusResponse(BaseModel):
    """Bot status response model."""
        bot_id: str
    bot_username: str
    bot_name: str
    status: str
    verified: bool
    created_at: datetime
    rate_limits: Dict[str, Any]
    capabilities: List[str]
    owner_info: Dict[str, str]

# In-memory storage for demo (replace with database in production)
bot_registrations: Dict[str, Dict[str, Any]] = {}
verification_codes: Dict[str, Dict[str, Any]] = {}

@router.post("/register", response_model=BotRegistrationResponse)
@rate_limit(requests_per_minute=5, requests_per_hour=20)
@audit_access("create", "bot_account")
async def register_bot(
    request: Request,
    bot_request: BotRegistrationRequest,
    background_tasks: BackgroundTasks
):
    """Register a new bot account with enhanced verification."""
    try:
        # Validate request
        validation_errors = await _validate_bot_registration(bot_request)
        if validation_errors:
            raise HTTPException(status_code=400, detail={
                "error": "Validation failed",
                "details": validation_errors
            })
        
        # Check if bot username already exists
        for bot_id, bot_data in bot_registrations.items():
            if bot_data.get("bot_username") == bot_request.bot_username:
                raise HTTPException(status_code=400, detail={
                    "error": "Bot username already exists",
                    "message": f"A bot with username '{bot_request.bot_username}' already exists"
                })
        
        # Generate bot credentials
        bot_id = f"bot_{secrets.token_urlsafe(16)}"
        bot_token = f"bot_token_{secrets.token_urlsafe(32)}"
        bot_secret = secrets.token_urlsafe(16)
        
        # Determine verification method
        verification_required = True
        verification_method = bot_request.verification_method
        verification_code = None
        
        if verification_method == "email":
            verification_code = secrets.token_urlsafe(8)
            # Store verification code
            verification_codes[bot_id] = {
                "code": verification_code,
                "method": "email",
                "expires_at": datetime.now() + timedelta(hours=24),
                "attempts": 0
            }
        elif verification_method == "manual":
            verification_required = True
            verification_method = "manual"
        
        # Calculate rate limits based on request volume and capabilities
        rate_limits = _calculate_bot_rate_limits(bot_request)
        
        # Store bot registration
        bot_data = {
            "bot_id": bot_id,
            "bot_name": bot_request.bot_name,
            "bot_username": bot_request.bot_username,
            "bot_description": bot_request.bot_description,
            "bot_type": bot_request.bot_type,
            "bot_capabilities": bot_request.bot_capabilities,
            "owner_username": bot_request.owner_username,
            "owner_email": bot_request.owner_email,
            "owner_organization": bot_request.owner_organization,
            "webhook_url": bot_request.webhook_url,
            "api_endpoints": bot_request.api_endpoints or [],
            "expected_request_volume": bot_request.expected_request_volume,
            "verification_method": verification_method,
            "business_verification": bot_request.business_verification,
            "contact_info": bot_request.contact_info or {},
            "use_case_details": bot_request.use_case_details,
            "bot_token": bot_token,
            "bot_secret": bot_secret,
            "rate_limits": rate_limits,
            "status": "pending_verification" if verification_required else "active",
            "verified": False,
            "created_at": datetime.now(),
            "client_ip": request.client.host if request.client else "unknown"
        }
        
        bot_registrations[bot_id] = bot_data
        
        # Send verification email if needed
        if verification_method == "email" and verification_code:
            background_tasks.add_task(
                _send_verification_email,
                bot_request.owner_email,
                bot_request.bot_name,
                verification_code,
                bot_id
            )
        
        # Prepare next steps
        next_steps = []
        if verification_required:
            if verification_method == "email":
                next_steps.append(f"Check your email ({bot_request.owner_email}) for verification code")
                next_steps.append("Use the verification code to complete bot registration")
            elif verification_method == "manual":
                next_steps.append("Your bot registration is pending manual review")
                next_steps.append("You will be contacted within 24-48 hours")
        
        next_steps.extend([
            "Review the bot documentation and API guidelines",
            "Test your bot in the sandbox environment",
            "Configure webhook endpoints if applicable"
        ])
        
        logger.info(f"Bot registration initiated: {bot_request.bot_username} (ID: {bot_id})")
        
        return BotRegistrationResponse(
            success=True,
            message="Bot registration initiated successfully",
            bot_id=bot_id,
            bot_token=bot_token if not verification_required else None,
            bot_secret=bot_secret if not verification_required else None,
            verification_required=verification_required,
            verification_method=verification_method,
            verification_code=verification_code if verification_method == "email" else None,
            rate_limits=rate_limits,
            next_steps=next_steps
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bot registration: {e}")
        raise HTTPException(status_code=500, detail={
            "error": "Registration failed",
            "message": "An internal error occurred during bot registration"
        })

@router.post("/verify", response_model=BotRegistrationResponse)
@rate_limit(requests_per_minute=10, requests_per_hour=50)
@audit_access("verify", "bot_account")
async def verify_bot(verification_request: BotVerificationRequest):
    """Verify bot account with verification code."""
    try:
        bot_id = verification_request.bot_id
        
        # Check if bot exists
        if bot_id not in bot_registrations:
            raise HTTPException(status_code=404, detail={
                "error": "Bot not found",
                "message": "Bot registration not found"
            })
        
        # Check if verification code exists
        if bot_id not in verification_codes:
            raise HTTPException(status_code=400, detail={
                "error": "No verification pending",
                "message": "No verification code found for this bot"
            })
        
        verification_data = verification_codes[bot_id]
        bot_data = bot_registrations[bot_id]
        
        # Check if verification code has expired
        if datetime.now() > verification_data["expires_at"]:
            del verification_codes[bot_id]
            raise HTTPException(status_code=400, detail={
                "error": "Verification expired",
                "message": "Verification code has expired. Please request a new one."
            })
        
        # Check verification attempts
        if verification_data["attempts"] >= 5:
            del verification_codes[bot_id]
            raise HTTPException(status_code=400, detail={
                "error": "Too many attempts",
                "message": "Too many verification attempts. Please request a new code."
            })
        
        # Verify code
        if verification_request.verification_code != verification_data["code"]:
            verification_data["attempts"] += 1
            raise HTTPException(status_code=400, detail={
                "error": "Invalid verification code",
                "message": f"Verification code is incorrect. {5 - verification_data['attempts']} attempts remaining."
            })
        
        # Verification successful
        bot_data["verified"] = True
        bot_data["status"] = "active"
        bot_data["verified_at"] = datetime.now()
        
        # Clean up verification code
        del verification_codes[bot_id]
        
        logger.info(f"Bot verification successful: {bot_data['bot_username']} (ID: {bot_id})")
        
        return BotRegistrationResponse(
            success=True,
            message="Bot verification successful",
            bot_id=bot_id,
            bot_token=bot_data["bot_token"],
            bot_secret=bot_data["bot_secret"],
            verification_required=False,
            rate_limits=bot_data["rate_limits"],
            next_steps=[
                "Your bot is now active and ready to use",
                "Configure your bot application with the provided credentials",
                "Start testing in the sandbox environment"
            ]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bot verification: {e}")
        raise HTTPException(status_code=500, detail={
            "error": "Verification failed",
            "message": "An internal error occurred during verification"
        })

@router.get("/status/{bot_id}", response_model=BotStatusResponse)
@rate_limit(requests_per_minute=30)
@audit_access("view", "bot_status")
async def get_bot_status(bot_id: str):
    """Get bot registration and verification status."""
    try:
        if bot_id not in bot_registrations:
            raise HTTPException(status_code=404, detail={
                "error": "Bot not found",
                "message": "Bot registration not found"
            })
        
        bot_data = bot_registrations[bot_id]
        
        return BotStatusResponse(
            bot_id=bot_id,
            bot_username=bot_data["bot_username"],
            bot_name=bot_data["bot_name"],
            status=bot_data["status"],
            verified=bot_data["verified"],
            created_at=bot_data["created_at"],
            rate_limits=bot_data["rate_limits"],
            capabilities=bot_data["bot_capabilities"],
            owner_info={
                "username": bot_data["owner_username"],
                "email": bot_data["owner_email"],
                "organization": bot_data.get("owner_organization", "")
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting bot status: {e}")
        raise HTTPException(status_code=500, detail={
            "error": "Status retrieval failed",
            "message": "An internal error occurred"
        })

async def _validate_bot_registration(bot_request: BotRegistrationRequest) -> List[str]:
    """Validate bot registration request."""
    errors = []
    
    try:
        # Validate bot name
        if len(bot_request.bot_name.strip()) < 3:
            errors.append("Bot name must be at least 3 characters long")
        
        # Validate bot type
        valid_types = [BotType.CHATBOT, BotType.AUTOMATION, BotType.INTEGRATION, 
                    BotType.MODERATION, BotType.ANALYTICS, BotType.CUSTOM]
        if bot_request.bot_type not in valid_types:
            errors.append(f"Invalid bot type. Must be one of: {', '.join(valid_types)}")
        
        # Validate capabilities
        if not bot_request.bot_capabilities:
            errors.append("At least one capability must be specified")
        
        # Validate request volume
        if bot_request.expected_request_volume > 10000:
            errors.append("High volume bots (>10,000 req/hour) require manual approval")
        
        # Validate verification method
        valid_methods = ["email", "phone", "manual"]
        if bot_request.verification_method not in valid_methods:
            errors.append(f"Invalid verification method. Must be one of: {', '.join(valid_methods)}")
        
        # Validate terms acceptance
        if not bot_request.terms_accepted:
            errors.append("Terms of service must be accepted")
        if not bot_request.privacy_policy_accepted:
            errors.append("Privacy policy must be accepted")
        
    except Exception as e:
        errors.append(f"Validation error: {str(e)}")
    
    return errors

def _calculate_bot_rate_limits(bot_request: BotRegistrationRequest) -> Dict[str, Any]:
    """Calculate rate limits based on bot capabilities and expected volume."""
    base_limits = {
        "requests_per_minute": 500,
        "requests_per_hour": 10000,
        "concurrent_requests": 50,
        "bandwidth_per_second": 10 * 1024 * 1024  # 10MB/s
    }
    
    # Adjust based on expected volume
    volume_multiplier = min(bot_request.expected_request_volume / 1000, 10)
    
    # Adjust based on capabilities
    capability_multiplier = 1.0
    high_volume_capabilities = [BotCapability.SEND_MESSAGES, BotCapability.MODERATE_CONTENT, 
                            BotCapability.ACCESS_ANALYTICS]
    
    for capability in bot_request.bot_capabilities:
        if capability in high_volume_capabilities:
            capability_multiplier += 0.5
    
    # Calculate final limits
    final_limits = {
        "requests_per_minute": int(base_limits["requests_per_minute"] * volume_multiplier * capability_multiplier),
        "requests_per_hour": int(base_limits["requests_per_hour"] * volume_multiplier * capability_multiplier),
        "concurrent_requests": int(base_limits["concurrent_requests"] * capability_multiplier),
        "bandwidth_per_second": int(base_limits["bandwidth_per_second"] * capability_multiplier)
    }
    
    # Apply reasonable caps
    final_limits["requests_per_minute"] = min(final_limits["requests_per_minute"], 2000)
    final_limits["requests_per_hour"] = min(final_limits["requests_per_hour"], 50000)
    final_limits["concurrent_requests"] = min(final_limits["concurrent_requests"], 200)
    
    return final_limits

async def _send_verification_email(email: str, bot_name: str, verification_code: str, bot_id: str):
    """Send verification email (placeholder implementation)."""
    try:
        # This would integrate with an actual email service
        logger.info(f"Sending verification email to {email} for bot {bot_name}")
        logger.info(f"Verification code: {verification_code} for bot ID: {bot_id}")
        
        # In a real implementation, this would send an actual email
        # using services like SendGrid, AWS SES, etc.
        
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")
