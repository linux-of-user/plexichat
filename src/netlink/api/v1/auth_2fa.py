"""
2FA Authentication API Endpoints for NetLink
Comprehensive 2FA management and verification endpoints.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import base64

from netlink.app.security.advanced_2fa import tfa_system, TwoFactorMethod
from netlink.app.security.comprehensive_security import require_security_level, SecurityLevel
from netlink.app.logger_config import logger


# Router
router = APIRouter(prefix="/auth/2fa", tags=["2fa"])


# Request/Response Models
class Setup2FARequest(BaseModel):
    methods: List[str]
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None


class Setup2FAResponse(BaseModel):
    success: bool
    setup_token: str
    methods: List[str]
    totp_secret: Optional[str] = None
    qr_code: Optional[str] = None
    backup_codes: List[str] = []


class Verify2FASetupRequest(BaseModel):
    setup_token: str
    verification_code: str


class Verify2FALoginRequest(BaseModel):
    code: str
    method: Optional[str] = None


class TwoFactorStatusResponse(BaseModel):
    enabled: bool
    methods: List[str] = []
    backup_codes_remaining: int = 0
    last_used: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None


class RegenerateBackupCodesResponse(BaseModel):
    success: bool
    backup_codes: List[str] = []


# Helper functions
def get_current_user_id(request: Request) -> int:
    """Get current user ID from request state."""
    user_id = getattr(request.state, 'user_id', None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user_id


def get_user_email(user_id: int) -> str:
    """Get user email (would typically query database)."""
    # This would query the database for user email
    # For now, return a placeholder
    return f"user{user_id}@example.com"


# API Endpoints
@router.post("/setup", response_model=Setup2FAResponse)
@require_security_level(SecurityLevel.SECURE)
async def setup_2fa(
    request: Setup2FARequest,
    http_request: Request
):
    """
    Initiate 2FA setup for the current user.
    
    Supports multiple 2FA methods:
    - TOTP (Time-based One-Time Password)
    - SMS (if phone number provided)
    - Email (if email provided)
    - Backup codes
    """
    try:
        user_id = get_current_user_id(http_request)
        user_email = get_user_email(user_id)
        
        # Validate requested methods
        valid_methods = [TwoFactorMethod.TOTP, TwoFactorMethod.SMS, 
                        TwoFactorMethod.EMAIL, TwoFactorMethod.BACKUP_CODES]
        
        invalid_methods = [method for method in request.methods if method not in valid_methods]
        if invalid_methods:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid 2FA methods: {invalid_methods}"
            )
        
        # Check if SMS method requires phone number
        if TwoFactorMethod.SMS in request.methods and not request.phone_number:
            raise HTTPException(
                status_code=400,
                detail="Phone number required for SMS 2FA"
            )
        
        # Check if email method requires email
        if TwoFactorMethod.EMAIL in request.methods and not request.email:
            request.email = user_email  # Use user's primary email
        
        # Initiate 2FA setup
        setup_result = tfa_system.initiate_2fa_setup(
            user_id=user_id,
            user_email=request.email or user_email,
            methods=request.methods
        )
        
        logger.info(f"2FA setup initiated for user {user_id} with methods: {request.methods}")
        
        return Setup2FAResponse(
            success=True,
            setup_token=setup_result["setup_token"],
            methods=setup_result["methods"],
            totp_secret=setup_result.get("totp_secret"),
            qr_code=setup_result.get("qr_code"),
            backup_codes=setup_result.get("backup_codes", [])
        )
        
    except Exception as e:
        logger.error(f"2FA setup error for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup 2FA")


@router.post("/setup/verify")
@require_security_level(SecurityLevel.SECURE)
async def verify_2fa_setup(
    request: Verify2FASetupRequest,
    http_request: Request
):
    """
    Verify 2FA setup with the provided verification code.
    Completes the 2FA setup process.
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Verify setup
        verification_result = tfa_system.verify_2fa_setup(
            setup_token=request.setup_token,
            verification_code=request.verification_code
        )
        
        if verification_result["success"]:
            logger.info(f"2FA setup completed for user {user_id}")
            
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": verification_result["message"],
                    "backup_codes": verification_result.get("backup_codes", [])
                }
            )
        else:
            logger.warning(f"2FA setup verification failed for user {user_id}: {verification_result['error']}")
            raise HTTPException(
                status_code=400,
                detail=verification_result["error"]
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA setup verification error: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify 2FA setup")


@router.post("/verify")
@require_security_level(SecurityLevel.BASIC)
async def verify_2fa_login(
    request: Verify2FALoginRequest,
    http_request: Request
):
    """
    Verify 2FA code during login process.
    Used to complete authentication when 2FA is required.
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Verify 2FA code
        verification_result = tfa_system.verify_2fa_login(
            user_id=user_id,
            code=request.code,
            method=request.method
        )
        
        if verification_result["success"]:
            # Upgrade session security level
            session_id = http_request.cookies.get('session_id')
            if session_id:
                # This would upgrade the session in the session manager
                # For now, just log the success
                logger.info(f"2FA verification successful for user {user_id}, method: {verification_result['method']}")
            
            response_data = {
                "success": True,
                "message": "2FA verification successful",
                "method": verification_result["method"]
            }
            
            # Add backup code info if applicable
            if "remaining_codes" in verification_result:
                response_data["backup_codes_remaining"] = verification_result["remaining_codes"]
                
            return JSONResponse(status_code=200, content=response_data)
            
        else:
            logger.warning(f"2FA verification failed for user {user_id}: {verification_result['error']}")
            raise HTTPException(
                status_code=401,
                detail=verification_result["error"]
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify 2FA")


@router.get("/status", response_model=TwoFactorStatusResponse)
@require_security_level(SecurityLevel.SECURE)
async def get_2fa_status(http_request: Request):
    """
    Get current 2FA status for the authenticated user.
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Get 2FA status
        status = tfa_system.get_user_2fa_status(user_id)
        
        return TwoFactorStatusResponse(
            enabled=status["enabled"],
            methods=status.get("methods", []),
            backup_codes_remaining=status.get("backup_codes_remaining", 0),
            last_used=status.get("last_used"),
            failed_attempts=status.get("failed_attempts", 0),
            locked_until=status.get("locked_until")
        )
        
    except Exception as e:
        logger.error(f"Failed to get 2FA status for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get 2FA status")


@router.post("/backup-codes/regenerate", response_model=RegenerateBackupCodesResponse)
@require_security_level(SecurityLevel.HIGH)
async def regenerate_backup_codes(http_request: Request):
    """
    Regenerate backup codes for the authenticated user.
    Requires high security level (2FA verification).
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Regenerate backup codes
        new_codes = tfa_system.regenerate_backup_codes(user_id)
        
        logger.info(f"Backup codes regenerated for user {user_id}")
        
        return RegenerateBackupCodesResponse(
            success=True,
            backup_codes=new_codes
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to regenerate backup codes for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to regenerate backup codes")


@router.delete("/disable")
@require_security_level(SecurityLevel.HIGH)
async def disable_2fa(http_request: Request):
    """
    Disable 2FA for the authenticated user.
    Requires high security level (2FA verification).
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Disable 2FA
        success = tfa_system.disable_2fa(user_id)
        
        if success:
            logger.info(f"2FA disabled for user {user_id}")
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "2FA has been disabled"
                }
            )
        else:
            raise HTTPException(status_code=400, detail="2FA was not enabled")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable 2FA for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable 2FA")


@router.get("/methods")
@require_security_level(SecurityLevel.BASIC)
async def get_available_2fa_methods():
    """
    Get list of available 2FA methods.
    """
    return JSONResponse(
        status_code=200,
        content={
            "methods": [
                {
                    "id": TwoFactorMethod.TOTP,
                    "name": "Authenticator App (TOTP)",
                    "description": "Use an authenticator app like Google Authenticator or Authy"
                },
                {
                    "id": TwoFactorMethod.SMS,
                    "name": "SMS",
                    "description": "Receive codes via SMS (requires phone number)"
                },
                {
                    "id": TwoFactorMethod.EMAIL,
                    "name": "Email",
                    "description": "Receive codes via email"
                },
                {
                    "id": TwoFactorMethod.BACKUP_CODES,
                    "name": "Backup Codes",
                    "description": "One-time use backup codes for recovery"
                }
            ]
        }
    )


@router.post("/test")
@require_security_level(SecurityLevel.SECURE)
async def test_2fa_code(
    request: Verify2FALoginRequest,
    http_request: Request
):
    """
    Test a 2FA code without affecting login state.
    Useful for testing authenticator app setup.
    """
    try:
        user_id = get_current_user_id(http_request)
        
        # Test the code
        verification_result = tfa_system.verify_2fa_login(
            user_id=user_id,
            code=request.code,
            method=request.method
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "valid": verification_result["success"],
                "method": verification_result.get("method"),
                "message": "Code is valid" if verification_result["success"] else "Code is invalid"
            }
        )
        
    except Exception as e:
        logger.error(f"2FA code test error: {e}")
        return JSONResponse(
            status_code=200,
            content={
                "valid": False,
                "message": "Unable to test code"
            }
        )
