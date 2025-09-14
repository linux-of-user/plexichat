import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

# from plexichat.core.authentication import get_auth_manager  # Duplicate import removed
from plexichat.core.auth.fastapi_adapter import get_current_user, rate_limit
from plexichat.core.authentication import MFAMethod, get_auth_manager

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()

logger = logging.getLogger(__name__)

# Mock data storage (replace with database in production)
users_db = [
    {"id": 1, "username": "admin", "email": "admin@plexichat.com", "is_active": True},
    {"id": 2, "username": "user1", "email": "user1@example.com", "is_active": True},
]

# Mock session storage (replace with database in production)
sessions_db = {}


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ErrorDetail(BaseModel):
    detail: str


class MFAChallengeRequest(BaseModel):
    """Request model for MFA challenge creation."""

    pass


class MFAVerifyRequest(BaseModel):
    """Request model for MFA verification."""

    challenge_id: str
    code: str


class MFAChallengeResponse(BaseModel):
    """Response model for MFA challenge creation."""

    challenge_id: str
    message: str
    requires_mfa: bool


class MFAVerifyResponse(BaseModel):
    """Response model for MFA verification."""

    success: bool
    message: str
    access_token: str | None = None


@router.post("/register", status_code=status.HTTP_201_CREATED)
@rate_limit(action="auth_register", limit=5, window_seconds=60)
async def register(user_data: UserRegister, request: Request):
    """
    Register a new user using the unified authentication manager.
    Performs password strength validation via SecuritySystem and delegates
    user creation to UnifiedAuthManager.register_user.
    """
    auth_manager = get_auth_manager()
    username = user_data.username
    password = user_data.password
    client_ip = None
    try:
        client_ip = request.client.host if request.client else None
    except Exception:
        client_ip = None

    # Perform password strength validation via underlying password manager if available
    try:
        pwd_manager = getattr(auth_manager.security_system, "password_manager", None)
        if pwd_manager:
            valid, issues = pwd_manager.validate_password_strength(password)
            if not valid:
                logger.warning(
                    f"Password strength validation failed for registration attempt: {username} from {client_ip} issues={issues}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"password_strength_issues": issues},
                )
    except HTTPException:
        raise
    except Exception as e:
        # If password manager is not available or fails, log and continue to let register_user handle final validation
        logger.debug(f"Password strength check error (ignored): {e}")

    # Attempt to register user
    try:
        success = auth_manager.register_user(
            username=username, password=password, permissions=set()
        )
    except Exception as e:
        logger.error(
            f"Exception during user registration for {username} from {client_ip}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user",
        )

    if not success:
        logger.info(f"Registration failed for username={username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed (username may already exist or password did not meet requirements)",
        )

    logger.info(f"User registered: username={username} from {client_ip}")
    return {"username": username}


@router.post("/login", response_model=TokenResponse)
@rate_limit(action="auth_login", limit=10, window_seconds=60)
async def login(login_data: UserLogin, request: Request):
    """
    Login a user and return an access token. Delegates authentication to UnifiedAuthManager.authenticate_user.
    """
    auth_manager = get_auth_manager()
    username = login_data.username
    password = login_data.password

    client_ip = None
    user_agent = None
    try:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    except Exception:
        client_ip = None
        user_agent = None

    try:
        auth_result = await auth_manager.authenticate_user(
            username=username,
            password=password,
            ip_address=client_ip,
            user_agent=user_agent,
        )
    except Exception as e:
        logger.error(
            f"Authentication error for username={username} from {client_ip}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to server error",
        )

    if not auth_result or not auth_result.success:
        logger.warning(f"Failed login attempt for username={username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=auth_result.error_message or "Incorrect username or password",
        )

    token = auth_result.token or ""
    if not token:
        logger.error(
            f"Authentication succeeded but no token issued for username={username} from {client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication succeeded but token issuance failed",
        )

    # Audit log
    logger.info(
        f"User logged in: username={username}, user_id={auth_result.user_id}, session_id={auth_result.session_id}, ip={client_ip}"
    )

    return TokenResponse(access_token=token)


@router.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """
    Get the current authenticated user's information.
    Uses token validation via UnifiedAuthManager to return a consistent user object.
    """
    # Return minimal safe user info
    return {
        "id": current_user.get("id"),
        "user_id": current_user.get("user_id"),
        "permissions": list(current_user.get("permissions", [])),
        "is_active": current_user.get("is_active", True),
        "is_admin": current_user.get("is_admin", False),
    }


@router.post(
    "/logout",
    responses={
        200: {"description": "Successfully logged out"},
        401: {"model": ErrorDetail},
    },
)
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Logout user by revoking token via UnifiedAuthManager.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    auth_manager = get_auth_manager()
    token = credentials.credentials


@router.post("/mfa/challenge", response_model=MFAChallengeResponse)
async def create_mfa_challenge(current_user: dict = Depends(get_current_user)):
    """
    Create an MFA challenge for the current user.
    This endpoint triggers MFA challenge creation for additional verification.
    """
    auth_manager = get_auth_manager()
    user_id = current_user.get("user_id") or current_user.get("id")

    try:
        challenge = await auth_manager.create_mfa_challenge(user_id, MFAMethod.TOTP)
        if challenge:
            return MFAChallengeResponse(
                challenge_id=challenge.challenge_id,
                message="MFA challenge created successfully",
                requires_mfa=True,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create MFA challenge",
            )
    except Exception as e:
        logger.error(f"Error creating MFA challenge for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create MFA challenge",
        )


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def verify_mfa_challenge(verify_data: MFAVerifyRequest):
    """
    Verify an MFA challenge code.
    This endpoint verifies the provided MFA code against the stored challenge.
    """
    auth_manager = get_auth_manager()
    challenge_id = verify_data.challenge_id
    code = verify_data.code

    try:
        success = await auth_manager.verify_mfa_challenge(challenge_id, code)
        if success:
            # For successful MFA verification, we need to get the access token
            # This is a simplified implementation - in production you'd get the token from the challenge
            return MFAVerifyResponse(
                success=True,
                message="MFA verification successful",
                access_token="verified_token_placeholder",  # In production, get from challenge storage
            )
        else:
            return MFAVerifyResponse(success=False, message="Invalid MFA code")
    except Exception as e:
        logger.error(f"Error verifying MFA challenge {challenge_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA challenge",
        )
    try:
        revoked = await auth_manager.revoke_token(token)
        if revoked:
            logger.info("Token revoked successfully")
            # performance_logger is not available in this scope, remove this line
            # if performance_logger:
            #     performance_logger.increment_counter("logout", 1)
            return {"message": "Successfully logged out"}
        else:
            logger.warning("Attempted to revoke token but operation reported failure")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to revoke token"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed due to server error",
        )


if __name__ == "__main__":
    # Example of how to run this API with uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
