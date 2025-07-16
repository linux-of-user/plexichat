import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select

from plexichat.interfaces.web.schemas.auth import TokenResponse, LoginRequest
from plexichat.interfaces.web.schemas.error import ErrorDetail, ValidationErrorResponse, FieldError
from plexichat.features.users.user import User
from plexichat.infrastructure.utils.security import create_access_token, verify_password

try:
    from jose import JWTError, jwt  # type: ignore[import]
except ImportError:
    try:
        import jwt as _jwt  # type: ignore[import]
        JWTError = Exception
        jwt = _jwt
    except ImportError:
        jwt = None
        JWTError = Exception

# Robust fallback for get_engine
try:
    from plexichat.core.database import get_engine  # type: ignore[reportAttributeAccessIssue]
except ImportError:
    def get_engine():
        return None
engine = get_engine()

# Robust fallback for settings
try:
    from plexichat.core.config import settings  # type: ignore[import]
except ImportError:
    class MockSettings:
        SECRET_KEY = "mock-secret"
        JWT_ALGORITHM = "HS256"
    settings = MockSettings()

logger = logging.getLogger(__name__)
# engine = get_engine() # This line is removed as per the edit hint

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")

@router.post(
    "/login",
    response_model=TokenResponse,
    responses={400: {"model": ValidationErrorResponse}, 429: {"description": "Rate limit exceeded"}}
)
async def login(request: Request, data: LoginRequest):
    logger.debug(f"Login attempt for username: {data.username}")
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == data.username)).first()
        if not user:
            logger.warning(f"Login failed: User '{data.username}' not found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ValidationErrorResponse(
                    code=40001,
                    message="Invalid credentials",
                    errors={
                        "username": FieldError(_errors=[ErrorDetail(code="USER_NOT_FOUND", message="User not found")])
                    }
                ).dict()
            )
        if not verify_password(data.password, user.password_hash):
            logger.warning(f"Login failed: Incorrect password for user '{data.username}'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ValidationErrorResponse(
                    code=40002,
                    message="Invalid credentials",
                    errors={
                        "password": FieldError(_errors=[ErrorDetail(code="INCORRECT_PASSWORD", message="Incorrect password")])
                    }
                ).dict()
            )

        token_data = {
            "sub": str(user.id),
            "iat": int(datetime.utcnow().timestamp()),
            "scopes": ["users:read", "users:write", "messages:read", "messages:write"]
        }
        access_token = create_access_token(token_data, scopes=token_data["scopes"])
        logger.info(f"User '{user.username}' logged in successfully at {datetime.utcnow().isoformat()}Z")
        return TokenResponse(access_token=access_token, token_type="bearer", scopes=token_data["scopes"])


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if jwt is None:
            raise credentials_exception
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with Session(engine) as session:
        user = session.get(User, int(user_id))
        if user is None:
            raise credentials_exception
        return user
