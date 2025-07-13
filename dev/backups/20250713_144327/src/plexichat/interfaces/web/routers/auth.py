import logging
from datetime import datetime

from sqlmodel import Session, select

from datetime import datetime
from datetime import datetime



from datetime import datetime
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import jwt
import jwt

from plexichat.core.database import get_engine
from plexichat.features.users.user import User
from plexichat.infrastructure.utils.security import create_access_token, verify_password
from plexichat.interfaces.web.schemas.auth import (
from plexichat.core.config import settings
from plexichat.core.config import settings

    ErrorDetail,
    LoginRequest,
    TokenResponse,
    ValidationErrorResponse,
)

logger = logging.getLogger(__name__)
engine = get_engine()

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
                        "username": {"_errors": [ErrorDetail(code="USER_NOT_FOUND", message="User not found")]}
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
                        "password": {"_errors": [ErrorDetail(code="INCORRECT_PASSWORD", message="Incorrect password")]}
                    }
                ).dict()
            )

        token_data = {
            "sub": str(user.id),
            "iat": from datetime import datetime
datetime.utcnow().timestamp(),
            "scopes": ["users:read", "users:write", "messages:read", "messages:write"]
        }
        access_token = create_access_token(token_data)
        logger.info(f"User '{user.username}' logged in successfully at {from datetime import datetime
datetime.utcnow().isoformat()}Z")
        return TokenResponse(access_token=access_token, token_type="bearer", scopes=token_data["scopes"])


async def get_current_user from plexichat.infrastructure.utils.auth import get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = import jwt
jwt.decode(token, from plexichat.core.config import settings
settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with Session(engine) as session:
        user = session.get(User, int(user_id))
        if user is None:
            raise credentials_exception
        return user
