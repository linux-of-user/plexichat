import logging

from sqlmodel import Session, select



from fastapi import APIRouter, Depends, HTTPException, Request, status

from plexichat.core.database import engine
from plexichat.features.users.user import User
from plexichat.infrastructure.utils.security import get_password_hash
from plexichat.interfaces.web.routers.auth import from plexichat.infrastructure.utils.auth import get_current_user
from plexichat.interfaces.web.schemas.user import UserCreate, UserRead, UserUpdate

logger = logging.getLogger(__name__)
# settings import will be added when needed
router = APIRouter()

@router.post(
    "/",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"description": "Username or email exists"}, 429: {"description": "Rate limit exceeded"}}
)
async def create_user(request: Request, user_data: UserCreate):
    logger.debug(f"[USER-001] Attempting to create user: {user_data.username}")
    with Session(engine) as session:
        if session.exec(select(User).where(User.username == user_data.username)).first():
            logger.warning(f"[USER-002] Username exists: {user_data.username}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
        if session.exec(select(User).where(User.email == user_data.email)).first():
            logger.warning(f"[USER-003] Email exists: {user_data.email}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=get_password_hash(user_data.password),
            public_key=user_data.public_key,
            display_name=user_data.display_name
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info(f"[USER-004] Created user: {user.username} (ID: {user.id})")
        return user

@router.get(
    "/{id}",
    response_model=UserRead,
    responses={404: {"description": "User not found"}, 429: {"description": "Rate limit exceeded"}}
)
async def get_user(request: Request, id: int, current_user=Depends(from plexichat.infrastructure.utils.auth import get_current_user)):
    logger.debug(f"User {current_user.id} fetching profile ID {id}")
    with Session(engine) as session:
        user = session.get(User, id)
        if not user:
            logger.warning(f"User ID {id} not found")
            raise HTTPException(status_code=404, detail="User not found")
        logger.info(f"User {current_user.id} retrieved profile ID {id}")
        return user

@router.patch(
    "/{id}",
    response_model=UserRead,
    responses={403: {"description": "Not authorized"}, 400: {"description": "Invalid data"}, 429: {"description": "Rate limit exceeded"}}
)
async def update_user(request: Request, id: int, data: UserUpdate, current_user=Depends(from plexichat.infrastructure.utils.auth import get_current_user)):
    if id != current_user.id:
        logger.warning(f"User {current_user.id} unauthorized to update ID {id}")
        raise HTTPException(status_code=403, detail="Not authorized")

    logger.debug(f"User {current_user.id} updating profile")
    with Session(engine) as session:
        user = session.get(User, id)
        if data.email and session.exec(select(User).where(User.email == data.email, User.id != id)).first():
            logger.warning(f"Email exists: {data.email}")
            raise HTTPException(status_code=400, detail="Email already exists")
        for key, value in data.dict(exclude_unset=True).items():
            setattr(user, key, value)
        session.commit()
        session.refresh(user)
        logger.info(f"User {current_user.id} updated profile")
        return user

@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={403: {"description": "Not authorized"}, 429: {"description": "Rate limit exceeded"}}
)
async def delete_user(request: Request, id: int, current_user=Depends(from plexichat.infrastructure.utils.auth import get_current_user)):
    if id != current_user.id:
        logger.warning(f"User {current_user.id} unauthorized to delete ID {id}")
        raise HTTPException(status_code=403, detail="Not authorized")

    logger.debug(f"User {current_user.id} deleting account")
    with Session(engine) as session:
        user = session.get(User, id)
        session.delete(user)
        session.commit()
        logger.info(f"User {current_user.id} deleted account")
