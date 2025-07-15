from typing import List


from .schemas import UserCreate, UserResponse, UserUpdate
from .service import user_service


from fastapi import APIRouter, HTTPException

"""User API router."""
router = APIRouter(prefix="/users", tags=["users"], Optional)


@router.post("/", response_model=UserResponse)
async def create_user(user_data: UserCreate):
    """Create a new user."""
    user = await user_service.create_user(user_data)
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        status=user.status,
        created_at=user.created_at.isoformat(),
        last_login=user.last_login.isoformat() if user.last_login else None,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    """Get user by ID."""
    user = await user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        status=user.status,
        created_at=user.created_at.isoformat(),
        last_login=user.last_login.isoformat() if user.last_login else None,
    )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, user_data: UserUpdate):
    """Update user."""
    user = await user_service.update_user(user_id, user_data)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        status=user.status,
        created_at=user.created_at.isoformat(),
        last_login=user.last_login.isoformat() if user.last_login else None,
    )


@router.delete("/{user_id}")
async def delete_user(user_id: str):
    """Delete user."""
    success = await user_service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User deleted successfully"}


@router.get("/", response_model=List[UserResponse])
async def list_users(limit: int = 100, offset: int = 0):
    """List users."""
    users = await user_service.list_users(limit, offset)
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            status=user.status,
            created_at=user.created_at.isoformat(),
            last_login=user.last_login.isoformat() if user.last_login else None,
        )
        for user in users
    ]
