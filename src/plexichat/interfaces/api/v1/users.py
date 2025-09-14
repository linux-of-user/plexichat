from datetime import datetime
import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, EmailStr, Field


# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}


router = APIRouter(prefix="/users", tags=["Users"])

# In-memory storage for demonstration
users_db: dict[str, dict] = {}


class UserProfile(BaseModel):
    id: str
    username: str
    email: EmailStr
    display_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    status: str | None = None
    timezone: str | None = None
    language: str | None = None
    theme: str | None = None
    created_at: datetime


class UserUpdate(BaseModel):
    display_name: str | None = None
    email: EmailStr | None = None
    bio: str | None = Field(None, max_length=500)
    avatar_url: str | None = None
    status: str | None = None
    timezone: str | None = None
    language: str | None = None
    theme: str | None = None


@router.get("/me", response_model=UserProfile)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    user_id = current_user["id"]
    if user_id in users_db:
        return UserProfile(**users_db[user_id])
    # Create a mock user if not found, for demonstration
    mock_user = {
        "id": user_id,
        "username": "mock_user",
        "email": "user@example.com",
        "display_name": "Mock User",
        "bio": "Hello, I'm a mock user for demonstration purposes.",
        "avatar_url": None,
        "status": "online",
        "timezone": "UTC",
        "language": "en",
        "theme": "dark",
        "created_at": datetime.now(),
    }
    users_db[user_id] = mock_user
    return UserProfile(**mock_user)


@router.put("/me", response_model=UserProfile)
async def update_my_profile(
    update_data: UserUpdate, current_user: dict = Depends(get_current_user)
):
    """Update the current authenticated user's profile."""
    user_id = current_user["id"]
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = users_db[user_id]
    update_dict = update_data.dict(exclude_unset=True)
    user_data.update(update_dict)
    users_db[user_id] = user_data

    return UserProfile(**user_data)


@router.get("/{user_id}", response_model=UserProfile)
async def get_user_profile(user_id: str):
    """Get a user's public profile."""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfile(**users_db[user_id])


@router.get("/", response_model=list[UserProfile])
async def list_users(
    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)
):
    """List all users (paginated)."""
    all_users = [UserProfile(**u) for u in users_db.values()]
    return all_users[offset : offset + limit]


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...), current_user: dict = Depends(get_current_user)
):
    """Upload avatar for the current user."""
    user_id = current_user["id"]

    # Validate file type
    allowed_types = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.",
        )

    # Validate file size (max 5MB)
    file_size = 0
    content = await file.read()
    file_size = len(content)
    if file_size > 5 * 1024 * 1024:  # 5MB
        raise HTTPException(
            status_code=400, detail="File too large. Maximum size is 5MB."
        )

    # Generate unique filename
    file_extension = os.path.splitext(file.filename)[1]
    unique_filename = f"{user_id}_{uuid.uuid4()}{file_extension}"

    # Ensure uploads directory exists
    upload_dir = "plexichat/data/uploads/avatars"
    os.makedirs(upload_dir, exist_ok=True)

    # Save file
    file_path = os.path.join(upload_dir, unique_filename)
    with open(file_path, "wb") as f:
        f.write(content)

    # Update user's avatar_url
    if user_id in users_db:
        users_db[user_id]["avatar_url"] = f"/uploads/avatars/{unique_filename}"
    else:
        # Create user if not exists
        mock_user = {
            "id": user_id,
            "username": "mock_user",
            "email": "user@example.com",
            "display_name": "Mock User",
            "bio": "Hello, I'm a mock user for demonstration purposes.",
            "avatar_url": f"/uploads/avatars/{unique_filename}",
            "status": "online",
            "timezone": "UTC",
            "language": "en",
            "theme": "dark",
            "created_at": datetime.now(),
        }
        users_db[user_id] = mock_user

    return {
        "avatar_url": f"/uploads/avatars/{unique_filename}",
        "message": "Avatar uploaded successfully",
    }


if __name__ == "__main__":
    # Example of how to run this API with uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
