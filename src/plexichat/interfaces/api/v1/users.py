from typing import Dict, List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}

router = APIRouter(prefix="/users", tags=["Users"])

# In-memory storage for demonstration
users_db: Dict[str, Dict] = {}

class UserProfile(BaseModel):
    id: str
    username: str
    email: EmailStr
    display_name: str
    created_at: datetime

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None

@router.get("/me", response_model=UserProfile)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    user_id = current_user["id"]
    if user_id in users_db:
        return UserProfile(**users_db[user_id])
    # Create a mock user if not found, for demonstration
    mock_user = {"id": user_id, "username": "mock_user", "email": "user@example.com", "display_name": "Mock User", "created_at": datetime.now()}
    users_db[user_id] = mock_user
    return UserProfile(**mock_user)

@router.put("/me", response_model=UserProfile)
async def update_my_profile(update_data: UserUpdate, current_user: dict = Depends(get_current_user)):
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

@router.get("/", response_model=List[UserProfile])
async def list_users(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    """List all users (paginated)."""
    all_users = [UserProfile(**u) for u in users_db.values()]
    return all_users[offset : offset + limit]

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
