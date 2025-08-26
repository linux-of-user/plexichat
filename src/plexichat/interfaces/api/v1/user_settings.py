import logging
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

# Mock user dependency
def get_current_user():
    return {"user_id": "mock_user"}

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/user-settings", tags=["User Settings"])

# In-memory storage for demonstration
user_settings_db: Dict[str, Dict] = {}

class UserSettings(BaseModel):
    theme: str = "dark"
    notifications_enabled: bool = True

class UserSettingsUpdate(BaseModel):
    theme: Optional[str] = None
    notifications_enabled: Optional[bool] = None

@router.get("/", response_model=UserSettings)
async def get_user_settings(current_user: dict = Depends(get_current_user)):
    """Get the current user's settings."""
    user_id = current_user["user_id"]
    if user_id not in user_settings_db:
        # Create default settings
        user_settings_db[user_id] = UserSettings().dict()
    return UserSettings(**user_settings_db[user_id])

@router.put("/", response_model=UserSettings)
async def update_user_settings(
    settings_update: UserSettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update the current user's settings."""
    user_id = current_user["user_id"]
    if user_id not in user_settings_db:
        user_settings_db[user_id] = UserSettings().dict()

    update_data = settings_update.dict(exclude_unset=True)
    user_settings_db[user_id].update(update_data)
    
    return UserSettings(**user_settings_db[user_id])

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
