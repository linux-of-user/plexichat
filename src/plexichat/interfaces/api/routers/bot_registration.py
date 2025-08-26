from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any, List
from datetime import datetime
import secrets
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/bots", tags=["bot-registration"])

# In-memory storage for demonstration
bot_registrations: Dict[str, Dict[str, Any]] = {}

class BotRegistrationRequest(BaseModel):
    bot_name: str = Field(..., min_length=3)
    owner_email: EmailStr

class BotRegistrationResponse(BaseModel):
    success: bool
    message: str
    bot_id: Optional[str] = None

@router.post("/register", response_model=BotRegistrationResponse)
async def register_bot(bot_request: BotRegistrationRequest, background_tasks: BackgroundTasks):
    """Registers a new bot account."""
    bot_id = f"bot_{secrets.token_urlsafe(8)}"

    bot_data = {
        "bot_id": bot_id,
        "bot_name": bot_request.bot_name,
        "owner_email": bot_request.owner_email,
        "status": "pending_verification",
        "created_at": datetime.now(),
    }
    bot_registrations[bot_id] = bot_data

    # Simulate sending a verification email
    background_tasks.add_task(
        lambda email, name: logger.info(f"Sending verification email to {email} for bot {name}"),
        bot_request.owner_email,
        bot_request.bot_name
    )

    return BotRegistrationResponse(
        success=True,
        message="Bot registration initiated. Please check your email for verification.",
        bot_id=bot_id
    )

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
