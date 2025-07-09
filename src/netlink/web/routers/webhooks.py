from fastapi import APIRouter, HTTPException, Header, Request

import logging import settings, logger

router = APIRouter()

@router.post(
    "/",
    status_code=200,
    responses={401: {"description": "Invalid secret"}, 429: {"description": "Rate limit exceeded"}}
)
async def receive_webhook(
    request: Request,
    event: dict,
    secret: str = Header(..., alias="X-Webhook-Secret")
):
    if secret != settings.WEBHOOK_SECRET:
        logger.warning("Invalid webhook secret")
        raise HTTPException(status_code=401, detail="Invalid secret")
    logger.info(f"Webhook processed: {event.get('event')}")
    return {}
