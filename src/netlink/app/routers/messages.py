from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlmodel import Session, select
from sqlalchemy import func

from app.logger_config import settings, logger
from app.db import engine
from app.models.message import Message
from app.schemas.error import ValidationErrorResponse
from app.schemas.message import MessageCreate, MessageRead
from app.routers.auth import get_current_user

router = APIRouter()

@router.post(
    "/",
    response_model=MessageRead,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ValidationErrorResponse}, 429: {"description": "Rate limit exceeded"}}
)
async def send_message(request: Request, data: MessageCreate, current_user=Depends(get_current_user)):
    logger.debug(f"User {current_user.id} sending message to recipient {data.recipient_id}")
    with Session(engine) as session:
        msg = Message(
            sender_id=current_user.id,
            recipient_id=data.recipient_id,
            content=data.content
        )
        session.add(msg)
        session.commit()
        session.refresh(msg)
        logger.info(f"Message {msg.id} sent from user {current_user.id} to {data.recipient_id}")
        return msg

@router.get(
    "/",
    response_model=dict,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def list_messages(request: Request, limit: int = 50, offset: int = 0, current_user=Depends(get_current_user)):
    logger.debug(f"Listing messages for user {current_user.id}")
    with Session(engine) as session:
        stmt = select(Message).where(
            (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
        ).order_by(Message.timestamp).limit(limit).offset(offset)
        messages = session.exec(stmt).all()

        total = session.exec(
            select(func.count()).select_from(Message).where(
                (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
            )
        ).one()[0]

        logger.info(f"User {current_user.id} retrieved {len(messages)} messages (total={total})")
        return {"messages": messages, "total": total, "limit": limit, "offset": offset}

@router.get(
    "/{message_id}",
    response_model=MessageRead,
    responses={404: {"description": "Message not found"}, 429: {"description": "Rate limit exceeded"}}
)
async def get_message(request: Request, message_id: int, current_user=Depends(get_current_user)):
    logger.debug(f"User {current_user.id} fetching message ID {message_id}")
    with Session(engine) as session:
        msg = session.get(Message, message_id)
        if not msg:
            logger.warning(f"Message ID {message_id} not found")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
        if msg.sender_id != current_user.id and msg.recipient_id != current_user.id:
            logger.warning(f"User {current_user.id} unauthorized to access message ID {message_id}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
        logger.info(f"User {current_user.id} retrieved message ID {message_id}")
        return msg
