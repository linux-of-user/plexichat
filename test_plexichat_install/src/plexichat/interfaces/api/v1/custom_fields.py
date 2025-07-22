"""
PlexiChat Custom Fields API
Endpoints for managing dynamic custom fields for users and messages.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, validator

from plexichat.core.auth import get_current_user
from plexichat.core.database import database_manager
from plexichat.infrastructure.services.security_service import security_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/custom-fields", tags=["custom-fields"])

# Supported field types
SUPPORTED_TYPES = ["string", "int", "float", "bool", "list", "dict", "datetime"]
RESERVED_FIELD_NAMES = ["id", "created_at", "updated_at", "password", "token", "secret"]

# Request/Response Models
class CustomFieldValue(BaseModel):
    """Custom field value with type information."""
    name: str = Field(..., min_length=1, max_length=50)
    value: Any
    field_type: str = Field(..., regex="^(string|int|float|bool|list|dict|datetime)$")
    
    @validator('name')
    def validate_name(cls, v):
        if v.lower() in RESERVED_FIELD_NAMES:
            raise ValueError(f"Field name '{v}' is reserved")
        # Prevent SQL injection and XSS
        import re
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError("Field name must start with letter and contain only letters, numbers, and underscores")
        return v
    
    @validator('value')
    def validate_value_type(cls, v, values):
        field_type = values.get('field_type')
        if not field_type:
            return v
            
        try:
            if field_type == "string":
                return str(v)
            elif field_type == "int":
                return int(v)
            elif field_type == "float":
                return float(v)
            elif field_type == "bool":
                return bool(v)
            elif field_type == "list":
                return list(v) if not isinstance(v, list) else v
            elif field_type == "dict":
                return dict(v) if not isinstance(v, dict) else v
            elif field_type == "datetime":
                if isinstance(v, str):
                    return datetime.fromisoformat(v.replace('Z', '+00:00'))
                return v
        except (ValueError, TypeError) as e:
            raise ValueError(f"Cannot convert value to {field_type}: {e}")
        
        return v

class CustomFieldsUpdate(BaseModel):
    """Update custom fields for a user or message."""
    fields: List[CustomFieldValue]
    
    @validator('fields')
    def validate_field_limits(cls, v):
        if len(v) > 50:  # Limit number of custom fields
            raise ValueError("Maximum 50 custom fields allowed")
        
        # Check for duplicate field names
        names = [field.name for field in v]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate field names not allowed")
        
        return v

class CustomFieldsResponse(BaseModel):
    """Response with custom fields."""
    custom_fields: Dict[str, Any]
    field_types: Dict[str, str]

# Utility Functions
def serialize_custom_fields(fields: List[CustomFieldValue]) -> Dict[str, Any]:
    """Serialize custom fields to JSON-compatible dict."""
    result = {}
    for field in fields:
        if field.field_type == "datetime" and isinstance(field.value, datetime):
            result[field.name] = field.value.isoformat()
        else:
            result[field.name] = field.value
    return result

def get_field_types(fields: List[CustomFieldValue]) -> Dict[str, str]:
    """Get field type mapping."""
    return {field.name: field.field_type for field in fields}

def validate_field_size(fields_dict: Dict[str, Any]) -> bool:
    """Validate total size of custom fields."""
    try:
        json_str = json.dumps(fields_dict)
        if len(json_str) > 10000:  # 10KB limit
            raise ValueError("Custom fields data too large (max 10KB)")
        return True
    except Exception:
        raise ValueError("Invalid custom fields data")

# User Custom Fields Endpoints
@router.post("/users/{user_id}", response_model=CustomFieldsResponse)
async def update_user_custom_fields(
    user_id: int,
    fields_update: CustomFieldsUpdate,
    current_user = Depends(get_current_user)
):
    """Update custom fields for a user."""
    try:
        # Security check - users can only update their own fields unless admin
        if current_user.id != user_id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only update your own custom fields"
            )
        
        # Serialize and validate
        fields_dict = serialize_custom_fields(fields_update.fields)
        field_types = get_field_types(fields_update.fields)
        validate_field_size(fields_dict)
        
        # Update in database using abstraction layer
        update_data = {
            "custom_fields": json.dumps(fields_dict),
            "updated_at": datetime.now()
        }
        
        await database_manager.update_record("users", user_id, update_data)
        
        # Log the change for security compliance
        await security_service.log_security_event(
            "custom_fields_updated",
            {
                "user_id": user_id,
                "updated_by": current_user.id,
                "field_count": len(fields_update.fields),
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return CustomFieldsResponse(
            custom_fields=fields_dict,
            field_types=field_types
        )
        
    except Exception as e:
        logger.error(f"Failed to update user custom fields: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update custom fields"
        )

@router.get("/users/{user_id}", response_model=CustomFieldsResponse)
async def get_user_custom_fields(
    user_id: int,
    current_user = Depends(get_current_user)
):
    """Get custom fields for a user."""
    try:
        # Security check - users can only view their own fields unless admin
        if current_user.id != user_id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only view your own custom fields"
            )
        
        # Get user from database
        user_data = await database_manager.get_record("users", user_id)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Parse custom fields
        custom_fields = {}
        field_types = {}
        
        if user_data.get("custom_fields"):
            try:
                custom_fields = json.loads(user_data["custom_fields"])
                # For now, infer types from values (in production, store types separately)
                for name, value in custom_fields.items():
                    if isinstance(value, str):
                        field_types[name] = "string"
                    elif isinstance(value, int):
                        field_types[name] = "int"
                    elif isinstance(value, float):
                        field_types[name] = "float"
                    elif isinstance(value, bool):
                        field_types[name] = "bool"
                    elif isinstance(value, list):
                        field_types[name] = "list"
                    elif isinstance(value, dict):
                        field_types[name] = "dict"
                    else:
                        field_types[name] = "string"
            except json.JSONDecodeError:
                logger.warning(f"Invalid custom fields JSON for user {user_id}")
        
        return CustomFieldsResponse(
            custom_fields=custom_fields,
            field_types=field_types
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user custom fields: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve custom fields"
        )

# Message Custom Fields Endpoints
@router.post("/messages/{message_id}", response_model=CustomFieldsResponse)
async def update_message_custom_fields(
    message_id: int,
    fields_update: CustomFieldsUpdate,
    current_user = Depends(get_current_user)
):
    """Update custom fields for a message."""
    try:
        # Check if user owns the message or is admin
        message_data = await database_manager.get_record("messages", message_id)
        if not message_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        if message_data.get("sender_id") != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only update custom fields for your own messages"
            )
        
        # Serialize and validate
        fields_dict = serialize_custom_fields(fields_update.fields)
        field_types = get_field_types(fields_update.fields)
        validate_field_size(fields_dict)
        
        # Update in database
        update_data = {
            "custom_fields": json.dumps(fields_dict),
            "edited_at": datetime.now()
        }
        
        await database_manager.update_record("messages", message_id, update_data)
        
        # Log the change
        await security_service.log_security_event(
            "message_custom_fields_updated",
            {
                "message_id": message_id,
                "updated_by": current_user.id,
                "field_count": len(fields_update.fields),
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return CustomFieldsResponse(
            custom_fields=fields_dict,
            field_types=field_types
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update message custom fields: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update custom fields"
        )

@router.get("/messages/{message_id}", response_model=CustomFieldsResponse)
async def get_message_custom_fields(
    message_id: int,
    current_user = Depends(get_current_user)
):
    """Get custom fields for a message."""
    try:
        # Get message from database
        message_data = await database_manager.get_record("messages", message_id)
        if not message_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        # Parse custom fields
        custom_fields = {}
        field_types = {}
        
        if message_data.get("custom_fields"):
            try:
                custom_fields = json.loads(message_data["custom_fields"])
                # Infer types from values
                for name, value in custom_fields.items():
                    if isinstance(value, str):
                        field_types[name] = "string"
                    elif isinstance(value, int):
                        field_types[name] = "int"
                    elif isinstance(value, float):
                        field_types[name] = "float"
                    elif isinstance(value, bool):
                        field_types[name] = "bool"
                    elif isinstance(value, list):
                        field_types[name] = "list"
                    elif isinstance(value, dict):
                        field_types[name] = "dict"
                    else:
                        field_types[name] = "string"
            except json.JSONDecodeError:
                logger.warning(f"Invalid custom fields JSON for message {message_id}")
        
        return CustomFieldsResponse(
            custom_fields=custom_fields,
            field_types=field_types
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get message custom fields: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve custom fields"
        )

# Admin endpoints for global field type management
@router.get("/types", response_model=Dict[str, List[str]])
async def get_supported_field_types(current_user = Depends(get_current_user)):
    """Get list of supported field types."""
    return {
        "supported_types": SUPPORTED_TYPES,
        "reserved_names": RESERVED_FIELD_NAMES
    }
