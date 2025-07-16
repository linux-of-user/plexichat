# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Error response schemas for PlexiChat API.
Enhanced with comprehensive error handling and validation.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Individual error detail with enhanced information."""
    code: str = Field(..., description="Error code", example="VALIDATION_ERROR")
    message: str = Field(..., description="Human-readable error message", example="Invalid input provided")
    field: Optional[str] = Field(None, description="Field that caused the error", example="username")
    value: Optional[Any] = Field(None, description="Invalid value that caused the error")


class FieldError(BaseModel):
    """Field-specific error information."""
    errors: List[ErrorDetail] = Field(..., description="List of errors for this field")


class ValidationErrorResponse(BaseModel):
    """Validation error response with detailed field information."""
    detail: str = Field(..., description="Error description", example="Validation failed")
    code: int = Field(default=400, description="HTTP status code")
    errors: Optional[Dict[str, FieldError]] = Field(None, description="Field-specific errors")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class ErrorResponse(BaseModel):
    """Generic error response with comprehensive details."""
    error: str = Field(..., description="Error type", example="INTERNAL_ERROR")
    message: str = Field(..., description="Error message", example="An unexpected error occurred")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")


class NotFoundResponse(BaseModel):
    """Not found error response."""
    detail: str = Field(default="Resource not found", description="Error message")
    resource_type: Optional[str] = Field(None, description="Type of resource not found")
    resource_id: Optional[str] = Field(None, description="ID of resource not found")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class UnauthorizedResponse(BaseModel):
    """Unauthorized error response."""
    detail: str = Field(default="Authentication required", description="Error message")
    auth_type: Optional[str] = Field(None, description="Required authentication type")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class ForbiddenResponse(BaseModel):
    """Forbidden error response."""
    detail: str = Field(default="Access forbidden", description="Error message")
    required_permission: Optional[str] = Field(None, description="Required permission")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class RateLimitResponse(BaseModel):
    """Rate limit error response."""
    detail: str = Field(default="Rate limit exceeded", description="Error message")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retrying")
    limit: Optional[int] = Field(None, description="Rate limit threshold")
    window: Optional[int] = Field(None, description="Rate limit window in seconds")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class ServerErrorResponse(BaseModel):
    """Server error response."""
    detail: str = Field(default="Internal server error", description="Error message")
    error_id: Optional[str] = Field(None, description="Error tracking ID")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class BadRequestResponse(BaseModel):
    """Bad request error response."""
    detail: str = Field(default="Bad request", description="Error message")
    invalid_fields: Optional[List[str]] = Field(None, description="List of invalid fields")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class ConflictResponse(BaseModel):
    """Conflict error response."""
    detail: str = Field(default="Resource conflict", description="Error message")
    conflicting_resource: Optional[str] = Field(None, description="Conflicting resource identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")


class ServiceUnavailableResponse(BaseModel):
    """Service unavailable error response."""
    detail: str = Field(default="Service temporarily unavailable", description="Error message")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retrying")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Error timestamp")
