from pydantic import BaseModel, Field
from typing import List, Dict

class ErrorDetail(BaseModel):
    code: str
    message: str

class FieldError(BaseModel):
    _errors: List[ErrorDetail]

class ValidationErrorResponse(BaseModel):
    code: int = Field(..., description="Discord-style error code")
    message: str = Field(..., description="Summary message")
    errors: Dict[str, FieldError]
