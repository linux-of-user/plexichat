from typing import List

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="Bearer token to authenticate subsequent requests")
    token_type: str = Field("bearer", description="Token type, always 'bearer'")
    scopes: List[str] = Field(..., description="OAuth2 scopes granted to the token")

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=12)
