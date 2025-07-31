from pydantic_settings import BaseSettings

class AuthSettings(BaseSettings):
    session_timeout_minutes: int = 30
    token_lifetime_hours: int = 24
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    admin_file: str = "data/admin.json"

    class Config:
        env_prefix = "AUTH_"
        env_file = ".env"

auth_settings = AuthSettings()
