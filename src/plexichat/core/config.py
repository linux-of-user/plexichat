from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "PlexiChat"
    admin_email: str = "admin@localhost"
    items_per_user: int = 50
    allowed_origins: list[str] = ["http://localhost:3000"]

    # Rate limiting
    rate_limit_default_requests_per_minute: int = 60
    rate_limit_default_requests_per_hour: int = 1000
    rate_limit_default_burst_limit: int = 10

    class Config:
        env_file = ".env"

settings = Settings()
