from datetime import datetime
from pydantic import BaseModel

class FileRecord(BaseModel):
    """File record model."""
    id: int
    filename: str
    file_path: str
    file_size: int
    content_type: str
    upload_date: datetime
    user_id: int
