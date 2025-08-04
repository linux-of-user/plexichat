from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class AuthStorage(ABC):
    @abstractmethod
    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_token(self, token: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_user(self, username: str, user_data: Dict[str, Any]):
        pass

    @abstractmethod
    async def save_session(self, session_id: str, session_data: Dict[str, Any]):
        pass

    @abstractmethod
    async def save_token(self, token: str, token_data: Dict[str, Any]):
        pass

    @abstractmethod
    async def delete_session(self, session_id: str):
        pass

    @abstractmethod
    async def delete_token(self, token: str):
        pass
