from typing import Dict, Any, Optional
from .storage import AuthStorage

class InMemoryStorage(AuthStorage):
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}

    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self.users.get(username)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    async def get_token(self, token: str) -> Optional[Dict[str, Any]]:
        return self.tokens.get(token)

    async def save_user(self, username: str, user_data: Dict[str, Any]):
        self.users[username] = user_data

    async def save_session(self, session_id: str, session_data: Dict[str, Any]):
        self.sessions[session_id] = session_data

    async def save_token(self, token: str, token_data: Dict[str, Any]):
        self.tokens[token] = token_data

    async def delete_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

    async def delete_token(self, token: str):
        if token in self.tokens:
            del self.tokens[token]
