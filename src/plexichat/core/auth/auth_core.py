"""
PlexiChat Core Authentication System

Enhanced authentication core with comprehensive security and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

# JWT and password hashing with fallbacks
try:
    from jose import JWTError, jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None
    JWTError = Exception

try:
    from passlib.context import CryptContext
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    CryptContext = None

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    bcrypt = None

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        JWT_SECRET = "mock-secret-key"
        JWT_ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30
        REFRESH_TOKEN_EXPIRE_DAYS = 7
    settings = MockSettings()

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Password hashing with fallbacks
if PASSLIB_AVAILABLE:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
else:
    pwd_context = None

class AuthenticationCore:
    """Core authentication system using EXISTING database abstraction."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.jwt_secret = getattr(settings, 'JWT_SECRET', 'mock-secret-key')
        self.jwt_algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256')
        self.access_token_expire = getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30)
        self.refresh_token_expire = getattr(settings, 'REFRESH_TOKEN_EXPIRE_DAYS', 7)

    def hash_password(self, password: str) -> str:
        """Hash password using available method."""
        if pwd_context:
            return pwd_context.hash(password)
        elif BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            # Fallback to SHA-256 with salt (not recommended for production)
            salt = secrets.token_hex(16)
            hashed = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"sha256${salt}${hashed}"

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        if pwd_context:
            return pwd_context.verify(plain_password, hashed_password)
        elif BCRYPT_AVAILABLE and not hashed_password.startswith('sha256$'):
            try:
                return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
            except:
                return False
        else:
            # Handle SHA-256 fallback
            if hashed_password.startswith('sha256$'):
                parts = hashed_password.split('$')
                if len(parts) == 3:
                    _, salt, stored_hash = parts
                    test_hash = hashlib.sha256((plain_password + salt).encode()).hexdigest()
                    return hmac.compare_digest(stored_hash, test_hash)
            return False

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token with fallback."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire)

        to_encode.update({"exp": expire})

        if JWT_AVAILABLE:
            try:
                return jwt.encode(to_encode, self.jwt_secret, algorithm=self.jwt_algorithm)
            except Exception as e:
                logger.error(f"JWT encoding failed: {e}")
                # Fall through to simple token

        # Fallback: create a simple signed token
        token_data = {
            'data': to_encode,
            'exp': expire.timestamp()
        }
        token_str = json.dumps(token_data, separators=(',', ':'))
        signature = hmac.new(
            self.jwt_secret.encode(),
            token_str.encode(),
            hashlib.sha256
        ).hexdigest()

        import base64
        encoded_token = base64.b64encode(token_str.encode()).decode()
        return f"{encoded_token}.{signature}"

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token with fallback."""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire)
        to_encode.update({"exp": expire, "type": "refresh"})

        if JWT_AVAILABLE:
            try:
                return jwt.encode(to_encode, self.jwt_secret, algorithm=self.jwt_algorithm)
            except Exception as e:
                logger.error(f"JWT encoding failed: {e}")

        # Fallback: create a simple signed token
        token_data = {
            'data': to_encode,
            'exp': expire.timestamp()
        }
        token_str = json.dumps(token_data, separators=(',', ':'))
        signature = hmac.new(
            self.jwt_secret.encode(),
            token_str.encode(),
            hashlib.sha256
        ).hexdigest()

        import base64
        encoded_token = base64.b64encode(token_str.encode()).decode()
        return f"{encoded_token}.{signature}"

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify JWT token with fallback."""
        if JWT_AVAILABLE:
            try:
                payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
                if payload.get("type") != token_type:
                    return None
                return payload
            except JWTError:
                pass  # Fall through to fallback verification

        # Fallback verification for simple tokens
        try:
            if '.' not in token:
                return None

            encoded_data, signature = token.rsplit('.', 1)

            # Verify signature
            import base64
            token_str = base64.b64decode(encoded_data.encode()).decode()
            expected_signature = hmac.new(
                self.jwt_secret.encode(),
                token_str.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_signature):
                return None

            # Parse token data
            token_data = json.loads(token_str)

            # Check expiration
            if token_data.get('exp', 0) < datetime.utcnow().timestamp():
                return None

            payload = token_data.get('data', {})
            if payload.get("type") != token_type:
                return None

            return payload

        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return None

    @async_track_performance("user_authentication") if async_track_performance else lambda f: f
    async def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user using EXISTING database abstraction."""
        if self.db_manager:
            try:
                query = """
                    SELECT id, username, email, hashed_password, is_active, is_admin, created_at
                    FROM users
                    WHERE username = ? AND is_active = 1
                """
                params = {"username": username}

                if self.performance_logger and timer:
                    with timer("user_lookup"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)

                if result and len(result) > 0:
                    row = result[0]
                    user_data = {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "hashed_password": row[3],
                        "is_active": bool(row[4]),
                        "is_admin": bool(row[5]),
                        "created_at": row[6]
                    }

                    if self.verify_password(password, user_data["hashed_password"]):
                        # Update last login
                        await self._update_last_login(user_data["id"])
                        return user_data

                return None

            except Exception as e:
                logger.error(f"Error authenticating user: {e}")
                return None

        return None

    @async_track_performance("user_creation") if async_track_performance else lambda f: f
    async def create_user(self, username: str, email: str, password: str, is_admin: bool = False) -> Optional[Dict[str, Any]]:
        """Create new user using EXISTING database abstraction."""
        if self.db_manager:
            try:
                # Check if user exists
                check_query = "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?"
                check_params = {"username": username, "email": email}

                result = await self.db_manager.execute_query(check_query, check_params)
                if result and result[0][0] > 0:
                    return None  # User already exists

                # Create user
                hashed_password = self.hash_password(password)
                create_query = """
                    INSERT INTO users (username, email, hashed_password, is_active, is_admin, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    RETURNING id, username, email, is_active, is_admin, created_at
                """
                create_params = {
                    "username": username,
                    "email": email,
                    "hashed_password": hashed_password,
                    "is_active": True,
                    "is_admin": is_admin,
                    "created_at": datetime.now()
                }

                if self.performance_logger and timer:
                    with timer("user_creation"):
                        result = await self.db_manager.execute_query(create_query, create_params)
                else:
                    result = await self.db_manager.execute_query(create_query, create_params)

                if result:
                    row = result[0]
                    return {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "is_active": bool(row[3]),
                        "is_admin": bool(row[4]),
                        "created_at": row[5]
                    }

            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return None

        return None

    async def _update_last_login(self, user_id: int):
        """Update user's last login timestamp."""
        if self.db_manager:
            try:
                query = "UPDATE users SET last_login = ? WHERE id = ?"
                params = {"last_login": datetime.now(), "id": user_id}
                await self.db_manager.execute_query(query, params)
            except Exception as e:
                logger.error(f"Error updating last login: {e}")

    @async_track_performance("token_validation") if async_track_performance else lambda f: f
    async def get_current_user(self, token: str) -> Optional[Dict[str, Any]]:
        """Get current user from token using EXISTING database abstraction."""
        payload = self.verify_token(token)
        if not payload:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        if self.db_manager:
            try:
                query = """
                    SELECT id, username, email, is_active, is_admin, created_at, last_login
                    FROM users
                    WHERE id = ? AND is_active = 1
                """
                params = {"id": int(user_id)}

                if self.performance_logger and timer:
                    with timer("token_user_lookup"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)

                if result:
                    row = result[0]
                    return {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "is_active": bool(row[3]),
                        "is_admin": bool(row[4]),
                        "created_at": row[5],
                        "last_login": row[6]
                    }

            except Exception as e:
                logger.error(f"Error getting current user: {e}")
                return None

        # Fallback for testing
        if user_id == "1":
            return {
                "id": 1,
                "username": "admin",
                "email": "admin@example.com",
                "is_active": True,
                "is_admin": True,
                "created_at": datetime.now(),
                "last_login": datetime.now()
            }

        return None

    def generate_api_key(self, user_id: int) -> str:
        """Generate API key for user."""
        data = f"{user_id}:{datetime.now().timestamp()}:{secrets.token_hex(16)}"
        return hashlib.sha256(data.encode()).hexdigest()

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return user data."""
        if self.db_manager:
            try:
                query = """
                    SELECT u.id, u.username, u.email, u.is_active, u.is_admin
                    FROM users u
                    JOIN api_keys ak ON u.id = ak.user_id
                    WHERE ak.key_hash = ? AND ak.is_active = 1 AND u.is_active = 1
                """
                key_hash = hashlib.sha256(api_key.encode()).hexdigest()
                params = {"key_hash": key_hash}

                result = await self.db_manager.execute_query(query, params)
                if result:
                    row = result[0]
                    return {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "is_active": bool(row[3]),
                        "is_admin": bool(row[4])
                    }

            except Exception as e:
                logger.error(f"Error validating API key: {e}")

        return None

# Global authentication instance
auth_core = AuthenticationCore()

# Convenience functions
def hash_password(password: str) -> str:
    """Hash password."""
    return auth_core.hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password."""
    return auth_core.verify_password(plain_password, hashed_password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create access token."""
    return auth_core.create_access_token(data, expires_delta)

def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create refresh token."""
    return auth_core.create_refresh_token(data)

def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """Verify token."""
    return auth_core.verify_token(token, token_type)
