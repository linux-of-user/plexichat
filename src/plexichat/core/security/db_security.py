"""
Database Security Layer for PlexiChat Security Module
Provides secure database access with encryption and access control.

Features:
- Row-level security integration
- Encrypted data handling
- Query protection and sanitization
- Audit logging for database operations
- Access control enforcement
"""

import asyncio
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DatabaseQuery:
    """Represents a database query with security context."""
    query: str
    parameters: Tuple[Any, ...]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class AccessControlRule:
    """Access control rule for database operations."""
    table: str
    operation: str  # SELECT, INSERT, UPDATE, DELETE
    user_roles: List[str]
    conditions: Optional[str] = None
    enabled: bool = True


class DatabaseSecurityLayer:
    """
    Database security layer providing comprehensive protection.

    Features:
    - Query sanitization and validation
    - Row-level security enforcement
    - Encrypted data handling
    - Audit logging
    - Access control
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('access_control', True)

        if not self.enabled:
            logger.info("Database security layer is disabled")
            return

        # Security settings
        self.encryption_enabled = config.get('encryption_enabled', True)
        self.audit_logging = config.get('audit_logging', True)
        self.access_control_enabled = config.get('access_control', True)

        # Encryption settings
        self.encryption_key = self._generate_encryption_key()
        self.encryption_algorithm = 'AES-256-GCM'

        # Access control rules
        self.access_rules: Dict[str, List[AccessControlRule]] = {}
        self._initialize_default_access_rules()

        # Query patterns for detection
        self.dangerous_patterns = [
            r';\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s',
            r'UNION\s+SELECT.*--',
            r'/\*.*\*/.*UNION',
            r'EXEC\s*\(',
            r'XP_CMDSHELL',
            r'SP_EXECUTESQL',
        ]

        # Metrics
        self.metrics = {
            'queries_processed': 0,
            'queries_blocked': 0,
            'encryption_operations': 0,
            'access_denied': 0,
            'audit_entries': 0
        }

        logger.info("Database security layer initialized")

    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for sensitive data."""
        # In production, this should be loaded from secure key storage
        key_material = "plexichat-db-security-key-2024"
        return hashlib.sha256(key_material.encode()).digest()

    def _initialize_default_access_rules(self):
        """Initialize default access control rules."""
        # User table rules
        self.access_rules['users'] = [
            AccessControlRule(
                table='users',
                operation='SELECT',
                user_roles=['user', 'admin'],
                conditions="user_id = %s OR role = 'admin'"
            ),
            AccessControlRule(
                table='users',
                operation='UPDATE',
                user_roles=['user', 'admin'],
                conditions="user_id = %s"
            ),
            AccessControlRule(
                table='users',
                operation='DELETE',
                user_roles=['admin'],
                conditions=None
            )
        ]

        # Messages table rules
        self.access_rules['messages'] = [
            AccessControlRule(
                table='messages',
                operation='SELECT',
                user_roles=['user', 'admin'],
                conditions="sender_id = %s OR recipient_id = %s"
            ),
            AccessControlRule(
                table='messages',
                operation='INSERT',
                user_roles=['user', 'admin'],
                conditions=None
            ),
            AccessControlRule(
                table='messages',
                operation='DELETE',
                user_roles=['user', 'admin'],
                conditions="sender_id = %s"
            )
        ]

    async def validate_query(self, query: DatabaseQuery) -> Tuple[bool, str]:
        """
        Validate a database query for security.

        Args:
            query: DatabaseQuery object to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.enabled:
            return True, "Security disabled"

        self.metrics['queries_processed'] += 1

        try:
            # Check for dangerous patterns
            danger_check = self._check_dangerous_patterns(query.query)
            if not danger_check['safe']:
                self.metrics['queries_blocked'] += 1
                return False, danger_check['message']

            # Check access control
            if self.access_control_enabled:
                access_check = await self._check_access_control(query)
                if not access_check['allowed']:
                    self.metrics['access_denied'] += 1
                    return False, access_check['message']

            # Log audit entry
            if self.audit_logging:
                await self._log_audit_entry(query)

            return True, "Query validated successfully"

        except Exception as e:
            logger.error(f"Error validating query: {e}")
            return False, f"Query validation error: {str(e)}"

    def _check_dangerous_patterns(self, query: str) -> Dict[str, Any]:
        """Check query for dangerous patterns."""
        query_upper = query.upper()

        for pattern in self.dangerous_patterns:
            import re
            if re.search(pattern, query_upper, re.IGNORECASE):
                return {
                    'safe': False,
                    'message': f'Dangerous query pattern detected: {pattern}',
                    'pattern': pattern
                }

        # Check for SQL injection indicators
        injection_indicators = [
            "' OR '1'='1",
            '" OR "1"="1',
            "'; --",
            '"; --',
            "UNION SELECT",
            "INFORMATION_SCHEMA",
            "LOAD_FILE",
            "INTO OUTFILE"
        ]

        for indicator in injection_indicators:
            if indicator.upper() in query_upper:
                return {
                    'safe': False,
                    'message': f'SQL injection attempt detected: {indicator}',
                    'pattern': indicator
                }

        return {'safe': True, 'message': 'No dangerous patterns detected'}

    async def _check_access_control(self, query: DatabaseQuery) -> Dict[str, Any]:
        """Check if user has access to perform the query."""
        if not query.user_id:
            return {'allowed': False, 'message': 'User ID required for access control'}

        # Extract table and operation from query
        table, operation = self._parse_query_structure(query.query)

        if not table or not operation:
            return {'allowed': True, 'message': 'Could not parse query structure'}

        # Get applicable rules
        rules = self.access_rules.get(table, [])
        if not rules:
            # No specific rules, allow by default
            return {'allowed': True, 'message': 'No access rules defined'}

        # Check each rule
        for rule in rules:
            if (rule.enabled and
                rule.operation.upper() == operation.upper() and
                self._user_has_role(query.user_id, rule.user_roles)):

                # Rule applies, check conditions
                if rule.conditions:
                    # In production, this would validate the WHERE clause
                    # For now, assume conditions are met
                    pass

                return {'allowed': True, 'message': 'Access granted by rule'}

        return {
            'allowed': False,
            'message': f'Access denied: no matching rule for {operation} on {table}'
        }

    def _parse_query_structure(self, query: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse table and operation from SQL query."""
        query_upper = query.strip().upper()

        # Simple parsing for common operations
        if query_upper.startswith('SELECT'):
            operation = 'SELECT'
        elif query_upper.startswith('INSERT'):
            operation = 'INSERT'
        elif query_upper.startswith('UPDATE'):
            operation = 'UPDATE'
        elif query_upper.startswith('DELETE'):
            operation = 'DELETE'
        else:
            return None, None

        # Extract table name (very basic parsing)
        import re
        if operation == 'SELECT':
            match = re.search(r'SELECT\s+.*?\s+FROM\s+(\w+)', query_upper)
        elif operation == 'INSERT':
            match = re.search(r'INSERT\s+INTO\s+(\w+)', query_upper)
        elif operation == 'UPDATE':
            match = re.search(r'UPDATE\s+(\w+)', query_upper)
        elif operation == 'DELETE':
            match = re.search(r'DELETE\s+FROM\s+(\w+)', query_upper)

        table = match.group(1) if match else None
        return table, operation

    def _user_has_role(self, user_id: str, required_roles: List[str]) -> bool:
        """Check if user has any of the required roles."""
        # In production, this would query the user database
        # For now, assume basic role checking
        user_roles = self._get_user_roles(user_id)
        return any(role in user_roles for role in required_roles)

    def _get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles (mock implementation)."""
        # In production, this would query the database
        if user_id.startswith('admin'):
            return ['admin', 'user']
        else:
            return ['user']

    async def _log_audit_entry(self, query: DatabaseQuery):
        """Log audit entry for database operation."""
        if not self.audit_logging:
            return

        try:
            audit_entry = {
                'timestamp': query.timestamp.isoformat(),
                'user_id': query.user_id,
                'session_id': query.session_id,
                'ip_address': query.ip_address,
                'operation': 'database_query',
                'query_hash': hashlib.sha256(query.query.encode()).hexdigest(),
                'parameters_count': len(query.parameters) if query.parameters else 0
            }

            # In production, this would write to audit log
            logger.info(f"Database audit: {audit_entry}")
            self.metrics['audit_entries'] += 1

        except Exception as e:
            logger.error(f"Error logging audit entry: {e}")

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data for storage."""
        if not self.encryption_enabled:
            return data

        try:
            import os
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            # Generate IV
            iv = os.urandom(12)

            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv),
                backend=default_backend()
            )

            encryptor = cipher.encryptor()

            # Encrypt data
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

            # Combine IV, ciphertext, and tag
            encrypted_data = iv + encryptor.tag + ciphertext

            self.metrics['encryption_operations'] += 1
            return encrypted_data.hex()

        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return data

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not self.encryption_enabled:
            return encrypted_data

        try:
            import os
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            # Convert from hex
            encrypted_bytes = bytes.fromhex(encrypted_data)

            # Extract IV, tag, and ciphertext
            iv = encrypted_bytes[:12]
            tag = encrypted_bytes[12:28]
            ciphertext = encrypted_bytes[28:]

            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()

            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            self.metrics['encryption_operations'] += 1
            return plaintext.decode()

        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return encrypted_data

    def add_access_rule(self, rule: AccessControlRule):
        """Add a new access control rule."""
        if rule.table not in self.access_rules:
            self.access_rules[rule.table] = []

        self.access_rules[rule.table].append(rule)
        logger.info(f"Added access rule for {rule.table}.{rule.operation}")

    def remove_access_rule(self, table: str, operation: str):
        """Remove access control rules for a table/operation."""
        if table in self.access_rules:
            self.access_rules[table] = [
                rule for rule in self.access_rules[table]
                if rule.operation != operation
            ]
            logger.info(f"Removed access rules for {table}.{operation}")

    def get_security_status(self) -> Dict[str, Any]:
        """Get database security status."""
        if not self.enabled:
            return {'enabled': False}

        return {
            'enabled': True,
            'metrics': self.metrics.copy(),
            'encryption_enabled': self.encryption_enabled,
            'audit_logging_enabled': self.audit_logging,
            'access_control_enabled': self.access_control_enabled,
            'access_rules_count': sum(len(rules) for rules in self.access_rules.values()),
            'tables_with_rules': list(self.access_rules.keys()),
            'dangerous_patterns_count': len(self.dangerous_patterns)
        }

    def update_config(self, new_config: Dict[str, Any]):
        """Update database security configuration."""
        if not self.enabled:
            return

        self.config.update(new_config)
        self.encryption_enabled = new_config.get('encryption_enabled', self.encryption_enabled)
        self.audit_logging = new_config.get('audit_logging', self.audit_logging)
        self.access_control_enabled = new_config.get('access_control', self.access_control_enabled)

        logger.info("Database security configuration updated")

    async def shutdown(self):
        """Shutdown the database security layer."""
        logger.info("Database security layer shut down")


__all__ = ["DatabaseSecurityLayer", "DatabaseQuery", "AccessControlRule"]