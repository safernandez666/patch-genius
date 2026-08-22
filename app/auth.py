"""Session authentication.

The public demo runs without accounts, but a deployment pointed at a real Wazuh
is showing an unpatched-CVE inventory of live infrastructure — an attacker's
shopping list — and the Configuration tab stores Wazuh credentials. Both require
a login, so authentication turns on automatically whenever the data source is not
the synthetic demo.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import asyncpg
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = structlog.get_logger(__name__)

SESSION_COOKIE = "patch_tracker_session"
SESSION_MAX_AGE = 8 * 60 * 60  # seconds

USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS app_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);
"""

_hasher = PasswordHasher()


class AuthError(RuntimeError):
    """Raised when authentication cannot be configured."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        _hasher.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


class AuthManager:
    def __init__(self, pool: asyncpg.Pool, secret_key: str) -> None:
        self._pool = pool
        self._serializer = URLSafeTimedSerializer(secret_key, salt="patch-tracker-session")

    async def init(self, bootstrap_user: str = "", bootstrap_password: str = "") -> None:
        """Create the users table and, on an empty install, the first account.

        The bootstrap credentials come from the environment and are only used when
        no account exists yet; changing them later does not silently reset a
        password someone has already rotated.
        """
        await self._pool.execute(USERS_TABLE_SQL)
        count = await self._pool.fetchval("SELECT COUNT(*) FROM app_users")
        if count:
            return
        if not bootstrap_user or not bootstrap_password:
            logger.warning("auth_no_bootstrap_user")
            return
        if len(bootstrap_password) < 12:
            raise AuthError("ADMIN_PASSWORD must be at least 12 characters")
        await self._pool.execute(
            "INSERT INTO app_users (username, password_hash) VALUES ($1, $2)",
            bootstrap_user,
            hash_password(bootstrap_password),
        )
        logger.info("auth_bootstrap_user_created", username=bootstrap_user)

    async def authenticate(self, username: str, password: str) -> Optional[str]:
        row = await self._pool.fetchrow(
            "SELECT username, password_hash FROM app_users WHERE username = $1", username
        )
        if row is None:
            # Hash anyway so a missing user and a wrong password take the same time.
            _hasher.hash(password)
            return None
        if not verify_password(row["password_hash"], password):
            return None
        await self._pool.execute(
            "UPDATE app_users SET last_login = NOW() WHERE username = $1", username
        )
        return row["username"]

    async def set_password(self, username: str, password: str) -> None:
        if len(password) < 12:
            raise AuthError("password must be at least 12 characters")
        await self._pool.execute(
            "UPDATE app_users SET password_hash = $1 WHERE username = $2",
            hash_password(password),
            username,
        )

    def issue_session(self, username: str) -> str:
        return self._serializer.dumps({"u": username})

    def read_session(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            return self._serializer.loads(token, max_age=SESSION_MAX_AGE)
        except (BadSignature, SignatureExpired):
            return None
