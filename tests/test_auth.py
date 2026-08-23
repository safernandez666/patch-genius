"""Unit tests for authentication and role checks."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from app.auth import AuthManager, hash_password, verify_password
from app.main import require_admin, require_user


class MockRecord:
    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


class MockPool:
    """Minimal asyncpg.Pool stand-in for AuthManager tests."""

    def __init__(self, users: Optional[List[Dict[str, Any]]] = None) -> None:
        self._users = {u["username"]: u for u in (users or [])}
        self.executed: List[str] = []

    async def execute(self, query: str, *args: Any) -> str:
        self.executed.append(query)
        if "INSERT INTO app_users" in query:
            self._users[args[0]] = {
                "username": args[0],
                "password_hash": args[1],
                "role": args[2] if len(args) > 2 else "admin",
            }
        elif "UPDATE app_users SET last_login" in query:
            pass
        return "INSERT 0 1"

    async def fetchval(self, query: str, *args: Any) -> Any:
        if "SELECT COUNT(*) FROM app_users" in query:
            return len(self._users)
        if "SELECT 1 FROM app_users LIMIT 1" in query:
            return 1 if self._users else None
        return None

    async def fetchrow(self, query: str, *args: Any) -> Optional[MockRecord]:
        if "SELECT username, password_hash FROM app_users" in query:
            user = self._users.get(args[0])
            if user is None:
                return None
            return MockRecord(
                {"username": user["username"], "password_hash": user["password_hash"]}
            )
        if "SELECT username, role FROM app_users" in query:
            user = self._users.get(args[0])
            if user is None:
                return None
            return MockRecord({"username": user["username"], "role": user.get("role", "admin")})
        return None


class MockCookies:
    def __init__(self, token: Optional[str] = None) -> None:
        self._token = token

    def get(self, name: str) -> Optional[str]:
        if name == "patch_tracker_session":
            return self._token
        return None


class MockRequest:
    def __init__(self, username: Optional[str] = None, role: str = "admin") -> None:
        self.app = MockApp(username, role)
        token = self.app.state.auth.issue_session(username) if username else None
        self.cookies = MockCookies(token)


class MockApp:
    def __init__(self, username: Optional[str] = None, role: str = "admin") -> None:
        pool = MockPool(
            [{"username": username, "password_hash": hash_password("secret123456"), "role": role}]
            if username
            else []
        )
        self.state = MockState(pool)


class MockState:
    def __init__(self, pool: MockPool) -> None:
        self.auth = AuthManager(pool, "a" * 32 + "b" * 12)


def _run(coro):
    return asyncio.run(coro)


def test_require_user_rejects_anonymous():
    req = MockRequest(None)
    with pytest.raises(Exception) as exc:
        _run(require_user(req))
    assert exc.value.status_code == 401


def test_require_user_returns_username():
    req = MockRequest("alice")
    assert _run(require_user(req)) == "alice"


def test_require_admin_rejects_non_admin():
    req = MockRequest("bob", role="readonly")
    with pytest.raises(Exception) as exc:
        _run(require_admin(req))
    assert exc.value.status_code == 403


def test_require_admin_accepts_admin():
    req = MockRequest("alice", role="admin")
    assert _run(require_admin(req)) == "alice"


def test_hash_and_verify_roundtrip():
    h = hash_password("my-long-password-123")
    assert verify_password(h, "my-long-password-123") is True
    assert verify_password(h, "wrong-password") is False


def test_authenticate_success():
    pool = MockPool(
        [{"username": "alice", "password_hash": hash_password("secret123456"), "role": "admin"}]
    )
    auth = AuthManager(pool, "x" * 44)
    assert _run(auth.authenticate("alice", "secret123456")) == "alice"


def test_authenticate_wrong_password():
    pool = MockPool(
        [{"username": "alice", "password_hash": hash_password("secret123456"), "role": "admin"}]
    )
    auth = AuthManager(pool, "x" * 44)
    assert _run(auth.authenticate("alice", "wrong")) is None


def test_is_admin():
    pool = MockPool(
        [
            {"username": "alice", "password_hash": hash_password("secret123456"), "role": "admin"},
            {"username": "bob", "password_hash": hash_password("secret123456"), "role": "readonly"},
        ]
    )
    auth = AuthManager(pool, "x" * 44)
    assert _run(auth.is_admin("alice")) is True
    assert _run(auth.is_admin("bob")) is False
    assert _run(auth.is_admin("unknown")) is False


def test_bootstrap_user_is_admin():
    pool = MockPool([])
    auth = AuthManager(pool, "x" * 44)
    _run(auth.init("admin", "bootstrap-password-1234"))
    assert _run(auth.is_admin("admin")) is True
