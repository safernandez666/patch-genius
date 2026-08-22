"""Runtime configuration for the Wazuh connection, stored encrypted in Postgres.

Connection settings are entered through the Configuration tab rather than baked
into the image, because this repo is public and every deployment points at a
different Wazuh. Secrets are encrypted at rest with Fernet; the key lives in
APP_SECRET_KEY and never touches the database or the repository.

There is no demo or sample mode: the dashboard shows what the configured Wazuh
reports, or nothing at all.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import asyncpg
import structlog
from cryptography.fernet import Fernet, InvalidToken

logger = structlog.get_logger(__name__)

CONFIG_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS app_config (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    indexer_url TEXT NOT NULL DEFAULT '',
    indexer_user TEXT NOT NULL DEFAULT '',
    indexer_password_enc BYTEA,
    verify_tls BOOLEAN NOT NULL DEFAULT FALSE,
    enrich_epss BOOLEAN NOT NULL DEFAULT TRUE,
    enrich_kev BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_minutes INTEGER NOT NULL DEFAULT 60,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by TEXT NOT NULL DEFAULT '',
    CHECK (id = 1)
);
"""

DEFAULTS: Dict[str, Any] = {
    "indexer_url": "",
    "indexer_user": "",
    "verify_tls": False,
    "enrich_epss": True,
    "enrich_kev": True,
    "refresh_minutes": 60,
}


class ConfigError(RuntimeError):
    """Raised when configuration cannot be read, written or decrypted."""


class ConfigStore:
    def __init__(self, pool: asyncpg.Pool, secret_key: str) -> None:
        self._pool = pool
        try:
            self._fernet = Fernet(
                secret_key.encode() if isinstance(secret_key, str) else secret_key
            )
        except (ValueError, TypeError) as exc:
            raise ConfigError(
                "APP_SECRET_KEY is not a valid Fernet key. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc

    async def init(self) -> None:
        await self._pool.execute(CONFIG_TABLE_SQL)
        await self._pool.execute(
            "INSERT INTO app_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
        )

    async def load(self) -> Dict[str, Any]:
        """Config with the password decrypted. Never send this to the browser."""
        row = await self._pool.fetchrow("SELECT * FROM app_config WHERE id = 1")
        if row is None:
            return {**DEFAULTS, "indexer_password": ""}
        cfg = {k: row[k] for k in DEFAULTS}
        cfg["indexer_password"] = self._decrypt(row["indexer_password_enc"])
        cfg["updated_at"] = row["updated_at"]
        cfg["updated_by"] = row["updated_by"]
        return cfg

    async def load_public(self) -> Dict[str, Any]:
        """Config safe to render in the UI: the password is replaced by a flag."""
        cfg = await self.load()
        password = cfg.pop("indexer_password", "")
        cfg["has_password"] = bool(password)
        return cfg

    async def save(self, updates: Dict[str, Any], updated_by: str) -> Dict[str, Any]:
        current = await self.load()

        refresh = int(updates.get("refresh_minutes", current["refresh_minutes"]))
        if not 5 <= refresh <= 1440:
            raise ConfigError("refresh_minutes must be between 5 and 1440")

        # An omitted password means "keep the stored one" — the UI never receives the
        # current value, so it cannot echo it back on save.
        password = updates.get("indexer_password")
        enc = self._encrypt(password) if password else self._encrypt(current["indexer_password"])

        await self._pool.execute(
            """
            UPDATE app_config SET
                indexer_url = $1, indexer_user = $2,
                indexer_password_enc = $3, verify_tls = $4, enrich_epss = $5,
                enrich_kev = $6, refresh_minutes = $7, updated_at = NOW(), updated_by = $8
            WHERE id = 1
            """,
            (updates.get("indexer_url", current["indexer_url"]) or "").strip().rstrip("/"),
            (updates.get("indexer_user", current["indexer_user"]) or "").strip(),
            enc,
            bool(updates.get("verify_tls", current["verify_tls"])),
            bool(updates.get("enrich_epss", current["enrich_epss"])),
            bool(updates.get("enrich_kev", current["enrich_kev"])),
            refresh,
            updated_by,
        )
        logger.info("app_config_updated", by=updated_by)
        return await self.load_public()

    def _encrypt(self, value: str) -> Optional[bytes]:
        return self._fernet.encrypt(value.encode()) if value else None

    def _decrypt(self, blob: Optional[bytes]) -> str:
        if not blob:
            return ""
        try:
            return self._fernet.decrypt(bytes(blob)).decode()
        except InvalidToken:
            # Almost always a rotated or lost APP_SECRET_KEY. Surface it as "no
            # password configured" so the app still starts and the operator can
            # re-enter it, rather than crash-looping on every request.
            logger.error("app_config_decrypt_failed")
            return ""
