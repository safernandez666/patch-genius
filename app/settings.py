"""Configuración mínima de la demo — solo lo que usan las rutas de vulnerabilidades."""

from __future__ import annotations

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.environ.get("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    postgres_host: str = Field(default="postgres")
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_user: str = Field(default="vulndemo")
    postgres_password: str = Field(default="vulndemo")
    postgres_db: str = Field(default="vulndemo")
    postgres_dsn_override: str = Field(default="")

    # Mismos defaults que el sistema del que se extrajo esta pantalla —
    # ver la fórmula en app/scoring.py:priority_score.
    vuln_cvss_weight: float = Field(default=5.0)
    vuln_epss_weight: float = Field(default=30.0)
    vuln_kev_weight: float = Field(default=20.0)
    vuln_epss_high_threshold: float = Field(default=0.5)
    vuln_priority_critical_threshold: float = Field(default=80.0)
    vuln_sla_critical_days: int = Field(default=15)

    # Fernet key protecting the Wazuh credentials stored in app_config. Generated
    # on first start and written to .env when absent; rotating it makes the stored
    # password unreadable and it has to be re-entered in the Configuration tab.
    app_secret_key: str = Field(default="")

    # Bootstrap account, used only while app_users is empty.
    admin_user: str = Field(default="admin")
    admin_password: str = Field(default="")

    # Origins allowed to call the API. "*" is only tolerable while the data is
    # synthetic; a Wazuh-backed deployment must name its real origin.
    cors_origins: str = Field(default="")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def postgres_dsn(self) -> str:
        if self.postgres_dsn_override:
            return self.postgres_dsn_override
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
