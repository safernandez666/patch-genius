"""Outbound integrations: SMTP, Jira, Slack and Microsoft Teams.

All four are optional and disabled by default. Each one carries exactly one
secret — an SMTP password, a Jira API token, or a webhook URL — and those are
stored encrypted by ConfigStore, never in the repository.

A webhook URL is itself a credential: anyone holding it can post into the
channel, so Slack and Teams treat theirs the same way as a password.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Dict

import httpx
import structlog

logger = structlog.get_logger(__name__)

TIMEOUT = 20.0


class NotifyError(RuntimeError):
    """Raised when an integration is misconfigured or the remote rejects us."""


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------
def send_email(cfg: Dict[str, Any], to: str, subject: str, body: str) -> None:
    """Send one message. Blocking — call it from a thread, not the event loop."""
    s = cfg.get("settings") or {}
    host, port = s.get("host", ""), int(s.get("port") or 587)
    if not host:
        raise NotifyError("SMTP host is not configured")

    msg = EmailMessage()
    msg["From"] = s.get("from_addr") or s.get("username") or "patch-genius@localhost"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if s.get("use_ssl"):
            server = smtplib.SMTP_SSL(
                host, port, timeout=TIMEOUT, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        with server:
            if not s.get("use_ssl") and s.get("use_tls", True):
                server.starttls(context=ssl.create_default_context())
            if s.get("username"):
                server.login(s["username"], cfg.get("secret") or "")
            server.send_message(msg)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise NotifyError(f"SMTP failed: {exc}") from exc
    logger.info("email_sent", to=to)


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------
async def jira_ping(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Verify credentials without creating anything."""
    s = cfg.get("settings") or {}
    base = (s.get("url") or "").rstrip("/")
    if not base:
        raise NotifyError("Jira URL is not configured")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"{base}/rest/api/3/myself", auth=(s.get("email", ""), cfg.get("secret") or "")
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NotifyError(f"Jira returned {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise NotifyError(f"cannot reach Jira: {exc}") from exc
    d = r.json()
    return {"account": d.get("displayName") or d.get("emailAddress") or "ok"}


# ---------------------------------------------------------------------------
# Slack / Microsoft Teams
# ---------------------------------------------------------------------------
async def post_webhook(cfg: Dict[str, Any], text: str, kind: str) -> None:
    """Post a message to an incoming webhook.

    Slack and Teams differ only in the JSON envelope, so they share a path.
    """
    url = cfg.get("secret") or ""
    if not url:
        raise NotifyError(f"{kind} webhook URL is not configured")
    payload = (
        {"text": text}
        if kind == "slack"
        else {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Patch Genius",
            "themeColor": "FF5722",
            "text": text,
        }
    )
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise NotifyError(f"{kind} returned {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise NotifyError(f"cannot reach {kind}: {exc}") from exc
    logger.info("webhook_posted", kind=kind)
