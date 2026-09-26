"""#17 — the public send_email() seam for app-specific mail.

Before this, the only way for an app to send anything other than a password
reset or a verification email was the private `_dispatch`. dyner.z's friend
invites (dyner.z#358) are the first caller.

The contract is the one the two fixed senders already honour, and the tests pin
each clause of it rather than just the happy path, because the failure mode this
package exists to stop repeating is mail that silently doesn't go.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from users.email_service import EmailConfig, EmailService


def _config(**overrides):
    base = dict(
        provider="resend",
        sender_email="noreply@dynerz.net",
        sender_name="dyner.z",
        enabled=True,
        api_key="re_test_key",
    )
    base.update(overrides)
    return EmailConfig(**base)


def _patch_httpx(status_code=200, raises=None):
    response = MagicMock(status_code=status_code, text="")
    response.json.return_value = {"id": "msg_1"}
    post = AsyncMock(side_effect=raises) if raises else AsyncMock(return_value=response)
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=MagicMock(post=post))
    client.__aexit__ = AsyncMock(return_value=False)
    module = MagicMock()
    module.AsyncClient = MagicMock(return_value=client)
    return patch.dict("sys.modules", {"httpx": module}), post


@pytest.mark.asyncio
async def test_sends_the_callers_subject_and_bodies():
    ctx, post = _patch_httpx()
    with ctx:
        ok = await EmailService(_config()).send_email(
            "friend@example.com", "You're invited", "plain body", "<p>html body</p>"
        )

    assert ok is True
    body = post.call_args.kwargs["json"]
    assert body["to"] == ["friend@example.com"]
    assert body["subject"] == "You're invited"
    assert body["text"] == "plain body"
    assert body["html"] == "<p>html body</p>"


@pytest.mark.asyncio
async def test_html_is_optional_and_falls_back_to_escaped_text():
    ctx, post = _patch_httpx()
    with ctx:
        ok = await EmailService(_config()).send_email("a@example.com", "s", "a < b\nline 2")

    assert ok is True
    html = post.call_args.kwargs["json"]["html"]
    # The text is escaped, never interpolated as markup.
    assert "a &lt; b" in html and "<br>" in html


@pytest.mark.asyncio
async def test_disabled_is_a_noop_that_reports_success_and_never_logs_the_body(caplog):
    """enabled=False must behave like the fixed senders. The body is NOT logged:
    for an app message it can hold a single-use link (dyner.z invites do)."""
    ctx, post = _patch_httpx()
    with ctx, caplog.at_level(logging.INFO):
        ok = await EmailService(_config(enabled=False)).send_email(
            "a@example.com", "Subject", "secret-token-in-body"
        )

    assert ok is True
    post.assert_not_called()
    assert "secret-token-in-body" not in caplog.text


@pytest.mark.asyncio
async def test_unconfigured_fails_loudly_before_any_request(caplog):
    ctx, post = _patch_httpx()
    with ctx, caplog.at_level(logging.ERROR):
        ok = await EmailService(_config(api_key=None)).send_email("a@example.com", "s", "b")

    assert ok is False
    post.assert_not_called()
    assert "Resend API key not configured" in caplog.text


@pytest.mark.asyncio
async def test_provider_failure_is_non_fatal():
    ctx, _ = _patch_httpx(raises=OSError("connection timed out"))
    with ctx:
        assert await EmailService(_config()).send_email("a@example.com", "s", "b") is False
