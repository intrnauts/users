"""#15 — the Resend HTTPS provider, and proof the dedup didn't change SES/SMTP.

SMTP is blocked outbound on the VPS these projects run on, and SES means an AWS
account this estate no longer has. Resend is the only transport that reaches the
outside world.

Half of these tests are about the *other* two providers: adding a third provider
meant collapsing four duplicated dispatch blocks into one, and a refactor of a
path nobody can exercise locally (SES needs AWS, SMTP is firewalled) is exactly
where a silent regression would hide.
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


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"id": "msg_123"}
        self.text = text

    def json(self):
        if self._payload is _Unparseable:
            raise ValueError("no json")
        return self._payload


class _Unparseable:
    pass


def _patch_httpx(response=None, raises=None):
    """Patch httpx.AsyncClient as the service imports it (lazily, inside the method)."""
    post = AsyncMock(side_effect=raises) if raises else AsyncMock(return_value=response or _Response())
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=MagicMock(post=post))
    client.__aexit__ = AsyncMock(return_value=False)
    module = MagicMock()
    module.AsyncClient = MagicMock(return_value=client)
    return patch.dict("sys.modules", {"httpx": module}), post


@pytest.mark.asyncio
async def test_password_reset_sends_via_resend_with_expected_payload():
    ctx, post = _patch_httpx()
    with ctx:
        svc = EmailService(_config())
        ok = await svc.send_password_reset_email(
            "user@example.com", "tok123", "https://dynerz.net/reset?token={token}"
        )

    assert ok is True
    (url,), kwargs = post.call_args
    assert url == "https://api.resend.com/emails"
    assert kwargs["headers"]["Authorization"] == "Bearer re_test_key"

    body = kwargs["json"]
    assert body["from"] == "dyner.z <noreply@dynerz.net>"
    assert body["to"] == ["user@example.com"]
    # The token must reach the user as a usable link, not as a raw token.
    assert "https://dynerz.net/reset?token=tok123" in body["html"]
    assert "https://dynerz.net/reset?token=tok123" in body["text"]


@pytest.mark.asyncio
async def test_verification_email_sends_via_resend():
    ctx, post = _patch_httpx()
    with ctx:
        svc = EmailService(_config())
        ok = await svc.send_verification_email(
            "user@example.com", "vtok", "https://dynerz.net/verify?token={token}"
        )

    assert ok is True
    assert "https://dynerz.net/verify?token=vtok" in post.call_args.kwargs["json"]["html"]


@pytest.mark.asyncio
async def test_api_error_is_non_fatal_and_logs_the_body(caplog):
    """A 4xx must return False, never raise — and must log the body, which carries
    the actual reason (unverified domain, bad key, rate limit)."""
    ctx, _ = _patch_httpx(_Response(status_code=403, text="domain not verified"))
    with ctx, caplog.at_level(logging.ERROR):
        svc = EmailService(_config())
        ok = await svc.send_password_reset_email("user@example.com", "tok")

    assert ok is False
    assert "403" in caplog.text and "domain not verified" in caplog.text


@pytest.mark.asyncio
async def test_network_failure_is_non_fatal(caplog):
    """The blocked-SMTP failure surfaced as an exception mid-request. Whatever the
    transport, an unreachable provider must not propagate out of the send."""
    ctx, _ = _patch_httpx(raises=OSError("connection timed out"))
    with ctx, caplog.at_level(logging.ERROR):
        svc = EmailService(_config())
        ok = await svc.send_password_reset_email("user@example.com", "tok")

    assert ok is False
    assert "connection timed out" in caplog.text


@pytest.mark.asyncio
async def test_success_with_unparseable_body_still_counts_as_sent():
    ctx, _ = _patch_httpx(_Response(status_code=200, payload=_Unparseable))
    with ctx:
        svc = EmailService(_config())
        assert await svc.send_password_reset_email("user@example.com", "tok") is True


@pytest.mark.asyncio
async def test_missing_api_key_fails_before_any_request():
    ctx, post = _patch_httpx()
    with ctx:
        svc = EmailService(_config(api_key=None))
        assert await svc.send_password_reset_email("user@example.com", "tok") is False
    post.assert_not_called()


@pytest.mark.asyncio
async def test_disabled_service_short_circuits_without_sending():
    """enabled=False is how prod runs today; it must stay a no-op that reports success."""
    ctx, post = _patch_httpx()
    with ctx:
        svc = EmailService(_config(enabled=False))
        assert await svc.send_password_reset_email("user@example.com", "tok") is True
    post.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_provider_is_rejected():
    svc = EmailService(_config(provider="carrier-pigeon"))
    assert await svc.send_password_reset_email("user@example.com", "tok") is False


# --- the dedup must not have changed SES or SMTP -------------------------------

@pytest.mark.asyncio
async def test_ses_still_dispatches_after_the_dedup():
    svc = EmailService(_config(provider="ses", api_key=None))
    svc._ses_client = MagicMock()  # as if boto3 had initialised
    with patch.object(svc, "_send_via_ses", return_value=True) as sender:
        assert await svc.send_password_reset_email("user@example.com", "tok") is True
    sender.assert_called_once()


@pytest.mark.asyncio
async def test_smtp_still_dispatches_after_the_dedup():
    svc = EmailService(_config(provider="smtp", api_key=None,
                               smtp_username="u", smtp_password="p"))
    with patch.object(svc, "_send_via_smtp", return_value=True) as sender:
        assert await svc.send_verification_email("user@example.com", "tok") is True
    sender.assert_called_once()


@pytest.mark.asyncio
async def test_ses_without_a_client_still_refuses_to_send():
    svc = EmailService(_config(provider="ses", api_key=None))
    svc._ses_client = None
    with patch.object(svc, "_send_via_ses") as sender:
        assert await svc.send_password_reset_email("user@example.com", "tok") is False
    sender.assert_not_called()
