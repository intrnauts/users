"""Email links per scope (#70): a URL template that's a path gets the base URL
of the account's scope in front. Absolute templates work as before."""

import logging

import pytest

from users import email_service as email_service_module
from users import scope as scope_module
from users import verification as verification_module
from users.models import (
    AccountDeletionRequest, AccountDeletionTokenAction, EmailChangeRequest,
    EmailChangeTokenAction, EmailVerificationResend, PasswordResetRequest, UserCreate
)
from users.scope import configure_scope, scoped_template
from users.verification import VerificationConfig, configure_verification

PASSWORD = "test_password_123"
EMAIL = "test@example.com"


class LinkRecorder:
    """Builds links the way EmailService does, and keeps every send."""

    def __init__(self):
        self.sent = []

    async def send_verification_email(self, recipient_email, verification_token, verification_url_template=None):
        link = verification_url_template.format(token=verification_token) if verification_url_template else verification_token
        self.sent.append(("verify", recipient_email, link))
        return True

    async def send_password_reset_email(self, recipient_email, reset_token, reset_url_template=None):
        link = reset_url_template.format(token=reset_token) if reset_url_template else reset_token
        self.sent.append(("reset", recipient_email, link))
        return True

    async def send_email_change_confirmation(self, recipient_email, confirm_link, ttl_hours):
        self.sent.append(("change-confirm", recipient_email, confirm_link))
        return True

    async def send_email_change_requested_notice(self, recipient_email, new_email, cancel_link):
        self.sent.append(("change-cancel", recipient_email, cancel_link))
        return True

    async def send_email_change_completed_notice(self, recipient_email, new_email, revert_link, ttl_days):
        self.sent.append(("change-revert", recipient_email, revert_link))
        return True

    async def send_account_deletion_requested(self, recipient_email, confirm_link, keep_link, purge_at):
        self.sent.append(("delete-confirm", recipient_email, confirm_link))
        self.sent.append(("delete-keep", recipient_email, keep_link))
        return True

    async def send_account_deletion_confirmed(self, recipient_email, restore_link, purge_at):
        self.sent.append(("delete-restore", recipient_email, restore_link))
        return True

    def links(self, kind):
        return [link for sent, _, link in self.sent if sent == kind]

    def token(self, kind):
        return self.links(kind)[-1].split("token=")[1]


@pytest.fixture(autouse=True)
def isolate_globals(monkeypatch):
    monkeypatch.setattr(verification_module, "_verification_config", None)
    monkeypatch.setattr(scope_module, "_enabled", False)
    monkeypatch.setattr(scope_module, "_request_scope", None)
    monkeypatch.setattr(scope_module, "_base_url", None)


@pytest.fixture
def emails(monkeypatch):
    recorder = LinkRecorder()
    monkeypatch.setattr(email_service_module, "_email_service", recorder)
    return recorder


def per_tenant(scope):
    return f"https://{scope}.example.com" if scope else "https://example.com"


def paths(**overrides):
    fields = dict(
        verification_url_template="/verify?token={token}",
        email_change_url_template="/email/{action}?token={token}",
        account_deletion_url_template="/delete/{action}?token={token}",
        allow_email_change=True,
        allow_self_delete=True,
    )
    fields.update(overrides)
    return VerificationConfig(**fields)


@pytest.mark.asyncio
class TestScopedLinks:

    @pytest.fixture(autouse=True)
    def scopes_with_base_url(self):
        configure_scope(enabled=True, base_url=per_tenant)

    async def test_verification_link_uses_the_accounts_scope(self, user_service, emails):
        configure_verification(paths())

        await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD, scope="acme"))
        await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD))

        acme, default = emails.links("verify")
        assert acme.startswith("https://acme.example.com/verify?token=")
        assert default.startswith("https://example.com/verify?token=")

    async def test_resend_uses_it_too(self, user_service, create_test_user, emails):
        configure_verification(paths(send_verification_on_register=False))
        await create_test_user(email=EMAIL, scope="acme")

        await user_service.resend_verification_email(
            EmailVerificationResend(email=EMAIL, scope="acme"),
            verification_url_template="/verify-again?token={token}"
        )

        assert emails.links("verify")[0].startswith("https://acme.example.com/verify-again?token=")

    async def test_password_reset_link(self, user_service, create_test_user, emails):
        await create_test_user(email=EMAIL, scope="acme", status="active")

        await user_service.request_password_reset(
            PasswordResetRequest(email=EMAIL, scope="acme"), reset_url_template="/reset?token={token}"
        )

        assert emails.links("reset")[0].startswith("https://acme.example.com/reset?token=")

    async def test_email_change_links(self, user_service, create_test_user, emails):
        configure_verification(paths(send_verification_on_register=False))
        user = await create_test_user(email=EMAIL, scope="acme", status="active")

        await user_service.request_email_change(
            user.id, EmailChangeRequest(current_password=PASSWORD, new_email="new@example.com")
        )
        await user_service.confirm_email_change(
            EmailChangeTokenAction(token=emails.token("change-confirm"))
        )

        for kind, action in [("change-confirm", "confirm"), ("change-cancel", "cancel"), ("change-revert", "revert")]:
            assert emails.links(kind)[0].startswith(f"https://acme.example.com/email/{action}?token=")

    async def test_account_deletion_links(self, user_service, create_test_user, emails):
        configure_verification(paths(send_verification_on_register=False))
        user = await create_test_user(email=EMAIL, scope="acme", status="active")

        await user_service.request_account_deletion(user.id, AccountDeletionRequest(current_password=PASSWORD))
        await user_service.confirm_account_deletion(
            AccountDeletionTokenAction(token=emails.token("delete-confirm"))
        )

        for kind, action in [("delete-confirm", "confirm"), ("delete-keep", "keep"), ("delete-restore", "restore")]:
            assert emails.links(kind)[0].startswith(f"https://acme.example.com/delete/{action}?token=")

    async def test_an_absolute_template_is_used_as_it_is(self, user_service, emails):
        configure_verification(paths(verification_url_template="https://fixed.example.com/v?token={token}"))

        await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD, scope="acme"))

        assert emails.links("verify")[0].startswith("https://fixed.example.com/v?token=")

    async def test_the_function_may_be_a_coroutine_and_braces_stay_literal(self):
        async def base_url(scope):
            return "https://x.example.com/{odd}/"
        configure_scope(enabled=True, base_url=base_url)

        template = await scoped_template("/v?token={token}", "acme")

        assert template.format(token="T") == "https://x.example.com/{odd}/v?token=T"


@pytest.mark.asyncio
class TestNoBaseUrl:

    async def test_absolute_templates_work_as_before(self, user_service, emails):
        configure_verification(VerificationConfig(verification_url_template="https://app.example.com/v?token={token}"))

        await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD))

        assert emails.links("verify")[0].startswith("https://app.example.com/v?token=")

    async def test_a_path_template_without_a_base_url_sends_nothing_and_logs(
        self, user_service, db_session, emails, caplog
    ):
        configure_verification(paths())

        with caplog.at_level(logging.ERROR):
            user = await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD))

        # Registration still succeeds; the email isn't sent and no token is issued
        assert user.id
        assert emails.sent == []
        assert "configure_scope(base_url=...)" in caplog.text
        from users.models import EmailVerificationToken
        assert db_session.query(EmailVerificationToken).count() == 0

    async def test_a_scope_whose_base_url_is_none_sends_nothing(self, user_service, emails):
        configure_scope(enabled=True, base_url=lambda scope: None)
        configure_verification(paths())

        await user_service.create_user(UserCreate(email=EMAIL, password=PASSWORD, scope="acme"))

        assert emails.sent == []

    async def test_a_base_url_function_needs_scopes_on(self):
        with pytest.raises(ValueError):
            configure_scope(enabled=False, base_url=per_tenant)
