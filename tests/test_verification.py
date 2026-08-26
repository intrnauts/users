import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException

from users import email_service as email_service_module
from users import verification as verification_module
from users.models import (
    EmailVerificationToken, PasswordResetToken, UserCreate, UserLogin,
    UserRegister, UserSelfUpdate, UserStatus,
    EmailVerificationConfirm, EmailVerificationResend,
    PasswordResetRequest, PasswordResetConfirm
)
from users.verification import VerificationConfig, configure_verification, hash_token

class FakeEmailService:
    """Captures the tokens that would have been emailed."""

    def __init__(self):
        self.verification_emails = []
        self.reset_emails = []

    async def send_verification_email(self, recipient_email, verification_token, verification_url_template=None):
        self.verification_emails.append((recipient_email, verification_token, verification_url_template))
        return True

    async def send_password_reset_email(self, recipient_email, reset_token, reset_url_template=None):
        self.reset_emails.append((recipient_email, reset_token, reset_url_template))
        return True

    @property
    def last_verification_token(self):
        return self.verification_emails[-1][1]

    @property
    def last_reset_token(self):
        return self.reset_emails[-1][1]

@pytest.fixture
def fake_email(monkeypatch):
    """Install a fake email service in place of the configured one."""
    service = FakeEmailService()
    monkeypatch.setattr(email_service_module, "_email_service", service)
    return service

@pytest.fixture(autouse=True)
def reset_verification_config(monkeypatch):
    """Keep the global verification policy at defaults unless a test sets it."""
    monkeypatch.setattr(verification_module, "_verification_config", None)

@pytest.fixture
def register_data():
    return UserCreate(
        email="newuser@example.com",
        username="newuser",
        password="test_password_123"
    )

@pytest.mark.asyncio
class TestRegistrationSendsVerification:
    async def test_register_emails_a_verification_token(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)

        assert len(fake_email.verification_emails) == 1
        recipient, token, _ = fake_email.verification_emails[0]
        assert recipient == register_data.email
        assert token

    async def test_new_user_starts_unverified(self, user_service, register_data, fake_email):
        user = await user_service.create_user(register_data)

        assert user.is_verified is False
        assert user.status == UserStatus.PENDING

    async def test_only_the_digest_is_stored(self, user_service, register_data, fake_email, db_session):
        await user_service.create_user(register_data)
        raw_token = fake_email.last_verification_token

        stored = db_session.query(EmailVerificationToken).all()
        assert len(stored) == 1
        assert stored[0].token != raw_token
        assert stored[0].token == hash_token(raw_token)

    async def test_registration_survives_a_broken_email_service(self, user_service, register_data):
        # No email service configured at all - get_email_service() raises.
        user = await user_service.create_user(register_data)

        assert user.id > 0

    async def test_registration_survives_a_failing_token_write(self, user_service, user_repository, register_data, fake_email, monkeypatch):
        async def boom(*args, **kwargs):
            raise RuntimeError("database is down")

        monkeypatch.setattr(user_repository, "create_email_verification_token", boom)

        user = await user_service.create_user(register_data)

        assert user.id > 0
        assert fake_email.verification_emails == []

    async def test_can_be_disabled(self, user_service, register_data, fake_email):
        configure_verification(VerificationConfig(send_verification_on_register=False))

        await user_service.create_user(register_data)

        assert fake_email.verification_emails == []

@pytest.mark.asyncio
class TestVerifyEmail:
    async def test_verifies_and_activates(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)

        verified = await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )

        assert verified.is_verified is True
        assert verified.status == UserStatus.ACTIVE

    async def test_respects_auto_activate_disabled(self, user_service, register_data, fake_email):
        configure_verification(VerificationConfig(auto_activate_on_verify=False))
        await user_service.create_user(register_data)

        verified = await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )

        assert verified.is_verified is True
        assert verified.status == UserStatus.PENDING

    async def test_does_not_downgrade_an_inactive_user(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="suspended@example.com",
            username="suspended",
            password="test_password_123",
            status=UserStatus.SUSPENDED
        ))

        verified = await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )

        # Only a PENDING signup gets promoted; a suspended account stays put.
        assert verified.is_verified is True
        assert verified.status == UserStatus.SUSPENDED

    async def test_rejects_unknown_token(self, user_service):
        with pytest.raises(HTTPException) as exc_info:
            await user_service.verify_email(EmailVerificationConfirm(token="not-a-real-token"))

        assert exc_info.value.status_code == 400
        assert "Invalid or expired" in str(exc_info.value.detail)

    async def test_token_cannot_be_replayed(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)
        token = fake_email.last_verification_token

        await user_service.verify_email(EmailVerificationConfirm(token=token))

        with pytest.raises(HTTPException) as exc_info:
            await user_service.verify_email(EmailVerificationConfirm(token=token))

        assert exc_info.value.status_code == 400

    async def test_rejects_expired_token(self, user_service, user_repository, register_data, fake_email):
        user = await user_service.create_user(register_data)

        expired_raw = "expired-token-value"
        await user_repository.delete_user_verification_tokens(user.id)
        await user_repository.create_email_verification_token(
            user_id=user.id,
            token_hash=hash_token(expired_raw),
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )

        with pytest.raises(HTTPException) as exc_info:
            await user_service.verify_email(EmailVerificationConfirm(token=expired_raw))

        assert exc_info.value.status_code == 400
        assert "expired" in str(exc_info.value.detail).lower()

    async def test_issuing_a_new_token_invalidates_the_old_one(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)
        first_token = fake_email.last_verification_token

        await user_service.resend_verification_email(
            EmailVerificationResend(email=register_data.email)
        )
        second_token = fake_email.last_verification_token
        assert first_token != second_token

        with pytest.raises(HTTPException):
            await user_service.verify_email(EmailVerificationConfirm(token=first_token))

        verified = await user_service.verify_email(EmailVerificationConfirm(token=second_token))
        assert verified.is_verified is True

@pytest.mark.asyncio
class TestResendVerification:
    async def test_unknown_email_reports_success_without_sending(self, user_service, fake_email):
        result = await user_service.resend_verification_email(
            EmailVerificationResend(email="nobody@example.com")
        )

        # Silent success, so the endpoint cannot be used to enumerate accounts.
        assert result is True
        assert fake_email.verification_emails == []

    async def test_already_verified_user_gets_no_new_token(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)
        await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )
        sent_so_far = len(fake_email.verification_emails)

        await user_service.resend_verification_email(
            EmailVerificationResend(email=register_data.email)
        )

        assert len(fake_email.verification_emails) == sent_so_far

@pytest.mark.asyncio
class TestRequireVerifiedEmailOnLogin:
    async def test_unverified_user_is_refused_when_required(self, user_service, fake_email):
        configure_verification(VerificationConfig(require_verified_email=True))
        await user_service.create_user(UserCreate(
            email="unverified@example.com",
            username="unverified",
            password="test_password_123",
            status=UserStatus.ACTIVE
        ))

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(
                email="unverified@example.com",
                password="test_password_123"
            ))

        assert exc_info.value.status_code == 401
        assert "verify your email" in str(exc_info.value.detail).lower()

    async def test_login_works_after_verifying(self, user_service, fake_email):
        configure_verification(VerificationConfig(require_verified_email=True))
        await user_service.create_user(UserCreate(
            email="willverify@example.com",
            username="willverify",
            password="test_password_123"
        ))

        await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )
        token = await user_service.login(UserLogin(
            email="willverify@example.com",
            password="test_password_123"
        ))

        assert token.access_token

    async def test_pending_signup_is_told_to_verify_not_to_wait_for_an_admin(self, user_service, register_data, fake_email):
        # status defaults to PENDING, and a verification email was just sent.
        await user_service.create_user(register_data)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(
                email=register_data.email, password=register_data.password
            ))

        assert "verify your email" in str(exc_info.value.detail).lower()

    async def test_pending_user_awaits_admin_when_verification_is_off(self, user_service, register_data, fake_email):
        configure_verification(VerificationConfig(send_verification_on_register=False))
        await user_service.create_user(register_data)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(
                email=register_data.email, password=register_data.password
            ))

        assert "admin approval" in str(exc_info.value.detail).lower()

    async def test_verified_but_unapproved_user_awaits_admin(self, user_service, register_data, fake_email):
        configure_verification(VerificationConfig(auto_activate_on_verify=False))
        await user_service.create_user(register_data)
        await user_service.verify_email(
            EmailVerificationConfirm(token=fake_email.last_verification_token)
        )

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(
                email=register_data.email, password=register_data.password
            ))

        assert "admin approval" in str(exc_info.value.detail).lower()

    async def test_unverified_user_may_log_in_by_default(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="legacy@example.com",
            username="legacy",
            password="test_password_123",
            status=UserStatus.ACTIVE
        ))

        token = await user_service.login(UserLogin(
            email="legacy@example.com",
            password="test_password_123"
        ))

        assert token.access_token

@pytest.mark.asyncio
class TestPasswordResetHardening:
    async def test_only_the_digest_is_stored(self, user_service, register_data, fake_email, db_session):
        await user_service.create_user(register_data)

        await user_service.request_password_reset(
            PasswordResetRequest(email=register_data.email)
        )
        raw_token = fake_email.last_reset_token

        stored = db_session.query(PasswordResetToken).all()
        assert len(stored) == 1
        assert stored[0].token != raw_token
        assert stored[0].token == hash_token(raw_token)

    async def test_reset_actually_changes_the_password(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)
        await user_service.request_password_reset(
            PasswordResetRequest(email=register_data.email)
        )

        await user_service.confirm_password_reset(PasswordResetConfirm(
            token=fake_email.last_reset_token,
            new_password="brand_new_password_456"
        ))

        assert await user_service.authenticate_user(UserLogin(
            email=register_data.email, password="brand_new_password_456"
        )) is not None
        assert await user_service.authenticate_user(UserLogin(
            email=register_data.email, password=register_data.password
        )) is None

    async def test_reset_token_cannot_be_replayed(self, user_service, register_data, fake_email):
        await user_service.create_user(register_data)
        await user_service.request_password_reset(
            PasswordResetRequest(email=register_data.email)
        )
        token = fake_email.last_reset_token

        await user_service.confirm_password_reset(PasswordResetConfirm(
            token=token, new_password="brand_new_password_456"
        ))

        with pytest.raises(HTTPException) as exc_info:
            await user_service.confirm_password_reset(PasswordResetConfirm(
                token=token, new_password="another_password_789"
            ))

        assert exc_info.value.status_code == 400

    async def test_unknown_email_reports_success_without_sending(self, user_service, fake_email):
        result = await user_service.request_password_reset(
            PasswordResetRequest(email="nobody@example.com")
        )

        assert result is True
        assert fake_email.reset_emails == []

@pytest.mark.asyncio
class TestChangePasswordPersists:
    async def test_new_password_is_actually_saved(self, user_service, register_data, fake_email):
        """Regression: change_password used to route through UserUpdate, which
        has no password field, so the change was silently discarded."""
        user = await user_service.create_user(register_data)

        await user_service.change_password(
            user.id, register_data.password, "brand_new_password_456"
        )

        assert await user_service.authenticate_user(UserLogin(
            email=register_data.email, password="brand_new_password_456"
        )) is not None
        assert await user_service.authenticate_user(UserLogin(
            email=register_data.email, password=register_data.password
        )) is None

    async def test_wrong_current_password_is_rejected(self, user_service, register_data, fake_email):
        user = await user_service.create_user(register_data)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.change_password(
                user.id, "not_the_current_password", "brand_new_password_456"
            )

        assert exc_info.value.status_code == 400

class TestPrivilegedFieldsAreNotSelfServe:
    def test_register_payload_drops_privileged_fields(self):
        payload = UserRegister(
            email="attacker@example.com",
            password="test_password_123",
            **{"is_superuser": True, "status": "active", "roles": ["admin"]}
        )

        created = payload.to_user_create()
        assert created.is_superuser is False
        assert created.status == UserStatus.PENDING
        assert created.roles == []

    def test_self_update_has_no_privileged_fields(self):
        fields = set(UserSelfUpdate.model_fields)

        assert fields.isdisjoint({"status", "is_superuser", "is_verified", "roles"})

@pytest.mark.asyncio
class TestEmailCaseNormalization:
    """Addresses are stored and matched in one canonical lowercase form.

    Without this, PGSMOKE@example.com and pgsmoke@example.com are two accounts
    on PostgreSQL, and a reset request silently misses the one it did not match.
    """

    async def test_registration_stores_the_canonical_form(self, user_service, fake_email):
        user = await user_service.create_user(UserCreate(
            email="Mixed.Case@Example.COM",
            username="mixed",
            password="test_password_123"
        ))

        assert user.email == "mixed.case@example.com"

    async def test_surrounding_whitespace_is_stripped(self):
        assert UserRegister(
            email="  spaced@example.com  ", password="test_password_123"
        ).email == "spaced@example.com"

    async def test_a_different_case_is_the_same_account(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="Original@Example.com",
            username="original",
            password="test_password_123"
        ))

        found = await user_service.get_user_by_email("ORIGINAL@EXAMPLE.COM")

        assert found is not None
        assert found.email == "original@example.com"

    async def test_cannot_register_the_same_address_twice_in_another_case(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="dup@example.com", username="dup", password="test_password_123"
        ))

        with pytest.raises(HTTPException) as exc_info:
            await user_service.create_user(UserCreate(
                email="DUP@Example.COM", username="dup2", password="test_password_123"
            ))

        assert exc_info.value.status_code == 400
        assert "Email already registered" in str(exc_info.value.detail)

    async def test_login_accepts_any_case(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="Login.User@Example.com",
            username="loginuser",
            password="test_password_123",
            status=UserStatus.ACTIVE
        ))

        token = await user_service.login(UserLogin(
            email="LOGIN.USER@EXAMPLE.COM", password="test_password_123"
        ))

        assert token.access_token

    async def test_password_reset_finds_the_account_in_another_case(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="Reset.Me@Example.com", username="resetme", password="test_password_123"
        ))

        await user_service.request_password_reset(
            PasswordResetRequest(email="RESET.ME@EXAMPLE.COM")
        )

        # A miss would be silent - enumeration safety means no error either way.
        assert len(fake_email.reset_emails) == 1
        await user_service.confirm_password_reset(PasswordResetConfirm(
            token=fake_email.last_reset_token, new_password="brand_new_password_456"
        ))
        assert await user_service.authenticate_user(UserLogin(
            email="reset.me@example.com", password="brand_new_password_456"
        )) is not None

    async def test_resend_verification_finds_the_account_in_another_case(self, user_service, fake_email):
        await user_service.create_user(UserCreate(
            email="Verify.Me@Example.com", username="verifyme", password="test_password_123"
        ))
        sent_at_registration = len(fake_email.verification_emails)

        await user_service.resend_verification_email(
            EmailVerificationResend(email="VERIFY.ME@EXAMPLE.COM")
        )

        assert len(fake_email.verification_emails) == sent_at_registration + 1

    async def test_updating_to_a_mixed_case_address_stores_canonical(self, user_service, user_repository, fake_email):
        from users.models import UserUpdate

        user = await user_service.create_user(UserCreate(
            email="before@example.com", username="updater", password="test_password_123"
        ))

        updated = await user_service.update_user(
            user.id, UserUpdate(email="After@Example.COM")
        )

        assert updated.email == "after@example.com"

    async def test_repository_normalizes_a_hand_built_usercreate(self, user_repository, fake_email):
        # Bypasses the schema validator entirely, using model_construct.
        raw = UserCreate.model_construct(
            email="Bypass@Example.COM", username="bypass",
            password="hashed", status=UserStatus.ACTIVE, is_superuser=False, roles=[]
        )

        created = await user_repository.create_user(raw)

        assert created.email == "bypass@example.com"
