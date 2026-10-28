"""Email change (#41): storage and configuration."""

from datetime import datetime, timedelta

import pytest

from users.models import EmailChangeToken, EmailChangeTokenPurpose, UserUpdate
from users.verification import VerificationConfig, hash_token


def test_email_change_is_off_by_default():
    config = VerificationConfig()
    assert config.allow_email_change is False
    assert config.email_change_revert_ttl_days == 7


@pytest.mark.asyncio
class TestEmailChangeTokenStorage:
    async def _token(self, user_repository, user_id, raw="raw-token", **overrides):
        fields = dict(
            purpose=EmailChangeTokenPurpose.CONFIRM.value,
            old_email="test@example.com",
            new_email="new@example.com",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        fields.update(overrides)
        return await user_repository.create_email_change_token(
            user_id, hash_token(raw), **fields
        )

    async def test_stores_a_digest_and_both_addresses(self, user_repository, create_test_user, db_session):
        user = await create_test_user()

        await self._token(user_repository, user.id, raw="raw-token")

        row = db_session.query(EmailChangeToken).one()
        assert row.token == hash_token("raw-token")
        assert row.token != "raw-token"
        assert row.purpose == "confirm"
        assert (row.old_email, row.new_email) == ("test@example.com", "new@example.com")
        assert row.used is False

    async def test_normalizes_both_addresses(self, user_repository, create_test_user):
        user = await create_test_user()

        token = await self._token(
            user_repository, user.id,
            old_email=" Test@Example.com ", new_email="NEW@example.COM",
        )

        assert (token.old_email, token.new_email) == ("test@example.com", "new@example.com")

    async def test_get_and_mark_used(self, user_repository, create_test_user):
        user = await create_test_user()
        await self._token(user_repository, user.id, raw="raw-token")

        found = await user_repository.get_email_change_token(hash_token("raw-token"))
        assert found is not None and found.user_id == user.id
        assert await user_repository.get_email_change_token("raw-token") is None

        assert await user_repository.mark_email_change_token_as_used(hash_token("raw-token")) is True
        assert (await user_repository.get_email_change_token(hash_token("raw-token"))).used is True
        assert await user_repository.mark_email_change_token_as_used(hash_token("missing")) is False

    async def test_delete_user_email_change_tokens_leaves_other_users_alone(self, user_repository, create_test_user, db_session):
        user = await create_test_user()
        other = await create_test_user(email="other@example.com", username="other")
        await self._token(user_repository, user.id, raw="a")
        await self._token(
            user_repository, user.id, raw="b",
            purpose=EmailChangeTokenPurpose.CANCEL.value,
        )
        await self._token(
            user_repository, other.id, raw="c", old_email="other@example.com",
        )

        await user_repository.delete_user_email_change_tokens(user.id)

        assert [t.user_id for t in db_session.query(EmailChangeToken).all()] == [other.id]

    async def test_delete_user_removes_their_email_change_tokens(self, user_service, user_repository, create_test_user, db_session):
        """The table references users with no ON DELETE CASCADE, like the others (#21)."""
        user = await create_test_user(status="inactive")
        await self._token(user_repository, user.id)

        assert await user_service.delete_user(user.id) is True

        assert await user_service.get_user_by_id(user.id) is None
        assert db_session.query(EmailChangeToken).count() == 0


# --- The flow: request, confirm, cancel, revert -------------------------------

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from users import email_service as email_service_module
from users import verification as verification_module
from users.auth import get_auth_manager
from users.dependencies import get_user_service
from users.models import (
    EmailChangeRequest, EmailChangeTokenAction, EmailVerificationToken,
    PasswordResetToken, UserLogin,
)
from users.routes import create_user_router
from users.verification import configure_verification

PASSWORD = "test_password_123"


class FakeEmailService:
    """Captures every email-change and reset email instead of sending it."""

    def __init__(self):
        self.confirmations = []   # (to, link)
        self.requested = []       # (to, new_email, cancel_link)
        self.completed = []       # (to, new_email, revert_link, ttl_days)
        self.resets = []          # (to, token)

    async def send_email_change_confirmation(self, recipient_email, confirm_link, ttl_hours):
        self.confirmations.append((recipient_email, confirm_link))
        return True

    async def send_email_change_requested_notice(self, recipient_email, new_email, cancel_link):
        self.requested.append((recipient_email, new_email, cancel_link))
        return True

    async def send_email_change_completed_notice(self, recipient_email, new_email, revert_link, ttl_days):
        self.completed.append((recipient_email, new_email, revert_link, ttl_days))
        return True

    async def send_password_reset_email(self, recipient_email, reset_token, reset_url_template=None):
        self.resets.append((recipient_email, reset_token))
        return True

    async def send_verification_email(self, recipient_email, verification_token, verification_url_template=None):
        return True


@pytest.fixture
def fake_email(monkeypatch):
    service = FakeEmailService()
    monkeypatch.setattr(email_service_module, "_email_service", service)
    return service


@pytest.fixture
def enabled(monkeypatch):
    """Turn email change on for one test; restored to defaults afterwards."""
    monkeypatch.setattr(verification_module, "_verification_config", None)
    return configure_verification(VerificationConfig(allow_email_change=True))


@pytest.fixture
def account(create_test_user):
    async def _make(email="test@example.com", username="testuser"):
        return await create_test_user(email=email, username=username, status="active")
    return _make


def _request(new_email="new@example.com", password=PASSWORD):
    return EmailChangeRequest(current_password=password, new_email=new_email)


def _action(token):
    return EmailChangeTokenAction(token=token)


def _password_works(user, password=PASSWORD):
    return get_auth_manager().verify_password(password, user.hashed_password)


def _purposes(db_session):
    return sorted(t.purpose for t in db_session.query(EmailChangeToken).filter_by(used=False))


@pytest.mark.asyncio
class TestRequestEmailChange:
    async def test_refused_while_the_flag_is_off(self, user_service, account, fake_email, monkeypatch):
        monkeypatch.setattr(verification_module, "_verification_config", None)
        user = await account()

        with pytest.raises(HTTPException) as exc:
            await user_service.request_email_change(user.id, _request())

        assert exc.value.status_code == 403
        assert fake_email.confirmations == []

    async def test_wrong_password_is_refused(self, user_service, account, fake_email, enabled, db_session):
        user = await account()

        with pytest.raises(HTTPException) as exc:
            await user_service.request_email_change(user.id, _request(password="wrong_password"))

        assert exc.value.status_code == 400
        assert db_session.query(EmailChangeToken).count() == 0
        assert fake_email.confirmations == [] and fake_email.requested == []

    async def test_current_or_taken_address_is_refused(self, user_service, account, fake_email, enabled):
        user = await account()
        await account(email="taken@example.com", username="taken")

        for address in ("TEST@example.com", "taken@example.com"):
            with pytest.raises(HTTPException) as exc:
                await user_service.request_email_change(user.id, _request(new_email=address))
            assert exc.value.status_code == 400

    async def test_nothing_changes_until_confirmed(self, user_service, user_repository, account, fake_email, enabled, db_session):
        user = await account()

        await user_service.request_email_change(user.id, _request(new_email="New@Example.com"))

        assert (await user_repository.get_user_by_id(user.id)).email == "test@example.com"
        assert _purposes(db_session) == ["cancel", "confirm"]
        assert [to for to, _ in fake_email.confirmations] == ["new@example.com"]
        assert fake_email.requested[0][:2] == ("test@example.com", "new@example.com")
        # Only digests are stored
        raw = fake_email.confirmations[0][1]
        assert db_session.query(EmailChangeToken).filter_by(token=raw).count() == 0

    async def test_a_new_request_replaces_the_pending_one(self, user_service, account, fake_email, enabled, db_session):
        user = await account()
        await user_service.request_email_change(user.id, _request(new_email="first@example.com"))
        first_confirm = fake_email.confirmations[0][1]

        await user_service.request_email_change(user.id, _request(new_email="second@example.com"))

        assert _purposes(db_session) == ["cancel", "confirm"]
        with pytest.raises(HTTPException):
            await user_service.confirm_email_change(_action(first_confirm))

    async def test_links_use_the_url_template(self, user_service, account, fake_email, monkeypatch):
        monkeypatch.setattr(verification_module, "_verification_config", None)
        configure_verification(VerificationConfig(
            allow_email_change=True,
            email_change_url_template="https://app.example.com/email/{action}?token={token}",
        ))
        user = await account()

        await user_service.request_email_change(user.id, _request())

        assert fake_email.confirmations[0][1].startswith("https://app.example.com/email/confirm?token=")
        assert fake_email.requested[0][2].startswith("https://app.example.com/email/cancel?token=")


@pytest.mark.asyncio
class TestConfirmEmailChange:
    async def _requested(self, user_service, account, fake_email, new_email="new@example.com"):
        user = await account()
        await user_service.request_email_change(user.id, _request(new_email=new_email))
        return user, fake_email.confirmations[-1][1], fake_email.requested[-1][2]

    async def test_applies_the_change_and_sends_a_revert_link(self, user_service, user_repository, account, fake_email, enabled, db_session):
        user, confirm, _ = await self._requested(user_service, account, fake_email)
        await user_repository.create_password_reset_token(user.id, hash_token("reset"), datetime.utcnow() + timedelta(hours=1))
        await user_repository.create_email_verification_token(user.id, hash_token("verify"), datetime.utcnow() + timedelta(hours=1))

        response = await user_service.confirm_email_change(_action(confirm))

        assert response.email == "new@example.com"
        assert response.is_verified is True
        assert _purposes(db_session) == ["revert"]
        assert db_session.query(PasswordResetToken).count() == 0
        assert db_session.query(EmailVerificationToken).count() == 0
        to, new_email, _, ttl_days = fake_email.completed[0]
        assert (to, new_email, ttl_days) == ("test@example.com", "new@example.com", 7)

    async def test_a_confirm_link_works_once(self, user_service, account, fake_email, enabled):
        _, confirm, _ = await self._requested(user_service, account, fake_email)
        await user_service.confirm_email_change(_action(confirm))

        with pytest.raises(HTTPException) as exc:
            await user_service.confirm_email_change(_action(confirm))
        assert exc.value.status_code == 400

    async def test_a_cancel_link_cannot_confirm(self, user_service, user_repository, account, fake_email, enabled):
        user, _, cancel = await self._requested(user_service, account, fake_email)

        with pytest.raises(HTTPException) as exc:
            await user_service.confirm_email_change(_action(cancel))

        assert exc.value.detail == "Invalid or expired email change token"
        assert (await user_repository.get_user_by_id(user.id)).email == "test@example.com"

    async def test_expired_link_is_refused(self, user_service, account, fake_email, enabled, db_session):
        _, confirm, _ = await self._requested(user_service, account, fake_email)
        db_session.query(EmailChangeToken).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
        db_session.commit()

        with pytest.raises(HTTPException) as exc:
            await user_service.confirm_email_change(_action(confirm))
        assert exc.value.detail == "Email change token has expired"

    async def test_address_taken_in_the_meantime_is_refused(self, user_service, user_repository, account, fake_email, enabled):
        user, confirm, _ = await self._requested(user_service, account, fake_email)
        await account(email="new@example.com", username="squatter")

        with pytest.raises(HTTPException) as exc:
            await user_service.confirm_email_change(_action(confirm))

        assert exc.value.detail == "Email already registered"
        assert (await user_repository.get_user_by_id(user.id)).email == "test@example.com"

    async def test_stale_request_is_refused(self, user_service, user_repository, account, fake_email, enabled):
        """The account's address changed after the request, e.g. by an admin."""
        user, confirm, _ = await self._requested(user_service, account, fake_email)
        await user_service.update_user(user.id, UserUpdate(email="admin-set@example.com"))

        with pytest.raises(HTTPException):
            await user_service.confirm_email_change(_action(confirm))
        assert (await user_repository.get_user_by_id(user.id)).email == "admin-set@example.com"


@pytest.mark.asyncio
class TestCancelEmailChange:
    async def test_cancel_stops_the_change_and_forces_a_password_reset(self, user_service, user_repository, account, fake_email, enabled, db_session):
        user = await account()
        await user_service.request_email_change(user.id, _request())
        confirm, cancel = fake_email.confirmations[0][1], fake_email.requested[0][2]

        assert await user_service.cancel_email_change(_action(cancel)) is True

        stored = await user_repository.get_user_by_id(user.id)
        assert stored.email == "test@example.com"
        assert not _password_works(stored)
        assert [to for to, _ in fake_email.resets] == ["test@example.com"]
        assert _purposes(db_session) == []
        with pytest.raises(HTTPException):
            await user_service.confirm_email_change(_action(confirm))


@pytest.mark.asyncio
class TestRevertEmailChange:
    async def _changed(self, user_service, account, fake_email, new_email="new@example.com", user=None):
        user = user or await account()
        await user_service.request_email_change(user.id, _request(new_email=new_email))
        await user_service.confirm_email_change(_action(fake_email.confirmations[-1][1]))
        return user, fake_email.completed[-1][2]

    async def test_revert_restores_the_old_address_and_forces_a_password_reset(self, user_service, user_repository, account, fake_email, enabled, db_session):
        user, revert = await self._changed(user_service, account, fake_email)

        assert await user_service.revert_email_change(_action(revert)) is True

        stored = await user_repository.get_user_by_id(user.id)
        assert stored.email == "test@example.com"
        assert stored.is_verified is True
        assert not _password_works(stored)
        assert [to for to, _ in fake_email.resets] == ["test@example.com"]
        assert db_session.query(EmailChangeToken).filter_by(used=False).count() == 0
        with pytest.raises(HTTPException):
            await user_service.revert_email_change(_action(revert))

    async def test_a_second_change_keeps_the_first_revert_link(self, user_service, user_repository, account, fake_email, enabled):
        user, first_revert = await self._changed(user_service, account, fake_email)
        await self._changed(user_service, account, fake_email, new_email="third@example.com", user=user)

        await user_service.revert_email_change(_action(first_revert))

        assert (await user_repository.get_user_by_id(user.id)).email == "test@example.com"

    async def test_revert_refused_when_the_old_address_was_taken(self, user_service, user_repository, account, fake_email, enabled):
        user, revert = await self._changed(user_service, account, fake_email)
        await account(email="test@example.com", username="squatter")

        with pytest.raises(HTTPException) as exc:
            await user_service.revert_email_change(_action(revert))

        assert exc.value.status_code == 409
        assert (await user_repository.get_user_by_id(user.id)).email == "new@example.com"

    async def test_revert_link_expires(self, user_service, account, fake_email, enabled, db_session):
        _, revert = await self._changed(user_service, account, fake_email)
        row = db_session.query(EmailChangeToken).filter_by(purpose="revert").one()
        assert row.expires_at - datetime.utcnow() > timedelta(days=6, hours=23)
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db_session.commit()

        with pytest.raises(HTTPException) as exc:
            await user_service.revert_email_change(_action(revert))
        assert exc.value.detail == "Email change token has expired"


# --- Over HTTP ----------------------------------------------------------------

@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


@pytest.mark.asyncio
async def test_full_flow_over_http(client, user_service, account, fake_email, enabled):
    await account()
    token = await user_service.login(UserLogin(email="test@example.com", password=PASSWORD))
    headers = {"Authorization": f"Bearer {token.access_token}"}

    response = client.post(
        "/users/me/email",
        json={"current_password": PASSWORD, "new_email": "new@example.com"},
        headers=headers,
    )
    assert response.status_code == 200

    # Confirm and revert need no login
    response = client.post("/users/me/email/confirm", json={"token": fake_email.confirmations[0][1]})
    assert response.status_code == 200
    assert response.json()["email"] == "new@example.com"

    response = client.post("/users/email/revert", json={"token": fake_email.completed[0][2]})
    assert response.status_code == 200
    assert (await user_service.get_user_by_email("test@example.com")) is not None


def test_request_needs_a_login(client, enabled):
    response = client.post(
        "/users/me/email", json={"current_password": PASSWORD, "new_email": "new@example.com"}
    )
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_put_me_points_to_the_new_endpoint(client, user_service, account):
    await account()
    token = await user_service.login(UserLogin(email="test@example.com", password=PASSWORD))

    response = client.put(
        "/users/me", json={"email": "new@example.com"},
        headers={"Authorization": f"Bearer {token.access_token}"},
    )

    assert response.status_code == 400
    assert "POST /me/email" in response.json()["detail"]
