"""Self-service account deletion (#29): deactivate at once, delete for good after
a period, with links to confirm, keep or restore."""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text

import users.deletion as deletion_module
from users import email_service as email_service_module
from users import verification as verification_module
from users.deletion import configure_user_deletion, purge_due_deletions
from users.dependencies import get_user_service
from users.models import (
    AccountDeletion, AccountDeletionRequest, AccountDeletionToken,
    AccountDeletionTokenAction, UserCreate, UserLogin, UserStatus, UserUpdate,
)
from users.routes import create_user_router
from users.verification import VerificationConfig, configure_verification

PASSWORD = "test_password_123"


class FakeEmailService:
    """Captures the account-deletion emails instead of sending them."""

    def __init__(self):
        self.requested = []   # (to, confirm_link, keep_link, purge_at)
        self.confirmed = []   # (to, restore_link, purge_at)
        self.deleted = []     # to

    async def send_account_deletion_requested(self, recipient_email, confirm_link, keep_link, purge_at):
        self.requested.append((recipient_email, confirm_link, keep_link, purge_at))
        return True

    async def send_account_deletion_confirmed(self, recipient_email, restore_link, purge_at):
        self.confirmed.append((recipient_email, restore_link, purge_at))
        return True

    async def send_account_deleted(self, recipient_email):
        self.deleted.append(recipient_email)
        return True

    async def send_account_suspended_notice(self, *args, **kwargs):
        return True

    async def send_verification_email(self, *args, **kwargs):
        return True

    # Links are the bare token unless a URL template is set
    def confirm_token(self):
        return self.requested[-1][1]

    def keep_token(self):
        return self.requested[-1][2]

    def restore_token(self):
        return self.confirmed[-1][1]


@pytest.fixture
def fake_email(monkeypatch):
    service = FakeEmailService()
    monkeypatch.setattr(email_service_module, "_email_service", service)
    return service


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    """Self-delete on for every test unless it sets its own policy."""
    monkeypatch.setattr(verification_module, "_verification_config", None)
    monkeypatch.setattr(deletion_module, "_on_user_delete", None)
    configure_verification(VerificationConfig(allow_self_delete=True))


@pytest.fixture
def member(create_test_user):
    async def _make(email="member@example.com", username="member", **kwargs):
        kwargs.setdefault("status", "active")
        return await create_test_user(email=email, username=username, **kwargs)
    return _make


def request(password=PASSWORD):
    return AccountDeletionRequest(current_password=password)


def action(token):
    return AccountDeletionTokenAction(token=token)


def later(days):
    return datetime.utcnow() + timedelta(days=days)


async def status_of(user_service, user_id):
    user = await user_service.get_user_by_id(user_id)
    return user.status if user else None


@pytest.mark.asyncio
class TestRequest:

    async def test_deactivates_and_emails_the_links(self, user_service, member, fake_email, db_session):
        user = await member()

        purge_at = await user_service.request_account_deletion(user.id, request())

        assert await status_of(user_service, user.id) == UserStatus.INACTIVE
        assert abs(purge_at - later(14)) < timedelta(minutes=1)
        to, confirm, keep, emailed_purge_at = fake_email.requested[0]
        assert to == "member@example.com" and confirm != keep
        assert emailed_purge_at == purge_at
        deletion = db_session.query(AccountDeletion).one()
        assert deletion.user_id == user.id and deletion.confirmed_at is None

    async def test_needs_the_current_password(self, user_service, member, fake_email, db_session):
        user = await member()

        with pytest.raises(HTTPException) as exc_info:
            await user_service.request_account_deletion(user.id, request("wrong"))

        assert exc_info.value.status_code == 400
        assert await status_of(user_service, user.id) == UserStatus.ACTIVE
        assert db_session.query(AccountDeletion).count() == 0
        assert fake_email.requested == []

    async def test_login_says_the_account_is_scheduled_for_deletion(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))

        assert exc_info.value.status_code == 401
        assert "scheduled for deletion" in exc_info.value.detail

    async def test_the_only_active_admin_cannot(self, user_service, member, fake_email):
        admin = await member(is_superuser=True)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.request_account_deletion(admin.id, request())

        assert exc_info.value.status_code == 409
        assert await status_of(user_service, admin.id) == UserStatus.ACTIVE

    async def test_an_admin_can_when_another_is_active(self, user_service, member, fake_email):
        admin = await member(is_superuser=True)
        await member(email="other@example.com", username="other", is_superuser=True)

        await user_service.request_account_deletion(admin.id, request())

        assert await status_of(user_service, admin.id) == UserStatus.INACTIVE

    async def test_a_stale_request_is_replaced(self, user_service, member, fake_email, db_session):
        """An admin reactivated the account while a request was pending."""
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.update_user(user.id, UserUpdate(status=UserStatus.ACTIVE))

        await user_service.request_account_deletion(user.id, request())

        assert db_session.query(AccountDeletion).count() == 1
        assert db_session.query(AccountDeletionToken).count() == 2


@pytest.mark.asyncio
class TestKeepConfirmRestore:

    async def test_keep_reactivates(self, user_service, member, fake_email, db_session):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        await user_service.keep_account(action(fake_email.keep_token()))

        assert await status_of(user_service, user.id) == UserStatus.ACTIVE
        assert db_session.query(AccountDeletion).count() == 0
        assert db_session.query(AccountDeletionToken).count() == 0
        await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))

    async def test_a_token_works_once(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.keep_account(action(fake_email.keep_token()))

        with pytest.raises(HTTPException) as exc_info:
            await user_service.keep_account(action(fake_email.keep_token()))

        assert exc_info.value.status_code == 400

    async def test_confirm_starts_the_grace_period(self, user_service, member, fake_email, db_session):
        configure_verification(VerificationConfig(
            allow_self_delete=True, account_deletion_grace_days=30
        ))
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        purge_at = await user_service.confirm_account_deletion(action(fake_email.confirm_token()))

        assert abs(purge_at - later(30)) < timedelta(minutes=1)
        assert await status_of(user_service, user.id) == UserStatus.INACTIVE
        deletion = db_session.query(AccountDeletion).one()
        assert deletion.confirmed_at is not None and deletion.purge_at == purge_at
        assert fake_email.confirmed[0][0] == "member@example.com"
        assert fake_email.confirmed[0][2] == purge_at

    async def test_confirming_spends_the_confirm_and_keep_links(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.confirm_account_deletion(action(fake_email.confirm_token()))

        for spent in (fake_email.confirm_token(), fake_email.keep_token()):
            with pytest.raises(HTTPException):
                await user_service.keep_account(action(spent))
        with pytest.raises(HTTPException):
            await user_service.confirm_account_deletion(action(fake_email.confirm_token()))

    async def test_restore_reactivates(self, user_service, member, fake_email, db_session):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.confirm_account_deletion(action(fake_email.confirm_token()))

        await user_service.restore_account(action(fake_email.restore_token()))

        assert await status_of(user_service, user.id) == UserStatus.ACTIVE
        assert db_session.query(AccountDeletion).count() == 0

    async def test_a_token_only_does_its_own_job(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        with pytest.raises(HTTPException) as exc_info:
            await user_service.confirm_account_deletion(action(fake_email.keep_token()))

        assert exc_info.value.status_code == 400
        with pytest.raises(HTTPException):
            await user_service.restore_account(action(fake_email.confirm_token()))

    async def test_an_expired_token_is_refused(self, user_service, member, fake_email):
        configure_verification(VerificationConfig(
            allow_self_delete=True, account_deletion_unconfirmed_days=0
        ))
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        with pytest.raises(HTTPException) as exc_info:
            await user_service.keep_account(action(fake_email.keep_token()))

        assert exc_info.value.status_code == 400
        assert "expired" in exc_info.value.detail

    async def test_restoring_leaves_an_admin_suspension_alone(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.suspend_user(user.id, "Spam")

        await user_service.keep_account(action(fake_email.keep_token()))

        assert await status_of(user_service, user.id) == UserStatus.SUSPENDED

    async def test_links_use_the_url_template(self, user_service, member, fake_email):
        configure_verification(VerificationConfig(
            allow_self_delete=True,
            account_deletion_url_template="https://app.example.com/account/delete/{action}?token={token}",
        ))
        user = await member()

        await user_service.request_account_deletion(user.id, request())

        _, confirm, keep, _ = fake_email.requested[0]
        assert confirm.startswith("https://app.example.com/account/delete/confirm?token=")
        assert keep.startswith("https://app.example.com/account/delete/keep?token=")


@pytest.mark.asyncio
class TestPurge:

    async def test_nothing_before_the_purge_date(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        assert await user_service.purge_due_deletions() == 0
        assert await status_of(user_service, user.id) == UserStatus.INACTIVE

    async def test_deletes_an_unconfirmed_request_once_due(self, user_service, member, fake_email, db_session):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        assert await user_service.purge_due_deletions(now=later(15)) == 1

        assert await user_service.get_user_by_id(user.id) is None
        assert db_session.query(AccountDeletion).count() == 0
        assert db_session.query(AccountDeletionToken).count() == 0
        assert fake_email.deleted == ["member@example.com"]

    async def test_a_confirmed_request_waits_for_its_own_date(self, user_service, member, fake_email):
        configure_verification(VerificationConfig(
            allow_self_delete=True, account_deletion_unconfirmed_days=1, account_deletion_grace_days=30
        ))
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.confirm_account_deletion(action(fake_email.confirm_token()))

        assert await user_service.purge_due_deletions(now=later(2)) == 0
        assert await user_service.purge_due_deletions(now=later(31)) == 1

    async def test_changing_the_period_later_does_not_move_a_request(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        configure_verification(VerificationConfig(
            allow_self_delete=True, account_deletion_unconfirmed_days=1
        ))

        assert await user_service.purge_due_deletions(now=later(2)) == 0

    async def test_runs_the_delete_hook(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        seen = []
        configure_user_deletion(on_user_delete=lambda db, u: seen.append(u.id))

        await user_service.purge_due_deletions(now=later(15))

        assert seen == [user.id]

    async def test_a_failing_hook_keeps_the_account_for_the_next_run(self, user_service, member, fake_email, db_session):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        def failing(db, u):
            raise RuntimeError("cleanup failed")

        configure_user_deletion(on_user_delete=failing)
        assert await user_service.purge_due_deletions(now=later(15)) == 0
        assert await status_of(user_service, user.id) == UserStatus.INACTIVE
        assert db_session.query(AccountDeletion).count() == 1

        configure_user_deletion(None)
        assert await user_service.purge_due_deletions(now=later(15)) == 1

    async def test_an_admin_reactivation_drops_the_request(self, user_service, member, fake_email, db_session):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.update_user(user.id, UserUpdate(status=UserStatus.ACTIVE))

        assert await user_service.purge_due_deletions(now=later(15)) == 0

        assert await status_of(user_service, user.id) == UserStatus.ACTIVE
        assert db_session.query(AccountDeletion).count() == 0

    async def test_running_twice_is_harmless(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        assert await user_service.purge_due_deletions(now=later(15)) == 1
        assert await user_service.purge_due_deletions(now=later(15)) == 0

    async def test_the_address_can_register_again(self, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())
        await user_service.purge_due_deletions(now=later(15))

        again = await user_service.create_user(UserCreate(
            email="member@example.com", username="member", password=PASSWORD
        ))

        assert again.email == "member@example.com"

    async def test_the_module_function_for_schedulers(self, user_service, member, fake_email, test_db):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        db = test_db()
        try:
            assert await purge_due_deletions(db, now=later(15)) == 1
        finally:
            db.close()


@pytest.mark.asyncio
class TestOff:

    async def test_every_step_is_refused(self, user_service, member, fake_email, db_session):
        configure_verification(VerificationConfig())
        user = await member()

        for call in (
            user_service.request_account_deletion(user.id, request()),
            user_service.confirm_account_deletion(action("x")),
            user_service.keep_account(action("x")),
            user_service.restore_account(action("x")),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await call
            assert exc_info.value.status_code == 403

        assert await status_of(user_service, user.id) == UserStatus.ACTIVE

    async def test_works_without_migration_0005(self, user_service, member, fake_email, db_session):
        """An app that leaves self-delete off needn't create the new tables."""
        configure_verification(VerificationConfig())
        db_session.execute(text("DROP TABLE users.account_deletion_tokens"))
        db_session.execute(text("DROP TABLE users.account_deletions"))
        db_session.commit()

        user = await member()
        token = await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))
        assert token.access_token
        await user_service.update_user(user.id, UserUpdate(first_name="Changed"))
        await user_service.update_user(user.id, UserUpdate(status=UserStatus.INACTIVE))
        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))
        assert "deactivated" in exc_info.value.detail
        await user_service.suspend_user(user.id, "Spam")
        assert await user_service.delete_user(user.id) is True


@pytest.mark.asyncio
class TestAdminDeleteLastAdmin:

    async def test_the_only_active_admin_cannot_be_deleted(self, user_service, member, fake_email):
        admin = await member(is_superuser=True, status="inactive")

        with pytest.raises(HTTPException) as exc_info:
            await user_service.delete_user(admin.id)

        assert exc_info.value.status_code == 409

    async def test_an_admin_can_be_deleted_when_another_is_active(self, user_service, member, fake_email):
        admin = await member(is_superuser=True, status="inactive")
        await member(email="other@example.com", username="other", is_superuser=True)

        assert await user_service.delete_user(admin.id) is True


# --- Routes ---------------------------------------------------------------------

@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


@pytest.mark.asyncio
class TestRoutes:

    async def test_the_whole_flow(self, client, user_service, member, fake_email):
        await member()
        token = (await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))).access_token
        headers = {"Authorization": f"Bearer {token}"}

        response = client.post("/users/me/delete", json={"current_password": PASSWORD}, headers=headers)
        assert response.status_code == 200
        assert "purge_at" in response.json()

        # The token stops working once the account is deactivated
        assert client.get("/users/me", headers=headers).status_code == 400

        confirmed = client.post("/users/delete/confirm", json={"token": fake_email.confirm_token()})
        assert confirmed.status_code == 200 and "purge_at" in confirmed.json()

        restored = client.post("/users/delete/restore", json={"token": fake_email.restore_token()})
        assert restored.status_code == 200
        await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))

    async def test_keep_through_the_route(self, client, user_service, member, fake_email):
        user = await member()
        await user_service.request_account_deletion(user.id, request())

        assert client.post("/users/delete/keep", json={"token": fake_email.keep_token()}).status_code == 200
        assert client.post("/users/delete/keep", json={"token": fake_email.keep_token()}).status_code == 400

    async def test_needs_a_login(self, client, fake_email):
        assert client.post("/users/me/delete", json={"current_password": PASSWORD}).status_code in (401, 403)

    async def test_off_is_403(self, client, user_service, member, fake_email):
        configure_verification(VerificationConfig())
        await member()
        token = (await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))).access_token

        response = client.post(
            "/users/me/delete", json={"current_password": PASSWORD},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert client.post("/users/delete/keep", json={"token": "x"}).status_code == 403
