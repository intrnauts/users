"""Suspension as a reversible admin action the user is told about, and the step
before an admin delete (#48)."""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import users.deletion as deletion_module
from users import email_service as email_service_module
from users import verification as verification_module
from users.deletion import configure_user_deletion
from users.dependencies import get_user_service
from users.models import UserLogin, UserStatus, UserUpdate
from users.routes import create_user_router
from users.verification import VerificationConfig, configure_verification

PASSWORD = "test_password_123"


class FakeEmailService:
    """Captures the suspension emails instead of sending them."""

    def __init__(self, fail=False):
        self.fail = fail
        self.suspended = []     # (to, reason, contact)
        self.reactivated = []   # to

    async def send_account_suspended_notice(self, recipient_email, reason=None, contact=None):
        if self.fail:
            raise RuntimeError("provider down")
        self.suspended.append((recipient_email, reason, contact))
        return True

    async def send_account_reactivated_notice(self, recipient_email):
        if self.fail:
            raise RuntimeError("provider down")
        self.reactivated.append(recipient_email)
        return True

    async def send_verification_email(self, recipient_email, verification_token, verification_url_template=None):
        return True


@pytest.fixture
def fake_email(monkeypatch):
    service = FakeEmailService()
    monkeypatch.setattr(email_service_module, "_email_service", service)
    return service


@pytest.fixture(autouse=True)
def default_policy(monkeypatch):
    """Every test starts from the default policy and no delete hook."""
    monkeypatch.setattr(verification_module, "_verification_config", None)
    monkeypatch.setattr(deletion_module, "_on_user_delete", None)


@pytest.fixture
def member(create_test_user):
    async def _make(email="member@example.com", username="member", status="active"):
        return await create_test_user(email=email, username=username, status=status)
    return _make


@pytest.mark.asyncio
class TestSuspend:

    async def test_suspend_with_a_reason(self, user_service, member, fake_email):
        user = await member()

        result = await user_service.suspend_user(user.id, "Spam in comments")

        assert result.status == UserStatus.SUSPENDED
        assert result.suspension_reason == "Spam in comments"
        assert result.suspended_at is not None
        assert fake_email.suspended == [("member@example.com", "Spam in comments", None)]

    async def test_suspend_without_a_reason(self, user_service, member, fake_email):
        user = await member()

        result = await user_service.suspend_user(user.id)

        assert result.status == UserStatus.SUSPENDED
        assert result.suspension_reason is None
        assert result.suspended_at is not None
        assert fake_email.suspended == [("member@example.com", None, None)]

    async def test_a_blank_reason_is_no_reason(self, user_service, member, fake_email):
        user = await member()

        result = await user_service.suspend_user(user.id, "   ")

        assert result.suspension_reason is None

    async def test_the_contact_goes_into_the_email(self, user_service, member, fake_email):
        configure_verification(VerificationConfig(suspension_contact="support@example.com"))
        user = await member()

        await user_service.suspend_user(user.id, "Spam")

        assert fake_email.suspended == [("member@example.com", "Spam", "support@example.com")]

    async def test_suspending_twice_is_refused(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "First")

        with pytest.raises(HTTPException) as exc_info:
            await user_service.suspend_user(user.id, "Second")

        assert exc_info.value.status_code == 409
        # The first suspension stands
        assert (await user_service.get_user_by_id(user.id)).suspension_reason == "First"
        assert len(fake_email.suspended) == 1

    async def test_unknown_user(self, user_service, fake_email):
        assert await user_service.suspend_user(99999) is None

    async def test_a_failed_email_does_not_undo_it(self, user_service, member, monkeypatch):
        monkeypatch.setattr(email_service_module, "_email_service", FakeEmailService(fail=True))
        user = await member()

        result = await user_service.suspend_user(user.id, "Spam")

        assert result.status == UserStatus.SUSPENDED

    async def test_a_suspended_user_cannot_log_in(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))

        assert exc_info.value.status_code == 401


@pytest.mark.asyncio
class TestReactivate:

    async def test_reactivate_clears_the_suspension(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        result = await user_service.reactivate_user(user.id)

        assert result.status == UserStatus.ACTIVE
        assert result.suspension_reason is None
        assert result.suspended_at is None
        assert fake_email.reactivated == ["member@example.com"]
        await user_service.login(UserLogin(email="member@example.com", password=PASSWORD))

    async def test_reactivating_an_unsuspended_user_is_refused(self, user_service, member, fake_email):
        user = await member(status="inactive")

        with pytest.raises(HTTPException) as exc_info:
            await user_service.reactivate_user(user.id)

        assert exc_info.value.status_code == 409
        assert (await user_service.get_user_by_id(user.id)).status == UserStatus.INACTIVE
        assert fake_email.reactivated == []

    async def test_unknown_user(self, user_service, fake_email):
        assert await user_service.reactivate_user(99999) is None


@pytest.mark.asyncio
class TestStatusThroughUpdate:
    """PUT /users/{id} with a status goes through the same code, emails included."""

    async def test_setting_suspended(self, user_service, member, fake_email):
        user = await member()

        result = await user_service.update_user(
            user.id, UserUpdate(status=UserStatus.SUSPENDED, first_name="Kept")
        )

        assert result.status == UserStatus.SUSPENDED
        assert result.suspended_at is not None
        assert result.first_name == "Kept"
        assert fake_email.suspended == [("member@example.com", None, None)]

    async def test_setting_active_from_suspended(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        result = await user_service.update_user(user.id, UserUpdate(status=UserStatus.ACTIVE))

        assert result.status == UserStatus.ACTIVE
        assert result.suspension_reason is None
        assert result.suspended_at is None
        assert fake_email.reactivated == ["member@example.com"]

    async def test_setting_inactive_from_suspended_clears_without_email(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        result = await user_service.update_user(user.id, UserUpdate(status=UserStatus.INACTIVE))

        assert result.status == UserStatus.INACTIVE
        assert result.suspension_reason is None
        assert fake_email.reactivated == []

    async def test_other_status_changes_send_nothing(self, user_service, member, fake_email):
        user = await member()

        result = await user_service.update_user(user.id, UserUpdate(status=UserStatus.INACTIVE))

        assert result.status == UserStatus.INACTIVE
        assert fake_email.suspended == [] and fake_email.reactivated == []

    async def test_resending_suspended_keeps_the_reason(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        result = await user_service.update_user(
            user.id, UserUpdate(status=UserStatus.SUSPENDED, last_name="Edited")
        )

        assert result.suspension_reason == "Spam"
        assert len(fake_email.suspended) == 1


@pytest.mark.asyncio
class TestAdminDelete:

    @pytest.mark.parametrize("status_", ["active", "pending"])
    async def test_refused_unless_suspended_or_inactive(self, user_service, member, fake_email, status_):
        user = await member(status=status_)

        with pytest.raises(HTTPException) as exc_info:
            await user_service.delete_user(user.id)

        assert exc_info.value.status_code == 409
        assert await user_service.get_user_by_id(user.id) is not None

    async def test_allowed_once_suspended(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        assert await user_service.delete_user(user.id) is True
        assert await user_service.get_user_by_id(user.id) is None

    async def test_allowed_when_inactive(self, user_service, member, fake_email):
        user = await member(status="inactive")

        assert await user_service.delete_user(user.id) is True

    async def test_the_guard_can_be_turned_off(self, user_service, member, fake_email):
        configure_verification(VerificationConfig(admin_delete_requires_suspension=False))
        user = await member()

        assert await user_service.delete_user(user.id) is True

    async def test_unknown_user(self, user_service, fake_email):
        assert await user_service.delete_user(99999) is False

    async def test_runs_the_delete_hook(self, user_service, member, fake_email):
        user = await member()
        await user_service.suspend_user(user.id)
        seen = []
        configure_user_deletion(on_user_delete=lambda db, u: seen.append(u.id))

        await user_service.delete_user(user.id)

        assert seen == [user.id]


# --- Routes ---------------------------------------------------------------------

@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router())
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


@pytest.fixture
def admin_headers(user_service, create_test_user):
    async def _make():
        admin = await create_test_user(
            email="admin@example.com", username="admin", status="active", is_superuser=True
        )
        token = await user_service.login(UserLogin(email="admin@example.com", password=PASSWORD))
        return admin, {"Authorization": f"Bearer {token.access_token}"}
    return _make


@pytest.mark.asyncio
class TestRoutes:

    async def test_suspend_with_a_reason(self, client, admin_headers, member, fake_email):
        _, headers = await admin_headers()
        user = await member()

        response = client.post(f"/users/{user.id}/suspend", json={"reason": "Spam"}, headers=headers)

        assert response.status_code == 200
        assert response.json()["status"] == "suspended"
        assert response.json()["suspension_reason"] == "Spam"
        assert response.json()["suspended_at"] is not None

    async def test_suspend_with_no_body(self, client, admin_headers, member, fake_email):
        _, headers = await admin_headers()
        user = await member()

        response = client.post(f"/users/{user.id}/suspend", headers=headers)

        assert response.status_code == 200
        assert response.json()["suspension_reason"] is None

    async def test_an_admin_cannot_suspend_themselves(self, client, admin_headers, user_service, fake_email):
        admin, headers = await admin_headers()

        response = client.post(f"/users/{admin.id}/suspend", headers=headers)

        assert response.status_code == 400
        assert (await user_service.get_user_by_id(admin.id)).status == UserStatus.ACTIVE

    async def test_reactivate(self, client, admin_headers, member, user_service, fake_email):
        _, headers = await admin_headers()
        user = await member()
        await user_service.suspend_user(user.id, "Spam")

        response = client.post(f"/users/{user.id}/reactivate", headers=headers)

        assert response.status_code == 200
        assert response.json()["status"] == "active"
        assert response.json()["suspension_reason"] is None

    async def test_unknown_user_is_404(self, client, admin_headers, fake_email):
        _, headers = await admin_headers()

        assert client.post("/users/99999/suspend", headers=headers).status_code == 404
        assert client.post("/users/99999/reactivate", headers=headers).status_code == 404

    async def test_delete_needs_a_suspension_first(self, client, admin_headers, member, fake_email):
        _, headers = await admin_headers()
        user = await member()

        refused = client.delete(f"/users/{user.id}", headers=headers)
        assert refused.status_code == 409
        assert refused.json()["detail"] == "Suspend or deactivate the account before deleting it"

        assert client.post(f"/users/{user.id}/suspend", headers=headers).status_code == 200
        assert client.delete(f"/users/{user.id}", headers=headers).status_code == 200

    async def test_needs_an_admin(self, client, member, user_service, fake_email):
        user = await member()
        await member(email="other@example.com", username="other")
        token = await user_service.login(UserLogin(email="other@example.com", password=PASSWORD))
        headers = {"Authorization": f"Bearer {token.access_token}"}

        assert client.post(f"/users/{user.id}/suspend", headers=headers).status_code == 403
        assert client.post(f"/users/{user.id}/reactivate", headers=headers).status_code == 403
