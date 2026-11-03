"""get_current_active_user and get_current_verified_user refuse with 403, and
the active-user check gives the same per-status message login does (#61)."""

from datetime import datetime, timedelta

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import users.verification as verification_module
from users.dependencies import get_current_verified_user, get_user_service
from users.models import UserLogin
from users.routes import create_user_router
from users.verification import VerificationConfig, configure_verification

PASSWORD = "test_password_123"

PENDING_APPROVAL = "Your account is pending admin approval."
VERIFY_EMAIL = "Please verify your email address before logging in."
DEACTIVATED = "Your account has been deactivated. Please contact an admin."
SCHEDULED = (
    "Your account is scheduled for deletion. "
    "Use the link in the email we sent to keep or restore it."
)
SUSPENDED = "Your account has been suspended. Please contact an admin."


@pytest.fixture(autouse=True)
def default_policy(monkeypatch):
    monkeypatch.setattr(verification_module, "_verification_config", None)
    configure_verification(VerificationConfig())


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))

    @app.get("/verified-only")
    async def verified_only(user=Depends(get_current_verified_user)):
        return {"id": user.id}

    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


async def logged_in(user_service, user_repository, create_test_user, verified=True):
    """An active user with a token, so the status can change under the token."""
    user = await create_test_user(username="member", status="active")
    await user_repository.set_verified(user.id, is_verified=verified)
    token = await user_service.login(UserLogin(email=user.email, password=PASSWORD))
    return user, {"Authorization": f"Bearer {token.access_token}"}


async def login_refusal(user_service, email="test@example.com"):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await user_service.login(UserLogin(email=email, password=PASSWORD))
    assert exc_info.value.status_code == 401
    return exc_info.value.detail


@pytest.mark.asyncio
class TestActiveUserDependency:

    async def test_active_user_gets_through(self, client, user_service, user_repository, create_test_user):
        _, headers = await logged_in(user_service, user_repository, create_test_user)

        assert client.get("/users/me", headers=headers).status_code == 200

    @pytest.mark.parametrize("new_status, message", [
        ("suspended", SUSPENDED),
        ("inactive", DEACTIVATED),
    ])
    async def test_refuses_with_403_and_logins_message(
        self, client, user_service, user_repository, create_test_user, new_status, message
    ):
        user, headers = await logged_in(user_service, user_repository, create_test_user)
        await user_repository.set_status(user.id, new_status)

        response = client.get("/users/me", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == message
        assert await login_refusal(user_service) == message

    async def test_pending_awaiting_admin(self, client, user_service, user_repository, create_test_user):
        user, headers = await logged_in(user_service, user_repository, create_test_user)
        await user_repository.set_status(user.id, "pending")

        response = client.get("/users/me", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == PENDING_APPROVAL

    async def test_pending_awaiting_verification(
        self, client, user_service, user_repository, create_test_user
    ):
        user, headers = await logged_in(user_service, user_repository, create_test_user, verified=False)
        await user_repository.set_status(user.id, "pending")

        response = client.get("/users/me", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == VERIFY_EMAIL
        assert await login_refusal(user_service) == VERIFY_EMAIL

    async def test_scheduled_for_deletion(
        self, client, user_service, user_repository, create_test_user
    ):
        configure_verification(VerificationConfig(allow_self_delete=True))
        user, headers = await logged_in(user_service, user_repository, create_test_user)
        await user_repository.create_account_deletion(
            user.id, datetime.utcnow(), datetime.utcnow() + timedelta(days=30), {}
        )
        await user_repository.set_status(user.id, "inactive")

        response = client.get("/users/me", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == SCHEDULED
        assert await login_refusal(user_service) == SCHEDULED


@pytest.mark.asyncio
class TestVerifiedUserDependency:

    async def test_verified_user_gets_through(self, client, user_service, user_repository, create_test_user):
        _, headers = await logged_in(user_service, user_repository, create_test_user)

        assert client.get("/verified-only", headers=headers).status_code == 200

    async def test_unverified_user_gets_403(self, client, user_service, user_repository, create_test_user):
        _, headers = await logged_in(user_service, user_repository, create_test_user, verified=False)

        response = client.get("/verified-only", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == "Email not verified"

    async def test_inactive_status_wins_over_verification(
        self, client, user_service, user_repository, create_test_user
    ):
        user, headers = await logged_in(user_service, user_repository, create_test_user, verified=False)
        await user_repository.set_status(user.id, "suspended")

        response = client.get("/verified-only", headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"] == SUSPENDED
