"""Access tokens carry the user id, so a token issued to a deleted account can't
reach a new account registered with the same email (#55)."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from users.auth import get_auth_manager
from users.dependencies import get_current_user_optional, get_user_service
from users.models import UserLogin
from users.routes import create_user_router

PASSWORD = "test_password_123"


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def bystander(create_test_user):
    """Another account, created after the one about to be deleted.

    SQLite gives a new row the highest id plus one, so deleting the newest user
    would hand its id to the next one. PostgreSQL sequences never reuse an id,
    which is what the package targets.
    """
    await create_test_user(email="bystander@example.com", username="bystander", status="active")


async def login(user_service, email="test@example.com"):
    token = await user_service.login(UserLogin(email=email, password=PASSWORD))
    return token.access_token


@pytest.mark.asyncio
class TestTokenUserId:

    async def test_login_puts_the_user_id_in_the_token(self, user_service, create_test_user, auth_config):
        user = await create_test_user(status="active")

        payload = jwt.decode(
            await login(user_service), auth_config.secret_key, algorithms=[auth_config.algorithm]
        )

        assert payload["uid"] == user.id
        assert payload["sub"] == "test@example.com"

    async def test_a_deleted_accounts_token_cannot_reach_a_new_one(
        self, client, user_service, user_repository, create_test_user
    ):
        old = await create_test_user(status="active")
        old_token = await login(user_service)
        await bystander(create_test_user)
        await user_repository.set_status(old.id, "inactive")
        await user_service.delete_user(old.id)

        # Someone registers the freed address while the old token is still valid
        new = await create_test_user(status="active")
        assert new.id != old.id

        assert client.get("/users/me", headers=bearer(old_token)).status_code == 401
        response = client.get("/users/me", headers=bearer(await login(user_service)))
        assert response.status_code == 200
        assert response.json()["id"] == new.id

    async def test_a_token_without_an_id_is_still_accepted(self, client, create_test_user):
        """Tokens issued before the upgrade carry no id; they work until they expire."""
        await create_test_user(status="active")
        legacy = get_auth_manager().create_access_token("test@example.com")

        assert client.get("/users/me", headers=bearer(legacy)).status_code == 200

    async def test_a_non_integer_id_is_rejected(self, auth_config):
        manager = get_auth_manager()
        for bad in ["7", 7.0, True]:
            token = jwt.encode(
                {"sub": "test@example.com", "uid": bad},
                auth_config.secret_key, algorithm=auth_config.algorithm,
            )
            assert manager.verify_token(token) is None

    async def test_optional_user_ignores_a_token_for_another_account(
        self, user_service, user_repository, create_test_user
    ):
        old = await create_test_user(status="active")
        old_token = await login(user_service)
        await bystander(create_test_user)
        await user_repository.set_status(old.id, "inactive")
        await user_service.delete_user(old.id)
        await create_test_user(status="active")

        class Credentials:
            credentials = old_token

        assert await get_current_user_optional(Credentials(), user_service) is None
