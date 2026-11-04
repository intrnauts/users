"""Who can change is_superuser and roles through PUT /users/{user_id}.

Only a superuser, never on their own account, and the only active admin keeps
superuser. Server code calling update_user() without an actor is trusted.
"""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from users.dependencies import get_user_service
from users.models import UserLogin, UserUpdate
from users.routes import create_user_router

PASSWORD = "test_password_123"


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router())
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


@pytest.fixture
def login(user_service):
    async def _login(email):
        token = await user_service.login(UserLogin(email=email, password=PASSWORD))
        return {"Authorization": f"Bearer {token.access_token}"}
    return _login


@pytest.fixture
def roles(create_test_permission, create_test_role):
    """A manager role that may edit users, and an editor role that may not."""
    async def _make():
        await create_test_permission(name="users:write", resource="users", action="write")
        await create_test_permission(name="posts:write", resource="posts", action="write")
        await create_test_role(name="user_manager", permissions=["users:write"])
        await create_test_role(name="editor", permissions=["posts:write"])
    return _make


@pytest.fixture
def people(create_test_user, roles):
    """An admin, a manager with users:write but not superuser, and a member."""
    async def _make():
        await roles()
        admin = await create_test_user(
            email="admin@example.com", username="admin", status="active", is_superuser=True
        )
        manager = await create_test_user(
            email="manager@example.com", username="manager", status="active",
            roles=["user_manager"],
        )
        member = await create_test_user(
            email="member@example.com", username="member", status="active"
        )
        return admin, manager, member
    return _make


async def _state(user_service, user_id):
    user = await user_service.get_user_by_id(user_id)
    return user.is_superuser, sorted(user.roles)


@pytest.mark.asyncio
class TestManagerWithoutSuperuser:

    @pytest.mark.parametrize("body", [
        {"is_superuser": True},
        {"roles": ["user_manager"]},
        {"roles": ["editor"]},
    ])
    async def test_cannot_change_admin_fields_on_others(self, client, people, login, user_service, body):
        _, _, member = await people()
        before = await _state(user_service, member.id)

        response = client.put(f"/users/{member.id}", json=body, headers=await login("manager@example.com"))

        assert response.status_code == 403
        assert await _state(user_service, member.id) == before

    @pytest.mark.parametrize("body", [
        {"is_superuser": True},
        {"roles": ["user_manager", "editor"]},
    ])
    async def test_cannot_change_their_own(self, client, people, login, user_service, body):
        _, manager, _ = await people()
        before = await _state(user_service, manager.id)

        response = client.put(f"/users/{manager.id}", json=body, headers=await login("manager@example.com"))

        assert response.status_code == 403
        assert await _state(user_service, manager.id) == before

    async def test_cannot_remove_superuser_from_an_admin(self, client, people, login, user_service):
        admin, _, _ = await people()

        response = client.put(
            f"/users/{admin.id}", json={"is_superuser": False}, headers=await login("manager@example.com")
        )

        assert response.status_code == 403
        assert (await user_service.get_user_by_id(admin.id)).is_superuser

    async def test_other_fields_still_work(self, client, people, login):
        _, _, member = await people()

        response = client.put(
            f"/users/{member.id}", json={"first_name": "Renamed"}, headers=await login("manager@example.com")
        )

        assert response.status_code == 200
        assert response.json()["first_name"] == "Renamed"

    async def test_sending_unchanged_values_is_not_a_change(self, client, people, login):
        _, _, member = await people()

        response = client.put(
            f"/users/{member.id}",
            json={"first_name": "Same", "is_superuser": False, "roles": []},
            headers=await login("manager@example.com"),
        )

        assert response.status_code == 200
        assert response.json()["first_name"] == "Same"


@pytest.mark.asyncio
class TestSuperuser:

    async def test_can_change_admin_fields_on_others(self, client, people, login, user_service):
        _, _, member = await people()
        headers = await login("admin@example.com")

        assert client.put(f"/users/{member.id}", json={"roles": ["editor"]}, headers=headers).status_code == 200
        assert client.put(f"/users/{member.id}", json={"is_superuser": True}, headers=headers).status_code == 200
        assert await _state(user_service, member.id) == (True, ["editor"])

        assert client.put(f"/users/{member.id}", json={"is_superuser": False}, headers=headers).status_code == 200
        assert (await user_service.get_user_by_id(member.id)).is_superuser is False

    @pytest.mark.parametrize("body", [{"is_superuser": False}, {"roles": ["editor"]}])
    async def test_cannot_change_their_own(self, client, people, login, user_service, create_test_user, body):
        admin, _, _ = await people()
        # A second active admin, so only the self rule can refuse it
        await create_test_user(
            email="second@example.com", username="second", status="active", is_superuser=True
        )
        before = await _state(user_service, admin.id)

        response = client.put(f"/users/{admin.id}", json=body, headers=await login("admin@example.com"))

        assert response.status_code == 400
        assert await _state(user_service, admin.id) == before


@pytest.mark.asyncio
class TestServerCode:
    """update_user() with no actor is server code and is trusted, as before."""

    async def test_no_actor_can_change_admin_fields(self, user_service, people):
        _, _, member = await people()

        result = await user_service.update_user(member.id, UserUpdate(is_superuser=True, roles=["editor"]))

        assert result.is_superuser is True
        assert result.roles == ["editor"]

    async def test_the_only_active_admin_keeps_superuser(self, user_service, people):
        admin, _, _ = await people()

        with pytest.raises(HTTPException) as exc:
            await user_service.update_user(admin.id, UserUpdate(is_superuser=False, first_name="Lost"))

        assert exc.value.status_code == 409
        kept = await user_service.get_user_by_id(admin.id)
        assert kept.is_superuser and kept.first_name != "Lost"

    async def test_allowed_while_another_admin_is_active(self, user_service, people, create_test_user):
        admin, _, _ = await people()
        await create_test_user(
            email="second@example.com", username="second", status="active", is_superuser=True
        )

        result = await user_service.update_user(admin.id, UserUpdate(is_superuser=False))

        assert result.is_superuser is False

    async def test_the_actor_rules_apply_when_an_actor_is_given(self, user_service, people):
        _, manager, member = await people()
        manager_row = await user_service.user_repo.get_user_by_id(manager.id)

        with pytest.raises(HTTPException) as exc:
            await user_service.update_user(member.id, UserUpdate(is_superuser=True), actor=manager_row)

        assert exc.value.status_code == 403
