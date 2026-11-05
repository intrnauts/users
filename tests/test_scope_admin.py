"""The scope boundary on admin routes (#70): with scopes on, an admin who isn't
a superuser only acts on accounts in their own scope. Superusers act across
scopes. With scopes off, nothing changes."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from users import email_service as email_service_module
from users import scope as scope_module
from users import verification as verification_module
from users.dependencies import get_user_service
from users.models import UserLogin
from users.routes import create_user_router
from users.verification import VerificationConfig, configure_verification

PASSWORD = "test_password_123"


class SilentEmailService:
    def __getattr__(self, name):
        if not name.startswith("send_"):
            raise AttributeError(name)

        async def send(*args, **kwargs):
            return True
        return send


@pytest.fixture(autouse=True)
def isolate_globals(monkeypatch):
    """Scopes on unless a test turns them off. Admin delete without suspending
    first, so delete can be tested on its own."""
    monkeypatch.setattr(verification_module, "_verification_config", None)
    monkeypatch.setattr(email_service_module, "_email_service", SilentEmailService())
    monkeypatch.setattr(scope_module, "_enabled", True)
    monkeypatch.setattr(scope_module, "_request_scope", None)
    configure_verification(VerificationConfig(admin_delete_requires_suspension=False))


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router())
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


@pytest.fixture
def login(user_service):
    async def _login(email, scope=""):
        token = await user_service.login(UserLogin(email=email, password=PASSWORD, scope=scope))
        return {"Authorization": f"Bearer {token.access_token}"}
    return _login


@pytest.fixture
def people(create_test_user, create_test_permission, create_test_role):
    """A superuser in the default scope, and in each of t1 and t2 a scope admin
    holding users:read/write/delete and a member. Each scope uses the same
    addresses, so the boundary can't be passed by matching emails."""
    async def _make():
        for action in ("read", "write", "delete"):
            await create_test_permission(name=f"users:{action}", resource="users", action=action)
        await create_test_role(
            name="user_manager", permissions=["users:read", "users:write", "users:delete"]
        )
        found = {"root": await create_test_user(
            email="root@example.com", username="root", status="active", is_superuser=True
        )}
        for scope in ("t1", "t2"):
            found[f"{scope}_admin"] = await create_test_user(
                email="admin@example.com", username="admin", scope=scope, status="active",
                roles=["user_manager"],
            )
            found[f"{scope}_member"] = await create_test_user(
                email="member@example.com", username="member", scope=scope, status="active",
            )
        return found
    return _make


def admin_calls(user_id):
    """Every admin route that names an account: (method, path, json)."""
    return [
        ("get", f"/users/{user_id}", None),
        ("put", f"/users/{user_id}", {"first_name": "Changed"}),
        ("post", f"/users/{user_id}/verify", None),
        ("post", f"/users/{user_id}/suspend", {"reason": "test"}),
        ("post", f"/users/{user_id}/reactivate", None),
        ("get", f"/users/{user_id}/permissions", None),
        ("delete", f"/users/{user_id}", None),
    ]


def call(client, headers, method, path, json):
    kwargs = {"headers": headers}
    if json is not None:
        kwargs["json"] = json
    return getattr(client, method)(path, **kwargs)


@pytest.mark.asyncio
class TestScopeAdmin:

    @pytest.mark.parametrize("index", range(7))
    async def test_another_scopes_account_looks_like_it_doesnt_exist(
        self, client, people, login, user_service, index
    ):
        found = await people()
        target = found["t2_member"]
        method, path, json = admin_calls(target.id)[index]

        response = call(client, await login("admin@example.com", "t1"), method, path, json)

        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"
        after = await user_service.get_user_by_id(target.id)
        assert after is not None
        assert (after.first_name, after.status) == (target.first_name, "active")

    async def test_every_route_works_on_your_own_scopes_accounts(self, client, people, login):
        found = await people()
        headers = await login("admin@example.com", "t1")

        statuses = [
            call(client, headers, method, path, json).status_code
            for method, path, json in admin_calls(found["t1_member"].id)
        ]

        assert statuses == [200] * 7

    async def test_the_list_shows_only_your_scope(self, client, people, login):
        found = await people()

        response = client.get("/users/", headers=await login("admin@example.com", "t1"))

        assert response.status_code == 200
        assert sorted(u["id"] for u in response.json()) == sorted(
            [found["t1_admin"].id, found["t1_member"].id]
        )
        assert {u["scope"] for u in response.json()} == {"t1"}

    async def test_filtering_the_list_by_another_scope_is_refused(self, client, people, login):
        await people()
        headers = await login("admin@example.com", "t1")

        assert client.get("/users/?scope_filter=t2", headers=headers).status_code == 403
        assert client.get("/users/?scope_filter=t1", headers=headers).status_code == 200


@pytest.mark.asyncio
class TestSuperuser:

    async def test_a_superuser_acts_across_scopes(self, client, people, login):
        found = await people()
        headers = await login("root@example.com")

        statuses = [
            call(client, headers, method, path, json).status_code
            for method, path, json in admin_calls(found["t2_member"].id)
        ]

        assert statuses == [200] * 7

    async def test_a_superuser_lists_every_scope_or_one(self, client, people, login):
        found = await people()
        headers = await login("root@example.com")

        everyone = client.get("/users/", headers=headers).json()
        assert len(everyone) == 5

        only_t2 = client.get("/users/?scope_filter=t2", headers=headers).json()
        assert sorted(u["id"] for u in only_t2) == sorted(
            [found["t2_admin"].id, found["t2_member"].id]
        )

        default = client.get("/users/?scope_filter=", headers=headers).json()
        assert [u["id"] for u in default] == [found["root"].id]


@pytest.mark.asyncio
class TestScopesOff:
    """Off, an admin with users:* acts on every account, as before."""

    @pytest.fixture(autouse=True)
    def scopes_off(self, monkeypatch):
        monkeypatch.setattr(scope_module, "_enabled", False)

    @pytest.fixture
    def default_scope_people(self, create_test_user, create_test_permission, create_test_role):
        async def _make():
            for action in ("read", "write", "delete"):
                await create_test_permission(name=f"users:{action}", resource="users", action=action)
            await create_test_role(
                name="user_manager", permissions=["users:read", "users:write", "users:delete"]
            )
            await create_test_user(
                email="admin@example.com", username="admin", status="active", roles=["user_manager"]
            )
            return await create_test_user(
                email="member@example.com", username="member", status="active"
            )
        return _make

    async def test_an_admin_acts_on_every_account(self, client, default_scope_people, login):
        member = await default_scope_people()
        headers = await login("admin@example.com")

        statuses = [
            call(client, headers, method, path, json).status_code
            for method, path, json in admin_calls(member.id)
        ]
        assert statuses == [200] * 7

    async def test_the_list_is_unchanged(self, client, default_scope_people, login):
        await default_scope_people()

        response = client.get("/users/", headers=await login("admin@example.com"))
        assert len(response.json()) == 2

    async def test_a_scope_filter_is_refused(self, client, default_scope_people, login):
        await default_scope_people()
        headers = await login("admin@example.com")

        response = client.get("/users/?scope_filter=t1", headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "Scopes are not enabled"
        assert client.get("/users/?scope_filter=", headers=headers).status_code == 200
