"""Scopes (#70): the same email can hold one account in each scope, and a token
only reaches the account, and the scope, it was issued for."""

import subprocess
import sys

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from jose import jwt

from users import email_service as email_service_module
from users import scope as scope_module
from users import verification as verification_module
from users.auth import get_auth_manager
from users.dependencies import get_user_service
from users.models import (
    EmailChangeRequest, EmailVerificationResend, PasswordResetRequest,
    PasswordResetToken, UserCreate, UserLogin, UserUpdate
)
from users.repository import SQLAlchemyUserRepository
from users.routes import create_user_router
from users.scope import configure_scope
from users.service import UserService
from users.verification import VerificationConfig, configure_verification, hash_token

PASSWORD = "test_password_123"
EMAIL = "test@example.com"


class RecordingEmailService:
    """Records every send, whatever the method."""

    def __init__(self):
        self.sent = []

    def __getattr__(self, name):
        if not name.startswith("send_"):
            raise AttributeError(name)

        async def send(*args, **kwargs):
            self.sent.append((name, args, kwargs))
            return True
        return send

    def recipients(self, name):
        return [kwargs.get("recipient_email") for sent, _, kwargs in self.sent if sent == name]


@pytest.fixture(autouse=True)
def isolate_globals(monkeypatch):
    """Scopes on, with no request-scope function, unless a test says otherwise."""
    monkeypatch.setattr(verification_module, "_verification_config", None)
    monkeypatch.setattr(scope_module, "_enabled", True)
    monkeypatch.setattr(scope_module, "_request_scope", None)


@pytest.fixture
def emails(monkeypatch):
    service = RecordingEmailService()
    monkeypatch.setattr(email_service_module, "_email_service", service)
    return service


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def account(create_test_user, scope="", email=EMAIL, **kwargs):
    kwargs.setdefault("username", f"user-{scope or 'default'}")
    return await create_test_user(email=email, scope=scope, status="active", **kwargs)


async def login(user_service, scope=None, email=EMAIL):
    token = await user_service.login(UserLogin(email=email, password=PASSWORD, scope=scope))
    return token.access_token


def claims(token, auth_config):
    return jwt.decode(token, auth_config.secret_key, algorithms=[auth_config.algorithm])


@pytest.mark.asyncio
class TestAccountsPerScope:

    async def test_the_same_email_and_username_can_exist_once_per_scope(self, create_test_user):
        default = await account(create_test_user, username="sam")
        tenant = await account(create_test_user, scope="t1", username="sam")

        assert default.id != tenant.id
        assert (default.scope, tenant.scope) == ("", "t1")

    async def test_email_is_still_unique_within_a_scope(self, create_test_user):
        await account(create_test_user, scope="t1")

        with pytest.raises(HTTPException) as error:
            await account(create_test_user, scope="t1", username="someone-else")
        assert error.value.detail == "Email already registered"

    async def test_username_is_still_unique_within_a_scope(self, create_test_user):
        await account(create_test_user, scope="t1", username="sam")

        with pytest.raises(HTTPException) as error:
            await account(create_test_user, scope="t1", email="other@example.com", username="sam")
        assert error.value.detail == "Username already taken"

    async def test_new_accounts_default_to_the_default_scope(self, create_test_user):
        user = await create_test_user(email=EMAIL)
        assert user.scope == ""

    async def test_lookups_stay_in_their_scope(self, user_service, create_test_user):
        await account(create_test_user, scope="t1")

        assert await user_service.get_user_by_email(EMAIL) is None
        assert (await user_service.get_user_by_email(EMAIL, "t1")).scope == "t1"

    async def test_untrusted_create_keeps_the_scope(self, user_service):
        user = await user_service.create_user(
            UserCreate(email=EMAIL, password=PASSWORD, scope="t1")
        )
        assert user.scope == "t1"

    async def test_an_admin_can_give_an_account_an_email_used_in_another_scope(
        self, user_service, create_test_user
    ):
        await account(create_test_user, scope="t1", email="taken@example.com")
        user = await account(create_test_user)

        updated = await user_service.update_user(user.id, UserUpdate(email="taken@example.com"))
        assert updated.email == "taken@example.com"

        await account(create_test_user, email="mine@example.com", username="other")
        with pytest.raises(HTTPException) as error:
            await user_service.update_user(user.id, UserUpdate(email="mine@example.com"))
        assert error.value.detail == "Email already registered"


@pytest.mark.asyncio
class TestLoginAndTokens:

    async def test_login_finds_the_account_in_the_named_scope(
        self, user_service, create_test_user, auth_config
    ):
        await account(create_test_user)
        tenant = await account(create_test_user, scope="t1")

        payload = claims(await login(user_service, scope="t1"), auth_config)

        assert payload["uid"] == tenant.id
        assert payload["scope"] == "t1"

    async def test_login_without_a_scope_uses_the_default(self, user_service, create_test_user, auth_config):
        default = await account(create_test_user)
        await account(create_test_user, scope="t1")

        payload = claims(await login(user_service), auth_config)

        assert payload["uid"] == default.id
        assert payload["scope"] == ""

    async def test_login_in_a_scope_without_the_account_fails(self, user_service, create_test_user):
        await account(create_test_user, scope="t1")

        with pytest.raises(HTTPException) as error:
            await login(user_service)
        assert error.value.status_code == 401

    async def test_each_scopes_token_reaches_its_own_account(self, client, user_service, create_test_user):
        default = await account(create_test_user)
        tenant = await account(create_test_user, scope="t1")

        me = client.get("/users/me", headers=bearer(await login(user_service)))
        assert (me.json()["id"], me.json()["scope"]) == (default.id, "")
        me = client.get("/users/me", headers=bearer(await login(user_service, scope="t1")))
        assert (me.json()["id"], me.json()["scope"]) == (tenant.id, "t1")

    async def test_a_token_naming_another_scope_is_rejected(self, client, create_test_user):
        tenant = await account(create_test_user, scope="t1")
        forged = get_auth_manager().create_access_token(EMAIL, user_id=tenant.id, scope="")

        assert client.get("/users/me", headers=bearer(forged)).status_code == 401

    async def test_a_token_from_before_scopes_counts_as_the_default_scope(self, client, create_test_user):
        """v0.7 tokens carry uid but no scope; they still work for default-scope accounts."""
        default = await account(create_test_user)
        tenant = await account(create_test_user, scope="t1")
        manager = get_auth_manager()

        assert client.get("/users/me", headers=bearer(
            manager.create_access_token(EMAIL, user_id=default.id)
        )).status_code == 200
        assert client.get("/users/me", headers=bearer(
            manager.create_access_token(EMAIL, user_id=tenant.id)
        )).status_code == 401

    async def test_a_token_without_an_id_finds_the_default_scope_account(self, client, create_test_user):
        default = await account(create_test_user)
        await account(create_test_user, scope="t1")
        legacy = get_auth_manager().create_access_token(EMAIL)

        response = client.get("/users/me", headers=bearer(legacy))
        assert response.status_code == 200
        assert response.json()["id"] == default.id

    async def test_changing_the_email_still_ends_tokens_for_the_old_one(
        self, client, user_service, create_test_user
    ):
        user = await account(create_test_user)
        token = await login(user_service)
        await user_service.update_user(user.id, UserUpdate(email="new@example.com"))

        assert client.get("/users/me", headers=bearer(token)).status_code == 401

    async def test_a_non_string_scope_claim_is_rejected(self, auth_config):
        token = jwt.encode(
            {"sub": EMAIL, "uid": 1, "scope": 5},
            auth_config.secret_key, algorithm=auth_config.algorithm,
        )
        assert get_auth_manager().verify_token(token) is None


@pytest.mark.asyncio
class TestRoutes:

    async def test_register_and_login_take_the_scope_from_the_body(self, client, emails):
        response = client.post("/users/register", json={
            "email": EMAIL, "password": PASSWORD, "scope": "t1"
        })
        assert response.status_code == 200
        assert response.json()["scope"] == "t1"

        # Same address in the default scope is a different account
        assert client.post("/users/register", json={
            "email": EMAIL, "password": PASSWORD
        }).status_code == 200

    async def test_login_route_uses_the_body_scope(self, client, create_test_user, auth_config):
        tenant = await account(create_test_user, scope="t1")

        response = client.post("/users/login", json={
            "email": EMAIL, "password": PASSWORD, "scope": "t1"
        })
        assert response.status_code == 200
        assert claims(response.json()["access_token"], auth_config)["uid"] == tenant.id

        assert client.post("/users/login", json={
            "email": EMAIL, "password": PASSWORD
        }).status_code == 401

    async def test_a_scope_longer_than_the_column_is_refused(self, client):
        assert client.post("/users/login", json={
            "email": EMAIL, "password": PASSWORD, "scope": "x" * 101
        }).status_code == 422


@pytest.mark.asyncio
class TestRequestScope:
    """An app that knows each request's scope registers a function for it."""

    @staticmethod
    def by_header(request):
        return request.headers.get("x-scope")

    async def test_the_request_scope_is_used_when_the_body_has_none(
        self, client, create_test_user, auth_config
    ):
        configure_scope(enabled=True, request_scope=self.by_header)
        tenant = await account(create_test_user, scope="t1")

        response = client.post(
            "/users/login", json={"email": EMAIL, "password": PASSWORD},
            headers={"x-scope": "t1"}
        )
        assert response.status_code == 200
        assert claims(response.json()["access_token"], auth_config)["uid"] == tenant.id

    async def test_a_body_scope_that_differs_is_refused(self, client, create_test_user):
        configure_scope(enabled=True, request_scope=self.by_header)
        await account(create_test_user, scope="t1")

        response = client.post(
            "/users/login", json={"email": EMAIL, "password": PASSWORD, "scope": "t1"},
            headers={"x-scope": "t2"}
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Scope doesn't match this request"

    async def test_a_token_is_rejected_in_another_scopes_request(
        self, client, user_service, create_test_user
    ):
        configure_scope(enabled=True, request_scope=self.by_header)
        await account(create_test_user, scope="t1")
        token = await login(user_service, scope="t1")

        assert client.get("/users/me", headers={**bearer(token), "x-scope": "t1"}).status_code == 200
        assert client.get("/users/me", headers={**bearer(token), "x-scope": "t2"}).status_code == 401

    async def test_no_request_scope_means_the_tokens_scope_stands(
        self, client, user_service, create_test_user
    ):
        configure_scope(enabled=True, request_scope=self.by_header)
        await account(create_test_user, scope="t1")
        token = await login(user_service, scope="t1")

        assert client.get("/users/me", headers=bearer(token)).status_code == 200

    async def test_the_function_may_be_a_coroutine(self, client, create_test_user):
        async def request_scope(request):
            return "t1"
        configure_scope(enabled=True, request_scope=request_scope)
        await account(create_test_user, scope="t1")

        assert client.post(
            "/users/login", json={"email": EMAIL, "password": PASSWORD}
        ).status_code == 200


@pytest.mark.asyncio
class TestPublicFlows:

    async def test_password_reset_goes_to_the_account_in_the_named_scope(
        self, user_service, create_test_user, db_session, emails
    ):
        await account(create_test_user)
        tenant = await account(create_test_user, scope="t1")

        await user_service.request_password_reset(PasswordResetRequest(email=EMAIL, scope="t1"))

        assert [row.user_id for row in db_session.query(PasswordResetToken).all()] == [tenant.id]

    async def test_password_reset_route_uses_the_body_scope(
        self, client, create_test_user, db_session, emails
    ):
        tenant = await account(create_test_user, scope="t1")

        assert client.post("/users/password-reset/request", json={"email": EMAIL}).status_code == 200
        assert db_session.query(PasswordResetToken).count() == 0

        client.post("/users/password-reset/request", json={"email": EMAIL, "scope": "t1"})
        assert [row.user_id for row in db_session.query(PasswordResetToken).all()] == [tenant.id]

    async def test_resend_verification_stays_in_its_scope(self, user_service, create_test_user, emails):
        configure_verification(VerificationConfig(send_verification_on_register=False))
        await create_test_user(email=EMAIL, scope="t1")

        await user_service.resend_verification_email(EmailVerificationResend(email=EMAIL))
        assert emails.recipients("send_verification_email") == []

        await user_service.resend_verification_email(EmailVerificationResend(email=EMAIL, scope="t1"))
        assert emails.recipients("send_verification_email") == [EMAIL]

    async def test_email_change_only_checks_the_accounts_own_scope(
        self, user_service, create_test_user, emails
    ):
        configure_verification(VerificationConfig(allow_email_change=True))
        await account(create_test_user, scope="t1", email="taken@example.com")
        user = await account(create_test_user)

        assert await user_service.request_email_change(
            user.id, EmailChangeRequest(current_password=PASSWORD, new_email="taken@example.com")
        ) is True

        await account(create_test_user, email="mine@example.com", username="other")
        with pytest.raises(HTTPException) as error:
            await user_service.request_email_change(
                user.id, EmailChangeRequest(current_password=PASSWORD, new_email="mine@example.com")
            )
        assert error.value.detail == "Email already registered"


@pytest.mark.asyncio
class TestScopesOff:
    """An app that doesn't turn scopes on behaves as before they existed."""

    @pytest.fixture(autouse=True)
    def scopes_off(self):
        configure_scope(enabled=False)

    async def test_off_is_the_default(self):
        # A fresh interpreter, since this module's fixtures set the flag
        result = subprocess.run(
            [sys.executable, "-c", "import users; print(users.scopes_enabled())"],
            capture_output=True, text=True, check=True
        )
        assert result.stdout.strip() == "False"

    @pytest.mark.parametrize("path,body", [
        ("/users/register", {"email": EMAIL, "password": PASSWORD, "scope": "t1"}),
        ("/users/login", {"email": EMAIL, "password": PASSWORD, "scope": "t1"}),
        ("/users/password-reset/request", {"email": EMAIL, "scope": "t1"}),
        ("/users/verify-email/resend", {"email": EMAIL, "scope": "t1"}),
    ])
    async def test_a_body_naming_a_scope_is_refused(self, client, emails, path, body):
        response = client.post(path, json=body)
        assert response.status_code == 400
        assert response.json()["detail"] == "Scopes are not enabled"

    async def test_nobody_can_create_a_second_account_for_an_address(self, client, create_test_user, emails):
        await account(create_test_user)

        assert client.post("/users/register", json={
            "email": EMAIL, "password": PASSWORD, "scope": "t1"
        }).status_code == 400
        assert client.post("/users/register", json={
            "email": EMAIL, "password": PASSWORD
        }).json()["detail"] == "Email already registered"

    async def test_server_code_cant_create_an_account_in_a_scope(self, user_service):
        with pytest.raises(HTTPException) as error:
            await user_service.create_user(
                UserCreate(email=EMAIL, password=PASSWORD, scope="t1"), trusted=True
            )
        assert error.value.status_code == 400

    async def test_the_default_scope_named_explicitly_is_fine(self, client, create_test_user):
        await account(create_test_user)

        assert client.post("/users/login", json={
            "email": EMAIL, "password": PASSWORD, "scope": ""
        }).status_code == 200

    async def test_everything_works_as_before(self, client, create_test_user, auth_config):
        user = await account(create_test_user)

        response = client.post("/users/login", json={"email": EMAIL, "password": PASSWORD})
        token = response.json()["access_token"]
        assert claims(token, auth_config)["scope"] == ""
        me = client.get("/users/me", headers=bearer(token))
        assert (me.json()["id"], me.json()["scope"]) == (user.id, "")

    async def test_a_request_scope_function_needs_scopes_on(self):
        with pytest.raises(ValueError):
            configure_scope(enabled=False, request_scope=lambda request: "t1")


class PreScopeRepository(SQLAlchemyUserRepository):
    """A custom repository written before scopes: its lookups take no scope."""

    async def get_user_by_email(self, email):
        return await super().get_user_by_email(email)

    async def get_user_by_username(self, username):
        return await super().get_user_by_username(username)


@pytest.mark.asyncio
async def test_a_custom_repository_without_scopes_keeps_working(db_session, auth_manager):
    service = UserService(PreScopeRepository(db_session))

    await service.create_user(
        UserCreate(email=EMAIL, username="sam", password=PASSWORD, status="active"), trusted=True
    )
    token = await service.login(UserLogin(email=EMAIL, password=PASSWORD))

    assert token.access_token
    assert (await service.get_user_by_email(EMAIL)).username == "sam"
