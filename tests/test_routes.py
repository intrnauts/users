import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from users.dependencies import get_user_service
from users.models import UserLogin
from users.routes import create_user_router


@pytest.fixture
def client(user_service):
    app = FastAPI()
    app.include_router(create_user_router(include_admin=False))
    app.dependency_overrides[get_user_service] = lambda: user_service
    return TestClient(app)


async def _login(user_service, create_test_user, email="test@example.com"):
    await create_test_user(email=email, username="testuser", status="active")
    token = await user_service.login(
        UserLogin(email=email, password="test_password_123")
    )
    return {"Authorization": f"Bearer {token.access_token}"}


@pytest.mark.asyncio
async def test_self_update_refuses_email(client, user_service, create_test_user):
    """PUT /users/me must not change the email (#42)"""
    headers = await _login(user_service, create_test_user)

    response = client.put(
        "/users/me",
        json={"email": "attacker@example.com", "first_name": "Changed"},
        headers=headers,
    )

    assert response.status_code == 400
    assert await user_service.get_user_by_email("attacker@example.com") is None
    user = await user_service.get_user_by_email("test@example.com")
    assert user is not None
    # The whole request is refused, not just the email field
    assert user.first_name != "Changed"


@pytest.mark.asyncio
async def test_self_update_without_email_still_works(client, user_service, create_test_user):
    headers = await _login(user_service, create_test_user)

    response = client.put(
        "/users/me", json={"first_name": "Changed"}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["first_name"] == "Changed"
    assert response.json()["email"] == "test@example.com"
