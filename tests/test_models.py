import pytest
from datetime import datetime
from pydantic import ValidationError
from users.models import (
    UserCreate, UserUpdate, UserResponse, UserLogin, Token,
    RoleCreate, RoleResponse, PermissionCreate, PermissionResponse,
    UserStatus, Permission
)

class TestUserCreate:
    def test_valid_user_create(self):
        user_data = UserCreate(
            email="test@example.com",
            password="test_password_123",
            username="testuser",
            first_name="Test",
            last_name="User"
        )

        assert user_data.email == "test@example.com"
        assert user_data.password == "test_password_123"
        assert user_data.username == "testuser"
        assert user_data.status == UserStatus.PENDING
        assert user_data.is_superuser is False

    def test_user_create_invalid_email(self):
        with pytest.raises(ValidationError):
            UserCreate(
                email="invalid_email",
                password="test_password_123"
            )

    def test_user_create_short_password(self):
        with pytest.raises(ValidationError):
            UserCreate(
                email="test@example.com",
                password="short"
            )

    def test_user_create_minimal(self):
        user_data = UserCreate(
            email="test@example.com",
            password="test_password_123"
        )

        assert user_data.email == "test@example.com"
        assert user_data.username is None
        assert user_data.roles == []

class TestUserUpdate:
    def test_user_update_partial(self):
        user_data = UserUpdate(
            first_name="Updated",
            status=UserStatus.ACTIVE
        )

        assert user_data.first_name == "Updated"
        assert user_data.status == UserStatus.ACTIVE
        assert user_data.email is None

    def test_user_update_empty(self):
        user_data = UserUpdate()

        assert user_data.email is None
        assert user_data.username is None

class TestUserResponse:
    def test_user_response_creation(self):
        user_data = UserResponse(
            id=1,
            email="test@example.com",
            username="testuser",
            status=UserStatus.ACTIVE,
            is_superuser=False,
            is_verified=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            roles=["user", "admin"]
        )

        assert user_data.id == 1
        assert user_data.email == "test@example.com"
        assert user_data.roles == ["user", "admin"]

class TestUserLogin:
    def test_valid_login(self):
        login_data = UserLogin(
            email="test@example.com",
            password="test_password_123"
        )

        assert login_data.email == "test@example.com"
        assert login_data.password == "test_password_123"

class TestToken:
    def test_token_creation(self):
        token = Token(
            access_token="test_token_12345",
            expires_in=3600
        )

        assert token.access_token == "test_token_12345"
        assert token.token_type == "bearer"
        assert token.expires_in == 3600

    def test_token_default_type(self):
        token = Token(access_token="test_token")

        assert token.token_type == "bearer"

class TestRoleCreate:
    def test_role_create_valid(self):
        role_data = RoleCreate(
            name="admin",
            description="Administrator role",
            permissions=["users:read", "users:write"]
        )

        assert role_data.name == "admin"
        assert role_data.description == "Administrator role"
        assert role_data.permissions == ["users:read", "users:write"]

    def test_role_create_minimal(self):
        role_data = RoleCreate(name="user")

        assert role_data.name == "user"
        assert role_data.description is None
        assert role_data.permissions == []

class TestRoleResponse:
    def test_role_response_creation(self):
        role_data = RoleResponse(
            id=1,
            name="admin",
            description="Administrator role",
            created_at=datetime.utcnow(),
            permissions=["users:read", "users:write"]
        )

        assert role_data.id == 1
        assert role_data.name == "admin"
        assert role_data.permissions == ["users:read", "users:write"]

class TestPermissionCreate:
    def test_permission_create_valid(self):
        permission_data = PermissionCreate(
            name="users:read",
            resource="users",
            action="read",
            description="Read access to users"
        )

        assert permission_data.name == "users:read"
        assert permission_data.resource == "users"
        assert permission_data.action == "read"
        assert permission_data.description == "Read access to users"

    def test_permission_create_minimal(self):
        permission_data = PermissionCreate(
            name="users:write",
            resource="users",
            action="write"
        )

        assert permission_data.name == "users:write"
        assert permission_data.description is None

class TestPermissionResponse:
    def test_permission_response_creation(self):
        permission_data = PermissionResponse(
            id=1,
            name="users:read",
            resource="users",
            action="read",
            description="Read access to users"
        )

        assert permission_data.id == 1
        assert permission_data.name == "users:read"

class TestEnums:
    def test_user_status_enum(self):
        assert UserStatus.ACTIVE == "active"
        assert UserStatus.INACTIVE == "inactive"
        assert UserStatus.SUSPENDED == "suspended"
        assert UserStatus.PENDING == "pending"

    def test_permission_enum(self):
        assert Permission.READ == "read"
        assert Permission.WRITE == "write"
        assert Permission.DELETE == "delete"
        assert Permission.ADMIN == "admin"

class TestModelValidation:
    def test_user_create_with_invalid_status(self):
        # This should work as status is validated by the enum
        user_data = UserCreate(
            email="test@example.com",
            password="test_password_123",
            status=UserStatus.ACTIVE
        )
        assert user_data.status == UserStatus.ACTIVE

    def test_user_response_requires_id(self):
        with pytest.raises(ValidationError):
            UserResponse(
                email="test@example.com",
                status=UserStatus.ACTIVE,
                is_superuser=False,
                is_verified=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
                # Missing required 'id' field
            )