import pytest
from fastapi import HTTPException
from users.models import UserCreate, UserUpdate, UserLogin, UserStatus

@pytest.mark.asyncio
class TestUserService:
    async def test_create_user_success(self, user_service, sample_user_data, auth_manager):
        user_response = await user_service.create_user(sample_user_data)

        assert user_response.email == sample_user_data.email
        assert user_response.username == sample_user_data.username
        assert user_response.first_name == sample_user_data.first_name
        assert user_response.last_name == sample_user_data.last_name
        assert user_response.status == UserStatus.PENDING
        assert user_response.is_superuser is False
        assert user_response.id > 0

    async def test_create_user_duplicate_email(self, user_service, sample_user_data):
        # Create first user
        await user_service.create_user(sample_user_data)

        # Try to create user with same email
        duplicate_user = UserCreate(
            email=sample_user_data.email,
            password="different_password_123",
            username="different_username"
        )

        with pytest.raises(HTTPException) as exc_info:
            await user_service.create_user(duplicate_user)

        assert exc_info.value.status_code == 400
        assert "Email already registered" in str(exc_info.value.detail)

    async def test_create_user_duplicate_username(self, user_service, sample_user_data):
        # Create first user
        await user_service.create_user(sample_user_data)

        # Try to create user with same username
        duplicate_user = UserCreate(
            email="different@example.com",
            password="test_password_123",
            username=sample_user_data.username
        )

        with pytest.raises(HTTPException) as exc_info:
            await user_service.create_user(duplicate_user)

        assert exc_info.value.status_code == 400
        assert "Username already taken" in str(exc_info.value.detail)

    async def test_authenticate_user_success(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Authenticate
        login_data = UserLogin(
            email=sample_user_data.email,
            password=sample_user_data.password
        )
        authenticated_user = await user_service.authenticate_user(login_data)

        assert authenticated_user is not None
        assert authenticated_user.email == sample_user_data.email

    async def test_authenticate_user_wrong_password(self, user_service, sample_user_data):
        # Create user
        await user_service.create_user(sample_user_data)

        # Try to authenticate with wrong password
        login_data = UserLogin(
            email=sample_user_data.email,
            password="wrong_password"
        )
        authenticated_user = await user_service.authenticate_user(login_data)

        assert authenticated_user is None

    async def test_authenticate_user_not_exists(self, user_service):
        login_data = UserLogin(
            email="nonexistent@example.com",
            password="any_password"
        )
        authenticated_user = await user_service.authenticate_user(login_data)

        assert authenticated_user is None

    async def test_login_success(self, user_service, sample_user_data):
        # Create user
        await user_service.create_user(sample_user_data)

        # Login
        login_data = UserLogin(
            email=sample_user_data.email,
            password=sample_user_data.password
        )
        token = await user_service.login(login_data)

        assert token.access_token is not None
        assert token.token_type == "bearer"
        assert token.expires_in > 0

    async def test_login_failure(self, user_service, sample_user_data):
        # Create user
        await user_service.create_user(sample_user_data)

        # Try to login with wrong password
        login_data = UserLogin(
            email=sample_user_data.email,
            password="wrong_password"
        )

        with pytest.raises(HTTPException) as exc_info:
            await user_service.login(login_data)

        assert exc_info.value.status_code == 401
        assert "Incorrect email or password" in str(exc_info.value.detail)

    async def test_get_user_by_id(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Get user by ID
        retrieved_user = await user_service.get_user_by_id(user_response.id)

        assert retrieved_user is not None
        assert retrieved_user.id == user_response.id
        assert retrieved_user.email == sample_user_data.email

    async def test_get_user_by_id_not_found(self, user_service):
        retrieved_user = await user_service.get_user_by_id(99999)
        assert retrieved_user is None

    async def test_get_user_by_email(self, user_service, sample_user_data):
        # Create user
        await user_service.create_user(sample_user_data)

        # Get user by email
        retrieved_user = await user_service.get_user_by_email(sample_user_data.email)

        assert retrieved_user is not None
        assert retrieved_user.email == sample_user_data.email

    async def test_update_user_success(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Update user
        update_data = UserUpdate(
            first_name="Updated",
            last_name="Name",
            status=UserStatus.ACTIVE
        )
        updated_user = await user_service.update_user(user_response.id, update_data)

        assert updated_user is not None
        assert updated_user.first_name == "Updated"
        assert updated_user.last_name == "Name"
        assert updated_user.status == UserStatus.ACTIVE

    async def test_update_user_not_found(self, user_service):
        update_data = UserUpdate(first_name="Updated")
        updated_user = await user_service.update_user(99999, update_data)

        assert updated_user is None

    async def test_update_user_duplicate_email(self, user_service, user_factory):
        # Create two users
        user1_data = user_factory.create_user_data(email="user1@example.com")
        user2_data = user_factory.create_user_data(email="user2@example.com")

        user1 = await user_service.create_user(user1_data)
        user2 = await user_service.create_user(user2_data)

        # Try to update user2 with user1's email
        update_data = UserUpdate(email="user1@example.com")

        with pytest.raises(HTTPException) as exc_info:
            await user_service.update_user(user2.id, update_data)

        assert exc_info.value.status_code == 400
        assert "Email already registered" in str(exc_info.value.detail)

    async def test_delete_user_success(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Delete user
        success = await user_service.delete_user(user_response.id)

        assert success is True

        # Verify user is deleted
        deleted_user = await user_service.get_user_by_id(user_response.id)
        assert deleted_user is None

    async def test_delete_user_not_found(self, user_service):
        success = await user_service.delete_user(99999)
        assert success is False

    async def test_list_users(self, user_service, user_factory):
        # Create multiple users
        users_data = user_factory.create_multiple_users(3)

        created_users = []
        for user_data in users_data:
            user = await user_service.create_user(user_data)
            created_users.append(user)

        # List users
        users_list = await user_service.list_users()

        assert len(users_list) == 3
        assert all(user.id in [u.id for u in created_users] for user in users_list)

    async def test_list_users_with_pagination(self, user_service, user_factory):
        # Create multiple users
        users_data = user_factory.create_multiple_users(5)

        for user_data in users_data:
            await user_service.create_user(user_data)

        # List users with pagination
        users_page1 = await user_service.list_users(skip=0, limit=3)
        users_page2 = await user_service.list_users(skip=3, limit=3)

        assert len(users_page1) == 3
        assert len(users_page2) == 2

    async def test_list_users_with_filters(self, user_service, user_factory):
        # Create users with different statuses
        active_user = user_factory.create_user_data(
            email="active@example.com",
            status=UserStatus.ACTIVE
        )
        pending_user = user_factory.create_user_data(
            email="pending@example.com",
            status=UserStatus.PENDING
        )

        await user_service.create_user(active_user)
        await user_service.create_user(pending_user)

        # Filter by status
        active_users = await user_service.list_users(filters={"status": UserStatus.ACTIVE})
        pending_users = await user_service.list_users(filters={"status": UserStatus.PENDING})

        assert len(active_users) == 1
        assert active_users[0].status == UserStatus.ACTIVE

        assert len(pending_users) == 1
        assert pending_users[0].status == UserStatus.PENDING

    async def test_verify_user(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Verify user
        verified_user = await user_service.verify_user(user_response.id)

        assert verified_user is not None
        assert verified_user.is_verified is True
        assert verified_user.status == UserStatus.ACTIVE

    async def test_verify_user_not_found(self, user_service):
        verified_user = await user_service.verify_user(99999)
        assert verified_user is None

    async def test_get_user_permissions(self, user_service, sample_user_data):
        # Create user
        user_response = await user_service.create_user(sample_user_data)

        # Get user permissions (should be empty for new user)
        permissions = await user_service.get_user_permissions(user_response.id)

        assert isinstance(permissions, list)
        # New user without roles should have no permissions
        assert len(permissions) == 0

@pytest.mark.asyncio
class TestRoleService:
    async def test_create_role_success(self, role_service, sample_role_data):
        role = await role_service.create_role(**sample_role_data)

        assert role.name == sample_role_data["name"]
        assert role.description == sample_role_data["description"]

    async def test_create_role_duplicate(self, role_service, sample_role_data):
        # Create first role
        await role_service.create_role(**sample_role_data)

        # Try to create role with same name
        with pytest.raises(HTTPException) as exc_info:
            await role_service.create_role(**sample_role_data)

        assert exc_info.value.status_code == 400
        assert "Role already exists" in str(exc_info.value.detail)

    async def test_get_role_by_name(self, role_service, sample_role_data):
        # Create role
        created_role = await role_service.create_role(**sample_role_data)

        # Get role by name
        retrieved_role = await role_service.get_role_by_name(sample_role_data["name"])

        assert retrieved_role is not None
        assert retrieved_role.id == created_role.id
        assert retrieved_role.name == sample_role_data["name"]

    async def test_list_roles(self, role_service, role_factory):
        # Create multiple roles
        roles_data = [
            role_factory.create_role_data(name="admin"),
            role_factory.create_role_data(name="user"),
            role_factory.create_role_data(name="viewer")
        ]

        for role_data in roles_data:
            await role_service.create_role(**role_data)

        # List roles
        roles_list = await role_service.list_roles()

        assert len(roles_list) == 3
        role_names = [role.name for role in roles_list]
        assert "admin" in role_names
        assert "user" in role_names
        assert "viewer" in role_names

    async def test_delete_role(self, role_service, sample_role_data):
        # Create role
        created_role = await role_service.create_role(**sample_role_data)

        # Delete role
        success = await role_service.delete_role(created_role.id)

        assert success is True

        # Verify role is deleted
        deleted_role = await role_service.get_role_by_name(sample_role_data["name"])
        assert deleted_role is None

@pytest.mark.asyncio
class TestPermissionService:
    async def test_create_permission_success(self, permission_service, sample_permission_data):
        permission = await permission_service.create_permission(**sample_permission_data)

        assert permission.name == sample_permission_data["name"]
        assert permission.resource == sample_permission_data["resource"]
        assert permission.action == sample_permission_data["action"]

    async def test_create_permission_duplicate(self, permission_service, sample_permission_data):
        # Create first permission
        await permission_service.create_permission(**sample_permission_data)

        # Try to create permission with same name
        with pytest.raises(HTTPException) as exc_info:
            await permission_service.create_permission(**sample_permission_data)

        assert exc_info.value.status_code == 400
        assert "Permission already exists" in str(exc_info.value.detail)

    async def test_list_permissions(self, permission_service, permission_factory):
        # Create multiple permissions
        permissions_data = [
            permission_factory.create_permission_data(name="users:read", action="read"),
            permission_factory.create_permission_data(name="users:write", action="write"),
            permission_factory.create_permission_data(name="roles:read", resource="roles", action="read")
        ]

        for permission_data in permissions_data:
            await permission_service.create_permission(**permission_data)

        # List permissions
        permissions_list = await permission_service.list_permissions()

        assert len(permissions_list) == 3
        permission_names = [perm.name for perm in permissions_list]
        assert "users:read" in permission_names
        assert "users:write" in permission_names
        assert "roles:read" in permission_names

    async def test_delete_permission(self, permission_service, sample_permission_data):
        # Create permission
        created_permission = await permission_service.create_permission(**sample_permission_data)

        # Delete permission
        success = await permission_service.delete_permission(created_permission.id)

        assert success is True