import pytest
import tempfile
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from users.models import Base
from users.auth import AuthConfig, configure_auth
from users.database import DatabaseConfig, configure_sync_database
from users.repository import SQLAlchemyUserRepository, RoleRepository, PermissionRepository
from users.service import UserService, RoleService, PermissionService

@pytest.fixture
def auth_config():
    """Test authentication configuration"""
    return AuthConfig(
        secret_key="test_secret_key_for_testing_12345",
        algorithm="HS256",
        access_token_expire_minutes=30
    )

@pytest.fixture
def auth_manager(auth_config):
    """Configured auth manager for testing"""
    return configure_auth(auth_config)

@pytest.fixture
def test_db():
    """Create a temporary SQLite database for testing"""
    # Create temporary file
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    database_url = f"sqlite:///{db_path}"

    # Create engine and tables
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(bind=engine)

    # Create session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    yield SessionLocal

    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def db_session(test_db):
    """Database session for testing"""
    session = test_db()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def user_repository(db_session):
    """User repository for testing"""
    return SQLAlchemyUserRepository(db_session)

@pytest.fixture
def role_repository(db_session):
    """Role repository for testing"""
    return RoleRepository(db_session)

@pytest.fixture
def permission_repository(db_session):
    """Permission repository for testing"""
    return PermissionRepository(db_session)

@pytest.fixture
def user_service(user_repository, role_repository, permission_repository):
    """User service for testing"""
    return UserService(user_repository, role_repository, permission_repository)

@pytest.fixture
def role_service(role_repository):
    """Role service for testing"""
    return RoleService(role_repository)

@pytest.fixture
def permission_service(permission_repository):
    """Permission service for testing"""
    return PermissionService(permission_repository)

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    from users.models import UserCreate
    return UserCreate(
        email="test@example.com",
        username="testuser",
        password="test_password_123",
        first_name="Test",
        last_name="User"
    )

@pytest.fixture
def sample_role_data():
    """Sample role data for testing"""
    return {
        "name": "test_role",
        "description": "Test role for testing",
        "permissions": []
    }

@pytest.fixture
def sample_permission_data():
    """Sample permission data for testing"""
    return {
        "name": "test:read",
        "resource": "test",
        "action": "read",
        "description": "Test permission for reading"
    }

@pytest.fixture(autouse=True)
def setup_auth_for_tests(auth_manager):
    """Automatically setup auth manager for all tests"""
    # This ensures the global auth manager is configured for dependency injection
    pass

@pytest.fixture
def create_test_user(user_service, auth_manager):
    """Helper fixture to create a test user"""
    async def _create_user(email="test@example.com", password="test_password_123", **kwargs):
        from users.models import UserCreate
        user_data = UserCreate(
            email=email,
            password=password,
            **kwargs
        )
        return await user_service.create_user(user_data)

    return _create_user

@pytest.fixture
def create_test_role(role_service):
    """Helper fixture to create a test role"""
    async def _create_role(name="test_role", description=None, permissions=None):
        return await role_service.create_role(name, description, permissions or [])

    return _create_role

@pytest.fixture
def create_test_permission(permission_service):
    """Helper fixture to create a test permission"""
    async def _create_permission(name="test:read", resource="test", action="read", description=None):
        return await permission_service.create_permission(name, resource, action, description)

    return _create_permission

# Async test utilities
@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# Database configuration for integration tests
@pytest.fixture
def db_config():
    """Database configuration for testing"""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    database_url = f"sqlite:///{db_path}"

    config = DatabaseConfig(database_url, echo=False)

    yield config

    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def db_manager(db_config):
    """Database manager for testing"""
    manager = configure_sync_database(db_config)
    manager.create_tables()

    yield manager

# Test data factories
class UserFactory:
    @staticmethod
    def create_user_data(**overrides):
        from users.models import UserCreate
        defaults = {
            "email": "test@example.com",
            "password": "test_password_123",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User"
        }
        defaults.update(overrides)
        return UserCreate(**defaults)

    @staticmethod
    def create_multiple_users(count=3):
        users = []
        for i in range(count):
            users.append(UserFactory.create_user_data(
                email=f"test{i}@example.com",
                username=f"testuser{i}"
            ))
        return users

class RoleFactory:
    @staticmethod
    def create_role_data(**overrides):
        defaults = {
            "name": "test_role",
            "description": "Test role",
            "permissions": []
        }
        defaults.update(overrides)
        return defaults

class PermissionFactory:
    @staticmethod
    def create_permission_data(**overrides):
        defaults = {
            "name": "test:read",
            "resource": "test",
            "action": "read",
            "description": "Test permission"
        }
        defaults.update(overrides)
        return defaults

@pytest.fixture
def user_factory():
    return UserFactory

@pytest.fixture
def role_factory():
    return RoleFactory

@pytest.fixture
def permission_factory():
    return PermissionFactory