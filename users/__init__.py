__version__ = "0.1.0"

# Core models and schemas
from .models import (
    User, Role, PermissionModel,
    UserCreate, UserUpdate, UserResponse, UserLogin, Token,
    RoleCreate, RoleResponse, PermissionCreate, PermissionResponse,
    UserStatus, Permission, configure_base
)

# Authentication
from .auth import (
    AuthConfig, AuthManager, PasswordManager, JWTManager,
    configure_auth, get_auth_manager
)

# Database
from .database import (
    DatabaseConfig, SyncDatabaseManager, AsyncDatabaseManager,
    configure_sync_database, configure_async_database,
    get_sync_db_manager, get_async_db_manager
)

# Repository layer
from .repository import (
    UserRepositoryInterface, SQLAlchemyUserRepository,
    RoleRepository, PermissionRepository
)

# Service layer
from .service import UserService, RoleService, PermissionService

# FastAPI dependencies
from .dependencies import (
    get_current_user, get_current_active_user, get_current_verified_user,
    get_current_superuser, get_current_user_optional,
    RequirePermissions, RequireRole,
    require_permission, require_permissions, require_role, require_roles,
    get_user_service, db_dependency
)

# FastAPI routes
from .routes import (
    create_user_router, create_role_router, create_permission_router
)

# MongoDB support (if available)
try:
    from .database import (
        MongoConfig, MongoManager, AsyncMongoManager,
        configure_mongo_database, configure_async_mongo_database,
        get_mongo_manager, get_async_mongo_manager
    )
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

# Convenience configuration functions
def setup_users_package(
    secret_key: str,
    database_url: str,
    algorithm: str = "HS256",
    access_token_expire_minutes: int = 30,
    create_tables: bool = True,
    **database_kwargs
):
    """
    Quick setup function for the users package with SQLAlchemy.

    Args:
        secret_key: JWT secret key
        database_url: Database connection URL
        algorithm: JWT algorithm (default: HS256)
        access_token_expire_minutes: Token expiry time in minutes
        create_tables: Whether to create database tables automatically
        **database_kwargs: Additional database configuration options

    Returns:
        Tuple of (auth_manager, db_manager)
    """

    # Configure authentication
    auth_config = AuthConfig(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes
    )
    auth_manager = configure_auth(auth_config)

    # Configure database
    db_config = DatabaseConfig(database_url, **database_kwargs)
    db_manager = configure_sync_database(db_config)

    # Configure database dependency
    db_dependency.set_session_factory(db_manager.get_session)

    # Create tables if requested
    if create_tables:
        db_manager.create_tables()

    return auth_manager, db_manager

async def setup_users_package_async(
    secret_key: str,
    database_url: str,
    algorithm: str = "HS256",
    access_token_expire_minutes: int = 30,
    create_tables: bool = True,
    **database_kwargs
):
    """
    Quick setup function for the users package with async SQLAlchemy.

    Args:
        secret_key: JWT secret key
        database_url: Database connection URL
        algorithm: JWT algorithm (default: HS256)
        access_token_expire_minutes: Token expiry time in minutes
        create_tables: Whether to create database tables automatically
        **database_kwargs: Additional database configuration options

    Returns:
        Tuple of (auth_manager, db_manager)
    """

    # Configure authentication
    auth_config = AuthConfig(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes
    )
    auth_manager = configure_auth(auth_config)

    # Configure database
    db_config = DatabaseConfig(database_url, **database_kwargs)
    db_manager = configure_async_database(db_config)

    # Create tables if requested
    if create_tables:
        await db_manager.create_tables()

    return auth_manager, db_manager

def create_default_permissions():
    """
    Create a set of default permissions for common resources.

    Returns:
        List of permission dictionaries
    """
    resources = ["users", "roles", "permissions"]
    actions = ["read", "write", "delete", "admin"]

    permissions = []
    for resource in resources:
        for action in actions:
            permissions.append({
                "name": f"{resource}:{action}",
                "resource": resource,
                "action": action,
                "description": f"{action.title()} access to {resource}"
            })

    return permissions

def create_default_roles():
    """
    Create a set of default roles with appropriate permissions.

    Returns:
        Dictionary of role configurations
    """
    return {
        "admin": {
            "name": "admin",
            "description": "Full system administrator",
            "permissions": [
                "users:read", "users:write", "users:delete", "users:admin",
                "roles:read", "roles:write", "roles:delete", "roles:admin",
                "permissions:read", "permissions:write", "permissions:delete", "permissions:admin"
            ]
        },
        "user_manager": {
            "name": "user_manager",
            "description": "Can manage users but not system roles/permissions",
            "permissions": [
                "users:read", "users:write", "users:delete"
            ]
        },
        "viewer": {
            "name": "viewer",
            "description": "Read-only access to user information",
            "permissions": [
                "users:read"
            ]
        }
    }

# Export convenience functions
__all__ = [
    # Core models
    "User", "Role", "PermissionModel",
    "UserCreate", "UserUpdate", "UserResponse", "UserLogin", "Token",
    "RoleCreate", "RoleResponse", "PermissionCreate", "PermissionResponse",
    "UserStatus", "Permission", "configure_base",

    # Authentication
    "AuthConfig", "AuthManager", "PasswordManager", "JWTManager",
    "configure_auth", "get_auth_manager",

    # Database
    "DatabaseConfig", "SyncDatabaseManager", "AsyncDatabaseManager",
    "configure_sync_database", "configure_async_database",
    "get_sync_db_manager", "get_async_db_manager",

    # Repository
    "UserRepositoryInterface", "SQLAlchemyUserRepository",
    "RoleRepository", "PermissionRepository",

    # Service
    "UserService", "RoleService", "PermissionService",

    # Dependencies
    "get_current_user", "get_current_active_user", "get_current_verified_user",
    "get_current_superuser", "get_current_user_optional",
    "RequirePermissions", "RequireRole",
    "require_permission", "require_permissions", "require_role", "require_roles",
    "get_user_service", "db_dependency",

    # Routes
    "create_user_router", "create_role_router", "create_permission_router",

    # Setup functions
    "setup_users_package", "setup_users_package_async",
    "create_default_permissions", "create_default_roles",

    # Constants
    "MONGODB_AVAILABLE",
]