from typing import Optional, List
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .auth import get_auth_manager
from .models import User, TokenData
from .service import UserService
from .repository import SQLAlchemyUserRepository

security = HTTPBearer()

class DatabaseDependency:
    """Base class for database dependency injection"""
    def __init__(self):
        self._db_session_factory = None

    def set_session_factory(self, session_factory):
        self._db_session_factory = session_factory

    def get_db(self) -> Session:
        if self._db_session_factory is None:
            raise RuntimeError("Database session factory not configured")

        db = self._db_session_factory()
        try:
            yield db
        finally:
            db.close()

# Global database dependency instance
db_dependency = DatabaseDependency()

def get_db() -> Session:
    """FastAPI dependency for database session"""
    return db_dependency.get_db()

def get_user_service(db: Session = Depends(get_db)) -> UserService:
    """FastAPI dependency for user service"""
    user_repo = SQLAlchemyUserRepository(db)
    return UserService(user_repo)

async def get_current_user_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenData:
    """Extract and validate JWT token"""
    auth_manager = get_auth_manager()
    token_data = auth_manager.verify_token(credentials.credentials)

    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data

async def get_current_user(
    token_data: TokenData = Depends(get_current_user_token),
    user_service: UserService = Depends(get_user_service)
) -> User:
    """Get current authenticated user"""
    user = await user_service.get_user_by_email(token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (not suspended/inactive)"""
    if current_user.status not in ["active"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user"""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )

    return current_user

async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current superuser"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    return current_user

class RequirePermissions:
    """Dependency class for checking specific permissions"""

    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    async def __call__(
        self,
        token_data: TokenData = Depends(get_current_user_token),
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user

        # Check if user has required permissions
        user_permissions = set(token_data.permissions)
        required_permissions = set(self.required_permissions)

        if not required_permissions.issubset(user_permissions):
            missing_permissions = required_permissions - user_permissions
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {', '.join(missing_permissions)}"
            )

        return current_user

class RequireRole:
    """Dependency class for checking specific roles"""

    def __init__(self, required_roles: List[str]):
        self.required_roles = required_roles

    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all roles
        if current_user.is_superuser:
            return current_user

        user_roles = {role.name for role in current_user.roles}
        required_roles = set(self.required_roles)

        if not required_roles.intersection(user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required one of roles: {', '.join(self.required_roles)}"
            )

        return current_user

# Convenience functions for common permission patterns
def require_permission(permission: str):
    """Require a single permission"""
    return RequirePermissions([permission])

def require_permissions(*permissions: str):
    """Require multiple permissions"""
    return RequirePermissions(list(permissions))

def require_role(role: str):
    """Require a single role"""
    return RequireRole([role])

def require_roles(*roles: str):
    """Require one of multiple roles"""
    return RequireRole(list(roles))

# Optional authentication dependency
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
    user_service: UserService = Depends(get_user_service)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    if credentials is None:
        return None

    try:
        auth_manager = get_auth_manager()
        token_data = auth_manager.verify_token(credentials.credentials)

        if token_data is None:
            return None

        user = await user_service.get_user_by_email(token_data.email)
        return user
    except Exception:
        return None