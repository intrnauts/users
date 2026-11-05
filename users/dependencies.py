from typing import Optional, List
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .auth import get_auth_manager
from .models import User, TokenData
from .service import UserService
from .repository import SQLAlchemyUserRepository
from .scope import DEFAULT_SCOPE, get_request_scope, scope_of

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
    yield from db_dependency.get_db()

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
    user_service: UserService = Depends(get_user_service),
    request: Request = None
) -> User:
    """Get current authenticated user"""
    user = await _user_for_token(token_data, user_service)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not await _token_is_for(token_data, user, request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def _token_scope(token_data: TokenData) -> str:
    """Tokens from before scopes were added count as the default scope (#70)."""
    return token_data.scope if token_data.scope is not None else DEFAULT_SCOPE

async def _user_for_token(token_data: TokenData, user_service: UserService):
    """The account a token names: by id when it carries one (#55, #70), else
    by email in the token's scope. Tokens from before the id was added carry
    none and are accepted until they expire."""
    if token_data.user_id is not None:
        return await user_service.get_user_by_id(token_data.user_id)
    return await user_service.get_user_by_email(token_data.email, _token_scope(token_data))

async def _token_is_for(token_data: TokenData, user, request: Optional[Request] = None) -> bool:
    """Whether a token was issued to this account.

    The email must still match, as it did when tokens were looked up by email,
    so changing the address still ends the sessions that used the old one. The
    scope must be the account's (#70) and, if the app says which scope the
    request belongs to, that one too.
    """
    if token_data.email != user.email:
        return False
    if token_data.user_id is not None and token_data.user_id != user.id:
        return False
    if _token_scope(token_data) != scope_of(user):
        return False
    request_scope = await get_request_scope(request)
    return request_scope is None or request_scope == scope_of(user)

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
) -> User:
    """Get current active user.

    Refuses any other status with a 403 and the same message login gives for
    it, e.g. a token issued before the account was suspended (#61).
    """
    refusal = await user_service.status_refusal(current_user)
    if refusal:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=refusal)

    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user"""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
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
    user_service: UserService = Depends(get_user_service),
    request: Request = None
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    if credentials is None:
        return None

    try:
        auth_manager = get_auth_manager()
        token_data = auth_manager.verify_token(credentials.credentials)

        if token_data is None:
            return None

        user = await _user_for_token(token_data, user_service)
        if user is None or not await _token_is_for(token_data, user, request):
            return None
        return user
    except Exception:
        return None