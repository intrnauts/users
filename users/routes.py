from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from .models import (
    UserCreate, UserUpdate, UserResponse, UserLogin, Token,
    RoleCreate, RoleResponse, PermissionCreate, PermissionResponse
)
from .service import UserService, RoleService, PermissionService
from .dependencies import (
    get_current_user, get_current_active_user, get_current_superuser,
    get_user_service, require_permission, require_role
)

def create_user_router(
    prefix: str = "/users",
    tags: List[str] = None,
    include_auth: bool = True,
    include_admin: bool = True
) -> APIRouter:
    """Create a FastAPI router with user management endpoints"""

    router = APIRouter(prefix=prefix, tags=tags or ["users"])

    if include_auth:
        @router.post("/register", response_model=UserResponse)
        async def register(
            user_data: UserCreate,
            user_service: UserService = Depends(get_user_service)
        ):
            """Register a new user"""
            return await user_service.create_user(user_data)

        @router.post("/login", response_model=Token)
        async def login(
            login_data: UserLogin,
            user_service: UserService = Depends(get_user_service)
        ):
            """Login and get access token"""
            return await user_service.login(login_data)

        @router.get("/me", response_model=UserResponse)
        async def get_current_user_info(
            current_user: UserResponse = Depends(get_current_active_user)
        ):
            """Get current user information"""
            return current_user

        @router.put("/me", response_model=UserResponse)
        async def update_current_user(
            user_data: UserUpdate,
            current_user = Depends(get_current_active_user),
            user_service: UserService = Depends(get_user_service)
        ):
            """Update current user information"""
            return await user_service.update_user(current_user.id, user_data)

        @router.post("/change-password")
        async def change_password(
            current_password: str,
            new_password: str,
            current_user = Depends(get_current_active_user),
            user_service: UserService = Depends(get_user_service)
        ):
            """Change user password"""
            success = await user_service.change_password(
                current_user.id, current_password, new_password
            )
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to change password"
                )
            return {"message": "Password changed successfully"}

    if include_admin:
        @router.get("/", response_model=List[UserResponse])
        async def list_users(
            skip: int = Query(0, ge=0),
            limit: int = Query(100, ge=1, le=1000),
            status_filter: Optional[str] = Query(None),
            role_filter: Optional[str] = Query(None),
            current_user = Depends(require_permission("users:read")),
            user_service: UserService = Depends(get_user_service)
        ):
            """List users (admin only)"""
            filters = {}
            if status_filter:
                filters["status"] = status_filter
            if role_filter:
                # This would need additional logic to filter by role
                pass

            return await user_service.list_users(skip, limit, filters)

        @router.get("/{user_id}", response_model=UserResponse)
        async def get_user(
            user_id: int,
            current_user = Depends(require_permission("users:read")),
            user_service: UserService = Depends(get_user_service)
        ):
            """Get user by ID (admin only)"""
            user = await user_service.get_user_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return user

        @router.put("/{user_id}", response_model=UserResponse)
        async def update_user(
            user_id: int,
            user_data: UserUpdate,
            current_user = Depends(require_permission("users:write")),
            user_service: UserService = Depends(get_user_service)
        ):
            """Update user (admin only)"""
            user = await user_service.update_user(user_id, user_data)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return user

        @router.delete("/{user_id}")
        async def delete_user(
            user_id: int,
            current_user = Depends(require_permission("users:delete")),
            user_service: UserService = Depends(get_user_service)
        ):
            """Delete user (admin only)"""
            success = await user_service.delete_user(user_id)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return {"message": "User deleted successfully"}

        @router.post("/{user_id}/verify", response_model=UserResponse)
        async def verify_user(
            user_id: int,
            current_user = Depends(require_permission("users:write")),
            user_service: UserService = Depends(get_user_service)
        ):
            """Verify user (admin only)"""
            user = await user_service.verify_user(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return user

        @router.get("/{user_id}/permissions")
        async def get_user_permissions(
            user_id: int,
            current_user = Depends(require_permission("users:read")),
            user_service: UserService = Depends(get_user_service)
        ):
            """Get user permissions (admin only)"""
            permissions = await user_service.get_user_permissions(user_id)
            return {"permissions": permissions}

    return router

def create_role_router(
    prefix: str = "/roles",
    tags: List[str] = None
) -> APIRouter:
    """Create a FastAPI router with role management endpoints"""

    router = APIRouter(prefix=prefix, tags=tags or ["roles"])

    @router.post("/", response_model=RoleResponse)
    async def create_role(
        role_data: RoleCreate,
        current_user = Depends(require_permission("roles:write")),
        role_service: RoleService = Depends(get_role_service)
    ):
        """Create a new role"""
        return await role_service.create_role(
            role_data.name, role_data.description, role_data.permissions
        )

    @router.get("/", response_model=List[RoleResponse])
    async def list_roles(
        current_user = Depends(require_permission("roles:read")),
        role_service: RoleService = Depends(get_role_service)
    ):
        """List all roles"""
        return await role_service.list_roles()

    @router.get("/{role_name}", response_model=RoleResponse)
    async def get_role(
        role_name: str,
        current_user = Depends(require_permission("roles:read")),
        role_service: RoleService = Depends(get_role_service)
    ):
        """Get role by name"""
        role = await role_service.get_role_by_name(role_name)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
        return role

    @router.delete("/{role_id}")
    async def delete_role(
        role_id: int,
        current_user = Depends(require_permission("roles:delete")),
        role_service: RoleService = Depends(get_role_service)
    ):
        """Delete role"""
        success = await role_service.delete_role(role_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )
        return {"message": "Role deleted successfully"}

    return router

def create_permission_router(
    prefix: str = "/permissions",
    tags: List[str] = None
) -> APIRouter:
    """Create a FastAPI router with permission management endpoints"""

    router = APIRouter(prefix=prefix, tags=tags or ["permissions"])

    @router.post("/", response_model=PermissionResponse)
    async def create_permission(
        permission_data: PermissionCreate,
        current_user = Depends(require_permission("permissions:write")),
        permission_service: PermissionService = Depends(get_permission_service)
    ):
        """Create a new permission"""
        return await permission_service.create_permission(
            permission_data.name,
            permission_data.resource,
            permission_data.action,
            permission_data.description
        )

    @router.get("/", response_model=List[PermissionResponse])
    async def list_permissions(
        current_user = Depends(require_permission("permissions:read")),
        permission_service: PermissionService = Depends(get_permission_service)
    ):
        """List all permissions"""
        return await permission_service.list_permissions()

    @router.delete("/{permission_id}")
    async def delete_permission(
        permission_id: int,
        current_user = Depends(require_permission("permissions:delete")),
        permission_service: PermissionService = Depends(get_permission_service)
    ):
        """Delete permission"""
        success = await permission_service.delete_permission(permission_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )
        return {"message": "Permission deleted successfully"}

    return router

# Dependency functions for services (will be implemented with proper DI)
def get_role_service():
    # This should be implemented with proper dependency injection
    # For now, returning None - will be configured by the user
    raise NotImplementedError("Role service dependency not configured")

def get_permission_service():
    # This should be implemented with proper dependency injection
    # For now, returning None - will be configured by the user
    raise NotImplementedError("Permission service dependency not configured")