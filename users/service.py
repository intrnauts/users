from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import secrets
from fastapi import HTTPException, status
from .models import User, UserCreate, UserUpdate, UserLogin, Token, UserResponse, PasswordResetRequest, PasswordResetConfirm
from .repository import UserRepositoryInterface, RoleRepository, PermissionRepository
from .auth import get_auth_manager
from .email_service import get_email_service

class UserService:
    def __init__(
        self,
        user_repository: UserRepositoryInterface,
        role_repository: RoleRepository = None,
        permission_repository: PermissionRepository = None
    ):
        self.user_repo = user_repository
        self.role_repo = role_repository
        self.permission_repo = permission_repository

    async def create_user(self, user_data: UserCreate) -> UserResponse:
        # Check if user already exists
        existing_user = await self.user_repo.get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        if user_data.username:
            existing_username = await self.user_repo.get_user_by_username(user_data.username)
            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        # Hash password
        auth_manager = get_auth_manager()
        hashed_password = auth_manager.hash_password(user_data.password)

        # Create user with hashed password
        user_create_data = user_data.model_copy()
        user_create_data.password = hashed_password

        db_user = await self.user_repo.create_user(user_create_data)

        return self._user_to_response(db_user)

    async def authenticate_user(self, login_data: UserLogin) -> Optional[User]:
        user = await self.user_repo.get_user_by_email(login_data.email)
        if not user:
            return None

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(login_data.password, user.hashed_password):
            return None

        # Update last login
        user.last_login = datetime.utcnow()
        return user

    async def login(self, login_data: UserLogin) -> Token:
        user = await self.authenticate_user(login_data)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user permissions
        permissions = await self.user_repo.get_user_permissions(user.id)

        # Create access token
        auth_manager = get_auth_manager()
        access_token = auth_manager.create_access_token(
            user_email=user.email,
            permissions=permissions
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_manager.get_token_expiry_time()
        )

    async def get_user_by_id(self, user_id: int) -> Optional[UserResponse]:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None
        return self._user_to_response(user)

    async def get_user_by_email(self, email: str) -> Optional[UserResponse]:
        user = await self.user_repo.get_user_by_email(email)
        if not user:
            return None
        return self._user_to_response(user)

    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[UserResponse]:
        # Check if email is being updated and if it's already taken
        if user_data.email:
            existing_user = await self.user_repo.get_user_by_email(user_data.email)
            if existing_user and existing_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )

        # Check if username is being updated and if it's already taken
        if user_data.username:
            existing_username = await self.user_repo.get_user_by_username(user_data.username)
            if existing_username and existing_username.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        user = await self.user_repo.update_user(user_id, user_data)
        if not user:
            return None
        return self._user_to_response(user)

    async def delete_user(self, user_id: int) -> bool:
        return await self.user_repo.delete_user(user_id)

    async def list_users(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Dict[str, Any] = None
    ) -> List[UserResponse]:
        users = await self.user_repo.list_users(skip, limit, filters)
        return [self._user_to_response(user) for user in users]

    async def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return False

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Hash new password and update
        new_hashed_password = auth_manager.hash_password(new_password)
        update_data = UserUpdate(password=new_hashed_password)
        await self.user_repo.update_user(user_id, update_data)
        return True

    async def verify_user(self, user_id: int) -> Optional[UserResponse]:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None

        update_data = UserUpdate(is_verified=True, status="active")
        updated_user = await self.user_repo.update_user(user_id, update_data)
        return self._user_to_response(updated_user)

    async def get_user_permissions(self, user_id: int) -> List[str]:
        return await self.user_repo.get_user_permissions(user_id)

    async def request_password_reset(
        self,
        request_data: PasswordResetRequest,
        reset_url_template: str = None
    ) -> bool:
        """
        Request a password reset for a user.

        Args:
            request_data: Password reset request with user email
            reset_url_template: URL template for reset link (e.g., "https://app.com/reset?token={token}")

        Returns:
            Always returns True to prevent email enumeration
        """
        # Look up user by email
        user = await self.user_repo.get_user_by_email(request_data.email)

        # Always return True even if user doesn't exist (prevent email enumeration)
        if not user:
            return True

        # Generate secure random token
        reset_token = secrets.token_urlsafe(32)

        # Token expires in 1 hour
        expires_at = datetime.utcnow() + timedelta(hours=1)

        # Delete any existing reset tokens for this user
        await self.user_repo.delete_user_reset_tokens(user.id)

        # Store token in database
        await self.user_repo.create_password_reset_token(
            user_id=user.id,
            token=reset_token,
            expires_at=expires_at
        )

        # Send reset email
        try:
            email_service = get_email_service()
            await email_service.send_password_reset_email(
                recipient_email=user.email,
                reset_token=reset_token,
                reset_url_template=reset_url_template
            )
        except Exception as e:
            # Log error but don't expose it to prevent information leakage
            import logging
            logging.error(f"Failed to send password reset email: {e}")

        return True

    async def confirm_password_reset(self, confirm_data: PasswordResetConfirm) -> bool:
        """
        Confirm password reset with token and set new password.

        Args:
            confirm_data: Password reset confirmation with token and new password

        Returns:
            True if password was reset successfully

        Raises:
            HTTPException: If token is invalid, expired, or already used
        """
        # Get token from database
        reset_token = await self.user_repo.get_password_reset_token(confirm_data.token)

        if not reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )

        # Check if token is already used
        if reset_token.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has already been used"
            )

        # Check if token is expired
        if datetime.utcnow() > reset_token.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired"
            )

        # Get the user
        user = await self.user_repo.get_user_by_id(reset_token.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Hash new password
        auth_manager = get_auth_manager()
        new_hashed_password = auth_manager.hash_password(confirm_data.new_password)

        # Update user's password
        user.hashed_password = new_hashed_password
        self.user_repo.db.commit()

        # Mark token as used
        await self.user_repo.mark_token_as_used(confirm_data.token)

        return True

    def _user_to_response(self, user: User) -> UserResponse:
        role_names = [role.name for role in user.roles] if user.roles else []
        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status,
            is_superuser=user.is_superuser,
            is_verified=user.is_verified,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login,
            roles=role_names
        )

class RoleService:
    def __init__(self, role_repository: RoleRepository):
        self.role_repo = role_repository

    async def create_role(self, name: str, description: str = None, permissions: List[str] = None):
        existing_role = await self.role_repo.get_role_by_name(name)
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role already exists"
            )

        return await self.role_repo.create_role(name, description, permissions)

    async def get_role_by_name(self, name: str):
        return await self.role_repo.get_role_by_name(name)

    async def list_roles(self):
        return await self.role_repo.list_roles()

    async def delete_role(self, role_id: int):
        return await self.role_repo.delete_role(role_id)

class PermissionService:
    def __init__(self, permission_repository: PermissionRepository):
        self.permission_repo = permission_repository

    async def create_permission(self, name: str, resource: str, action: str, description: str = None):
        existing_permission = await self.permission_repo.get_permission_by_name(name)
        if existing_permission:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission already exists"
            )

        return await self.permission_repo.create_permission(name, resource, action, description)

    async def list_permissions(self):
        return await self.permission_repo.list_permissions()

    async def delete_permission(self, permission_id: int):
        return await self.permission_repo.delete_permission(permission_id)