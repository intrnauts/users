from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from .models import User, Role, PermissionModel, PasswordResetToken, UserCreate, UserUpdate

class UserRepositoryInterface(ABC):
    @abstractmethod
    async def create_user(self, user_data: UserCreate) -> User:
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[User]:
        pass

    @abstractmethod
    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        pass

    @abstractmethod
    async def delete_user(self, user_id: int) -> bool:
        pass

    @abstractmethod
    async def list_users(self, skip: int = 0, limit: int = 100, filters: Dict[str, Any] = None) -> List[User]:
        pass

    @abstractmethod
    async def get_user_permissions(self, user_id: int) -> List[str]:
        pass

    @abstractmethod
    async def create_password_reset_token(self, user_id: int, token: str, expires_at: datetime) -> PasswordResetToken:
        pass

    @abstractmethod
    async def get_password_reset_token(self, token: str) -> Optional[PasswordResetToken]:
        pass

    @abstractmethod
    async def mark_token_as_used(self, token: str) -> bool:
        pass

    @abstractmethod
    async def delete_user_reset_tokens(self, user_id: int) -> bool:
        pass

class SQLAlchemyUserRepository(UserRepositoryInterface):
    def __init__(self, db_session: Session):
        self.db = db_session

    async def create_user(self, user_data: UserCreate) -> User:
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            status=user_data.status,
            is_superuser=user_data.is_superuser,
            hashed_password=user_data.password  # This should be hashed before calling
        )

        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)

        # Add roles if specified
        if user_data.roles:
            roles = self.db.query(Role).filter(Role.name.in_(user_data.roles)).all()
            db_user.roles.extend(roles)
            self.db.commit()
            self.db.refresh(db_user)

        return db_user

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()

    async def get_user_by_username(self, username: str) -> Optional[User]:
        return self.db.query(User).filter(User.username == username).first()

    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        db_user = await self.get_user_by_id(user_id)
        if not db_user:
            return None

        update_data = user_data.model_dump(exclude_unset=True)
        roles_to_update = update_data.pop('roles', None)

        for field, value in update_data.items():
            setattr(db_user, field, value)

        if roles_to_update is not None:
            roles = self.db.query(Role).filter(Role.name.in_(roles_to_update)).all()
            db_user.roles = roles

        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    async def delete_user(self, user_id: int) -> bool:
        db_user = await self.get_user_by_id(user_id)
        if not db_user:
            return False

        self.db.delete(db_user)
        self.db.commit()
        return True

    async def list_users(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Dict[str, Any] = None
    ) -> List[User]:
        query = self.db.query(User)

        if filters:
            filter_conditions = []
            for key, value in filters.items():
                if hasattr(User, key):
                    if isinstance(value, list):
                        filter_conditions.append(getattr(User, key).in_(value))
                    else:
                        filter_conditions.append(getattr(User, key) == value)

            if filter_conditions:
                query = query.filter(and_(*filter_conditions))

        return query.offset(skip).limit(limit).all()

    async def get_user_permissions(self, user_id: int) -> List[str]:
        user = await self.get_user_by_id(user_id)
        if not user:
            return []

        permissions = set()
        for role in user.roles:
            for permission in role.permissions:
                permissions.add(f"{permission.resource}:{permission.action}")

        return list(permissions)

    async def create_password_reset_token(self, user_id: int, token: str, expires_at: datetime) -> PasswordResetToken:
        """Create a new password reset token"""
        reset_token = PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            used=False
        )
        self.db.add(reset_token)
        self.db.commit()
        self.db.refresh(reset_token)
        return reset_token

    async def get_password_reset_token(self, token: str) -> Optional[PasswordResetToken]:
        """Get password reset token by token string"""
        return self.db.query(PasswordResetToken).filter(
            PasswordResetToken.token == token
        ).first()

    async def mark_token_as_used(self, token: str) -> bool:
        """Mark a password reset token as used"""
        reset_token = await self.get_password_reset_token(token)
        if not reset_token:
            return False

        reset_token.used = True
        self.db.commit()
        return True

    async def delete_user_reset_tokens(self, user_id: int) -> bool:
        """Delete all password reset tokens for a user"""
        tokens = self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id
        ).all()

        for token in tokens:
            self.db.delete(token)

        self.db.commit()
        return True

class RoleRepository:
    def __init__(self, db_session: Session):
        self.db = db_session

    async def create_role(self, name: str, description: str = None, permissions: List[str] = None) -> Role:
        db_role = Role(name=name, description=description)
        self.db.add(db_role)
        self.db.commit()
        self.db.refresh(db_role)

        if permissions:
            perms = self.db.query(PermissionModel).filter(PermissionModel.name.in_(permissions)).all()
            db_role.permissions.extend(perms)
            self.db.commit()
            self.db.refresh(db_role)

        return db_role

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        return self.db.query(Role).filter(Role.name == name).first()

    async def list_roles(self) -> List[Role]:
        return self.db.query(Role).all()

    async def delete_role(self, role_id: int) -> bool:
        role = self.db.query(Role).filter(Role.id == role_id).first()
        if not role:
            return False

        self.db.delete(role)
        self.db.commit()
        return True

class PermissionRepository:
    def __init__(self, db_session: Session):
        self.db = db_session

    async def create_permission(
        self,
        name: str,
        resource: str,
        action: str,
        description: str = None
    ) -> PermissionModel:
        db_permission = PermissionModel(
            name=name,
            resource=resource,
            action=action,
            description=description
        )
        self.db.add(db_permission)
        self.db.commit()
        self.db.refresh(db_permission)
        return db_permission

    async def get_permission_by_name(self, name: str) -> Optional[PermissionModel]:
        return self.db.query(PermissionModel).filter(PermissionModel.name == name).first()

    async def list_permissions(self) -> List[PermissionModel]:
        return self.db.query(PermissionModel).all()

    async def delete_permission(self, permission_id: int) -> bool:
        permission = self.db.query(PermissionModel).filter(PermissionModel.id == permission_id).first()
        if not permission:
            return False

        self.db.delete(permission)
        self.db.commit()
        return True