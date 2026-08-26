from datetime import datetime
from typing import Optional, List, Annotated
from enum import Enum
from pydantic import BaseModel, EmailStr, Field, BeforeValidator
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# Default Base - can be overridden by configure_base()
Base = declarative_base()

def configure_base(custom_base=None):
    """Configure the SQLAlchemy Base class for the users package.

    Args:
        custom_base: Custom SQLAlchemy declarative base. If None, uses default.
    """
    global Base
    if custom_base is not None:
        Base = custom_base

def normalize_email(email):
    """Canonicalise an email address for storage and lookup.

    Domains are case-insensitive per RFC 5321, and while the local part is
    formally case-sensitive, no mail provider in practice treats
    User@example.com and user@example.com as different mailboxes. Without a
    single canonical form the same person can hold two accounts, and a password
    reset silently misses an account whose stored address differs only in case.

    Non-string input is passed through untouched for Pydantic to reject.
    """
    if isinstance(email, str):
        return email.strip().lower()
    return email

# Email fields normalize before validation, so every schema that carries an
# address - and therefore every route - agrees on one canonical form.
NormalizedEmail = Annotated[EmailStr, BeforeValidator(normalize_email)]
OptionalNormalizedEmail = Annotated[Optional[EmailStr], BeforeValidator(normalize_email)]
NormalizedEmailStr = Annotated[str, BeforeValidator(normalize_email)]

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

# Association table for user roles (many-to-many)
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('users.roles.id'), primary_key=True),
    schema='users'
)

# Association table for role permissions (many-to-many)
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('users.roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('users.permissions.id'), primary_key=True),
    schema='users'
)

class User(Base):
    __tablename__ = "users"
    __table_args__ = {'schema': 'users'}

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    status = Column(String(20), default=UserStatus.PENDING)
    is_superuser = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    user_metadata = Column(Text, nullable=True)  # JSON field for additional data

    roles = relationship("Role", secondary=user_roles, back_populates="users")

class Role(Base):
    __tablename__ = "roles"
    __table_args__ = {'schema': 'users'}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("PermissionModel", secondary=role_permissions, back_populates="roles")

class PermissionModel(Base):
    __tablename__ = "permissions"
    __table_args__ = {'schema': 'users'}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    resource = Column(String(100), nullable=False)  # e.g., "users", "posts", "comments"
    action = Column(String(50), nullable=False)     # e.g., "read", "write", "delete"
    description = Column(Text, nullable=True)

    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = {'schema': 'users'}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.users.id'), nullable=False)
    # SHA-256 digest of the token, never the token itself. See users.verification.
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")

class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    __table_args__ = {'schema': 'users'}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.users.id'), nullable=False)
    # SHA-256 digest of the token, never the token itself. See users.verification.
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")

# Pydantic schemas for API
class UserBase(BaseModel):
    email: NormalizedEmail
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    status: UserStatus = UserStatus.PENDING
    is_superuser: bool = False

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    roles: Optional[List[str]] = []

class UserRegister(BaseModel):
    """Payload for public self-service registration.

    Deliberately excludes status, is_superuser and roles: those are attacker
    controlled on a public endpoint. Use UserCreate for admin or programmatic
    creation where those fields are meant to be settable.
    """
    email: NormalizedEmail
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    password: str = Field(..., min_length=8)

    def to_user_create(self) -> "UserCreate":
        """Convert to a UserCreate with privileged fields forced to defaults."""
        return UserCreate(
            email=self.email,
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name,
            password=self.password,
            status=UserStatus.PENDING,
            is_superuser=False,
            roles=[]
        )

class UserSelfUpdate(BaseModel):
    """Fields a user is allowed to change on their own account.

    Deliberately excludes status, is_superuser, is_verified and roles, so that
    the self-service endpoint cannot be used for privilege escalation.
    """
    email: OptionalNormalizedEmail = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class UserUpdate(BaseModel):
    email: OptionalNormalizedEmail = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    status: Optional[UserStatus] = None
    is_superuser: Optional[bool] = None
    roles: Optional[List[str]] = None

class UserResponse(UserBase):
    id: int
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    roles: List[str] = []

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    email: NormalizedEmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    email: Optional[str] = None
    permissions: List[str] = []

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    permissions: Optional[List[str]] = []

class RoleResponse(RoleBase):
    id: int
    created_at: datetime
    permissions: List[str] = []

    class Config:
        from_attributes = True

class PermissionBase(BaseModel):
    name: str
    resource: str
    action: str
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class PermissionResponse(PermissionBase):
    id: int

    class Config:
        from_attributes = True

# Password reset schemas
class PasswordResetRequest(BaseModel):
    email: NormalizedEmail

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

# Email verification schemas
class EmailVerificationConfirm(BaseModel):
    token: str

class EmailVerificationResend(BaseModel):
    email: NormalizedEmail