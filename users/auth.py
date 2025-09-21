from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from .models import TokenData

class AuthConfig:
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        password_schemes: List[str] = None
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.password_schemes = password_schemes or ["bcrypt"]

class PasswordManager:
    def __init__(self, schemes: List[str] = None):
        schemes = schemes or ["bcrypt"]
        self.pwd_context = CryptContext(schemes=schemes, deprecated="auto")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

    def hash_password(self, password: str) -> str:
        return self.pwd_context.hash(password)

class JWTManager:
    def __init__(self, config: AuthConfig):
        self.config = config

    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.config.access_token_expire_minutes
            )

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode,
            self.config.secret_key,
            algorithm=self.config.algorithm
        )
        return encoded_jwt

    def verify_token(self, token: str) -> Optional[TokenData]:
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm]
            )
            email: str = payload.get("sub")
            permissions: List[str] = payload.get("permissions", [])

            if email is None:
                return None

            return TokenData(email=email, permissions=permissions)
        except JWTError:
            return None

    def create_user_token(
        self,
        user_email: str,
        permissions: List[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        permissions = permissions or []
        data = {
            "sub": user_email,
            "permissions": permissions
        }
        return self.create_access_token(data, expires_delta)

class AuthManager:
    def __init__(self, config: AuthConfig):
        self.config = config
        self.password_manager = PasswordManager(config.password_schemes)
        self.jwt_manager = JWTManager(config)

    def hash_password(self, password: str) -> str:
        return self.password_manager.hash_password(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.password_manager.verify_password(plain_password, hashed_password)

    def create_access_token(
        self,
        user_email: str,
        permissions: List[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        return self.jwt_manager.create_user_token(user_email, permissions, expires_delta)

    def verify_token(self, token: str) -> Optional[TokenData]:
        return self.jwt_manager.verify_token(token)

    def get_token_expiry_time(self) -> int:
        return self.config.access_token_expire_minutes * 60

# Default auth manager instance (will be configured by the user)
_auth_manager: Optional[AuthManager] = None

def get_auth_manager() -> AuthManager:
    if _auth_manager is None:
        raise RuntimeError(
            "Auth manager not configured. Call configure_auth() first."
        )
    return _auth_manager

def configure_auth(config: AuthConfig) -> AuthManager:
    global _auth_manager
    _auth_manager = AuthManager(config)
    return _auth_manager