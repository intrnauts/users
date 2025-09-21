import pytest
from datetime import datetime, timedelta
from users.auth import AuthConfig, AuthManager, PasswordManager, JWTManager, configure_auth

class TestPasswordManager:
    def setup_method(self):
        self.password_manager = PasswordManager()

    def test_hash_password(self):
        password = "test_password_123"
        hashed = self.password_manager.hash_password(password)

        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")

    def test_verify_password_correct(self):
        password = "test_password_123"
        hashed = self.password_manager.hash_password(password)

        assert self.password_manager.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        password = "test_password_123"
        wrong_password = "wrong_password"
        hashed = self.password_manager.hash_password(password)

        assert self.password_manager.verify_password(wrong_password, hashed) is False

class TestJWTManager:
    def setup_method(self):
        self.config = AuthConfig(
            secret_key="test_secret_key_12345",
            algorithm="HS256",
            access_token_expire_minutes=30
        )
        self.jwt_manager = JWTManager(self.config)

    def test_create_access_token(self):
        data = {"sub": "test@example.com", "permissions": ["users:read"]}
        token = self.jwt_manager.create_access_token(data)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_token_valid(self):
        data = {"sub": "test@example.com", "permissions": ["users:read"]}
        token = self.jwt_manager.create_access_token(data)

        token_data = self.jwt_manager.verify_token(token)

        assert token_data is not None
        assert token_data.email == "test@example.com"
        assert token_data.permissions == ["users:read"]

    def test_verify_token_invalid(self):
        invalid_token = "invalid.token.here"
        token_data = self.jwt_manager.verify_token(invalid_token)

        assert token_data is None

    def test_create_user_token(self):
        email = "test@example.com"
        permissions = ["users:read", "users:write"]

        token = self.jwt_manager.create_user_token(email, permissions)
        token_data = self.jwt_manager.verify_token(token)

        assert token_data.email == email
        assert token_data.permissions == permissions

    def test_token_expiry(self):
        config = AuthConfig(
            secret_key="test_secret_key_12345",
            access_token_expire_minutes=0  # Immediate expiry
        )
        jwt_manager = JWTManager(config)

        data = {"sub": "test@example.com"}
        token = jwt_manager.create_access_token(
            data,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )

        token_data = jwt_manager.verify_token(token)
        assert token_data is None

class TestAuthManager:
    def setup_method(self):
        self.config = AuthConfig(
            secret_key="test_secret_key_12345",
            algorithm="HS256",
            access_token_expire_minutes=30
        )
        self.auth_manager = AuthManager(self.config)

    def test_hash_password(self):
        password = "test_password_123"
        hashed = self.auth_manager.hash_password(password)

        assert hashed != password
        assert len(hashed) > 0

    def test_verify_password(self):
        password = "test_password_123"
        hashed = self.auth_manager.hash_password(password)

        assert self.auth_manager.verify_password(password, hashed) is True
        assert self.auth_manager.verify_password("wrong", hashed) is False

    def test_create_access_token(self):
        email = "test@example.com"
        permissions = ["users:read"]

        token = self.auth_manager.create_access_token(email, permissions)
        token_data = self.auth_manager.verify_token(token)

        assert token_data.email == email
        assert token_data.permissions == permissions

    def test_get_token_expiry_time(self):
        expiry_time = self.auth_manager.get_token_expiry_time()
        assert expiry_time == 30 * 60  # 30 minutes in seconds

class TestAuthConfiguration:
    def test_configure_auth(self):
        config = AuthConfig(secret_key="test_key")
        auth_manager = configure_auth(config)

        assert isinstance(auth_manager, AuthManager)
        assert auth_manager.config.secret_key == "test_key"

    def test_get_auth_manager_configured(self):
        config = AuthConfig(secret_key="test_key")
        configure_auth(config)

        from users.auth import get_auth_manager
        auth_manager = get_auth_manager()

        assert isinstance(auth_manager, AuthManager)

    def test_get_auth_manager_not_configured(self):
        # Reset global state
        import users.auth
        users.auth._auth_manager = None

        from users.auth import get_auth_manager

        with pytest.raises(RuntimeError, match="Auth manager not configured"):
            get_auth_manager()

class TestAuthConfig:
    def test_auth_config_defaults(self):
        config = AuthConfig(secret_key="test_key")

        assert config.secret_key == "test_key"
        assert config.algorithm == "HS256"
        assert config.access_token_expire_minutes == 30
        assert config.password_schemes == ["bcrypt"]

    def test_auth_config_custom(self):
        config = AuthConfig(
            secret_key="custom_key",
            algorithm="HS512",
            access_token_expire_minutes=60,
            password_schemes=["argon2", "bcrypt"]
        )

        assert config.secret_key == "custom_key"
        assert config.algorithm == "HS512"
        assert config.access_token_expire_minutes == 60
        assert config.password_schemes == ["argon2", "bcrypt"]