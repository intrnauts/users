# Users Package

A flexible and robust user management package for FastAPI backends, providing authentication, authorization, and role-based access control (RBAC) out of the box.

## Features

- 🔐 **JWT Authentication** - Secure token-based authentication
- 👥 **User Management** - Complete CRUD operations for users
- 🛡️ **Role-Based Access Control (RBAC)** - Flexible permission system
- 📧 **Email Integration** - AWS SES support for password reset and verification
- 🔑 **Password Reset** - Secure token-based password reset flow
- 🔧 **Database Adapters** - Support for SQLAlchemy and MongoDB
- 🚀 **FastAPI Integration** - Ready-to-use dependencies and routers
- 🧪 **Comprehensive Testing** - Full test suite included
- 📖 **Type Safety** - Full type hints with Pydantic models
- ⚡ **Easy Setup** - Minimal configuration required

## Installation

```bash
pip install users
```

For MongoDB support:
```bash
pip install users[mongodb]
```

For development:
```bash
pip install users[dev]
```

## Quick Start

### Basic FastAPI Integration

```python
from fastapi import FastAPI, Depends
from users import (
    setup_users_package,
    create_user_router,
    get_current_active_user,
    UserResponse
)

app = FastAPI()

# Configure the users package
auth_manager, db_manager = setup_users_package(
    secret_key="your-secret-key-here",
    database_url="sqlite:///./users.db"
)

# Include user authentication routes
user_router = create_user_router()
app.include_router(user_router)

# Example protected route
@app.get("/protected")
async def protected_route(
    current_user: UserResponse = Depends(get_current_active_user)
):
    return {"message": f"Hello {current_user.email}!"}
```

### User Registration and Login

```python
# Register a new user
user_data = {
    "email": "user@example.com",
    "password": "secure_password_123",
    "username": "john_doe",
    "first_name": "John",
    "last_name": "Doe"
}
# POST /users/register

# Login
login_data = {
    "email": "user@example.com",
    "password": "secure_password_123"
}
# POST /users/login
# Returns: {"access_token": "...", "token_type": "bearer", "expires_in": 3600}
```

## Advanced Usage

### Role-Based Access Control

```python
from users import require_permission, require_role, RequirePermissions

# Require specific permission
@app.get("/admin/users")
async def list_users(
    current_user = Depends(require_permission("users:read"))
):
    # Only users with "users:read" permission can access
    return {"users": [...]}

# Require specific role
@app.get("/admin/dashboard")
async def admin_dashboard(
    current_user = Depends(require_role("admin"))
):
    # Only users with "admin" role can access
    return {"dashboard": "data"}

# Require multiple permissions
@app.get("/reports")
async def generate_reports(
    current_user = Depends(RequirePermissions(["users:read", "reports:generate"]))
):
    # Requires both permissions
    return {"report": "data"}
```

### Custom Database Configuration

```python
from users import (
    AuthConfig, DatabaseConfig,
    configure_auth, configure_sync_database,
    db_dependency
)

# Custom authentication configuration
auth_config = AuthConfig(
    secret_key="your-secret-key",
    algorithm="HS256",
    access_token_expire_minutes=60
)
auth_manager = configure_auth(auth_config)

# Custom database configuration
db_config = DatabaseConfig(
    database_url="postgresql://user:pass@localhost/dbname",
    echo=True,
    pool_size=20,
    max_overflow=30
)
db_manager = configure_sync_database(db_config)
db_dependency.set_session_factory(db_manager.get_session)

# Create tables
db_manager.create_tables()
```

### Creating Default Roles and Permissions

```python
from users import (
    create_default_permissions,
    create_default_roles,
    RoleService,
    PermissionService
)

# Initialize default permissions
permissions_data = create_default_permissions()
for perm_data in permissions_data:
    await permission_service.create_permission(**perm_data)

# Initialize default roles
roles_data = create_default_roles()
for role_name, role_data in roles_data.items():
    await role_service.create_role(**role_data)
```

### Manual Service Usage

```python
from users import UserService, UserCreate

# Create user service
user_service = UserService(user_repository)

# Create a user programmatically
user_data = UserCreate(
    email="admin@example.com",
    password="admin_password_123",
    is_superuser=True,
    roles=["admin"]
)
user = await user_service.create_user(user_data)

# Authenticate user
from users.models import UserLogin
login_data = UserLogin(email="admin@example.com", password="admin_password_123")
token = await user_service.login(login_data)
```

## Configuration

### Environment Variables

```bash
# Required
SECRET_KEY="your-jwt-secret-key"
DATABASE_URL="sqlite:///./users.db"

# Optional
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES="30"
```

### Supported Databases

- **SQLite**: `sqlite:///./database.db`
- **PostgreSQL**: `postgresql://user:pass@localhost/dbname`
- **MySQL**: `mysql://user:pass@localhost/dbname`
- **MongoDB**: Use MongoDB-specific configuration (optional dependency)

## API Endpoints

### Authentication
- `POST /users/register` - Register new user
- `POST /users/login` - Login and get access token
- `GET /users/me` - Get current user info
- `PUT /users/me` - Update current user
- `POST /users/change-password` - Change password (requires current password)
- `POST /users/password-reset/request` - Request password reset (sends email)
- `POST /users/password-reset/confirm` - Confirm password reset with token

### User Management (Admin)
- `GET /users/` - List users
- `GET /users/{user_id}` - Get user by ID
- `PUT /users/{user_id}` - Update user
- `DELETE /users/{user_id}` - Delete user
- `POST /users/{user_id}/verify` - Verify user
- `GET /users/{user_id}/permissions` - Get user permissions

### Role Management
- `POST /roles/` - Create role
- `GET /roles/` - List roles
- `GET /roles/{role_name}` - Get role
- `DELETE /roles/{role_id}` - Delete role

### Permission Management
- `POST /permissions/` - Create permission
- `GET /permissions/` - List permissions
- `DELETE /permissions/{permission_id}` - Delete permission

## Email Integration & Password Reset

The users package now includes built-in support for email notifications using AWS SES, with a focus on password reset functionality.

### Setup Email Service

```python
from users import setup_users_package, EmailConfig

# Configure email service with AWS SES
email_config = EmailConfig(
    aws_region="us-east-1",
    sender_email="noreply@yourdomain.com",
    sender_name="Your App Name",
    enabled=True  # Set to False to disable email sending (for testing)
)

# Setup users package with email support
auth_manager, db_manager = setup_users_package(
    secret_key="your-secret-key",
    database_url="sqlite:///./users.db",
    email_config=email_config
)
```

### Configure Password Reset URL

When creating the user router, you can specify a URL template for password reset links:

```python
from users import create_user_router

# The {token} placeholder will be replaced with the actual reset token
user_router = create_user_router(
    password_reset_url_template="https://yourapp.com/reset-password?token={token}"
)

app.include_router(user_router, prefix="/api/users")
```

### Password Reset Flow

**1. User requests password reset:**

```bash
curl -X POST "http://localhost:8000/api/users/password-reset/request" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

Response:
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

The user will receive an email with a reset link (valid for 1 hour).

**2. User confirms password reset with token:**

```bash
curl -X POST "http://localhost:8000/api/users/password-reset/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123...",
    "new_password": "newSecurePassword123"
  }'
```

Response:
```json
{
  "message": "Password has been reset successfully"
}
```

### Email Configuration (AWS SES)

To use AWS SES for sending emails:

1. **Verify your sender email address** in AWS SES Console
2. **Configure AWS credentials** (one of the following):
   - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
   - AWS CLI configuration (`~/.aws/credentials`)
   - IAM role (for EC2/ECS deployments)

3. **Required IAM permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "*"
    }
  ]
}
```

### Environment Variables

```bash
# Email Configuration
EMAIL_ENABLED=True
EMAIL_SENDER_EMAIL=noreply@yourdomain.com
EMAIL_SENDER_NAME=Your App Name
AWS_REGION=us-east-1

# Password Reset
PASSWORD_RESET_URL_TEMPLATE=https://yourapp.com/reset-password?token={token}
```

### Security Features

- **Token expiration**: Reset tokens expire after 1 hour
- **One-time use**: Tokens are marked as used after successful password reset
- **Email enumeration prevention**: API always returns success, even if email doesn't exist
- **Secure token generation**: Uses `secrets.token_urlsafe()` for cryptographically secure tokens
- **Token invalidation**: All existing tokens are deleted when a new one is requested

### Disable Email for Testing

During development or testing, you can disable email sending:

```python
email_config = EmailConfig(
    enabled=False  # Emails won't be sent, but tokens will be logged
)
```

When disabled, the reset token will be logged to the console instead of sent via email.

## Models

### User Model
```python
{
    "id": 1,
    "email": "user@example.com",
    "username": "john_doe",
    "first_name": "John",
    "last_name": "Doe",
    "status": "active",
    "is_superuser": false,
    "is_verified": true,
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z",
    "last_login": "2023-01-01T00:00:00Z",
    "roles": ["user", "viewer"]
}
```

### Token Response
```python
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 3600
}
```

## Testing

Run tests with pytest:

```bash
# Install test dependencies
pip install users[dev]

# Run tests
pytest

# Run with coverage
pytest --cov=users

# Run specific test file
pytest tests/test_auth.py
```

## Examples

Check the `examples/` directory for complete example applications:

- `basic_fastapi_app.py` - Simple FastAPI app with authentication
- `advanced_fastapi_app.py` - Advanced app with RBAC and permissions

Run examples:
```bash
cd examples
python basic_fastapi_app.py
# or
python advanced_fastapi_app.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run tests and ensure they pass
6. Submit a pull request

## Security Considerations

- Always use a strong, random secret key in production
- Use HTTPS in production
- Regularly rotate JWT secret keys
- Implement proper CORS policies
- Use environment variables for sensitive configuration
- Enable database connection encryption in production

## License

MIT License - see LICENSE file for details.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: See `/docs` endpoint when running the API
- Examples: Check the `examples/` directory

## Changelog

### v0.2.0 (Latest)
- 📧 Added email service integration with AWS SES
- 🔑 Added password reset functionality
- 📝 Added email verification support (coming soon)
- 🔒 Enhanced security with token expiration and one-time use
- 📚 Updated documentation with email integration examples
- ✨ Added `PasswordResetRequest`, `PasswordResetConfirm`, and `PasswordChange` schemas
- 🗃️ Added `PasswordResetToken` database model

### v0.1.0
- Initial release
- JWT authentication
- User management
- Role-based access control
- SQLAlchemy support
- FastAPI integration
- Comprehensive test suite