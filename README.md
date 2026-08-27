# Users Package

A flexible and robust user management package for FastAPI backends, providing authentication, authorization, and role-based access control (RBAC) out of the box.

## Features

- 🔐 **JWT Authentication** - Secure token-based authentication
- 👥 **User Management** - Complete CRUD operations for users
- 🛡️ **Role-Based Access Control (RBAC)** - Flexible permission system
- 📧 **Email Integration** - AWS SES and SMTP support for password reset and verification
- ✉️ **Email Verification** - Signup verification flow with configurable activation policy
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
- `POST /users/verify-email` - Confirm an email address with the token from the verification email
- `POST /users/verify-email/resend` - Request a fresh verification email
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

### Choosing a provider

| provider | transport | when to use |
|---|---|---|
| `resend` | HTTPS POST to the Resend API | **Default choice.** The only one that works where outbound SMTP is blocked — which is the case on most VPS hosts, DigitalOcean included. Needs `pip install 'users[resend]'`. |
| `ses` | HTTPS (boto3) | You already run on AWS. Also unaffected by SMTP blocks. |
| `smtp` | SMTP over implicit TLS (port 465) | Local development, or a host you know permits outbound SMTP. |

⚠️ **Check that outbound SMTP works before choosing `smtp`.** Many providers block ports
25/465/587 by default and do not announce it; sends then fail with a connection timeout at
request time, long after deployment. Test from the host itself:

```bash
nc -zv smtp.gmail.com 465     # times out if blocked
```

Whichever provider you pick, sending as your own domain requires **SPF and DKIM DNS
records** for it. Without them mail is delivered to spam, which looks like success from the
application's side.

### Environment Variables

```bash
# Email Configuration
EMAIL_ENABLED=True
EMAIL_PROVIDER=resend
EMAIL_SENDER_EMAIL=noreply@yourdomain.com
EMAIL_SENDER_NAME=Your App Name

# provider="resend"
RESEND_API_KEY=re_xxxxxxxxxxxx

# provider="ses"
AWS_REGION=us-east-1

# Password Reset
PASSWORD_RESET_URL_TEMPLATE=https://yourapp.com/reset-password?token={token}
```

### Security Features

Both the password reset and email verification flows share these properties:

- **Hashed at rest**: only a SHA-256 digest of each token is stored. The raw token
  exists in the email and nowhere else, so a database dump, leaked backup or SQL
  injection yields no usable link
- **Token expiration**: reset tokens expire after 1 hour, verification tokens after 24
- **One-time use**: tokens are burned on success and cannot be replayed
- **Email enumeration prevention**: the request endpoints always return success,
  whether or not the address belongs to an account
- **Secure token generation**: 256 bits of entropy from `secrets.token_urlsafe()`
- **Token invalidation**: issuing a new token deletes any outstanding ones

### Disable Email for Testing

During development or testing, you can disable email sending:

```python
email_config = EmailConfig(
    enabled=False  # Emails won't be sent, but tokens will be logged
)
```

When disabled, the reset token will be logged to the console instead of sent via email.

## Email Addresses Are Case-Insensitive

Addresses are trimmed and lowercased before they are stored or matched, so
`Manzoor@Example.com`, `manzoor@example.com` and `MANZOOR@EXAMPLE.COM` are one
account everywhere: registration, login, password reset and verification.

Domains are case-insensitive per RFC 5321, and while the local part is formally
case-sensitive, no mail provider treats it that way. PostgreSQL compares strings
case-sensitively, so without this the same person could hold two accounts and a
password reset could silently miss the one it did not match - silently, because
the endpoint is deliberately enumeration-safe and reports success either way.

Normalization happens in two places: a `BeforeValidator` on every schema that
carries an address, and again in `SQLAlchemyUserRepository`, so a caller that
builds a `UserCreate` by hand cannot bypass it. `normalize_email()` is exported
if you need the same canonical form in your own code.

```python
from users import normalize_email

normalize_email("  Manzoor@Example.COM ")  # "manzoor@example.com"
```

`username` is **not** normalized - it is a display name, and you may want to
preserve its casing. If you want usernames case-insensitive too, that is your
application's call.

### Migrating existing data

**Rows written before this change may hold mixed case, and those users will not
be found at login until they are backfilled.** Apply
`migrations/0002_normalize_email_case.py`.

If two accounts differ only by case, the migration aborts and names them rather
than half-applying:

```
RuntimeError: Cannot normalize email case: these addresses map to more than one account.

  dupe@example.com <- 2 accounts: 4:Dupe@Example.com, 5:dupe@example.com
```

Deciding which account survives is not something a migration should guess at.
Merge or delete the duplicates - checking which one owns the real data, including
rows in your own tables keyed on the user id - then run it again.

## Email Verification

New signups are emailed a verification link. Confirming it sets `is_verified`
and, by default, promotes the account from `pending` to `active`.

### Setup

```python
from users import setup_users_package, EmailConfig, VerificationConfig

setup_users_package(
    secret_key="your-secret-key",
    database_url="postgresql://user:pass@localhost/db",
    email_config=EmailConfig(
        provider="resend",
        api_key=os.getenv("RESEND_API_KEY"),
        sender_email="noreply@yourdomain.com",
        sender_name="Your App",
    ),
    verification_config=VerificationConfig(
        verification_url_template="https://yourapp.com/verify-email?token={token}",
        require_verified_email=True,
    ),
)
```

### Configuration

| Setting | Default | Effect |
|---|---|---|
| `send_verification_on_register` | `True` | Email a verification link from `create_user()` |
| `auto_activate_on_verify` | `True` | Move a `pending` user to `active` on verification. Set `False` to keep an admin approval step after verification |
| `require_verified_email` | `False` | Refuse login until the address is verified |
| `verification_token_ttl_hours` | `24` | Verification link lifetime |
| `password_reset_token_ttl_hours` | `1` | Reset link lifetime |
| `verification_url_template` | `None` | URL containing a `{token}` placeholder. Without one the email carries the bare token |

### Flow

```
POST /users/register        -> status=pending, is_verified=false, email sent
                               (status, is_superuser and roles in the request
                                body are ignored - see UserRegister)

# user clicks the link, your frontend reads ?token= and posts it back
POST /users/verify-email    {"token": "..."}
                            -> is_verified=true, status=active

POST /users/login           -> access token

# link expired or never arrived
POST /users/verify-email/resend  {"email": "user@example.com"}
```

`verify-email/resend` always returns success, whether or not the address exists,
so it cannot be used to enumerate accounts. Issuing a new token invalidates any
previous one.

### Keeping an admin approval step

With `auto_activate_on_verify=False`, verification proves the address but leaves
the account `pending`, and an admin still has to activate it:

```python
VerificationConfig(auto_activate_on_verify=False)
```

`POST /users/{user_id}/verify` remains available as an admin override that marks
a user verified and active without a token.

### Database migration

Email verification adds one table, `users.email_verification_tokens`. A ready
Alembic revision is in `migrations/0001_add_email_verification_tokens.py`:

```bash
cp migrations/0001_add_email_verification_tokens.py <your-project>/alembic/versions/
# set down_revision to your current head, then
alembic upgrade head
```

It creates the table and deletes the rows in `users.password_reset_tokens`.
Those rows hold plaintext tokens that digest lookup can no longer match, so they
are unusable but would still hand out a working reset link to anyone who reads
the table. Anyone mid-reset requests a new link.

For a brand new database, `setup_users_package(create_tables=True)` now creates
the `users` schema before the tables, so no manual `CREATE SCHEMA` is needed.

Users who registered before this change have `is_verified = false`. Leave
`require_verified_email` off until you have either backfilled them or asked them
to verify, or they will be locked out.

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
- Rate-limit `/users/login`, `/users/password-reset/request` and
  `/users/verify-email/resend` at your gateway - the package does not do this
- Note that a password reset does not revoke access tokens already issued to
  that user; they remain valid until they expire

## License

MIT License - see LICENSE file for details.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: See `/docs` endpoint when running the API
- Examples: Check the `examples/` directory

## Changelog

### v0.3.0 (Latest)
- 📧 Email addresses are now normalized to trimmed lowercase on both storage and
  lookup, so case can no longer split one mailbox across two accounts or make a
  password reset silently miss. Exported as `normalize_email()`.
  **Existing mixed-case rows need `migrations/0002_normalize_email_case.py`**
- ✉️ Added email verification for new signups: `POST /users/verify-email` and
  `POST /users/verify-email/resend`, the `EmailVerificationToken` model and
  `EmailVerificationConfirm` / `EmailVerificationResend` schemas
- ⚙️ Added `VerificationConfig` to control activation and login policy
- 🔒 Reset and verification tokens are now stored as SHA-256 digests rather than
  in plaintext. **Outstanding password reset links stop working on upgrade**
- 🛡️ `POST /users/register` now takes `UserRegister`, which ignores `status`,
  `is_superuser` and `roles`; `PUT /users/me` now takes `UserSelfUpdate`. Both
  previously accepted `UserCreate`/`UserUpdate` and allowed self-escalation
- 🐛 Fixed `change_password()` silently discarding the new password, and
  `verify_user()` silently discarding `is_verified` — both routed through
  `UserUpdate`, which has no such fields
- 🐛 Fixed `confirm_password_reset()` reaching into the repository's session
- 🐘 `create_tables()` now issues `CREATE SCHEMA IF NOT EXISTS` before creating
  tables. The models are schema-qualified (`schema='users'`), so bootstrapping a
  fresh PostgreSQL database previously failed with `InvalidSchemaName`
- 📌 Pinned `bcrypt<4.1` — passlib 1.7.4 raises `ValueError` on every hash with
  bcrypt 4.1+ — and declared the `pydantic[email]` extra that `EmailStr` needs

### v0.2.0
- 📧 Added email service integration with AWS SES
- 🔑 Added password reset functionality
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