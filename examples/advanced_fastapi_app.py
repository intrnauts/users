"""
Advanced FastAPI application example using the users package.

This example demonstrates:
- Role-based access control (RBAC)
- Custom permissions
- Database initialization with default data
- Multiple routers
- Advanced configuration
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn

# Import the users package
from users import (
    setup_users_package,
    create_user_router,
    create_role_router,
    create_permission_router,
    get_current_active_user,
    require_permission,
    require_role,
    UserResponse,
    UserCreate,
    create_default_permissions,
    create_default_roles,
    get_sync_db_manager,
    RoleRepository,
    PermissionRepository,
    UserService,
    RoleService,
    PermissionService
)

# Database initialization
async def init_database():
    """Initialize database with default roles and permissions"""

    # Get database session
    db_manager = get_sync_db_manager()
    db = db_manager.get_session()

    try:
        # Create repositories and services
        role_repo = RoleRepository(db)
        permission_repo = PermissionRepository(db)
        permission_service = PermissionService(permission_repo)
        role_service = RoleService(role_repo)

        # Create default permissions
        permissions_data = create_default_permissions()
        for perm_data in permissions_data:
            try:
                await permission_service.create_permission(**perm_data)
            except Exception:
                # Permission already exists
                pass

        # Create default roles
        roles_data = create_default_roles()
        for role_name, role_data in roles_data.items():
            try:
                await role_service.create_role(**role_data)
            except Exception:
                # Role already exists
                pass

        print("Database initialized with default roles and permissions")

    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    await init_database()
    yield
    # Shutdown
    pass

# Create FastAPI app with lifespan
app = FastAPI(
    title="Advanced Users Package Example API",
    description="Advanced example API showcasing RBAC and permissions",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Configure the users package
auth_manager, db_manager = setup_users_package(
    secret_key="advanced-secret-key-change-in-production",
    database_url="sqlite:///./advanced_users.db",
    access_token_expire_minutes=60,
    create_tables=True
)

# Include routers
user_router = create_user_router(
    prefix="/api/users",
    tags=["User Management"],
    include_auth=True,
    include_admin=True
)

role_router = create_role_router(
    prefix="/api/roles",
    tags=["Role Management"]
)

permission_router = create_permission_router(
    prefix="/api/permissions",
    tags=["Permission Management"]
)

app.include_router(user_router)
app.include_router(role_router)
app.include_router(permission_router)

# Example routes with different permission levels

@app.get("/api/public")
async def public_route():
    """Public route - no authentication required"""
    return {"message": "This is a public endpoint"}

@app.get("/api/authenticated")
async def authenticated_route(current_user: UserResponse = Depends(get_current_active_user)):
    """Authenticated route - requires valid token"""
    return {
        "message": f"Hello authenticated user {current_user.email}!",
        "user_id": current_user.id
    }

@app.get("/api/admin-only")
async def admin_only_route(
    current_user: UserResponse = Depends(require_role("admin"))
):
    """Admin-only route - requires admin role"""
    return {
        "message": "This is an admin-only endpoint",
        "admin_user": current_user.email
    }

@app.get("/api/user-readers")
async def user_readers_route(
    current_user: UserResponse = Depends(require_permission("users:read"))
):
    """Route for users with read permission"""
    return {
        "message": "You have permission to read users",
        "user": current_user.email
    }

@app.get("/api/user-managers")
async def user_managers_route(
    current_user: UserResponse = Depends(require_role("user_manager"))
):
    """Route for user managers"""
    return {
        "message": "Welcome, user manager!",
        "manager": current_user.email
    }

@app.post("/api/admin/create-admin-user")
async def create_admin_user(
    user_data: UserCreate,
    current_user: UserResponse = Depends(require_role("admin"))
):
    """Create admin user - admin only"""
    # This would typically use the user service
    return {
        "message": f"Admin user creation requested by {current_user.email}",
        "new_user_email": user_data.email
    }

# Analytics endpoints (example of granular permissions)
@app.get("/api/analytics/users")
async def user_analytics(
    current_user: UserResponse = Depends(require_permission("users:read"))
):
    """User analytics - requires users:read permission"""
    return {
        "total_users": 100,
        "active_users": 85,
        "new_users_this_month": 15
    }

@app.get("/api/analytics/admin")
async def admin_analytics(
    current_user: UserResponse = Depends(require_permission("users:admin"))
):
    """Admin analytics - requires admin permissions"""
    return {
        "system_health": "good",
        "database_size": "50MB",
        "active_sessions": 25,
        "security_events": 2
    }

# Multi-permission example
from users import RequirePermissions

@app.get("/api/reports/comprehensive")
async def comprehensive_reports(
    current_user: UserResponse = Depends(
        RequirePermissions(["users:read", "roles:read"])
    )
):
    """Comprehensive reports - requires multiple permissions"""
    return {
        "message": "Comprehensive report data",
        "requested_by": current_user.email,
        "required_permissions": ["users:read", "roles:read"]
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return {
        "error": True,
        "message": exc.detail,
        "status_code": exc.status_code
    }

# Health check with authentication status
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "advanced-users-api",
        "features": [
            "authentication",
            "authorization",
            "rbac",
            "user_management",
            "role_management",
            "permission_management"
        ]
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with comprehensive API information"""
    return {
        "message": "Advanced Users Package Example API",
        "version": "1.0.0",
        "documentation": "/docs",
        "features": {
            "authentication": "JWT-based authentication",
            "authorization": "Role-based access control (RBAC)",
            "user_management": "Full CRUD operations for users",
            "role_management": "Dynamic role creation and assignment",
            "permission_management": "Granular permission system"
        },
        "endpoints": {
            "public": "GET /api/public",
            "authentication": {
                "register": "POST /api/users/register",
                "login": "POST /api/users/login",
                "profile": "GET /api/users/me"
            },
            "user_management": {
                "list_users": "GET /api/users/",
                "get_user": "GET /api/users/{user_id}",
                "update_user": "PUT /api/users/{user_id}",
                "delete_user": "DELETE /api/users/{user_id}"
            },
            "role_management": {
                "list_roles": "GET /api/roles/",
                "create_role": "POST /api/roles/",
                "delete_role": "DELETE /api/roles/{role_id}"
            },
            "examples": {
                "authenticated": "GET /api/authenticated",
                "admin_only": "GET /api/admin-only",
                "user_readers": "GET /api/user-readers",
                "user_managers": "GET /api/user-managers",
                "comprehensive_reports": "GET /api/reports/comprehensive"
            }
        },
        "default_roles": ["admin", "user_manager", "viewer"],
        "sample_permissions": [
            "users:read", "users:write", "users:delete", "users:admin",
            "roles:read", "roles:write", "roles:delete", "roles:admin"
        ]
    }

if __name__ == "__main__":
    uvicorn.run(
        "advanced_fastapi_app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )