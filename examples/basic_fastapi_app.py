"""
Basic FastAPI application example using the users package.

This example shows how to integrate the users package into a FastAPI application
with SQLite database and basic authentication.
"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import the users package
from users import (
    setup_users_package,
    create_user_router,
    get_current_active_user,
    UserResponse
)

# Create FastAPI app
app = FastAPI(
    title="Users Package Example API",
    description="Example API using the users package for authentication and user management",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure the users package
auth_manager, db_manager = setup_users_package(
    secret_key="your-secret-key-change-this-in-production",
    database_url="sqlite:///./users_example.db",
    create_tables=True
)

# Include user routes
user_router = create_user_router(
    prefix="/api/users",
    tags=["users"],
    include_auth=True,
    include_admin=True
)
app.include_router(user_router)

# Example protected route
@app.get("/api/protected")
async def protected_route(current_user: UserResponse = Depends(get_current_active_user)):
    """Example of a protected route that requires authentication"""
    return {
        "message": f"Hello {current_user.email}!",
        "user_id": current_user.id,
        "roles": current_user.roles
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "users-example-api"}

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Users Package Example API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "register": "POST /api/users/register",
            "login": "POST /api/users/login",
            "me": "GET /api/users/me",
            "protected": "GET /api/protected"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "basic_fastapi_app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )