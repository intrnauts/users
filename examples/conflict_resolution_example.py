"""
Example showing how to resolve conflicts when integrating with existing applications.

This example demonstrates:
1. How to use existing SQLAlchemy Base class
2. How to avoid metadata conflicts
"""

from fastapi import FastAPI
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Your existing application's Base class
AppBase = declarative_base()

# Example: Your existing model with a metadata column
class AppModel(AppBase):
    __tablename__ = "app_models"

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    metadata = Column(String(500))  # Your existing metadata column

# Configure the users package to use your existing Base
import users
users.configure_base(AppBase)

# Now the users package will use your Base class instead of creating its own
from users import (
    setup_users_package,
    create_user_router,
    User  # This will now inherit from AppBase, not users.Base
)

# Example FastAPI app
app = FastAPI(title="App with Users Package")

# Setup the users package
auth_manager, db_manager = setup_users_package(
    secret_key="your-secret-key-here",
    database_url="sqlite:///./test.db",
    create_tables=True
)

# Add user routes
app.include_router(
    create_user_router(),
    prefix="/api/users",
    tags=["users"]
)

# Verify that all models use the same Base
print(f"User model base: {User.__class__.__bases__}")
print(f"AppModel base: {AppModel.__class__.__bases__}")
print(f"Same metadata: {User.metadata is AppModel.metadata}")

# Example endpoint using both your models and user models
@app.get("/verify-integration")
async def verify_integration():
    return {
        "users_table": User.__tablename__,
        "app_table": AppModel.__tablename__,
        "same_base": User.__class__.__bases__ == AppModel.__class__.__bases__,
        "users_metadata_column": "user_metadata",  # Note: renamed to avoid conflict
        "app_metadata_column": "metadata"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)