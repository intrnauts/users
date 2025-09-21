from typing import Optional, AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from .models import Base

class DatabaseConfig:
    def __init__(
        self,
        database_url: str,
        echo: bool = False,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_pre_ping: bool = True
    ):
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_pre_ping = pool_pre_ping

class SyncDatabaseManager:
    """Synchronous database manager for SQLAlchemy"""

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = create_engine(
            config.database_url,
            echo=config.echo,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout,
            pool_pre_ping=config.pool_pre_ping
        )
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(bind=self.engine)

    def drop_tables(self):
        """Drop all tables"""
        Base.metadata.drop_all(bind=self.engine)

    def get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()

    def get_session_dependency(self):
        """FastAPI dependency for database session"""
        db = self.get_session()
        try:
            yield db
        finally:
            db.close()

class AsyncDatabaseManager:
    """Asynchronous database manager for SQLAlchemy"""

    def __init__(self, config: DatabaseConfig):
        self.config = config
        # Convert sync URL to async if needed
        async_url = config.database_url
        if async_url.startswith("postgresql://"):
            async_url = async_url.replace("postgresql://", "postgresql+asyncpg://")
        elif async_url.startswith("mysql://"):
            async_url = async_url.replace("mysql://", "mysql+aiomysql://")

        self.engine = create_async_engine(
            async_url,
            echo=config.echo,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout,
            pool_pre_ping=config.pool_pre_ping
        )
        self.AsyncSessionLocal = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def create_tables(self):
        """Create all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self):
        """Drop all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def get_session(self) -> AsyncSession:
        """Get async database session"""
        return self.AsyncSessionLocal()

    async def get_session_dependency(self) -> AsyncGenerator[AsyncSession, None]:
        """FastAPI dependency for async database session"""
        async with self.AsyncSessionLocal() as session:
            yield session

# MongoDB support (optional)
try:
    from motor.motor_asyncio import AsyncIOMotorClient
    from pymongo import MongoClient

    class MongoConfig:
        def __init__(
            self,
            connection_string: str,
            database_name: str,
            max_pool_size: int = 100,
            min_pool_size: int = 0,
            server_selection_timeout_ms: int = 5000
        ):
            self.connection_string = connection_string
            self.database_name = database_name
            self.max_pool_size = max_pool_size
            self.min_pool_size = min_pool_size
            self.server_selection_timeout_ms = server_selection_timeout_ms

    class MongoManager:
        """MongoDB database manager"""

        def __init__(self, config: MongoConfig):
            self.config = config
            self.client = MongoClient(
                config.connection_string,
                maxPoolSize=config.max_pool_size,
                minPoolSize=config.min_pool_size,
                serverSelectionTimeoutMS=config.server_selection_timeout_ms
            )
            self.database = self.client[config.database_name]

        def get_database(self):
            """Get MongoDB database"""
            return self.database

        def close(self):
            """Close MongoDB connection"""
            self.client.close()

    class AsyncMongoManager:
        """Async MongoDB database manager"""

        def __init__(self, config: MongoConfig):
            self.config = config
            self.client = AsyncIOMotorClient(
                config.connection_string,
                maxPoolSize=config.max_pool_size,
                minPoolSize=config.min_pool_size,
                serverSelectionTimeoutMS=config.server_selection_timeout_ms
            )
            self.database = self.client[config.database_name]

        def get_database(self):
            """Get async MongoDB database"""
            return self.database

        async def close(self):
            """Close async MongoDB connection"""
            self.client.close()

except ImportError:
    # MongoDB dependencies not installed
    class MongoConfig:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "MongoDB support requires 'motor' and 'pymongo'. "
                "Install with: pip install users[mongodb]"
            )

    class MongoManager:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "MongoDB support requires 'motor' and 'pymongo'. "
                "Install with: pip install users[mongodb]"
            )

    class AsyncMongoManager:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "MongoDB support requires 'motor' and 'pymongo'. "
                "Install with: pip install users[mongodb]"
            )

# Global database manager instances
_sync_db_manager: Optional[SyncDatabaseManager] = None
_async_db_manager: Optional[AsyncDatabaseManager] = None
_mongo_manager: Optional[MongoManager] = None
_async_mongo_manager: Optional[AsyncMongoManager] = None

def configure_sync_database(config: DatabaseConfig) -> SyncDatabaseManager:
    """Configure synchronous database"""
    global _sync_db_manager
    _sync_db_manager = SyncDatabaseManager(config)
    return _sync_db_manager

def configure_async_database(config: DatabaseConfig) -> AsyncDatabaseManager:
    """Configure asynchronous database"""
    global _async_db_manager
    _async_db_manager = AsyncDatabaseManager(config)
    return _async_db_manager

def configure_mongo_database(config: MongoConfig) -> MongoManager:
    """Configure MongoDB"""
    global _mongo_manager
    _mongo_manager = MongoManager(config)
    return _mongo_manager

def configure_async_mongo_database(config: MongoConfig) -> AsyncMongoManager:
    """Configure async MongoDB"""
    global _async_mongo_manager
    _async_mongo_manager = AsyncMongoManager(config)
    return _async_mongo_manager

def get_sync_db_manager() -> SyncDatabaseManager:
    """Get configured sync database manager"""
    if _sync_db_manager is None:
        raise RuntimeError("Sync database not configured")
    return _sync_db_manager

def get_async_db_manager() -> AsyncDatabaseManager:
    """Get configured async database manager"""
    if _async_db_manager is None:
        raise RuntimeError("Async database not configured")
    return _async_db_manager

def get_mongo_manager() -> MongoManager:
    """Get configured MongoDB manager"""
    if _mongo_manager is None:
        raise RuntimeError("MongoDB not configured")
    return _mongo_manager

def get_async_mongo_manager() -> AsyncMongoManager:
    """Get configured async MongoDB manager"""
    if _async_mongo_manager is None:
        raise RuntimeError("Async MongoDB not configured")
    return _async_mongo_manager