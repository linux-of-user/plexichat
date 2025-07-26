# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import os
from datetime import datetime
from typing import Optional


from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from plexichat.app.database.database_manager import ()
import stat
import time

    API,
    Database,
    DatabaseConfig,
    DatabaseType,
    Management,
    PlexiChat.,
    Provides,
    """,
    administration,
    and,
    capabilities.,
    database,
    endpoints,
    for,
    from,
    get_database_manager,
    import,
    logger,
    migration,
    monitoring,
    plexichat.app.logger_config,
)


# Pydantic models for API
class DatabaseConfigRequest(BaseModel):
    db_type: str
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = "plexichat"
    username: Optional[str] = None
    password: Optional[str] = None
    file_path: Optional[str] = None
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    echo: bool = False
    ssl_mode: Optional[str] = None
    charset: str = "utf8mb4"


class BackupRequest(BaseModel):
    backup_path: str
    include_timestamp: bool = True


class RestoreRequest(BaseModel):
    backup_path: str
    confirm: bool = False


class MigrationRequest(BaseModel):
    target_config: DatabaseConfigRequest
    backup_source: bool = True


router = APIRouter(prefix="/api/v1/database", tags=["Database Management"])


@router.get("/info")
async def get_database_info():
    """Get database information and statistics."""
    try:
        manager = await get_database_manager()
        info = await manager.get_database_info()

        return {
            "success": True,
            "database_info": info
        }

    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/test")
async def test_database_connection():
    """Test database connection and performance."""
    try:
        manager = await get_database_manager()
        test_result = await manager.test_connection()

        return {
            "success": True,
            "connection_test": test_result
        }

    except Exception as e:
        logger.error(f"Failed to test database connection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/supported_types")
async def get_supported_database_types():
    """Get list of supported database types."""
    return {
        "success": True,
        "supported_types": [
            {
                "type": db_type.value,
                "name": db_type.value.title(),
                "description": f"{db_type.value.title()} database support"
            }
            for db_type in DatabaseType
        ]
    }


@router.post("/backup")
async def create_database_backup()
    request: BackupRequest,
    background_tasks: BackgroundTasks
):
    """Create a database backup."""
    try:
        manager = await get_database_manager()

        # Add timestamp to backup path if requested
        backup_path = request.backup_path
        if request.include_timestamp:
timestamp = datetime.now()
datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
            name, ext = os.path.splitext(backup_path)
            backup_path = f"{name}_{timestamp}{ext}"

        # Ensure backup directory exists
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)

        # Create backup in background
        background_tasks.add_task(manager.backup_database, backup_path)

        return {
            "success": True,
            "message": "Database backup started",
            "backup_path": backup_path,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to create database backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/restore")
async def restore_database_backup()
    request: RestoreRequest,
    background_tasks: BackgroundTasks
):
    """Restore database from backup."""
    try:
        if not request.confirm:
            raise HTTPException()
                status_code=400,
                detail="Database restore requires confirmation. Set 'confirm' to true."
            )

        if not os.path.exists(request.backup_path):
            raise HTTPException()
                status_code=404,
                detail=f"Backup file not found: {request.backup_path}"
            )

        manager = await get_database_manager()

        # Restore database in background
        background_tasks.add_task(manager.restore_database, request.backup_path)

        return {
            "success": True,
            "message": "Database restore started",
            "backup_path": request.backup_path,
            "timestamp": datetime.now().isoformat(),
            "warning": "Database will be unavailable during restore process"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore database: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/migrate")
async def migrate_database()
    request: MigrationRequest,
    background_tasks: BackgroundTasks
):
    """Migrate database to a different type or location."""
    try:
        manager = await get_database_manager()

        # Validate target database type
        try:
            target_db_type = DatabaseType(request.target_config.db_type)
        except ValueError:
            raise HTTPException()
                status_code=400,
                detail=f"Unsupported database type: {request.target_config.db_type}"
            )

        # Create target database config
        target_config = DatabaseConfig()
            db_type=target_db_type,
            host=request.target_config.host,
            port=request.target_config.port,
            database=request.target_config.database,
            username=request.target_config.username,
            password=request.target_config.password,
            file_path=request.target_config.file_path,
            pool_size=request.target_config.pool_size,
            max_overflow=request.target_config.max_overflow,
            pool_timeout=request.target_config.pool_timeout,
            echo=request.target_config.echo,
            ssl_mode=request.target_config.ssl_mode,
            charset=request.target_config.charset
        )

        # Create backup if requested
        if request.backup_source:
            backup_path = f"backups/pre_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            await manager.backup_database(backup_path)

        # Start migration in background
        background_tasks.add_task(manager.migrate_to_database, target_config)

        return {
            "success": True,
            "message": "Database migration started",
            "source_type": manager.config.db_type.value,
            "target_type": target_config.db_type.value,
            "backup_created": request.backup_source,
            "timestamp": datetime.now().isoformat(),
            "warning": "Database will be unavailable during migration process"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to migrate database: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reconnect")
async def reconnect_database():
    """Reconnect to the database."""
    try:
        manager = await get_database_manager()

        # Disconnect and reconnect
        await manager.disconnect()
        success = await manager.connect()

        if success:
            return {
                "success": True,
                "message": "Database reconnected successfully",
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise HTTPException()
                status_code=500,
                detail="Failed to reconnect to database"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reconnect database: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backups")
async def list_database_backups(backup_dir: str = "backups"):
    """List available database backups."""
    try:
        if not os.path.exists(backup_dir):
            return {
                "success": True,
                "backups": [],
                "backup_directory": backup_dir,
                "message": "Backup directory does not exist"
            }

        backups = []
        for filename in os.listdir(backup_dir):
            file_path = os.path.join(backup_dir, filename)
            if os.path.isfile(file_path):
                stat = os.stat(file_path)
                backups.append({)
                    "filename": filename,
                    "path": file_path,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })

        # Sort by creation time (newest first)
        backups.sort(key=lambda b: b["created_at"], reverse=True)

        return {
            "success": True,
            "backups": backups,
            "backup_directory": backup_dir,
            "total_backups": len(backups)
        }

    except Exception as e:
        logger.error(f"Failed to list database backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/backups/{filename}")
async def delete_database_backup(filename: str, backup_dir: str = "backups"):
    """Delete a database backup file."""
    try:
        file_path = os.path.join(backup_dir, filename)

        if not os.path.exists(file_path):
            raise HTTPException()
                status_code=404,
                detail=f"Backup file not found: {filename}"
            )

        # Security check - ensure file is in backup directory
        if not os.path.abspath(file_path).startswith(os.path.abspath(backup_dir)):
            raise HTTPException()
                status_code=400,
                detail="Invalid backup file path"
            )

        os.remove(file_path)

        return {
            "success": True,
            "message": f"Backup file deleted: {filename}",
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete backup file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_database_statistics():
    """Get comprehensive database statistics."""
    try:
        manager = await get_database_manager()

        # Get basic info
        info = await manager.get_database_info()

        # Get connection test
        connection_test = await manager.test_connection()

        # Calculate additional statistics
        stats = {
            "database_type": info.get("database_type"),
            "database_name": info.get("database_name"),
            "is_connected": info.get("is_connected"),
            "table_count": info.get("table_count", 0),
            "connection_response_time_ms": connection_test.get("response_time_ms"),
            "last_test_successful": connection_test.get("success"),
            "engine_info": info.get("engine_info", {}),
            "timestamp": datetime.now().isoformat()
        }

        # Add database-specific stats
        if "file_size" in info:
            stats["file_size_bytes"] = info["file_size"]
            stats["file_size_mb"] = round(info["file_size"] / (1024 * 1024), 2)

        if "version" in info:
            stats["database_version"] = info["version"]

        return {
            "success": True,
            "statistics": stats
        }

    except Exception as e:
        logger.error(f"Failed to get database statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize")
async def optimize_database():
    """Optimize database performance."""
    try:
        manager = await get_database_manager()

        optimization_results = []

        if manager.config.db_type == DatabaseType.SQLITE:
            # SQLite optimization using abstraction layer
            try:
                await manager.optimize_database()
                optimization_results.append("Database optimization completed")
            except Exception as e:
                optimization_results.append(f"Optimization failed: {str(e)}")

        elif manager.config.db_type == DatabaseType.POSTGRESQL:
            # PostgreSQL optimization
            with manager.engine.connect() as conn:
                # Analyze tables
                conn.execute("ANALYZE")
                optimization_results.append("Table statistics updated")

        elif manager.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            # MySQL/MariaDB optimization
            with manager.engine.connect() as conn:
                # Analyze tables
                inspector = inspect(manager.engine)
                tables = inspector.get_table_names()

                for table in tables:
                    conn.execute(f"ANALYZE TABLE {table}")

                optimization_results.append(f"Analyzed {len(tables)} tables")

        return {
            "success": True,
            "message": "Database optimization completed",
            "optimizations": optimization_results,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to optimize database: {e}")
        raise HTTPException(status_code=500, detail=str(e))
