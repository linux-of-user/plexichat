import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from sqlalchemy import create_engine

from plexichat.core.database_setup_wizard import database_wizard
from plexichat.core.external_database import (
    API,
    Comprehensive,
    Database,
    DatabaseEngine,
    DatabaseProvider,
    ExternalDatabaseConfig,
    ExternalDatabaseManager,
    PlexiChat,
    Setup,
    """,
    and,
    configuration,
    database,
    endpoints.,
    external_db_manager,
    from,
    import,
    plexichat.core.external_database,
    plexichat.infrastructure.utils.auth,
    setup,
    verify_admin_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/database/setup", tags=["database-setup"])
security = HTTPBearer()

class DatabaseTypeRequest(BaseModel):
    """Database type selection request."""
    database_type: str

class ConnectionDetailsRequest(BaseModel):
    """Connection details request."""
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = "plexichat"
    file_path: Optional[str] = None  # For SQLite

class AuthenticationRequest(BaseModel):
    """Authentication details request."""
    username: str
    password: str

class AdvancedSettingsRequest(BaseModel):
    """Advanced settings request."""
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    ssl_mode: Optional[str] = None
    charset: str = "utf8mb4"
    connect_timeout: int = 30

class SchemaInitRequest(BaseModel):
    """Schema initialization request."""
    create_sample_data: bool = False
    drop_existing: bool = False

class MigrationRequest(BaseModel):
    """Database migration request."""
    source_database_url: str
    backup_source: bool = True

class ExternalDatabaseRequest(BaseModel):
    """External database configuration request."""
    provider: str
    engine: str
    host: str
    port: int
    database: str
    username: str
    password: str
    ssl_enabled: bool = True
    ssl_mode: str = "require"
    pool_size: int = 10
    max_overflow: int = 20
    region: Optional[str] = None
    instance_id: Optional[str] = None

@router.get("/status")
async def get_setup_status():
    """Get current setup wizard status."""
    try:
        status = database_wizard.get_wizard_status()
        return {
            "success": True,
            "data": status
        }
    except Exception as e:
        logger.error(f"Failed to get setup status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/database-types")
async def get_database_types():
    """Get available database types."""
    try:
        types = database_wizard.get_database_types()
        return {
            "success": True,
            "data": types
        }
    except Exception as e:
        logger.error(f"Failed to get database types: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/database-type")
async def set_database_type(
    request: DatabaseTypeRequest,
    token: str = Depends(security)
):
    """Set the database type."""
    verify_admin_token(token.credentials)
    
    try:
        result = database_wizard.set_database_type(request.database_type)
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set database type: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/connection-details")
async def set_connection_details(
    request: ConnectionDetailsRequest,
    token: str = Depends(security)
):
    """Set database connection details."""
    verify_admin_token(token.credentials)
    
    try:
        details = request.dict(exclude_unset=True)
        result = database_wizard.set_connection_details(details)
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set connection details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/authentication")
async def set_authentication(
    request: AuthenticationRequest,
    token: str = Depends(security)
):
    """Set database authentication details."""
    verify_admin_token(token.credentials)
    
    try:
        auth_details = request.dict()
        result = database_wizard.set_authentication(auth_details)
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set authentication: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/advanced-settings")
async def set_advanced_settings(
    request: AdvancedSettingsRequest,
    token: str = Depends(security)
):
    """Set advanced database from plexichat.core.config import settings
settings."""
    verify_admin_token(token.credentials)
    
    try:
        settings = request.dict()
        result = database_wizard.set_advanced_settings(settings)
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set advanced settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/test-connection")
async def test_connection(token: str = Depends(security)):
    """Test database connection."""
    verify_admin_token(token.credentials)
    
    try:
        result = await database_wizard.test_connection()
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            return {
                "success": False,
                "error": result["error"],
                "data": result
            }
            
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/initialize-schema")
async def initialize_schema(
    request: SchemaInitRequest,
    token: str = Depends(security)
):
    """Initialize database schema."""
    verify_admin_token(token.credentials)
    
    try:
        options = request.dict()
        result = await database_wizard.initialize_schema(options)
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Schema initialization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/save-configuration")
async def save_configuration(token: str = Depends(security)):
    """Save database configuration."""
    verify_admin_token(token.credentials)
    
    try:
        result = database_wizard.save_configuration()
        
        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summary")
async def get_setup_summary(token: str = Depends(security)):
    """Get complete setup summary."""
    verify_admin_token(token.credentials)
    
    try:
        summary = database_wizard.get_setup_summary()
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        logger.error(f"Failed to get setup summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reset")
async def reset_wizard(token: str = Depends(security)):
    """Reset the setup wizard."""
    verify_admin_token(token.credentials)
    
    try:
        result = database_wizard.reset_wizard()
        return {
            "success": True,
            "message": result["message"],
            "data": result
        }
    except Exception as e:
        logger.error(f"Failed to reset wizard: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/migration/analyze")
async def analyze_migration(
    request: MigrationRequest,
    token: str = Depends(security)
):
    """Analyze database for migration."""
    verify_admin_token(token.credentials)
    
    try:
        result = database_wizard.get_migration_options(request.source_database_url)
        
        if result["success"]:
            return {
                "success": True,
                "data": result["migration_info"]
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Migration analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def get_database_health():
    """Get database health status."""
    try:
        # Check if database is configured and accessible
        status = database_wizard.get_wizard_status()
        
        if status["connection_configured"] and status["test_results"]:
            test_results = status["test_results"]
            
            return {
                "success": True,
                "data": {
                    "status": "healthy" if test_results.get("connection_successful") else "unhealthy",
                    "connection_successful": test_results.get("connection_successful", False),
                    "database_exists": test_results.get("database_exists", False),
                    "permissions_ok": test_results.get("permissions_ok", False),
                    "version_info": test_results.get("version_info"),
                    "response_time_ms": test_results.get("response_time_ms", 0),
                    "last_tested": "recently"
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "status": "not_configured",
                    "message": "Database setup not completed"
                }
            }
            
    except Exception as e:
        logger.error(f"Failed to get database health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# External Database Endpoints

@router.get("/external/providers")
async def get_external_providers():
    """Get supported external database providers."""
    try:
        providers = external_db_manager.get_supported_providers()
        return {
            "success": True,
            "data": {
                "providers": providers,
                "total_count": len(providers)
            }
        }
    except Exception as e:
        logger.error(f"Failed to get external providers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/external/provider/{provider}/guide")
async def get_provider_setup_guide(provider: str):
    """Get setup guide for specific external database provider."""
    try:
        provider_enum = DatabaseProvider(provider)
        guide = external_db_manager.get_provider_setup_guide(provider_enum)
        provider_info = external_db_manager.get_provider_info(provider_enum)

        return {
            "success": True,
            "data": {
                "provider": provider,
                "provider_info": provider_info,
                "setup_guide": guide
            }
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")
    except Exception as e:
        logger.error(f"Failed to get provider guide: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/external/configure")
async def configure_external_database(
    request: ExternalDatabaseRequest,
    token: str = Depends(security)
):
    """Configure external database connection."""
    verify_admin_token(token.credentials)

    try:
        # Create configuration object
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider(request.provider),
            engine=DatabaseEngine(request.engine),
            host=request.host,
            port=request.port,
            database=request.database,
            username=request.username,
            password=request.password,
            ssl_enabled=request.ssl_enabled,
            ssl_mode=request.ssl_mode,
            pool_size=request.pool_size,
            max_overflow=request.max_overflow,
            region=request.region,
            instance_id=request.instance_id
        )

        result = await external_db_manager.configure_external_database(config)

        if result["success"]:
            return {
                "success": True,
                "message": result["message"],
                "data": result
            }
        else:
            raise HTTPException(status_code=400, detail=result["error"])

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {e}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to configure external database: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/external/health")
async def get_external_database_health(token: str = Depends(security)):
    """Get external database health status."""
    verify_admin_token(token.credentials)

    try:
        health = await external_db_manager.get_connection_health()
        return {
            "success": True,
            "data": health
        }
    except Exception as e:
        logger.error(f"Failed to get external database health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/external/test")
async def test_external_database(
    request: ExternalDatabaseRequest,
    token: str = Depends(security)
):
    """Test external database connection without saving configuration."""
    verify_admin_token(token.credentials)

    try:
        # Create temporary configuration
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider(request.provider),
            engine=DatabaseEngine(request.engine),
            host=request.host,
            port=request.port,
            database=request.database,
            username=request.username,
            password=request.password,
            ssl_enabled=request.ssl_enabled,
            ssl_mode=request.ssl_mode
        )

        # Create temporary manager for testing
        temp_manager = ExternalDatabaseManager()
        temp_manager.config = config

        temp_manager.engine = create_engine(config.get_connection_string())

        result = await temp_manager._test_external_connection()

        return {
            "success": result["success"],
            "data": result["test_results"],
            "message": "Connection test completed" if result["success"] else "Connection test failed"
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {e}")
    except Exception as e:
        logger.error(f"External database test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
